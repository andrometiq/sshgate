package main

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

type fixture struct {
	mountIDs  []uint64
	devices   []*os.File
	log       *os.File
	data      []byte
	subtype   bool
	writeback bool
	failures  chan error
	workers   sync.WaitGroup
	mu        sync.Mutex
	failure   error
	stopping  bool
}

func mountDevice(point string, subtype bool) (*os.File, error) {
	if os.Geteuid() == 0 {
		fd, err := unix.Open("/dev/fuse", unix.O_RDWR|unix.O_CLOEXEC, 0)
		if err != nil {
			return nil, err
		}
		kind := "fuse"
		if subtype {
			kind = "fuse.sgtest"
		}
		options := fmt.Sprintf("fd=%d,rootmode=40000,user_id=%d,group_id=%d", fd, os.Getuid(), os.Getgid())
		if err = unix.Mount("sgtest", point, kind, unix.MS_NOSUID|unix.MS_NODEV, options); err != nil {
			unix.Close(fd)
			return nil, err
		}
		return os.NewFile(uintptr(fd), "/dev/fuse"), nil
	}
	pair, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	parent, child := os.NewFile(uintptr(pair[0]), "fuse-parent"), os.NewFile(uintptr(pair[1]), "fuse-child")
	defer parent.Close()
	defer child.Close()
	options := "rw,nosuid,nodev,fsname=sgtest"
	if subtype {
		options += ",subtype=sgtest"
	}
	command := exec.Command("fusermount3", "-o", options, "--", point)
	command.Env = append(os.Environ(), "_FUSE_COMMFD=3")
	command.ExtraFiles = []*os.File{child}
	command.Stderr = os.Stderr
	if err = command.Start(); err != nil {
		return nil, err
	}
	child.Close()
	// A deadline prevents a broken helper from hanging CI before its setup verdict.
	unix.SetsockoptTimeval(pair[0], unix.SOL_SOCKET, unix.SO_RCVTIMEO, &unix.Timeval{Sec: 10})
	payload, control := make([]byte, 1), make([]byte, unix.CmsgSpace(4))
	var n int
	var receiveErr error
	for {
		_, n, _, _, receiveErr = unix.Recvmsg(pair[0], payload, control, 0)
		if receiveErr != unix.EINTR {
			break
		}
	}
	if receiveErr != nil {
		command.Process.Kill()
		command.Wait()
		return nil, receiveErr
	}
	messages, err := unix.ParseSocketControlMessage(control[:n])
	if err != nil {
		command.Process.Kill()
		command.Wait()
		return nil, err
	}
	var received []int
	for _, message := range messages {
		fds, e := unix.ParseUnixRights(&message)
		if e != nil {
			err = e
			break
		}
		received = append(received, fds...)
	}
	waitErr := command.Wait()
	if err != nil || waitErr != nil || len(received) != 1 {
		for _, fd := range received {
			unix.Close(fd)
		}
		return nil, fmt.Errorf("fusermount fd handoff: descriptors=%d parse=%v helper=%v", len(received), err, waitErr)
	}
	unix.CloseOnExec(received[0])
	return os.NewFile(uintptr(received[0]), "/dev/fuse"), nil
}

func (f *fixture) fuse(point string) error {
	device, err := mountDevice(point, f.subtype)
	if err != nil {
		return err
	}
	f.devices = append(f.devices, device)
	ready := make(chan struct{})
	f.workers.Add(1)
	go func() {
		defer f.workers.Done()
		s := server{writeback: f.writeback, log: f.log, data: append([]byte(nil), f.data...), uid: uint32(os.Getuid()), gid: uint32(os.Getgid())}
		buffer := make([]byte, 256*1024)
		initialized := false
		for {
			n, err := device.Read(buffer)
			if errors.Is(err, unix.ENODEV) || errors.Is(err, os.ErrClosed) {
				f.mu.Lock()
				stopping := f.stopping
				f.mu.Unlock()
				if !stopping {
					f.fail(err)
				}
				return
			}
			if err != nil {
				f.fail(err)
				return
			}
			request := buffer[:n]
			response, err := s.dispatch(request)
			if err != nil {
				f.fail(err)
				return
			}
			if response != nil {
				if _, err = device.Write(response); err != nil {
					f.fail(err)
					return
				}
			}
			if !initialized && len(request) >= 48 && wire.Uint32(request[4:]) == 26 && wire.Uint32(request[40:]) == 7 {
				initialized = true
				close(ready)
			}
		}
	}()
	select {
	case <-ready:
		return f.rememberMount(point)
	case err := <-f.failures:
		return err
	case <-time.After(10 * time.Second):
		return fmt.Errorf("FUSE INIT timeout")
	}
}

func (f *fixture) tmpfs(point string) error {
	if err := unix.Mount("tmpfs", point, "tmpfs", unix.MS_NOSUID|unix.MS_NODEV, "mode=0755"); err != nil {
		return err
	}
	if err := f.rememberMount(point); err != nil {
		return err
	}
	return nil
}
func (f *fixture) rememberMount(point string) error {
	var state unix.Statx_t
	if err := unix.Statx(unix.AT_FDCWD, point, unix.AT_STATX_DONT_SYNC, unix.STATX_MNT_ID, &state); err != nil {
		return err
	}
	if state.Mask&unix.STATX_MNT_ID == 0 {
		return fmt.Errorf("mount identity unavailable for %s", point)
	}
	f.mountIDs = append(f.mountIDs, state.Mnt_id)
	return nil
}

func mountPointForID(id uint64) (string, error) {
	data, err := os.ReadFile("/proc/self/mountinfo")
	if err != nil {
		return "", err
	}
	return mountPointFromInfo(string(data), id)
}
func mountPointFromInfo(info string, id uint64) (string, error) {
	for _, line := range strings.Split(info, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 6 {
			continue
		}
		number, err := strconv.ParseUint(fields[0], 10, 64)
		if err != nil {
			return "", err
		}
		if number == id {
			return strings.NewReplacer("\\040", " ", "\\011", "\t", "\\012", "\n", "\\134", "\\").Replace(fields[4]), nil
		}
	}
	return "", fmt.Errorf("owned mount %d disappeared", id)
}

func (f *fixture) fail(err error) {
	f.mu.Lock()
	f.failure = errors.Join(f.failure, err)
	f.mu.Unlock()
	select {
	case f.failures <- err:
	default:
	}
}

func (f *fixture) close() error {
	f.mu.Lock()
	f.stopping = true
	f.mu.Unlock()
	for i := len(f.mountIDs) - 1; i >= 0; i-- {
		point, err := mountPointForID(f.mountIDs[i])
		if err != nil {
			f.fail(err)
			continue
		}
		if err = unix.Unmount(point, unix.MNT_DETACH); err != nil {
			if os.Geteuid() != 0 {
				output, fallbackErr := exec.Command("fusermount3", "-uz", "--", point).CombinedOutput()
				if fallbackErr != nil {
					f.fail(fmt.Errorf("unmount %s: %w; fusermount: %v: %s", point, err, fallbackErr, output))
				}
			} else {
				f.fail(fmt.Errorf("unmount %s: %w", point, err))
			}
		}
	}
	for _, device := range f.devices {
		if err := device.Close(); err != nil {
			f.fail(fmt.Errorf("close FUSE device: %w", err))
		}
	}

	f.workers.Wait()
	f.mu.Lock()
	defer f.mu.Unlock()
	verdict := "VERDICT ok\n"
	if f.failure != nil {
		verdict = "VERDICT fail " + strings.ReplaceAll(f.failure.Error(), "\n", "; ") + "\n"
	}
	_, err := f.log.WriteString(verdict)
	return errors.Join(f.failure, err, f.log.Sync())
}

func run() (result error) {
	point := flag.String("mount", "", "FUSE mount point")
	logPath := flag.String("log", "", "outside request log")
	writeback := flag.Bool("writeback", false, "buffer writes in the kernel page cache")
	subtype := flag.Bool("subtype", false, "mount as fuse.sgtest")
	nested := flag.Bool("nested", false, "mount another FUSE at nested/")
	over := flag.String("stack-over", "", "tmpfs then FUSE")
	under := flag.String("stack-under", "", "FUSE then tmpfs")
	stack := flag.String("stack3", "", "tmpfs/FUSE/tmpfs/FUSE")
	overlay := flag.String("overlay", "", "overlay view (FUSE lower at --mount)")
	loop := flag.String("loop", "", "root CI tmpfs-backed ext4 mount point")
	ci := flag.Bool("ci", false, "disposable CI root fixtures authorized")
	content := flag.String("content", "", "file supplying f contents (default fixture data)")
	flag.Parse()
	if *loop != "" {
		if !*ci || os.Geteuid() != 0 {
			return fmt.Errorf("loop requires root and --ci")
		}
		return loopFixture(*loop)
	}
	if *logPath == "" {
		return fmt.Errorf("--log is required")
	}
	modes := 0
	for _, p := range []string{*over, *under, *stack, *overlay} {
		if p != "" {
			modes++
		}
	}
	if modes > 1 {
		return fmt.Errorf("stack/overlay modes are exclusive")
	}
	for _, p := range []string{*over, *under, *stack} {
		if p != "" {
			*point = p
		}
	}
	if *point == "" {
		return fmt.Errorf("--mount or stack point is required")
	}
	absolute, err := filepath.Abs(*point)
	if err != nil {
		return err
	}
	*point = absolute
	if err = os.MkdirAll(*point, 0755); err != nil {
		return err
	}
	log, err := os.OpenFile(*logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
	if err != nil {
		return err
	}
	defer log.Close()
	data := []byte("fixture\n")
	if *content != "" {
		data, err = os.ReadFile(*content)
		if err != nil {
			return err
		}
	}
	f := &fixture{writeback: *writeback, log: log, data: data, subtype: *subtype, failures: make(chan error, 8)}
	defer func() { result = errors.Join(result, f.close()) }()
	if *over != "" || *stack != "" {
		if err = f.tmpfs(*point); err != nil {
			return err
		}
	}
	if err = f.fuse(*point); err != nil {
		return err
	}
	if *under != "" || *stack != "" {
		if err = f.tmpfs(*point); err != nil {
			return err
		}
		if err = os.WriteFile(filepath.Join(*point, "f"), data, 0644); err != nil {
			return err
		}
	}
	if *stack != "" {
		if err = f.fuse(*point); err != nil {
			return err
		}
	}
	if *nested {
		if err = f.fuse(filepath.Join(*point, "nested")); err != nil {
			return err
		}
	}
	if *overlay != "" {
		if strings.ContainsAny(*point+*overlay, ",:\\") {
			return fmt.Errorf("overlay paths contain mount-option separators")
		}
		second := *overlay + "-lower"
		if err = os.MkdirAll(second, 0755); err != nil {
			return err
		}
		if err = f.tmpfs(second); err != nil {
			return err
		}
		if err = os.MkdirAll(*overlay, 0755); err != nil {
			return err
		}
		if err = unix.Mount("overlay", *overlay, "overlay", unix.MS_RDONLY, "lowerdir="+*point+":"+second); err != nil {
			return err
		}
		if err = f.rememberMount(*overlay); err != nil {
			return err
		}
	}
	fmt.Println("READY pid=" + strconv.Itoa(os.Getpid()))
	signals := make(chan os.Signal, 1)
	signal.Notify(signals, syscall.SIGTERM, syscall.SIGINT, syscall.SIGUSR1)
	defer signal.Stop(signals)
	for {
		select {
		case sig := <-signals:
			if sig != syscall.SIGUSR1 {
				return nil
			}
			// Requests record their effects before replying. The caller sends this only
			// after its synchronous operation completed; Sync is the record barrier.
			if _, err := f.log.WriteString("BARRIER\n"); err != nil {
				f.fail(err)
				return err
			}
			if err := f.log.Sync(); err != nil {
				f.fail(err)
				return err
			}
		case err := <-f.failures:
			return err
		}
	}
}
func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "SETUP:", err)
		os.Exit(1)
	}
}
