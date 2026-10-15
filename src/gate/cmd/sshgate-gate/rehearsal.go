package main

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"time"
	"unsafe"

	"github.com/karthikeyan5/sshgate/src/gate"
	"github.com/karthikeyan5/sshgate/src/gate/confine"
	"golang.org/x/sys/unix"
)

// The rehearsal runs the selftest's probe menu inside the real read jail,
// under a candidate pin's Spec, against fixtures built here and proved live,
// and checks every effect from outside. The selftest's own report is an
// attestation; the outside checks decide.

// Test-only seams (package variables, never the environment).
var (
	// selftestBinaryFn names the binary the rehearsal runs as the selftest.
	// Tests point it at a non-race build: a race-built binary never runs
	// under the jail's seccomp filter.
	selftestBinaryFn = selftestBinary
	// rehearsalSpecHook adjusts the rehearsal's Spec (ForceABI).
	rehearsalSpecHook func(*confine.Spec)
	// rehearsalObserveHook sees the result after the outside checks.
	rehearsalObserveHook func(*rehearsalResult)
	// fixtureTmp is where the /tmp canary goes: the host's /tmp, which the
	// jail shows read-only.
	fixtureTmp = "/tmp"
)

// selftestBinary is the running gate binary, provided the file at its path is
// the one running.
func selftestBinary() (string, error) {
	path, err := os.Executable()
	if err != nil {
		return "", err
	}
	var onDisk, running unix.Stat_t
	if err := unix.Lstat(path, &onDisk); err != nil {
		return "", err
	}
	if err := unix.Stat("/proc/self/exe", &running); err != nil {
		return "", err
	}
	if onDisk.Dev != running.Dev || onDisk.Ino != running.Ino {
		return "", errors.New("the gate binary on disk is not the running one")
	}
	return path, nil
}

// rehearsalRow is one selftest row: its errno name, whether it was reported,
// and whether that errno is in the row's set.
type rehearsalRow struct {
	Name      string `json:"name"`
	Errno     string `json:"errno"`
	Attempted bool   `json:"attempted"`
	Pass      bool   `json:"pass"`
}

// rehearsalResult is one rehearsal. Skipped says why it could not run;
// Failures lists every check that did not hold.
type rehearsalResult struct {
	Ran      bool           `json:"ran"`
	Skipped  string         `json:"skipped,omitempty"`
	Strict   bool           `json:"strict"`
	ABI      int            `json:"abi"`
	Net      bool           `json:"net"`
	Rows     []rehearsalRow `json:"rows"`
	Failures []string       `json:"failures"`
	Passed   bool           `json:"passed"`
}

// fail records a failed check.
func (r *rehearsalResult) fail(format string, args ...any) {
	r.Failures = append(r.Failures, fmt.Sprintf(format, args...))
}

// finish decides Passed: the rehearsal ran, no check failed, and the rows are
// exactly rehearsalRows (tcp6-connect may be absent), each reported and in
// its set.
func (r *rehearsalResult) finish() {
	names := make([]string, 0, len(r.Rows))
	pass := true
	for _, row := range r.Rows {
		names = append(names, row.Name)
		pass = pass && row.Attempted && row.Pass
	}
	withoutTCP6 := slices.DeleteFunc(slices.Clone(rehearsalRows), func(name string) bool { return name == "tcp6-connect" })
	complete := slices.Equal(names, rehearsalRows) || slices.Equal(names, withoutTCP6)
	r.Passed = r.Ran && len(r.Failures) == 0 && pass && complete
}

// fixtures are the rehearsal's targets: a canary file and FIFO in a private
// directory under the gate dir, Unix and TCP listeners, a live process that is
// not the gate's child, a /tmp canary, and a /dev/shm name.
type fixtures struct {
	dir, canary, fifo, unixPath, abstract, tmp, shm string
	fifoRead, fifoWrite                             int
	listeners                                       map[string]int // unix, abstract, tcp4, tcp6
	tcp4, tcp6                                      string
	pid, pidfd                                      int
	childStdin                                      *os.File
	envNonce, writeNonce                            string
}

func randomToken(bytes int) string {
	b := make([]byte, bytes)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// childSubreaper reports this process's PR_GET_CHILD_SUBREAPER bit.
func childSubreaper() (bool, error) {
	var value int32
	err := unix.Prctl(unix.PR_GET_CHILD_SUBREAPER, uintptr(unsafe.Pointer(&value)), 0, 0, 0)
	return value != 0, err
}

// buildFixtures builds the fixtures under gateDir. It must run before this
// process makes any jail attempt: an attempt makes the gate a subreaper, and
// the fixture child would then be the gate's descendant, which the cleanup
// after a jailed run kills.
func buildFixtures(gateDir string) (_ *fixtures, err error) {
	if subreaper, err := childSubreaper(); err != nil || subreaper {
		return nil, errors.New("fixtures must be built before any jail attempt")
	}
	f := &fixtures{fifoRead: -1, fifoWrite: -1, listeners: map[string]int{}, pid: -1, pidfd: -1,
		envNonce: randomToken(16), writeNonce: randomToken(16), abstract: "sshgate-doctor-" + randomToken(8), shm: "sshgate-doctor-" + randomToken(8)}
	defer func() {
		if err != nil {
			_ = f.teardown()
		}
	}()
	if f.dir, err = os.MkdirTemp(gateDir, ".doctor-"); err != nil {
		return nil, err
	}
	f.canary, f.fifo, f.unixPath = filepath.Join(f.dir, "canary"), filepath.Join(f.dir, "fifo"), filepath.Join(f.dir, "sock")
	if len(f.unixPath) >= len(unix.RawSockaddrUnix{}.Path) {
		return nil, fmt.Errorf("the fixture socket path %s is too long for a Unix socket", f.unixPath)
	}
	if err = os.WriteFile(f.canary, []byte("canary "+randomToken(16)+"\n"), 0o644); err != nil {
		return nil, err
	}
	if err = os.Chmod(f.canary, 0o644); err != nil {
		return nil, err
	}
	if err = unix.Mkfifo(f.fifo, 0o644); err != nil {
		return nil, err
	}
	if f.fifoRead, err = unix.Open(f.fifo, unix.O_RDONLY|unix.O_NONBLOCK|unix.O_CLOEXEC, 0); err != nil {
		return nil, err
	}
	// The control writer stays open, so an empty FIFO reads EAGAIN, not EOF.
	if f.fifoWrite, err = unix.Open(f.fifo, unix.O_WRONLY|unix.O_NONBLOCK|unix.O_CLOEXEC, 0); err != nil {
		return nil, err
	}
	if err = f.listen(); err != nil {
		return nil, err
	}
	tmp, err := os.CreateTemp(fixtureTmp, "sshgate-doctor-")
	if err != nil {
		return nil, err
	}
	f.tmp = tmp.Name()
	_, err = tmp.WriteString("tmp canary " + randomToken(16) + "\n")
	err = errors.Join(err, tmp.Chmod(0o644), tmp.Close())
	if err != nil {
		return nil, err
	}
	return f, f.startChild()
}

// listen opens the non-blocking listeners: pathname and abstract Unix, TCP on
// 127.0.0.1, and TCP on ::1 when the host has it.
func (f *fixtures) listen() error {
	type listener struct {
		name    string
		family  int
		address unix.Sockaddr
	}
	for _, l := range []listener{
		{"unix", unix.AF_UNIX, &unix.SockaddrUnix{Name: f.unixPath}},
		{"abstract", unix.AF_UNIX, &unix.SockaddrUnix{Name: "@" + f.abstract}},
		{"tcp4", unix.AF_INET, &unix.SockaddrInet4{Addr: [4]byte{127, 0, 0, 1}}},
		{"tcp6", unix.AF_INET6, &unix.SockaddrInet6{Addr: [16]byte{15: 1}}},
	} {
		fd, err := unix.Socket(l.family, unix.SOCK_STREAM|unix.SOCK_NONBLOCK|unix.SOCK_CLOEXEC, 0)
		if err == nil {
			if err = unix.Bind(fd, l.address); err == nil {
				err = unix.Listen(fd, 8)
			}
			if err != nil {
				_ = unix.Close(fd)
			}
		}
		if err != nil {
			if l.name == "tcp6" {
				continue // no ::1 on this host: the tcp6 row is skipped
			}
			return fmt.Errorf("%s listener: %w", l.name, err)
		}
		f.listeners[l.name] = fd
		bound, err := unix.Getsockname(fd)
		switch address := bound.(type) {
		case *unix.SockaddrInet4:
			f.tcp4 = "127.0.0.1:" + strconv.Itoa(address.Port)
		case *unix.SockaddrInet6:
			f.tcp6 = "[::1]:" + strconv.Itoa(address.Port)
		}
		if err != nil {
			return err
		}
	}
	return nil
}

// fixtureChildScript starts the child in the background. The background
// command's stdin is /dev/null in dash and bash alike unless redirected, so
// the held pipe is passed through fd 4.
const fixtureChildScript = `exec 4<&0; /bin/sh -c 'echo $$ >&3; exec 3>&-; read x' <&4 4<&- &`

// startChild starts the child: a /bin/sh that blocks reading a pipe the gate
// holds, carrying envNonce in its environment. It is a grandchild through a
// setsid intermediate that exits at once, so the gate is not its parent.
func (f *fixtures) startChild() error {
	pidRead, pidWrite, err := os.Pipe()
	if err != nil {
		return err
	}
	defer pidRead.Close()
	stdinRead, stdinWrite, err := os.Pipe()
	if err != nil {
		_ = pidWrite.Close()
		return err
	}
	f.childStdin = stdinWrite
	intermediate := exec.Command("/bin/sh", "-c", fixtureChildScript)
	intermediate.Stdin, intermediate.ExtraFiles = stdinRead, []*os.File{pidWrite}
	intermediate.Env = append(os.Environ(), "SSHGATE_DOCTOR_NONCE="+f.envNonce)
	intermediate.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	err = intermediate.Start()
	_ = pidWrite.Close()
	_ = stdinRead.Close()
	if err != nil {
		return err
	}
	line, readErr := bufio.NewReader(pidRead).ReadString('\n')
	if err := intermediate.Wait(); err != nil {
		return fmt.Errorf("fixture child: %w", err)
	}
	if f.pid, err = strconv.Atoi(strings.TrimSpace(line)); err != nil || f.pid <= 1 {
		return fmt.Errorf("fixture child pid %q: %v", line, errors.Join(readErr, err))
	}
	f.pidfd, err = unix.PidfdOpen(f.pid, 0)
	return err
}

// processFacts are a process's state letter, nice value and TracerPid.
type processFacts struct{ state, nice, tracer, ppid string }

func readProcessFacts(pid int) (processFacts, error) {
	stat, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/stat")
	if err != nil {
		return processFacts{}, err
	}
	text := string(stat)
	fields := strings.Fields(text[strings.LastIndexByte(text, ')')+1:])
	if len(fields) < 17 {
		return processFacts{}, errors.New("short /proc stat")
	}
	facts := processFacts{state: fields[0], ppid: fields[1], nice: fields[16]}
	status, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/status")
	for _, line := range strings.Split(string(status), "\n") {
		if value, ok := strings.CutPrefix(line, "TracerPid:"); ok {
			facts.tracer = strings.TrimSpace(value)
		}
	}
	return facts, err
}

// fixtureState is what the outside checks compare before and after the run.
type fixtureState struct {
	canary, tmp         string
	canaryStat, tmpStat unix.Stat_t
	listing             []string
	child               processFacts
}

func (f *fixtures) snapshot() (fixtureState, error) {
	var s fixtureState
	canary, err := os.ReadFile(f.canary)
	tmp, tmpErr := os.ReadFile(f.tmp)
	s.canary, s.tmp = string(canary), string(tmp)
	entries, listErr := os.ReadDir(f.dir)
	for _, entry := range entries {
		s.listing = append(s.listing, entry.Name())
	}
	child, childErr := readProcessFacts(f.pid)
	s.child = child
	return s, errors.Join(err, tmpErr, listErr, childErr, unix.Stat(f.canary, &s.canaryStat), unix.Stat(f.tmp, &s.tmpStat))
}

// sameFile compares the stat fields a write, chmod, utime, rename or link
// would change.
func sameFile(a, b unix.Stat_t) bool {
	return a.Ino == b.Ino && a.Size == b.Size && a.Mode == b.Mode && a.Nlink == b.Nlink && a.Mtim == b.Mtim && a.Ctim == b.Ctim
}

// acceptAll drains a listener: the payload of each accepted connection.
func acceptAll(listener int) ([]string, error) {
	var payloads []string
	for {
		connection, _, err := unix.Accept4(listener, unix.SOCK_CLOEXEC)
		if errors.Is(err, unix.EAGAIN) {
			return payloads, nil
		}
		if err != nil {
			return payloads, err
		}
		buffer := make([]byte, 128)
		poll := []unix.PollFd{{Fd: int32(connection), Events: unix.POLLIN}}
		_, _ = unix.Poll(poll, 1000)
		n, _ := unix.Read(connection, buffer)
		payloads = append(payloads, string(buffer[:max(n, 0)]))
		_ = unix.Close(connection)
	}
}

// liveness proves every fixture can show its effect: each listener accepts a
// connection, the FIFO carries a byte, the child is alive, carries envNonce
// and is not the gate's child. "" means live.
func (f *fixtures) liveness() string {
	targets := map[string]unix.Sockaddr{"unix": &unix.SockaddrUnix{Name: f.unixPath}, "abstract": &unix.SockaddrUnix{Name: "@" + f.abstract}}
	if address, ok := parseLoopback(f.tcp4); ok {
		targets["tcp4"] = address
	}
	if address, ok := parseLoopback(f.tcp6); ok {
		targets["tcp6"] = address
	}
	families := map[string]int{"unix": unix.AF_UNIX, "abstract": unix.AF_UNIX, "tcp4": unix.AF_INET, "tcp6": unix.AF_INET6}
	for name, listener := range f.listeners {
		if err := connectTo(families[name], targets[name], f.writeNonce); err != nil {
			return name + " listener: " + err.Error()
		}
		if accepted, err := acceptAll(listener); err != nil || len(accepted) != 1 {
			return fmt.Sprintf("%s listener accepted %d: %v", name, len(accepted), err)
		}
	}
	if _, err := unix.Write(f.fifoWrite, []byte("x")); err != nil {
		return "fifo write: " + err.Error()
	}
	buffer := make([]byte, 8)
	if n, err := unix.Read(f.fifoRead, buffer); err != nil || n != 1 {
		return "fifo read: " + fmt.Sprint(err)
	}
	if _, err := unix.Read(f.fifoRead, buffer); !errors.Is(err, unix.EAGAIN) {
		return "fifo not drained: " + fmt.Sprint(err)
	}
	if err := unix.PidfdSendSignal(f.pidfd, 0, nil, 0); err != nil {
		return "child not alive: " + err.Error()
	}
	environ, err := os.ReadFile("/proc/" + strconv.Itoa(f.pid) + "/environ")
	if err != nil || !strings.Contains(string(environ), f.envNonce) {
		return "child environment unreadable"
	}
	if facts, err := readProcessFacts(f.pid); err != nil || facts.ppid == strconv.Itoa(os.Getpid()) {
		return "child is the gate's child"
	}
	return ""
}

// selftestArgs are the selftest's arguments for these fixtures.
func (f *fixtures) selftestArgs(outer [2]uint64, net bool) []string {
	netValue := "deny"
	if net {
		netValue = "allow"
	}
	args := []string{
		fmt.Sprintf("--outer-ns=%d:%d", outer[0], outer[1]),
		"--canary=" + f.canary, "--fifo=" + f.fifo, "--unix=" + f.unixPath, "--abstract=" + f.abstract,
		"--tcp4=" + f.tcp4, "--pid=" + strconv.Itoa(f.pid), "--tmp=" + f.tmp, "--shm=" + f.shm,
		"--nonce=" + f.writeNonce, "--net=" + netValue,
	}
	if f.tcp6 != "" {
		args = append(args, "--tcp6="+f.tcp6)
	}
	return args
}

func shellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

// rehearse runs the selftest in the read jail of cand (sealed with seal, the
// last jail attempt of this process) and checks the result.
func (f *fixtures) rehearse(ctx context.Context, cand confine.Pin, seal func() error) rehearsalResult {
	r := rehearsalResult{Net: cand.Net}
	if reason := f.liveness(); reason != "" {
		r.Skipped = "could not run: " + reason
		return r
	}
	before, err := f.snapshot()
	binary, binaryErr := selftestBinaryFn()
	outer, outerErr := ownNamespaces()
	if err = errors.Join(err, binaryErr, outerErr); err != nil {
		r.Skipped = "could not run: " + err.Error()
		return r
	}
	spec := readSpecBase(pinState{valid: true, pin: cand}, cand.Net, false)
	if rehearsalSpecHook != nil {
		rehearsalSpecHook(&spec)
	}
	spec.Cwd = "/"
	r.Strict = spec.Strict
	if !spec.Strict {
		r.fail("the candidate's Spec is not strict")
	}
	words := []string{"exec", shellQuote(binary), sentinelSelftest}
	for _, arg := range f.selftestArgs(outer, cand.Net) {
		words = append(words, shellQuote(arg))
	}
	sink, closeSink, err := devNullSink(ctx)
	if err != nil {
		r.Skipped = "could not run: " + err.Error()
		return r
	}
	res, err := executeCommand(ctx, strings.Join(words, " "), gate.ExecOpts{Confine: &spec, Seal: seal, CaptureLimit: 64 << 10, ClientSink: sink})
	closeSink()
	r.Ran = true
	f.checkRun(&r, spec, res, err)
	r.Rows = f.attest(&r, res.Stdout)
	f.observe(&r, before)
	if rehearsalObserveHook != nil {
		rehearsalObserveHook(&r)
	}
	r.finish()
	return r
}

// checkRun requires a clean jailed run of the selftest under the exact Spec.
func (f *fixtures) checkRun(r *rehearsalResult, spec confine.Spec, res gate.ExecResult, err error) {
	if err != nil || res.ExitCode != 0 || res.Stderr != "" {
		r.fail("selftest run: exit %d, %v, stderr %q", res.ExitCode, err, res.Stderr)
	}
	jail := res.Jail
	if jail == nil {
		r.fail("the selftest did not run in the jail")
		return
	}
	r.ABI = jail.ABI
	if jail.Profile != confine.ProfileROv1 || jail.ABI < 1 || spec.ForceABI == 1 && jail.ABI != 1 || jail.Net != spec.Net || len(jail.Unmet) > 0 {
		r.fail("jail facts: profile %q, ABI %d, net %v, unmet %v", jail.Profile, jail.ABI, jail.Net, jail.Unmet)
	}
}

// attest parses the selftest's report: every row once, in order, each errno
// in its row's set, tcp6 skipped exactly when there is no ::1 listener, the
// END count right, and the child's nonce nowhere.
func (f *fixtures) attest(r *rehearsalResult, stdout string) []rehearsalRow {
	if strings.Contains(stdout, f.envNonce) {
		r.fail("the selftest output carries the child's environment")
	}
	lines := strings.Split(strings.TrimSuffix(stdout, "\n"), "\n")
	if len(lines) != len(rehearsalRows)+1 {
		r.fail("selftest report has %d lines", len(lines))
		return nil
	}
	var rows []rehearsalRow
	for i, name := range rehearsalRows {
		if name == "tcp6-connect" && f.tcp6 == "" {
			if lines[i] != "SELFTEST tcp6-connect skipped" {
				r.fail("tcp6-connect not skipped")
			}
			continue
		}
		errno, ok := strings.CutPrefix(lines[i], "SELFTEST "+name+" errno=")
		set := rowErrnos[name]
		if name == "tcp4-connect" || name == "tcp6-connect" {
			set = tcpRowErrnos(r.Net)
		}
		rows = append(rows, rehearsalRow{Name: name, Errno: errno, Attempted: ok, Pass: ok && slices.Contains(set, errno)})
	}
	if lines[len(lines)-1] != "SELFTEST-END "+strconv.Itoa(len(rows)) {
		r.fail("selftest END line %q", lines[len(lines)-1])
	}
	return rows
}

// observe makes the authoritative outside checks.
func (f *fixtures) observe(r *rehearsalResult, before fixtureState) {
	after, err := f.snapshot()
	if err != nil {
		r.fail("fixture state: %v", err)
	}
	if after.canary != before.canary || !sameFile(after.canaryStat, before.canaryStat) || !slices.Equal(after.listing, before.listing) {
		r.fail("the canary or its directory changed")
	}
	if n, err := unix.Read(f.fifoRead, make([]byte, 8)); n > 0 || !errors.Is(err, unix.EAGAIN) {
		r.fail("the FIFO received bytes: %d, %v", n, err)
	}
	for _, name := range []string{"unix", "abstract", "tcp4", "tcp6"} {
		listener, ok := f.listeners[name]
		if !ok {
			continue
		}
		accepted, err := acceptAll(listener)
		want := 0
		if r.Net && (name == "tcp4" || name == "tcp6") {
			want = 1
		}
		if err != nil || len(accepted) != want || want == 1 && accepted[0] != f.writeNonce {
			r.fail("the %s listener accepted %d connection(s): %v", name, len(accepted), err)
		}
	}
	// The state letter is not compared: the child may still be running when
	// the "before" snapshot is taken. Stopped, traced or dead is the effect.
	unchanged := after.child.nice == before.child.nice && after.child.tracer == before.child.tracer && after.child.ppid == before.child.ppid
	if err := unix.PidfdSendSignal(f.pidfd, 0, nil, 0); err != nil || !unchanged || after.child.state == "" || strings.ContainsAny(after.child.state, "TtZX") {
		r.fail("the child changed: %+v, was %+v", after.child, before.child)
	}
	if after.tmp != before.tmp || !sameFile(after.tmpStat, before.tmpStat) {
		r.fail("the /tmp canary changed")
	}
	if _, err := os.Lstat(f.tmp + ".sibling"); err == nil {
		r.fail("a /tmp sibling was created")
	}
	if _, err := os.Lstat("/dev/shm/" + f.shm); err == nil {
		r.fail("the selftest's /dev/shm file reached the host")
	}
}

// teardown releases the fixtures: the child is continued, killed and waited
// for through its pidfd; every descriptor is closed; the files are removed.
func (f *fixtures) teardown() error {
	var errs []error
	if f.pidfd >= 0 {
		_ = unix.PidfdSendSignal(f.pidfd, unix.SIGCONT, nil, 0)
		if err := unix.PidfdSendSignal(f.pidfd, unix.SIGKILL, nil, 0); err != nil && !errors.Is(err, unix.ESRCH) {
			errs = append(errs, fmt.Errorf("kill fixture child: %w", err))
		}
		// The pidfd becomes readable once the child has exited.
		poll := []unix.PollFd{{Fd: int32(f.pidfd), Events: unix.POLLIN}}
		if n, err := unix.Poll(poll, int((2 * time.Second).Milliseconds())); err != nil || n != 1 {
			errs = append(errs, errors.New("fixture child did not exit"))
		}
		_ = unix.Close(f.pidfd)
	}
	if f.childStdin != nil {
		_ = f.childStdin.Close()
	}
	for _, fd := range []int{f.fifoRead, f.fifoWrite} {
		if fd >= 0 {
			_ = unix.Close(fd)
		}
	}
	for _, listener := range f.listeners {
		_, _ = acceptAll(listener)
		_ = unix.Close(listener)
	}
	if f.dir != "" {
		errs = append(errs, os.RemoveAll(f.dir))
	}
	for _, path := range []string{f.tmp, f.tmp + ".sibling", "/dev/shm/" + f.shm} {
		if path != "" && path != ".sibling" {
			if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
				errs = append(errs, err)
			}
		}
	}
	return errors.Join(errs...)
}

// devNullSink is a client sink that discards: a doctor attempt's output is
// not the operator's.
func devNullSink(ctx context.Context) (*gate.ClientSink, func(), error) {
	devNull, err := os.OpenFile(os.DevNull, os.O_WRONLY, 0)
	if err != nil {
		return nil, nil, err
	}
	sink, err := gate.NewClientSink(ctx, devNull, devNull)
	if err != nil {
		_ = devNull.Close()
		return nil, nil, err
	}
	return sink, func() { _ = sink.Close(); _ = devNull.Close() }, nil
}
