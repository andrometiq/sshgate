//go:build linux

package confine

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"

	"github.com/karthikeyan5/sshgate/src/gate/confine/jailmut"
	"golang.org/x/sys/unix"
)

// maxCmdBytes caps the command string the worker reads from fd 3, so a stuck or
// hostile writer cannot make the worker buffer without bound.
const maxCmdBytes = 1 << 20

// command clones the shim; the command and status travel on fd 3 and fd 4.
func (s Spec) command(ctx context.Context, cmd string) (*Jailed, error) {
	if s.Cwd == "" {
		var cwdErr error
		s.Cwd, cwdErr = unix.Getwd()
		if cwdErr != nil || !filepath.IsAbs(s.Cwd) {
			s.Cwd = "/"
		}
	}
	if !jailmut.On("P-SPEC") && s.validate(false) != nil {
		return nil, &SetupError{Stage: "spec", Errno: unix.EINVAL}
	}
	var err error
	s.ParentNS, err = namespaceIDs()
	if err != nil {
		return nil, &SetupError{Stage: "spec", Errno: errnoOf(err)}
	}

	specJSON, err := json.Marshal(s)
	if err != nil {
		return nil, fmt.Errorf("confine: marshal spec: %w", err)
	}

	cmdR, cmdW, err := os.Pipe()
	if err != nil {
		return nil, fmt.Errorf("confine: command pipe: %w", err)
	}
	statusR, statusW, err := os.Pipe()
	if err != nil {
		_ = cmdR.Close()
		_ = cmdW.Close()
		return nil, fmt.Errorf("confine: status pipe: %w", err)
	}

	c := exec.CommandContext(ctx, "/proc/self/exe", SentinelShim, string(specJSON))
	if !jailmut.On("P-CWD") {
		c.Dir = "/"
	}
	c.ExtraFiles = []*os.File{cmdR, statusW} // -> child fd 3 (command), fd 4 (status)
	c.SysProcAttr = cloneSysProcAttr()

	return &Jailed{
		Cmd:       c,
		strict:    s.Strict,
		spec:      s,
		cmd:       cmd,
		cmdW:      cmdW,
		statusR:   statusR,
		childEnds: []*os.File{cmdR, statusW},
	}, nil
}

// cloneSysProcAttr is the rung-1 clone policy: new user+mount+ipc
// namespaces (the ipc one isolates host SysV IPC and POSIX message queues),
// identity uid/gid maps (so reads of the user's own files keep correct
// ownership), and the mount-phase capabilities carried as ambient caps so they
// survive the shim->worker execve. The worker drops them before running /bin/sh.
func cloneSysProcAttr() *syscall.SysProcAttr {
	uid, gid := os.Getuid(), os.Getgid()
	attr := &syscall.SysProcAttr{
		Cloneflags:  syscall.CLONE_NEWUSER | syscall.CLONE_NEWNS | syscall.CLONE_NEWIPC,
		AmbientCaps: []uintptr{unix.CAP_SYS_ADMIN, unix.CAP_SETPCAP},
		Setpgid:     true,
		Pdeathsig:   syscall.SIGKILL,
	}
	if jailmut.On("P-CLONE-IPC") {
		attr.Cloneflags &^= syscall.CLONE_NEWIPC
	}
	if uid == 0 {
		// A root SSH user needs a full-range identity map: CAP_DAC_READ_SEARCH in
		// a child userns only applies to inodes whose uid AND gid are mapped in,
		// so a single-id map would break root reads of other users' files.
		const fullRange = 4294967295
		attr.UidMappings = []syscall.SysProcIDMap{{ContainerID: 0, HostID: 0, Size: fullRange}}
		attr.GidMappings = []syscall.SysProcIDMap{{ContainerID: 0, HostID: 0, Size: fullRange}}
		attr.GidMappingsEnableSetgroups = true
	} else {
		attr.UidMappings = []syscall.SysProcIDMap{{ContainerID: uid, HostID: uid, Size: 1}}
		attr.GidMappings = []syscall.SysProcIDMap{{ContainerID: gid, HostID: gid, Size: 1}}
		attr.GidMappingsEnableSetgroups = false // required for an unprivileged map
	}
	return attr
}

// RunShim is the subreaper for a confined command. It
// forks exactly one worker, forwards fd 3/4, then reaps. It only ever reduces
// privilege, so a direct local caller gains nothing.
func RunShim(args []string) int {
	cmdR := os.NewFile(3, "cmdR")
	statusW := os.NewFile(4, "statusW")
	if cmdR == nil || statusW == nil {
		return ExitSetupFailed
	}

	if err := EnableSubreaper(); err != nil {
		_, _ = io.WriteString(statusW, formatFailReport("shim", errnoOf(err)))
		return ExitSetupFailed
	}
	if err := sealShim(); err != nil {
		_, _ = io.WriteString(statusW, formatFailReport("nsverify", errnoOf(err)))
		return ExitSetupFailed
	}
	if _, err := childPIDs(); err != nil {
		_, _ = io.WriteString(statusW, formatFailReport("shim", errnoOf(err)))
		return ExitSetupFailed
	}
	terminated := make(chan os.Signal, 1)
	signal.Notify(terminated, syscall.SIGTERM)
	defer signal.Stop(terminated)
	c := exec.Command("/proc/self/exe", append([]string{SentinelWorker}, args...)...)
	c.Stdin, c.Stdout, c.Stderr = os.Stdin, os.Stdout, os.Stderr
	c.ExtraFiles = []*os.File{cmdR, statusW}
	if err := c.Start(); err != nil {
		_, _ = io.WriteString(statusW, formatFailReport("shim", errnoOf(err)))
		return ExitSetupFailed
	}
	if jailmut.On("SHIM-NOCAPS") {
		if err := clearShimCaps(); err != nil {
			_, _ = io.WriteString(statusW, formatFailReport("shim", errnoOf(err)))
			_ = c.Process.Kill()
			return ExitSetupFailed
		}
	}
	// Keep the status pipe through cleanup; the worker closes it on exec.
	_ = cmdR.Close()
	defer statusW.Close()
	return reap(c.Process.Pid, terminated, statusW)
}

// RunWorker is the __jailexec entrypoint: it applies every restriction on a
// single locked OS thread and execs /bin/sh -c <cmd>. It fails closed — any
// setup error writes "F<stage>:<errno>" to fd 4 and exits WITHOUT execve.
func RunWorker(args []string) int {
	runtime.LockOSThread()

	statusW := os.NewFile(4, "statusW")
	if statusW == nil {
		return ExitSetupFailed
	}
	unix.CloseOnExec(4) // a successful execve closes fd 4, flushing EOF to the parent

	fail := func(stage string, err error) int {
		// The structured report (stage + errno) goes to the parent on fd 4; the
		// detailed message goes to the gate's stderr log channel for diagnosis.
		if err != nil {
			fmt.Fprintf(os.Stderr, "gate-jail: setup failed at %s: %v\n", stage, err)
		}
		_, _ = io.WriteString(statusW, formatFailReport(stage, errnoOf(err)))
		return ExitSetupFailed
	}

	if len(args) < 1 {
		return fail("spec", unix.EINVAL)
	}
	var spec Spec
	err := decodeSpec(args[0], &spec)
	if st, errno := spec.inject(); err == nil && st == "spec" {
		err = errno
	}
	if !jailmut.On("P-FAULT-spec") && err != nil {
		return fail("spec", err)
	}

	cmdR := os.NewFile(3, "cmdR")
	if cmdR == nil {
		return fail("cmdread", unix.EBADF)
	}
	cmdBytes, rerr := readCapped(cmdR, maxCmdBytes)
	_ = cmdR.Close()
	if st, errno := spec.inject(); st == "cmdread" {
		rerr = errno
	}
	if !jailmut.On("P-FAULT-cmdread") && rerr != nil {
		return fail("cmdread", rerr)
	}
	cmd := string(cmdBytes)

	abi := effectiveABI(probeLandlockABI(), spec.ForceABI)
	rootSSH := os.Getuid() == 0

	err = verifyNamespaces(spec.ParentNS)
	if st, errno := spec.inject(); st == "nsverify" {
		err = errno
	}
	if !jailmut.On("P-NSVERIFY") && err != nil {
		return fail("nsverify", err)
	}
	facts, mountErr := setupMounts(spec)
	err = mountErr
	if st, errno := spec.inject(); st == "mounts" {
		err = errno
	}
	if !jailmut.On("P-FAULT-mounts") && err != nil {
		var setup *SetupError
		if errors.As(err, &setup) {
			return fail(setup.Stage, setup.Errno)
		}
		return fail("mounts", err)
	}
	err = setNoNewPrivs()
	if st, errno := spec.inject(); st == "nnp" {
		err = errno
	}
	if !jailmut.On("P-FAULT-nnp") && err != nil {
		return fail("nnp", err)
	}
	err = dropCaps(rootSSH)
	if st, errno := spec.inject(); st == "caps" {
		err = errno
	}
	if !jailmut.On("P-FAULT-caps") && err != nil {
		return fail("caps", err)
	}
	err = setRlimits()
	if st, errno := spec.inject(); st == "rlimits" {
		err = errno
	}
	if !jailmut.On("P-FAULT-rlimits") && err != nil {
		return fail("rlimits", err)
	}
	err = applyLandlock(abi, writableSet())
	restrictedABI := 0
	if err == nil {
		restrictedABI = abi
	}
	if st, errno := spec.inject(); st == "landlock" {
		err = errno
	}
	if !jailmut.On("P-FAULT-landlock") && err != nil {
		return fail("landlock", err)
	}
	filter := buildFilter(filterParams{
		allowInet: spec.Net,
		abi:       abi,
	})
	err = installSeccomp(filter, spec)
	if err != nil {
		var setup *SetupError
		if errors.As(err, &setup) {
			return fail(setup.Stage, setup.Errno)
		}
		return fail("seccomp", err)
	}
	execPath := "/bin/sh"
	if st, _ := spec.inject(); st == "exec" {
		execPath = "/nonexistent/sh"
	}
	// Close any inherited fd above stderr on execve so only 0/1/2 survive into the
	// jailed command. fd 4 (status) is already CLOEXEC and fd 3 (command) is
	// closed; this neutralises any OTHER fd the parent may have leaked. An
	// inherited WRITABLE fd would otherwise get past both the read-only mount and
	// Landlock (it is already open), so this is defence in depth on top of the
	// gate's own O_CLOEXEC discipline.
	err = closeInheritedFDs()
	if stage, errno := spec.inject(); stage == "fds" {
		err = errno
	}
	if !jailmut.On("P-FAULT-fds") && err != nil {
		return fail("fds", err)
	}
	cwd, reset, cwdErr := resolveCwd(spec.Cwd)
	facts.CwdReset = reset
	if reset {
		fmt.Fprintln(os.Stderr, "gate: note: the working directory is not visible in the read view; the read ran from /")
	}
	if stage, errno := spec.inject(); stage == "cwd" {
		cwdErr = errno
	}
	if !jailmut.On("P-FAULT-cwd") && cwdErr != nil {
		return fail("cwd", cwdErr)
	}
	err = selfcheck(spec, restrictedABI, &facts)
	if stage, errno := spec.inject(); stage == "selfcheck" {
		err = errno
	}
	if !jailmut.On("P-FAULT-selfcheck") && err != nil {
		return fail("selfcheck", err)
	}
	facts.Profile, facts.ABI, facts.Net = spec.Profile, restrictedABI, spec.Net
	err = establishSession()
	if stage, errno := spec.inject(); stage == "session" {
		err = errno
	}
	if !jailmut.On("P-FAULT-session") && err != nil {
		return fail("session", err)
	}
	// Report success, then hand off to /bin/sh. The execve closes fd 4 (CLOEXEC),
	// leaving only the shim able to append cleanup metadata.
	if err := writeExecReport(statusW, facts); err != nil {
		return fail("report", err)
	}
	execErr := unix.Exec(execPath, []string{"sh", "-c", cmd}, jailEnv(cwd))
	if jailmut.On("P-FAULT-exec") {
		return ExitSetupFailed
	}
	return fail("exec", execErr) // only reached if execve failed
}

// effectiveABI applies a Spec's ForceABI to the probed ABI. It can only lower
// the ABI: ForceNoLandlock (any negative value) yields 0, i.e. no Landlock.
func effectiveABI(probed, force int) int {
	switch {
	case force < 0:
		return 0
	case force > 0 && force < probed:
		return force
	default:
		return probed
	}
}

// writableSet names the private writable mounts and the null device.
func writableSet() []string {
	return []string{"/dev/shm", "/dev/null"}
}

// jailEnv builds the child environment: the gate's env with the temp/history
// variables redirected into the jail's writable area, so incidental read-time
// writes (pagers, shell history, sort -T) land somewhere writable and nothing
// else breaks.
func jailEnv(cwd string) []string {
	overrides := map[string]string{
		"TMPDIR": "/dev/shm", "TMP": "/dev/shm", "TEMP": "/dev/shm", "TMPPREFIX": "/dev/shm",
		"HISTFILE": "/dev/shm/.sh_history", "XDG_CACHE_HOME": "/dev/shm/.cache", "XDG_STATE_HOME": "/dev/shm/.state", "XDG_RUNTIME_DIR": "/dev/shm", "LESSHISTFILE": "-", "PWD": cwd,
	}
	var out []string
	for _, kv := range os.Environ() {
		keep := !strings.HasPrefix(kv, "SSH_ORIGINAL_COMMAND=")
		for k := range overrides {
			if len(kv) > len(k) && kv[:len(k)] == k && kv[len(k)] == '=' {
				keep = false
				break
			}
		}
		if keep {
			out = append(out, kv)
		}
	}
	for k, v := range overrides {
		out = append(out, k+"="+v)
	}
	return out
}

// readCapped reads up to max bytes, returning an error if the source produces
// more.
func readCapped(r io.Reader, max int) ([]byte, error) {
	buf, err := io.ReadAll(io.LimitReader(r, int64(max)+1))
	if err != nil {
		return nil, err
	}
	if len(buf) > max {
		return nil, fmt.Errorf("command exceeds %d bytes", max)
	}
	return buf, nil
}

// closeInheritedFDs is fail-closed even on ENOSYS; the supported floor has close_range.
func closeInheritedFDs() error { return unix.CloseRange(3, ^uint(0), unix.CLOSE_RANGE_CLOEXEC) }

func sealShim() error {
	if jailmut.On("P-SHIM-SEAL") {
		return nil
	}
	return unix.Prctl(unix.PR_SET_DUMPABLE, 0, 0, 0, 0)
}

func resolveCwd(cwd string) (string, bool, error) {
	if jailmut.On("P-CWD") {
		actual, err := unix.Getwd()
		return actual, false, err
	}
	err := unix.Chdir(cwd)
	if err == nil {
		return cwd, false, nil
	}
	switch err {
	case unix.ENOENT, unix.ENOTDIR, unix.EACCES, unix.ELOOP, unix.ENAMETOOLONG:
		err = unix.Chdir("/")
		return "/", true, err
	default:
		return "", false, err
	}
}

// errnoOf extracts a syscall.Errno from err, or 0 if there is none.
func errnoOf(err error) syscall.Errno {
	var e syscall.Errno
	if errors.As(err, &e) {
		return e
	}
	return 0
}

func clearShimCaps() error {
	if unix.Gettid() != unix.Getpid() {
		return unix.EINVAL
	}
	header := unix.CapUserHeader{Version: unix.LINUX_CAPABILITY_VERSION_3}
	data := [2]unix.CapUserData{}
	if err := unix.Capset(&header, &data[0]); err != nil {
		return err
	}
	return unix.Prctl(unix.PR_CAP_AMBIENT, unix.PR_CAP_AMBIENT_CLEAR_ALL, 0, 0, 0)
}
