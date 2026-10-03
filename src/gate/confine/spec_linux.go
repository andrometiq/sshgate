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
	c.Dir = "/"
	c.ExtraFiles = []*os.File{cmdR, statusW} // -> child fd 3 (command), fd 4 (status)
	c.SysProcAttr = cloneSysProcAttr()

	return &Jailed{
		Cmd:       c,
		strict:    s.Strict,
		cmd:       cmd,
		cmdW:      cmdW,
		statusR:   statusR,
		childEnds: []*os.File{cmdR, statusW},
	}, nil
}

// cloneSysProcAttr is the rung-1 clone policy: new user+mount+pid+ipc
// namespaces (the ipc one isolates host SysV IPC and POSIX message queues),
// identity uid/gid maps (so reads of the user's own files keep correct
// ownership), and the mount-phase capabilities carried as ambient caps so they
// survive the shim->worker execve. The worker drops them before running /bin/sh.
func cloneSysProcAttr() *syscall.SysProcAttr {
	uid, gid := os.Getuid(), os.Getgid()
	attr := &syscall.SysProcAttr{
		Cloneflags:  syscall.CLONE_NEWUSER | syscall.CLONE_NEWNS | syscall.CLONE_NEWPID | syscall.CLONE_NEWIPC,
		AmbientCaps: []uintptr{unix.CAP_SYS_ADMIN, unix.CAP_SETPCAP},
		Setpgid:     true,
		Pdeathsig:   syscall.SIGKILL,
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

// RunShim is the __jail entrypoint: pid 1 of the new pid namespace on rung 1. It
// forks exactly one worker, forwards fd 3/4, then reaps. It only ever reduces
// privilege, so a direct local caller gains nothing.
func RunShim(args []string) int {
	cmdR := os.NewFile(3, "cmdR")
	statusW := os.NewFile(4, "statusW")
	if cmdR == nil || statusW == nil {
		return ExitSetupFailed
	}

	if !jailmut.On("P-SHIM-PID1") && os.Getpid() != 1 {
		_, _ = io.WriteString(statusW, formatFailReport("nsverify", unix.EPERM))
		return ExitSetupFailed
	}
	if err := unix.Prctl(unix.PR_SET_DUMPABLE, 0, 0, 0, 0); err != nil {
		_, _ = io.WriteString(statusW, formatFailReport("nsverify", errnoOf(err)))
		return ExitSetupFailed
	}
	c := exec.Command("/proc/self/exe", append([]string{SentinelWorker}, args...)...)
	c.Stdin, c.Stdout, c.Stderr = os.Stdin, os.Stdout, os.Stderr
	c.ExtraFiles = []*os.File{cmdR, statusW}
	if err := c.Start(); err != nil {
		_, _ = io.WriteString(statusW, formatFailReport("shim", errnoOf(err)))
		return ExitSetupFailed
	}
	// Drop our copies so the parent sees EOF on the status pipe once the worker
	// is done, and the command pipe's only reader is the worker.
	_ = cmdR.Close()
	_ = statusW.Close()
	return reap(c.Process.Pid)
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
	if st, errno := spec.inject(); st == "landlock" {
		err = errno
	}
	if !jailmut.On("P-FAULT-landlock") && err != nil {
		return fail("landlock", err)
	}
	filter := buildFilter(filterParams{
		allowInet:        spec.Net,
		denyOpenByHandle: rootSSH,
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
	if len(facts.Unmet) > 0 || len(facts.CoverAtAncestor) > 0 || facts.CwdReset {
		raw, _ := json.Marshal(facts)
		_, _ = fmt.Fprintf(statusW, "I%s\n", raw)
	}
	// Report success, then hand off to /bin/sh. The execve closes fd 4 (CLOEXEC),
	// so the parent reads exactly "X" then EOF.
	_, _ = io.WriteString(statusW, statusReachedExec)
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

// reap is the pid-1 reaper loop. It returns as soon as the worker (its direct
// child) is reaped, mirroring the worker's status; it never blocks waiting for
// backgrounded descendants (pid-namespace teardown kills any stragglers).
func reap(workerPid int) int {
	for {
		var ws unix.WaitStatus
		pid, err := unix.Wait4(-1, &ws, 0, nil)
		if err == unix.EINTR {
			continue
		}
		if err != nil {
			// ECHILD before the worker was reaped: nothing left to wait on.
			return ExitSetupFailed
		}
		if pid == workerPid {
			// Drain any already-exited orphans without blocking, then exit.
			for {
				var z unix.WaitStatus
				p, e := unix.Wait4(-1, &z, unix.WNOHANG, nil)
				if e != nil || p <= 0 {
					break
				}
			}
			if ws.Signaled() {
				return 128 + int(ws.Signal())
			}
			return ws.ExitStatus()
		}
		// An orphan exited before the worker; keep waiting for the worker.
	}
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

func resolveCwd(cwd string) (string, bool, error) {
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
