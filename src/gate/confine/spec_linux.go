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
	"runtime"
	"strconv"
	"syscall"

	"golang.org/x/sys/unix"
)

// maxCmdBytes caps the command string the worker reads from fd 3, so a stuck or
// hostile writer cannot make the worker buffer without bound.
const maxCmdBytes = 1 << 20

// command builds the Jailed Cmd that runs `sh -c cmd` inside the jail. On rung 1
// it re-execs the __jail shim with the clone SysProcAttr; on rung 2 it re-execs
// __jailexec directly. The command travels on fd 3 and the setup status on fd 4,
// never on argv.
func (s Spec) command(ctx context.Context, cmd string) (*Jailed, error) {
	if s.Rung == Rung3Unconfined {
		return nil, errors.New("confine: Command called for rung 3 (the gate must pass a nil *Spec)")
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

	var sentinel string
	var attr *syscall.SysProcAttr
	if s.Rung == Rung1Full {
		sentinel = SentinelShim
		attr = cloneSysProcAttr()
	} else {
		sentinel = SentinelWorker
		attr = &syscall.SysProcAttr{Setpgid: true}
	}

	c := exec.CommandContext(ctx, "/proc/self/exe", sentinel, string(specJSON))
	c.ExtraFiles = []*os.File{cmdR, statusW} // -> child fd 3 (command), fd 4 (status)
	c.SysProcAttr = attr

	return &Jailed{
		Cmd:       c,
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
	if err := json.Unmarshal([]byte(args[0]), &spec); err != nil {
		return fail("spec", err)
	}

	cmdR := os.NewFile(3, "cmdR")
	if cmdR == nil {
		return fail("cmdread", unix.EBADF)
	}
	cmdBytes, rerr := readCapped(cmdR, maxCmdBytes)
	_ = cmdR.Close()
	if spec.InjectFailAt == "cmdread" {
		return fail("cmdread", unix.EINTR)
	}
	if rerr != nil {
		return fail("cmdread", rerr)
	}
	cmd := string(cmdBytes)

	abi := effectiveABI(probeLandlockABI(), spec.ForceABI)
	rootSSH := os.Getuid() == 0

	// mounts (rung 1 only) -> NNP -> cap drop -> rlimits -> Landlock -> seccomp.
	if spec.Rung == Rung1Full {
		if spec.InjectFailAt == "mounts" {
			return fail("mounts", unix.EPERM)
		}
		if err := setupMounts(); err != nil {
			return fail("mounts", err)
		}
	}
	if spec.InjectFailAt == "nnp" {
		return fail("nnp", unix.EPERM)
	}
	if err := setNoNewPrivs(); err != nil {
		return fail("nnp", err)
	}
	if spec.InjectFailAt == "caps" {
		return fail("caps", unix.EPERM)
	}
	if err := dropCaps(spec.Rung, rootSSH); err != nil {
		return fail("caps", err)
	}
	if spec.InjectFailAt == "rlimits" {
		return fail("rlimits", unix.EPERM)
	}
	if err := setRlimits(spec.Rung); err != nil {
		return fail("rlimits", err)
	}
	if spec.InjectFailAt == "landlock" {
		return fail("landlock", unix.EPERM)
	}
	if err := applyLandlock(spec.Rung, abi, writableSet(&spec)); err != nil {
		return fail("landlock", err)
	}
	if spec.InjectFailAt == "seccomp" {
		return fail("seccomp", unix.EPERM)
	}
	filter := buildFilter(filterParams{
		allowInet:        spec.AllowInet,
		denyMetadata:     spec.Rung == Rung2Landlock,
		denyTruncate:     spec.Rung == Rung2Landlock && abi < 3,
		denyTtyIoctl:     spec.Rung == Rung2Landlock && abi < 5,
		denyOpenByHandle: rootSSH && spec.Rung == Rung1Full,
	})
	if err := installSeccomp(filter); err != nil {
		return fail("seccomp", err)
	}

	if spec.InjectFailAt == "exec" {
		return fail("exec", unix.ENOENT)
	}
	// Close any inherited fd above stderr on execve so only 0/1/2 survive into the
	// jailed command. fd 4 (status) is already CLOEXEC and fd 3 (command) is
	// closed; this neutralises any OTHER fd the parent may have leaked. An
	// inherited WRITABLE fd would otherwise get past both the read-only mount and
	// Landlock (it is already open), so this is defence in depth on top of the
	// gate's own O_CLOEXEC discipline.
	closeInheritedFDs()
	// Report success, then hand off to /bin/sh. The execve closes fd 4 (CLOEXEC),
	// so the parent reads exactly "X" then EOF.
	_, _ = io.WriteString(statusW, statusReachedExec)
	execErr := unix.Exec("/bin/sh", []string{"sh", "-c", cmd}, jailEnv(&spec))
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

// writableSet is the per-rung list of paths Landlock lets the jailed command
// write to.
func writableSet(spec *Spec) []string {
	switch spec.Rung {
	case Rung1Full:
		return []string{"/tmp", "/var/tmp", "/dev/shm", "/dev/null"}
	case Rung2Landlock:
		w := []string{"/dev/null"}
		if spec.ScratchDir != "" {
			w = append([]string{spec.ScratchDir}, w...)
		}
		return w
	default:
		return nil
	}
}

// jailEnv builds the child environment: the gate's env with the temp/history
// variables redirected into the jail's writable area, so incidental read-time
// writes (pagers, shell history, sort -T) land somewhere writable and nothing
// else breaks.
func jailEnv(spec *Spec) []string {
	base := spec.ScratchDir
	if spec.Rung == Rung1Full {
		base = "/tmp" // tmpfs inside the jail
	}
	overrides := map[string]string{}
	if base != "" {
		overrides["TMPDIR"] = base
		overrides["TMP"] = base
		overrides["TEMP"] = base
		overrides["HISTFILE"] = base + "/.sh_history"
		overrides["XDG_CACHE_HOME"] = base + "/.cache"
	}
	var out []string
	for _, kv := range os.Environ() {
		keep := true
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

// closeInheritedFDs marks every fd >= 3 close-on-exec so only 0/1/2 survive the
// execve to /bin/sh. fd 4 is already CLOEXEC and fd 3 is closed by the caller, so
// in practice this closes any stray fd the parent leaked. CLOSE_RANGE_CLOEXEC
// does not close fd 4 now, so the immediately-following status write still works.
// Best effort: on a kernel without close_range it falls back to /proc/self/fd,
// and the primary guarantee remains the gate's own O_CLOEXEC discipline.
func closeInheritedFDs() {
	if err := unix.CloseRange(3, ^uint(0), unix.CLOSE_RANGE_CLOEXEC); err == nil {
		return
	}
	ents, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		return
	}
	for _, e := range ents {
		n, err := strconv.Atoi(e.Name())
		if err != nil || n < 5 { // 3 closed, 4 already CLOEXEC
			continue
		}
		unix.CloseOnExec(n)
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
