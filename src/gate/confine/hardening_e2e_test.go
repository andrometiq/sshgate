//go:build linux && jail_e2e

package confine

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"github.com/karthikeyan5/sshgate/src/gate/confine/jailmut"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestJailMatrixP12(t *testing.T) {
	for _, cfg := range []struct {
		name string
		abi  int
	}{{"native", 0}, {"abi1", 1}} {
		t.Run(cfg.name, func(t *testing.T) {
			spec := Spec{Profile: ProfileROv1, ForceABI: cfg.abi, Net: true}
			t.Run("L-SCRATCH-META", func(t *testing.T) { legScratchMetadata(t, spec) })
			t.Run("L-FILEATTR-ERRNO", func(t *testing.T) { legFileattrErrno(t, spec) })
			t.Run("L-LL-REQUIRED", func(t *testing.T) {
				p := newProof(t, "L-LL-REQUIRED")
				hardeningControl(t, p, spec)
				withoutLandlock := spec
				withoutLandlock.ForceABI = ForceNoLandlock
				stage, errno := "landlock", syscall.ENOSYS
				if jailmut.On("P-LL-REQUIRED") {
					stage, errno = "selfcheck", 0
				}
				p.Jailed("attempt", runJailed(t, p, withoutLandlock, RunPlan{Mode: SetupAbort, Stage: stage, Errno: errno, Command: "echo COMMAND_RAN"}))
				mutationAbort(t, "L-LL-REQUIRED", "selfcheck", stage == "selfcheck")
				p.Finish()
			})
			t.Run("L-ROOT-STATE", func(t *testing.T) { legRootState(t, spec) })
			t.Run("L-ROOT-NPROC", func(t *testing.T) { legRootNproc(t, spec) })
			t.Run("L-ROOT-PROC", func(t *testing.T) { legRootProc(t, spec) })
			t.Run("L-INJECT-ERRNO", func(t *testing.T) {
				p := newProof(t, "L-INJECT-ERRNO")
				hardeningControl(t, p, spec)
				injected := spec
				injected.InjectFailAt = "cmdread:EACCES"
				plan := hardeningAbortPlan("cmdread", syscall.EACCES, jailmut.On("P-FAULT-cmdread"))
				p.Jailed("attempt", runJailed(t, p, injected, plan))
				mutationEffect(t, "L-INJECT-ERRNO", "reached-exec", plan.Mode == Execute)
				p.Finish()
			})
			t.Run("L-SPEC-REJECT", func(t *testing.T) { legSpecReject(t, cfg.abi) })
			t.Run("L-NSVERIFY-user", func(t *testing.T) { legNamespace(t, spec, "user") })
			t.Run("L-NSVERIFY-mnt", func(t *testing.T) { legNamespace(t, spec, "mnt") })
			t.Run("L-NSVERIFY-pid", func(t *testing.T) { legNamespace(t, spec, "pid") })
			t.Run("L-NSVERIFY-ipc", func(t *testing.T) { legNamespace(t, spec, "ipc") })
			t.Run("L-HOSTMOUNTS-UNCHANGED", func(t *testing.T) {
				p := newProof(t, "L-HOSTMOUNTS-UNCHANGED")
				before, err := os.ReadFile("/proc/self/mountinfo")
				mutationSetup(t, err)
				stage := "nsverify"
				if jailmut.On("P-NSVERIFY") {
					stage = "private"
				}
				result := runJailed(t, p, spec, RunPlan{Mode: SetupAbort, Stage: stage, Errno: syscall.EPERM, Command: "echo COMMAND_RAN", Configure: func(j *Jailed) { j.Cmd.SysProcAttr.Cloneflags = syscall.CLONE_NEWUSER }})
				p.Jailed("attempt", result)
				after, err := os.ReadFile("/proc/self/mountinfo")
				p.Observed("mounts", Observation{Conclusive: err == nil, Sealed: true, Valid: bytes.Equal(before, after), Detail: "host mountinfo after completed setup abort"})
				mutationAbort(t, "L-HOSTMOUNTS-UNCHANGED", "private", stage == "private")
				p.Finish()
			})
			t.Run("L-FAULT-nsverify", func(t *testing.T) { legFault(t, spec, "nsverify") })
			t.Run("L-FAULT-spec", func(t *testing.T) { legFault(t, spec, "spec") })
			t.Run("L-FAULT-cmdread", func(t *testing.T) { legFault(t, spec, "cmdread") })
			t.Run("L-FAULT-mounts", func(t *testing.T) { legFault(t, spec, "mounts") })
			t.Run("L-FAULT-nnp", func(t *testing.T) { legFault(t, spec, "nnp") })
			t.Run("L-FAULT-caps", func(t *testing.T) { legFault(t, spec, "caps") })
			t.Run("L-FAULT-rlimits", func(t *testing.T) { legFault(t, spec, "rlimits") })
			t.Run("L-FAULT-landlock", func(t *testing.T) { legFault(t, spec, "landlock") })
			t.Run("L-FAULT-seccomp", func(t *testing.T) { legFault(t, spec, "seccomp") })
			t.Run("L-FAULT-tsync", func(t *testing.T) { legFault(t, spec, "tsync") })
			t.Run("L-FAULT-fds", func(t *testing.T) { legFault(t, spec, "fds") })
			t.Run("L-FAULT-cwd", func(t *testing.T) { legFault(t, spec, "cwd") })
			t.Run("L-FAULT-selfcheck", func(t *testing.T) { legFault(t, spec, "selfcheck") })
			t.Run("L-FAULT-session", func(t *testing.T) { legFault(t, spec, "session") })
			t.Run("L-FAULT-exec", func(t *testing.T) { legFault(t, spec, "exec") })
		})
	}
}

func runP12(t *testing.T, spec Spec, command string, change func(*Jailed)) jailResult {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	jailed, err := spec.Command(ctx, command)
	if err != nil {
		return jailResult{setupErr: err, exit: -1}
	}
	defer jailed.Abort()
	if change != nil {
		change(jailed)
	}
	var out, diagnostic bytes.Buffer
	jailed.Cmd.Stdout = &out
	jailed.Cmd.Stderr = &diagnostic
	mutationSetup(t, jailed.Cmd.Start())
	_ = jailed.Started()
	err = jailed.Cmd.Wait()
	_, setupErr := jailed.Status()
	return jailResult{exit: exitCodeOf(err), stdout: out.String(), stderr: diagnostic.String(), setupErr: setupErr}
}

func p12Control(t *testing.T, spec Spec) {
	t.Helper()
	result := runP12(t, spec, "echo CONTROL_RAN", nil)
	if result.setupErr != nil || result.exit != 0 || strings.TrimSpace(result.stdout) != "CONTROL_RAN" {
		t.Fatalf("SETUP: intact jail control: %+v", result)
	}
}

func expectP12Abort(t *testing.T, leg, stage string, errno syscall.Errno, result jailResult) {
	t.Helper()
	if result.setupErr == nil {
		mutationEffect(t, leg, "reached-exec", true)
		return
	}
	var setup *SetupError
	if !errors.As(result.setupErr, &setup) || setup.Stage != stage || setup.Errno != errno {
		t.Fatalf("SETUP: wanted %s/%v, got %+v", stage, errno, result)
	}
	if result.stdout != "" {
		t.Fatalf("SETUP: abort produced command output %q", result.stdout)
	}
}

func hardeningControl(t *testing.T, p *proof, spec Spec) {
	result := runJailed(t, p, spec, RunPlan{Mode: Execute, Ops: []ProofOp{{Name: "control", Command: "printf CONTROL_RAN", Outcomes: []OpOutcome{{Stdout: "CONTROL_RAN"}}}}})
	p.Control("intact", ControlResult{Valid: true, Jailed: &result})
}
func hardeningAbortPlan(stage string, errno syscall.Errno, removed bool) RunPlan {
	if removed && stage == "exec" {
		return RunPlan{Mode: SilentExecFailure, Command: "printf COMMAND_RAN"}
	}
	if removed {
		return RunPlan{Mode: Execute, Ops: []ProofOp{{Name: "attempt", Command: "printf COMMAND_RAN", Outcomes: []OpOutcome{{Stdout: "COMMAND_RAN"}}}}}
	}
	return RunPlan{Mode: SetupAbort, Stage: stage, Errno: errno, Command: "printf COMMAND_RAN"}
}
func legFault(t *testing.T, spec Spec, stage string) {
	p := newProof(t, "L-FAULT-"+stage)
	hardeningControl(t, p, spec)
	spec.InjectFailAt = stage
	errno := syscall.EIO
	if stage == "exec" {
		errno = syscall.ENOENT
	}
	id := "P-FAULT-" + stage
	if stage == "nsverify" {
		id = "P-NSVERIFY"
	}
	if stage == "tsync" {
		id = "P-SC-TSYNC"
	}
	plan := hardeningAbortPlan(stage, errno, jailmut.On(id))
	p.Jailed("attempt", runJailed(t, p, spec, plan))
	mutationEffect(t, "L-FAULT-"+stage, "reached-exec", plan.Mode != SetupAbort)
	p.Finish()
}
func legNamespace(t *testing.T, spec Spec, namespace string) {
	p := newProof(t, "L-NSVERIFY-"+namespace)
	hardeningControl(t, p, spec)
	var results []JailedResult
	if namespace == "pid" {
		expected, err := os.Readlink("/proc/self/ns/pid")
		mutationSetup(t, err)
		results = append(results, runJailed(t, p, spec, RunPlan{Mode: Execute, Ops: []ProofOp{{Name: "pid", Command: "readlink /proc/self/ns/pid", Outcomes: []OpOutcome{{Stdout: expected + "\n"}}}}}))
	}
	before, err := os.ReadFile("/proc/self/mountinfo")
	mutationSetup(t, err)
	plan := hardeningAbortPlan("nsverify", syscall.EPERM, jailmut.On("P-NSVERIFY"))
	plan.Configure = func(j *Jailed) { j.Cmd.Args = append(j.Cmd.Args, "same-"+namespace) }
	results = append(results, runJailed(t, p, spec, plan))
	p.Jailed("attempt", results...)
	after, err := os.ReadFile("/proc/self/mountinfo")
	p.Observed("mounts", Observation{Conclusive: err == nil, Sealed: true, Valid: bytes.Equal(before, after), Detail: "host mountinfo after completed namespace attempt"})
	mutationEffect(t, "L-NSVERIFY-"+namespace, "reached-exec", plan.Mode == Execute)
	p.Finish()
}

func legSpecReject(t *testing.T, abi int) {
	p := newProof(t, "L-SPEC-REJECT")
	defer p.Finish()
	home, err := os.UserHomeDir()
	mutationSetup(t, err)
	directory, err := os.MkdirTemp(home, ".sshgate-jailtest-")
	mutationSetup(t, err)
	t.Cleanup(func() { _ = os.RemoveAll(directory) })
	target := filepath.Join(directory, "target")
	mutationSetup(t, os.WriteFile(target, []byte("canary"), 0600))
	command := "chmod 0644 " + target
	control := exec.Command("/bin/sh", "-c", command)
	mutationSetup(t, control.Run())
	info, err := os.Stat(target)
	mutationSetup(t, err)
	if info.Mode().Perm() != 0644 {
		t.Fatal("SETUP: chmod control did not change mode")
	}
	mutationSetup(t, os.Chmod(target, 0600))
	spec := Spec{Profile: ProfileROv1, ForceABI: abi, Net: true}
	hardeningControl(t, p, spec)
	plan := hardeningAbortPlan("spec", syscall.EINVAL, jailmut.On("P-SPEC"))
	if plan.Mode == Execute {
		plan.Ops[0].Command = "LC_ALL=C " + command + "; printf COMMAND_RAN"
		plan.Ops[0].Outcomes = []OpOutcome{{Stdout: "COMMAND_RAN", Stderr: "chmod: changing permissions of '" + target + "': Operation not permitted\n"}, {Stdout: "COMMAND_RAN", Stderr: "chmod: changing permissions of '" + target + "': Read-only file system\n"}}
	}
	plan.Configure = func(j *Jailed) {
		if err := json.Unmarshal([]byte(j.Cmd.Args[2]), &spec); err != nil {
			unexpected(t, "%v", err)
			t.FailNow()
		}
		spec.Profile = "invalid"
		raw, err := json.Marshal(spec)
		mutationSetup(t, err)
		j.Cmd.Args[2] = string(raw)
		if jailmut.On("P-SPEC") {
			j.spec.Profile = spec.Profile
		}
	}
	result := runJailed(t, p, spec, plan)
	p.Jailed("attempt", result)
	info, err = os.Stat(target)
	mutationSetup(t, err)
	if info.Mode().Perm() != 0600 {
		unexpected(t, "invalid spec changed target mode")
		t.FailNow()
	}
	p.Observed("target", Observation{Conclusive: true, Sealed: true, Valid: info.Mode().Perm() == 0600, Detail: "target mode after completed invalid-spec attempt"})
	// The complete frame proves reaching exec even for the injected profile.
	if result.setupErr == nil || strings.Contains(result.stdout, "COMMAND_RAN") {
		if result.exit != 0 || !strings.Contains(result.stdout, "COMMAND_RAN") {
			t.Fatalf("SETUP: invalid spec did not finish command: %+v", result)
		}
		mutationEffect(t, "L-SPEC-REJECT", "reached-exec", true)
		return
	}
	var setup *SetupError
	if !errors.As(result.setupErr, &setup) || setup.Stage != "spec" || setup.Errno != syscall.EINVAL {
		t.Fatalf("SETUP: expected spec EINVAL, got %+v", result)
	}
}

func legRootState(t *testing.T, spec Spec) {
	p := newProof(t, "L-ROOT-STATE")
	if os.Geteuid() != 0 {
		p.Omit("root-only")
		return
	}
	defer p.Finish()
	probe := buildProbe(t)
	controlCommand := exec.Command(probe, "root-state", "unused")
	var controlStderr bytes.Buffer
	controlCommand.Stderr = &controlStderr
	control, err := controlCommand.Output()
	mutationSetup(t, err)
	if controlStderr.Len() != 0 {
		t.Fatalf("SETUP: control stderr %q", controlStderr.String())
	}
	mutationSetup(t, validateHardeningControl("root-state", string(control)))
	if strings.Contains(string(control), "CapEff:\t0000000000000004\n") {
		t.Fatal("SETUP: root capability control already at jail floor")
	}
	if !strings.Contains(string(control), "CapEff:") {
		t.Fatal("SETUP: missing root capability control")
	}

	p.Control("probe", ControlResult{Valid: true, Detail: "unjailed capability floor differs"})
	result := hardeningProbe(t, p, spec, probe+" root-state unused", 0)
	if result.setupErr != nil || result.exit != 0 {
		t.Fatalf("SETUP: root state: %+v", result)
	}
	for _, name := range []string{"uid_map", "gid_map"} {
		start := strings.Index(result.stdout, name+":\n")
		if start < 0 {
			unexpected(t, "missing %s", name)
			t.FailNow()
		}
		line := strings.SplitN(result.stdout[start+len(name)+2:], "\n", 2)[0]
		if strings.Join(strings.Fields(line), " ") != "0 0 4294967295" {
			unexpected(t, "%s is not full-range: %q", name, line)
		}
	}
	for _, name := range []string{"CapPrm", "CapEff", "CapBnd", "CapInh", "CapAmb"} {
		want := uint64(0)
		if name == "CapPrm" || name == "CapEff" || name == "CapBnd" {
			want = 4
		}
		found := false
		for _, line := range strings.Split(result.stdout, "\n") {
			if strings.HasPrefix(line, name+":") {
				found = true
				value, err := strconv.ParseUint(strings.TrimSpace(strings.TrimPrefix(line, name+":")), 16, 64)
				if err != nil || value != want {
					unexpected(t, "%s got %q want %#x", name, line, want)
				}
			}
		}
		if !found {
			unexpected(t, "missing %s", name)
		}
	}
	if !strings.Contains(result.stdout, "open_by_handle_at=1\n") {
		unexpected(t, "open_by_handle_at did not return EPERM")
	}
	// The init-userns capability check also denies handles; pin the filter wall independently.
	if evalFilter(t, buildFilter(filterParams{}), dataFor(unix.SYS_OPEN_BY_HANDLE_AT, x8664)) != actDeny {
		unexpected(t, "root filter permits open_by_handle_at")
	}
	p.Observed("probe", Observation{Conclusive: true, Sealed: true, Valid: !t.Failed(), Detail: "complete framed operation and all post-operation assertions checked"})
}

func legRootNproc(t *testing.T, spec Spec) {
	p := newProof(t, "L-ROOT-NPROC")
	if os.Geteuid() != 0 {
		p.Omit("root-only")
		return
	}
	defer p.Finish()
	probe := buildProbe(t)
	controlCommand := exec.Command(probe, "root-nproc", "unused")
	var controlStderr bytes.Buffer
	controlCommand.Stderr = &controlStderr
	control, err := controlCommand.Output()
	mutationSetup(t, err)
	if controlStderr.Len() != 0 {
		t.Fatalf("SETUP: control stderr %q", controlStderr.String())
	}
	mutationSetup(t, validateHardeningControl("root-nproc", string(control)))
	if !strings.Contains(string(control), "fork-root=ok") {
		t.Fatalf("SETUP: root control %s", control)
	}
	p.Control("probe", ControlResult{Valid: true, Detail: "unjailed root fork completed"})
	result := hardeningProbe(t, p, spec, probe+" root-nproc unused", 0)
	if result.setupErr != nil || result.exit != 0 || (!strings.Contains(result.stdout, "fork-root=ok") || !strings.Contains(result.stdout, "nproc=256:256")) {
		unexpected(t, "root NPROC exemption: %+v", result)
		t.FailNow()
	}
	p.Observed("probe", Observation{Conclusive: true, Sealed: true, Valid: !t.Failed(), Detail: "complete framed operation and all post-operation assertions checked"})
}

func legRootProc(t *testing.T, spec Spec) {
	p := newProof(t, "L-ROOT-PROC")
	if os.Geteuid() != 0 {
		p.Omit("root-only")
		return
	}
	if os.Getenv("SSHGATE_JAIL_CI") != "1" {
		p.Omit("ci-only")
		return
	}
	defer p.Finish()
	const path = "/proc/sys/kernel/printk"
	before, err := os.ReadFile(path)
	mutationSetup(t, err)
	mutationSetup(t, os.WriteFile(path, before, 0600))
	p.Control("probe", ControlResult{Valid: true, Detail: "unjailed printk write completed"})
	result := hardeningProbe(t, p, spec, "LC_ALL=C /bin/sh -c "+proofShellQuote("printf '%s' '"+strings.TrimSpace(string(before))+"' > "+path), -1)
	if result.setupErr != nil {
		t.Fatalf("SETUP: %+v", result)
	}
	if result.exit == 0 || !strings.Contains(strings.ToLower(result.stderr), "read-only") {
		unexpected(t, "expected EROFS: %+v", result)
		t.FailNow()
	}
	after, err := os.ReadFile(path)
	mutationSetup(t, err)
	if !bytes.Equal(before, after) {
		unexpected(t, "printk changed")
		t.FailNow()
	}
	p.Observed("probe", Observation{Conclusive: true, Sealed: true, Valid: !t.Failed(), Detail: "complete framed operation and all post-operation assertions checked"})
}

func legScratchMetadata(t *testing.T, spec Spec) {
	p := newProof(t, "L-SCRATCH-META")
	defer p.Finish()
	probe := buildProbe(t)
	target := filepath.Join(t.TempDir(), "metadata")
	mutationSetup(t, os.WriteFile(target, []byte("canary"), 0600))
	controlCommand := exec.Command(probe, "metadata", target)
	var controlStderr bytes.Buffer
	controlCommand.Stderr = &controlStderr
	control, err := controlCommand.Output()
	mutationSetup(t, err)
	mutationSetup(t, validateHardeningEffectControl("metadata", string(control), controlStderr.String(), 0))
	for _, op := range []string{"chmod", "chown", "setxattr", "utimensat"} {
		if !strings.Contains(string(control), op+"=ok\n") {
			t.Fatalf("SETUP: control %s", control)
		}
	}
	p.Control("probe", ControlResult{Valid: true, Detail: "all unjailed metadata operations succeeded"})
	command := "umask 077; test ! -e /dev/shm/metadata && printf canary > /dev/shm/metadata && " + probe + " metadata-snapshot /dev/shm/metadata before && { " + probe + " metadata /dev/shm/metadata; metadata_status=$?; " + probe + " metadata-snapshot /dev/shm/metadata after || exit $?; exit $metadata_status; }"
	result := hardeningProbe(t, p, spec, command, -1)
	before, after, _, err := parseHardeningMetadata(result.stdout)
	mutationSetup(t, err)
	if result.setupErr != nil {
		t.Fatalf("SETUP: metadata: %+v", result)
	}
	success := 0
	// Linux 6.1 tmpfs has no user xattrs: with the filter removed, setxattr
	// reaches tmpfs and fails EOPNOTSUPP. The filter itself always gives EPERM.
	xattrUnsupported := strings.Contains(result.stdout, "setxattr=95\n")
	for _, op := range []string{"chmod", "chown", "setxattr", "utimensat"} {
		if strings.Contains(result.stdout, op+"=ok\n") || op == "setxattr" && xattrUnsupported {
			success++
			continue
		}
		if !strings.Contains(result.stdout, op+"=1\n") {
			t.Fatalf("SETUP: missing EPERM for %s: %+v", op, result)
		}
	}
	switch success {
	case 0:
		if before != after {
			t.Fatalf("SETUP: denied metadata changed state: before=%+v after=%+v", before, after)
		}
		if result.exit != 1 {
			t.Fatalf("SETUP: denied metadata exit: %+v", result)
		}
	case 4:
		wantXattr := "test"
		if xattrUnsupported {
			wantXattr = "unsupported"
		}
		if after.mode != "644" || after.seconds != "1000" || after.nanoseconds != "0" || after.xattr != wantXattr {
			t.Fatalf("SETUP: metadata effect snapshot incomplete: %+v", after)
		}
		if result.exit == 0 == xattrUnsupported || !strings.Contains(result.stdout, "mode=644\n") || !strings.Contains(result.stdout, "mtime=1000\n") || !xattrUnsupported && !strings.Contains(result.stdout, "xattr=test\n") {
			t.Fatalf("SETUP: metadata effect incomplete: %+v", result)
		}
		mutationEffect(t, "L-SCRATCH-META", "metadata", true)
	default:
		t.Fatalf("SETUP: partial metadata mutation: %+v", result)
	}
	p.Observed("probe", Observation{Conclusive: true, Sealed: true, Valid: !t.Failed(), Detail: "complete framed operation and all post-operation assertions checked"})
}

func legFileattrErrno(t *testing.T, spec Spec) {
	p := newProof(t, "L-FILEATTR-ERRNO")
	defer p.Finish()
	probe := buildProbe(t)
	file, err := os.CreateTemp("/dev/shm", "sshgate-fileattr-")
	mutationSetup(t, err)
	target := file.Name()
	mutationSetup(t, file.Close())
	t.Cleanup(func() { _ = os.Remove(target) })
	controlCommand := exec.Command(probe, "fileattr", target)
	var controlStderr bytes.Buffer
	controlCommand.Stderr = &controlStderr
	control, err := controlCommand.Output()
	var exit *exec.ExitError
	if err != nil && !errors.As(err, &exit) {
		mutationSetup(t, err)
	}
	mutationSetup(t, validateHardeningEffectControl("fileattr", string(control), controlStderr.String(), proofExit(err)))
	expected := map[string]string{}
	for _, op := range []string{"setflags", "setflags32", "fssetxattr"} {
		for _, line := range strings.Split(string(control), "\n") {
			if strings.HasPrefix(line, op+"=") {
				expected[op] = line
			}
		}
		if expected[op] == "" || expected[op] == op+"=1" {
			t.Fatalf("SETUP: fileattr control unavailable: %s", control)
		}
	}
	p.Control("probe", ControlResult{Valid: true, Detail: "all unjailed fileattr responses established"})
	result := hardeningProbe(t, p, spec, "printf canary > /dev/shm/fileattr; "+probe+" fileattr /dev/shm/fileattr", -1)
	if result.setupErr != nil || !strings.Contains(result.stdout, "open=ok\n") {
		t.Fatalf("SETUP: fileattr: %+v", result)
	}
	unfiltered := 0
	for op, want := range expected {
		if strings.Contains(result.stdout, op+"=1\n") {
			continue
		}
		if !strings.Contains(result.stdout, want+"\n") {
			t.Fatalf("SETUP: unexpected fileattr response for %s: %+v control=%s", op, result, control)
		}
		unfiltered++
	}
	if unfiltered != 0 && unfiltered != 3 {
		t.Fatalf("SETUP: partial fileattr mutation: %+v", result)
	}
	expectedExit := 0
	if exit != nil {
		expectedExit = exit.ExitCode()
	}
	if unfiltered == 3 && result.exit != expectedExit {
		t.Fatalf("SETUP: fileattr exit differs from control: %+v", result)
	}
	if unfiltered == 0 && result.exit != 3 {
		t.Fatalf("SETUP: denied fileattr exit: %+v", result)
	}
	mutationEffect(t, "L-FILEATTR-ERRNO", "fileattr-errno", unfiltered == 3)
	p.Observed("probe", Observation{Conclusive: true, Sealed: true, Valid: !t.Failed(), Detail: "complete framed operation and all post-operation assertions checked"})
}

func hardeningProbe(t *testing.T, p *proof, spec Spec, command string, wantExit int) JailedResult {
	result := runJailed(t, p, spec, RunPlan{Mode: Execute, Ops: []ProofOp{{Name: "probe", Command: command, Validate: func(stdout, stderr string, exit int) error {
		return validateHardeningReport(p.caseDef.Name, stdout, stderr, exit, wantExit)
	}}}})
	p.Jailed("probe", result)
	return result
}
