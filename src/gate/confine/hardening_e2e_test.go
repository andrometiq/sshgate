//go:build linux && jail_e2e

package confine

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
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
				p12Control(t, spec)
				withoutLandlock := spec
				withoutLandlock.ForceABI = ForceNoLandlock
				result := runP12(t, withoutLandlock, "echo COMMAND_RAN", nil)
				expectP12Abort(t, "L-LL-REQUIRED", "landlock", syscall.ENOSYS, result)
			})
			if os.Geteuid() == 0 {
				t.Run("L-ROOT-STATE", func(t *testing.T) { legRootState(t, spec) })
				t.Run("L-ROOT-NPROC", func(t *testing.T) { legRootNproc(t, spec) })
				if os.Getenv("SSHGATE_JAIL_CI") == "1" {
					t.Run("L-ROOT-PROC", func(t *testing.T) { legRootProc(t, spec) })
				} else {
					t.Log("MUTATE-OMITTED(ci-only): L-ROOT-PROC")
				}
			} else {
				t.Log("MUTATE-OMITTED(root): L-ROOT-STATE L-ROOT-NPROC L-ROOT-PROC")
			}
			t.Run("L-INJECT-ERRNO", func(t *testing.T) {
				p12Control(t, spec)
				injected := spec
				injected.InjectFailAt = "cmdread:EACCES"
				result := runP12(t, injected, "echo COMMAND_RAN", nil)
				expectP12Abort(t, "L-INJECT-ERRNO", "cmdread", syscall.EACCES, result)
			})
			t.Run("L-SPEC-REJECT", func(t *testing.T) { legSpecReject(t, cfg.abi) })
			t.Run("L-NSVERIFY-user", func(t *testing.T) { legNamespace(t, spec, "user") })
			t.Run("L-NSVERIFY-mnt", func(t *testing.T) { legNamespace(t, spec, "mnt") })
			t.Run("L-NSVERIFY-pid", func(t *testing.T) { legNamespace(t, spec, "pid") })
			t.Run("L-NSVERIFY-ipc", func(t *testing.T) { legNamespace(t, spec, "ipc") })
			t.Run("L-NSVERIFY-parent", func(t *testing.T) {
				p12Control(t, spec)
				result := runP12(t, spec, "echo COMMAND_RAN", func(j *Jailed) { j.Cmd.Args[1] = SentinelWorker })
				expectP12Abort(t, "L-NSVERIFY-parent", "nsverify", syscall.EPERM, result)
			})
			t.Run("L-HOSTMOUNTS-UNCHANGED", func(t *testing.T) {
				before, err := os.ReadFile("/proc/self/mountinfo")
				mutationSetup(t, err)
				result := runP12(t, spec, "echo COMMAND_RAN", func(j *Jailed) { j.Cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true} })
				var setup *SetupError
				if !errors.As(result.setupErr, &setup) || setup.Stage != "nsverify" {
					t.Fatalf("SETUP: clobber did not abort: %+v", result)
				}
				after, err := os.ReadFile("/proc/self/mountinfo")
				mutationSetup(t, err)
				if !bytes.Equal(before, after) {
					t.Fatal("host mountinfo changed")
				}
			})
			t.Run("L-FAULT-nsverify", func(t *testing.T) { legFault(t, spec, "nsverify") })
			t.Run("L-SHIM-PID1", func(t *testing.T) { legShimPID1(t, spec) })
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
	return jailResult{exit: exitCodeOf(err), stdout: out.String(), stderr: diagnostic.String(), setupErr: jailed.Status()}
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

func legFault(t *testing.T, spec Spec, stage string) {
	p12Control(t, spec)
	spec.InjectFailAt = stage
	result := runP12(t, spec, "echo COMMAND_RAN", nil)
	errno := syscall.EIO
	if stage == "exec" {
		errno = syscall.ENOENT
	}
	expectP12Abort(t, "L-FAULT-"+stage, stage, errno, result)
}

func legNamespace(t *testing.T, spec Spec, namespace string) {
	p12Control(t, spec)
	before, err := os.ReadFile("/proc/self/mountinfo")
	mutationSetup(t, err)
	result := runP12(t, spec, "echo COMMAND_RAN", func(j *Jailed) { j.Cmd.Args = append(j.Cmd.Args, "same-"+namespace) })
	expectP12Abort(t, "L-NSVERIFY-"+namespace, "nsverify", syscall.EPERM, result)
	after, err := os.ReadFile("/proc/self/mountinfo")
	mutationSetup(t, err)
	if !bytes.Equal(before, after) {
		t.Fatal("host mountinfo changed")
	}
}

func legShimPID1(t *testing.T, spec Spec) {
	p12Control(t, spec)
	result := runP12(t, spec, "echo COMMAND_RAN", func(j *Jailed) {
		j.Cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
		j.Cmd.Args[2] = "{}"
	})
	var setup *SetupError
	if errors.As(result.setupErr, &setup) && setup.Stage == "spec" {
		mutationAbort(t, "L-SHIM-PID1", "spec", true)
		return
	}
	expectP12Abort(t, "L-SHIM-PID1", "nsverify", syscall.EPERM, result)
}

func legSpecReject(t *testing.T, abi int) {
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
	p12Control(t, spec)
	result := runP12(t, spec, command+"; echo COMMAND_RAN", func(j *Jailed) {
		if err := json.Unmarshal([]byte(j.Cmd.Args[2]), &spec); err != nil {
			t.Fatal(err)
		}
		spec.Profile = "invalid"
		raw, err := json.Marshal(spec)
		mutationSetup(t, err)
		j.Cmd.Args[2] = string(raw)
	})
	info, err = os.Stat(target)
	mutationSetup(t, err)
	if info.Mode().Perm() != 0600 {
		t.Fatal("invalid spec changed target mode")
	}
	if result.setupErr == nil {
		if result.exit != 0 || !strings.Contains(result.stdout, "COMMAND_RAN\n") {
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
	probe := buildProbe(t)
	control, err := exec.Command(probe, "root-state", "unused").CombinedOutput()
	mutationSetup(t, err)
	if strings.Contains(string(control), "CapEff:\t0000000000000004\n") {
		t.Fatal("SETUP: root capability control already at jail floor")
	}
	if !strings.Contains(string(control), "CapEff:") {
		t.Fatal("SETUP: missing root capability control")
	}

	result := runP12(t, spec, probe+" root-state unused", nil)
	if result.setupErr != nil || result.exit != 0 {
		t.Fatalf("SETUP: root state: %+v", result)
	}
	for _, name := range []string{"uid_map", "gid_map"} {
		start := strings.Index(result.stdout, name+":\n")
		if start < 0 {
			t.Fatalf("missing %s", name)
		}
		line := strings.SplitN(result.stdout[start+len(name)+2:], "\n", 2)[0]
		if strings.Join(strings.Fields(line), " ") != "0 0 4294967295" {
			t.Errorf("%s is not full-range: %q", name, line)
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
					t.Errorf("%s got %q want %#x", name, line, want)
				}
			}
		}
		if !found {
			t.Errorf("missing %s", name)
		}
	}
	if !strings.Contains(result.stdout, "open_by_handle_at=1\n") {
		t.Error("open_by_handle_at did not return EPERM")
	}
	// The init-userns capability check also denies handles; pin the filter wall independently.
	if evalFilter(t, buildFilter(filterParams{denyOpenByHandle: true}), dataFor(unix.SYS_OPEN_BY_HANDLE_AT, x8664)) != actDeny {
		t.Error("root filter permits open_by_handle_at")
	}
}

func legRootNproc(t *testing.T, spec Spec) {
	probe := buildProbe(t)
	control, err := exec.Command(probe, "root-nproc", "unused").CombinedOutput()
	mutationSetup(t, err)
	if !strings.Contains(string(control), "fork-root=ok") {
		t.Fatalf("SETUP: root control %s", control)
	}
	result := runP12(t, spec, probe+" root-nproc unused", nil)
	if result.setupErr != nil || result.exit != 0 || (!strings.Contains(result.stdout, "fork-root=ok") || !strings.Contains(result.stdout, "nproc=256:256")) {
		t.Fatalf("root NPROC exemption: %+v", result)
	}
}

func legRootProc(t *testing.T, spec Spec) {
	const path = "/proc/sys/kernel/printk"
	before, err := os.ReadFile(path)
	mutationSetup(t, err)
	mutationSetup(t, os.WriteFile(path, before, 0600))
	result := runP12(t, spec, "printf '%s' '"+strings.TrimSpace(string(before))+"' > "+path, nil)
	if result.setupErr != nil {
		t.Fatalf("SETUP: %+v", result)
	}
	if result.exit == 0 || !strings.Contains(strings.ToLower(result.stderr), "read-only") {
		t.Fatalf("expected EROFS: %+v", result)
	}
	after, err := os.ReadFile(path)
	mutationSetup(t, err)
	if !bytes.Equal(before, after) {
		t.Fatal("printk changed")
	}
}

func legScratchMetadata(t *testing.T, spec Spec) {
	probe := buildProbe(t)
	target := filepath.Join(t.TempDir(), "metadata")
	mutationSetup(t, os.WriteFile(target, []byte("canary"), 0600))
	control, err := exec.Command(probe, "metadata", target).CombinedOutput()
	mutationSetup(t, err)
	for _, op := range []string{"chmod", "chown", "setxattr", "utimensat"} {
		if !strings.Contains(string(control), op+"=ok\n") {
			t.Fatalf("SETUP: control %s", control)
		}
	}
	result := runP12(t, spec, "umask 077; printf canary > /dev/shm/metadata; "+probe+" metadata /dev/shm/metadata", nil)
	if result.setupErr != nil {
		t.Fatalf("SETUP: metadata: %+v", result)
	}
	success := 0
	for _, op := range []string{"chmod", "chown", "setxattr", "utimensat"} {
		if strings.Contains(result.stdout, op+"=ok\n") {
			success++
			continue
		}
		if !strings.Contains(result.stdout, op+"=1\n") {
			t.Fatalf("SETUP: missing EPERM for %s: %+v", op, result)
		}
	}
	switch success {
	case 0:
		if result.exit != 1 {
			t.Fatalf("SETUP: denied metadata exit: %+v", result)
		}
	case 4:
		if result.exit != 0 || !strings.Contains(result.stdout, "mode=644\n") || !strings.Contains(result.stdout, "mtime=1000\n") || !strings.Contains(result.stdout, "xattr=test\n") {
			t.Fatalf("SETUP: metadata effect incomplete: %+v", result)
		}
		mutationEffect(t, "L-SCRATCH-META", "metadata", true)
	default:
		t.Fatalf("SETUP: partial metadata mutation: %+v", result)
	}
}

func legFileattrErrno(t *testing.T, spec Spec) {
	probe := buildProbe(t)
	file, err := os.CreateTemp("/dev/shm", "sshgate-fileattr-")
	mutationSetup(t, err)
	target := file.Name()
	mutationSetup(t, file.Close())
	t.Cleanup(func() { _ = os.Remove(target) })
	control, err := exec.Command(probe, "fileattr", target).CombinedOutput()
	var exit *exec.ExitError
	if err != nil && !errors.As(err, &exit) {
		mutationSetup(t, err)
	}
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
	result := runP12(t, spec, "printf canary > /dev/shm/fileattr; "+probe+" fileattr /dev/shm/fileattr", nil)
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
}
