//go:build linux && jail_e2e

package confine

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

func legCoverLoop(t *testing.T, spec Spec) {
	if !coverNamespace(t, false) {
		return
	}
	p := newProof(t, "L-COVER-LOOP")
	point := filepath.Join(t.TempDir(), "loop")
	fixture := startCoverFuse(t, point, "--loop", point, "--ci")
	control, err := os.ReadFile(filepath.Join(point, "f"))
	mutationSetup(t, err)
	if string(control) != "loop-canary\n" {
		t.Fatal("SETUP: loop control missing canary")
	}
	p.Control("canary", ControlResult{Valid: string(control) == "loop-canary\n", Detail: "loop canary"})
	result := runJailed(t, p, spec, RunPlan{Mode: Execute, Ops: []ProofOp{{Name: "directory", Command: "ls -A " + coverQuote(point), Validate: func(stdout, stderr string, exit int) error {
		if stderr != "" || exit != 0 {
			return fmt.Errorf("directory listing: exit=%d stderr=%q", exit, stderr)
		}
		return nil
	}}}})
	p.Jailed("probe", result)
	coverRan(t, result.jailResult)
	mutationEffect(t, "L-COVER-LOOP", "visible", strings.Contains(result.stdout, "f"))
	mutationEffect(t, "L-COVER-LOOP", "nonempty", result.stdout != "")
	p.Observed("directory", Observation{Conclusive: true, Sealed: true, Valid: result.stdout == "" || result.stdout == "f\nlost+found\n", Detail: "completed directory listing"})
	mutationSetup(t, fixture.Stop())
	p.Finish()
}

func autofsKinds(t *testing.T, point string) []string {
	t.Helper()
	entries, err := readMountInfo()
	mutationSetup(t, err)
	var kinds []string
	for _, entry := range entries {
		if entry.point == point {
			kinds = append(kinds, entry.fstype)
		}
	}
	return kinds
}
func legAutofs(t *testing.T, spec Spec) {
	p := newProof(t, "L-AUTOFS")
	if os.Geteuid() != 0 || os.Getenv("SSHGATE_JAIL_CI") != "1" {
		t.Fatal("SETUP: autofs needs disposable root CI")
	}
	point := filepath.Join(t.TempDir(), "automount")
	mutationSetup(t, os.MkdirAll(point, 0755))
	command := exec.Command("systemd-mount", "--automount=yes", "--collect", "-t", "tmpfs", "tmpfs", point)
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("SETUP: systemd automount: %v: %s", err, output)
	}
	t.Cleanup(func() {
		output, err := exec.Command("systemd-mount", "--umount", point).CombinedOutput()
		if err != nil {
			unexpected(t, "autofs cleanup: %v: %s", err, output)
		}
	})
	kinds := autofsKinds(t, point)
	if len(kinds) != 1 || kinds[0] != "autofs" {
		t.Fatalf("SETUP: trigger not initially dormant: %v", kinds)
	}
	result := runJailed(t, p, spec, RunPlan{Mode: Execute, Ops: []ProofOp{{Name: "directory", Command: "ls -A " + coverQuote(point), Outcomes: []OpOutcome{{Stdout: "", Stderr: "", Exit: 0}}}}})
	p.Jailed("probe", result)
	coverRan(t, result.jailResult)
	kinds = autofsKinds(t, point)
	triggered := len(kinds) != 1 || kinds[0] != "autofs"
	mutationEffect(t, "L-AUTOFS", "triggered", triggered)
	p.Observed("mounts", Observation{Conclusive: true, Sealed: true, Valid: len(kinds) > 0, Detail: "mountinfo after synchronous listing"})
	if result.exit != 0 || result.stdout != "" {
		unexpected(t, "autofs cover not empty: %+v", result)
	}
	output, err = exec.Command("ls", "-A", point).CombinedOutput()
	if err != nil {
		t.Fatalf("SETUP: automount control: %v: %s", err, output)
	}
	kinds = autofsKinds(t, point)
	if len(kinds) < 2 || kinds[len(kinds)-1] != "tmpfs" {
		t.Fatalf("SETUP: unjailed control did not trigger: %v", kinds)
	}
	p.Control("trigger", ControlResult{Valid: len(kinds) >= 2 && kinds[len(kinds)-1] == "tmpfs", Detail: "control triggered tmpfs"})
	p.Finish()
}

func legBinfmtFixed(t *testing.T, spec Spec) {
	if !coverNamespace(t, false) {
		return
	}
	p := newProof(t, "L-BINFMT-FIXED-CHAR")
	directory := t.TempDir()
	point := filepath.Join(directory, "fuse")
	fixture := startCoverFuse(t, point, "--content", "/bin/echo")
	p.ObserveWith("fuse", fixture)
	registry := filepath.Join(directory, "binfmt")
	mutationSetup(t, os.Mkdir(registry, 0755))
	mutationSetup(t, unix.Mount("binfmt_misc", registry, "binfmt_misc", unix.MS_NOSUID|unix.MS_NODEV, ""))
	t.Cleanup(func() {
		if err := unix.Unmount(registry, unix.MNT_DETACH); err != nil {
			unexpected(t, "binfmt unmount: %v", err)
		}
	})
	name := fmt.Sprintf("sshgate-fixed-%d", os.Getpid())
	registration := fmt.Sprintf(":%s:M::SG22FIXED::%s/f:F", name, point)
	mutationSetup(t, os.WriteFile(filepath.Join(registry, "register"), []byte(registration), 0600))
	t.Cleanup(func() {
		if err := os.WriteFile(filepath.Join(registry, name), []byte("-1"), 0600); err != nil {
			unexpected(t, "binfmt unregister: %v", err)
		}
	})
	image := filepath.Join(directory, "fixed-image")
	mutationSetup(t, os.WriteFile(image, []byte("SG22FIXED\n"), 0755))
	control, err := exec.Command(image, "INTERPRETER_RAN").CombinedOutput()
	if err != nil || !strings.Contains(string(control), "INTERPRETER_RAN") {
		t.Fatalf("SETUP: fixed interpreter control: %v: %s", err, control)
	}
	p.Control("interpreter", ControlResult{Valid: err == nil && strings.Contains(string(control), "INTERPRETER_RAN"), Detail: "fixed interpreter control"})
	releaseMark := fixture.mark(t)
	interpreter, err := os.Open(filepath.Join(point, "f"))
	mutationSetup(t, err)
	mutationSetup(t, unix.Fadvise(int(interpreter.Fd()), 0, 0, unix.FADV_DONTNEED))
	mutationSetup(t, interpreter.Close())
	fixture.waitRelease(t, releaseMark)
	mark := fixture.mark(t)
	result := runJailed(t, p, spec, RunPlan{Mode: Execute, Ops: []ProofOp{{Name: "interpreter", Command: coverQuote(image) + " INTERPRETER_RAN", Validate: func(stdout, stderr string, exit int) error {
		if exit != 0 || stderr != "" || !strings.Contains(stdout, "INTERPRETER_RAN") {
			return fmt.Errorf("interpreter completion: %d %q %q", exit, stdout, stderr)
		}
		return nil
	}}}})
	p.Jailed("probe", result)
	coverRan(t, result.jailResult)
	if result.exit != 0 || !strings.Contains(result.stdout, "INTERPRETER_RAN") {
		unexpected(t, "R18 fixed interpreter residual absent: %+v", result)
	}
	fixture.seal(t)
	log := fixture.since(t, mark)
	if !coverHasRecord(log, "READ") {
		unexpected(t, "R18 fixed interpreter did not delegate reads after cover: %s", log)
	}
	p.Observed("read", Observation{Conclusive: true, Sealed: true, Valid: coverHasRecord(log, "READ"), Detail: "R18 retained interpreter FUSE read"})
	p.Finish()
}
