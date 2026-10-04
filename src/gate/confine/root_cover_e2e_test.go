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
	point := filepath.Join(t.TempDir(), "loop")
	startCoverFuse(t, point, "--loop", point, "--ci")
	control, err := os.ReadFile(filepath.Join(point, "f"))
	mutationSetup(t, err)
	if string(control) != "loop-canary\n" {
		t.Fatal("SETUP: loop control missing canary")
	}
	result, _ := coverResult(t, spec, "ls -A "+coverQuote(point), nil)
	coverRan(t, result)
	mutationEffect(t, "L-COVER-LOOP", "visible", strings.Contains(result.stdout, "f"))
	if result.exit != 0 || result.stdout != "" {
		t.Errorf("loop cover is not empty: %+v", result)
	}
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
			t.Errorf("autofs cleanup: %v: %s", err, output)
		}
	})
	kinds := autofsKinds(t, point)
	if len(kinds) != 1 || kinds[0] != "autofs" {
		t.Fatalf("SETUP: trigger not initially dormant: %v", kinds)
	}
	result, _ := coverResult(t, spec, "ls -A "+coverQuote(point), nil)
	coverRan(t, result)
	kinds = autofsKinds(t, point)
	triggered := len(kinds) != 1 || kinds[0] != "autofs"
	mutationEffect(t, "L-AUTOFS", "triggered", triggered)
	if result.exit != 0 || result.stdout != "" {
		t.Errorf("autofs cover not empty: %+v", result)
	}
	output, err = exec.Command("ls", "-A", point).CombinedOutput()
	if err != nil {
		t.Fatalf("SETUP: automount control: %v: %s", err, output)
	}
	kinds = autofsKinds(t, point)
	if len(kinds) < 2 || kinds[len(kinds)-1] != "tmpfs" {
		t.Fatalf("SETUP: unjailed control did not trigger: %v", kinds)
	}
}

func legBinfmtFixed(t *testing.T, spec Spec) {
	if !coverNamespace(t, false) {
		return
	}
	directory := t.TempDir()
	point := filepath.Join(directory, "fuse")
	fixture := startCoverFuse(t, point, "--content", "/bin/echo")
	registry := filepath.Join(directory, "binfmt")
	mutationSetup(t, os.Mkdir(registry, 0755))
	mutationSetup(t, unix.Mount("binfmt_misc", registry, "binfmt_misc", unix.MS_NOSUID|unix.MS_NODEV, ""))
	t.Cleanup(func() {
		if err := unix.Unmount(registry, unix.MNT_DETACH); err != nil {
			t.Errorf("binfmt unmount: %v", err)
		}
	})
	name := fmt.Sprintf("sshgate-fixed-%d", os.Getpid())
	registration := fmt.Sprintf(":%s:M::SG22FIXED::%s/f:F", name, point)
	mutationSetup(t, os.WriteFile(filepath.Join(registry, "register"), []byte(registration), 0600))
	t.Cleanup(func() {
		if err := os.WriteFile(filepath.Join(registry, name), []byte("-1"), 0600); err != nil {
			t.Errorf("binfmt unregister: %v", err)
		}
	})
	image := filepath.Join(directory, "fixed-image")
	mutationSetup(t, os.WriteFile(image, []byte("SG22FIXED\n"), 0755))
	control, err := exec.Command(image, "INTERPRETER_RAN").CombinedOutput()
	if err != nil || !strings.Contains(string(control), "INTERPRETER_RAN") {
		t.Fatalf("SETUP: fixed interpreter control: %v: %s", err, control)
	}
	interpreter, err := os.Open(filepath.Join(point, "f"))
	mutationSetup(t, err)
	mutationSetup(t, unix.Fadvise(int(interpreter.Fd()), 0, 0, unix.FADV_DONTNEED))
	mutationSetup(t, interpreter.Close())
	mark := fixture.mark(t)
	result, _ := coverResult(t, spec, coverQuote(image)+" INTERPRETER_RAN", nil)
	coverRan(t, result)
	if result.exit != 0 || !strings.Contains(result.stdout, "INTERPRETER_RAN") {
		t.Errorf("R18 fixed interpreter residual absent: %+v", result)
	}
	log := fixture.since(t, mark)
	if !strings.Contains(log, "READ\n") {
		t.Errorf("R18 fixed interpreter did not delegate reads after cover: %s", log)
	}
	t.Log("CHARACTERISATION R18: fixed binfmt interpreter executes through retained FUSE reference")
}
