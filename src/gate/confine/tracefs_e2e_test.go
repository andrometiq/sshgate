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

func legTracefs(t *testing.T, spec Spec) {
	if os.Geteuid() != 0 || os.Getenv("SSHGATE_JAIL_CI") != "1" {
		t.Fatal("SETUP: tracefs requires disposable root CI")
	}
	if !catalogueNamespace(t, true) {
		return
	}
	point := filepath.Join(t.TempDir(), "tracefs")
	mutationSetup(t, os.Mkdir(point, 0755))
	mutationSetup(t, unix.Mount("tracefs", point, "tracefs", unix.MS_NOSUID|unix.MS_NODEV, ""))
	t.Cleanup(func() {
		if err := unix.Unmount(point, unix.MNT_DETACH); err != nil {
			t.Errorf("tracefs unmount: %v", err)
		}
	})
	instance := filepath.Join(point, "instances", fmt.Sprintf("sshgate-%d", os.Getpid()))
	mutationSetup(t, os.Mkdir(instance, 0700))
	t.Cleanup(func() {
		if err := os.Remove(instance); err != nil {
			t.Errorf("trace instance cleanup: %v", err)
		}
	})
	mutationSetup(t, os.WriteFile(filepath.Join(instance, "tracing_on"), []byte("1"), 0600))
	marker := fmt.Sprintf("sshgate-trace-canary-%d", os.Getpid())
	mutationSetup(t, os.WriteFile(filepath.Join(instance, "trace_marker"), []byte(marker+"\n"), 0600))
	readTrace := func() string {
		data, err := os.ReadFile(filepath.Join(instance, "trace"))
		mutationSetup(t, err)
		return string(data)
	}
	if !strings.Contains(readTrace(), marker) {
		t.Fatal("SETUP: trace marker not recorded")
	}
	probe := buildProbe(t)
	pipe := filepath.Join(instance, "trace_pipe")
	result := runP12(t, spec, coverQuote(probe)+" trace-drain "+coverQuote(pipe), nil)
	coverRan(t, result)
	consumed := !strings.Contains(readTrace(), marker)
	mutationEffect(t, "L-TRACEFS", "trace-consumed", consumed)
	if consumed {
		if !strings.Contains(result.stdout, marker) {
			t.Error("marker disappeared without being read by jail")
		}
		mutationSetup(t, os.WriteFile(filepath.Join(instance, "trace_marker"), []byte(marker+"\n"), 0600))
	} else if !strings.Contains(result.stdout, "open=2\n") {
		t.Errorf("trace pipe not hidden: %+v", result)
	}
	control, err := exec.Command(probe, "trace-drain", pipe).CombinedOutput()
	mutationSetup(t, err)
	if !strings.Contains(string(control), marker) || strings.Contains(readTrace(), marker) {
		t.Fatalf("SETUP: trace pipe control did not consume marker: %s", control)
	}
}
