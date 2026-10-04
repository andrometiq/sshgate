//go:build linux && jail_e2e

package confine

import (
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestPhase1CrashFileObserver(t *testing.T) {
	directory := t.TempDir()
	since := time.Now().Add(-time.Second)
	if waitFileCore(t, directory, since, 0) {
		t.Fatal("empty fixture recorded a core")
	}
	path := filepath.Join(directory, "core.123")
	if err := os.WriteFile(path, []byte("unrelated file"), 0600); err != nil {
		t.Fatal(err)
	}
	if waitFileCore(t, directory, since, 0) {
		t.Fatal("non-core file recorded a core")
	}
	header := make([]byte, 18)
	copy(header, []byte{0x7f, 'E', 'L', 'F'})
	header[16] = 4
	if err := os.WriteFile(path, header, 0600); err != nil {
		t.Fatal(err)
	}
	if !waitFileCore(t, directory, since, 0) {
		t.Fatal("new ELF core was not recorded")
	}
	if waitFileCore(t, directory, time.Now().Add(time.Second), 0) {
		t.Fatal("old core was recorded")
	}
}

func TestPhase1CrashOutput(t *testing.T) {
	good := jailResult{exit: 139, stdout: "pid=2\nhostpid=123\n"}
	if err := crashOutputError(good, false); err != nil {
		t.Fatal(err)
	}
	for _, result := range []jailResult{
		{exit: 0, stdout: good.stdout},
		{exit: 137, stdout: good.stdout},
		{exit: 139, stdout: "hostpid=123\n"},
		{exit: 139, stdout: good.stdout, stderr: "panic"},
		{exit: 139, stdout: "lower=22\n" + good.stdout},
	} {
		if crashOutputError(result, false) == nil {
			t.Fatalf("accepted malformed crash: %+v", result)
		}
	}
	good.stdout = "lower=1\n" + good.stdout
	if err := crashOutputError(good, true); err != nil {
		t.Fatal(err)
	}
}

func TestPhase1CrashFilePattern(t *testing.T) {
	for _, row := range []struct{ pattern, want string }{
		{"core.%P.%p", "/fixture/core.123.2"},
		{"/cores/core.%P.%p", "/cores/core.123.2"},
		{"core[1]", `/fixture/core\[1]`},
	} {
		if got := crashPIDFileGlob(row.pattern, "/fixture", "pid=2\nhostpid=123\n", 123); got != row.want {
			t.Errorf("%q: %q, want %q", row.pattern, got, row.want)
		}
	}
}

func TestPhase1CrashWrapper(t *testing.T) {
	if os.Getenv("SSHGATE_TEST_CRASH_WRAPPER") == "child" {
		file := os.NewFile(3, "inherited")
		data, err := io.ReadAll(file)
		if err != nil || string(data) != "descriptor-preserved" {
			t.Fatalf("inherited descriptor: %q %v", data, err)
		}
		return
	}
	directory := t.TempDir()
	wrapper := filepath.Join(directory, "wrapper")
	if err := os.WriteFile(wrapper, []byte("#!/bin/sh\nshift 2\nexec \"$@\"\n"), 0700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(directory, "inherited")
	if err := os.WriteFile(path, []byte("descriptor-preserved"), 0600); err != nil {
		t.Fatal(err)
	}
	file, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	command := exec.Command("/proc/self/exe", "-test.run=^TestPhase1CrashWrapper$")
	command.Env = append(os.Environ(), "SSHGATE_TEST_CRASH_WRAPPER=child")
	command.ExtraFiles = []*os.File{file}
	if err := wrapCrashLimits(command, wrapper); err != nil {
		t.Fatal(err)
	}
	output, err := command.CombinedOutput()
	if err != nil || !strings.Contains(string(output), "PASS") {
		t.Fatalf("wrapped child: %v: %s", err, output)
	}
}
