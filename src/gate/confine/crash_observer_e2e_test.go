//go:build linux && jail_e2e

package confine

import (
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
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

func TestM2CoreRecordWindow(t *testing.T) {
	good := "{\"pid\":42,\"signal\":11,\"bytes\":123}\n"
	sentinel := "{\"pid\":43,\"signal\":11,\"bytes\":123}\n"
	for _, row := range []struct {
		name, data    string
		found, failed bool
	}{
		{"present", good + sentinel, true, false},
		{"absent", sentinel, false, false},
		{"empty", "", false, true},
		{"target failure", "{\"pid\":42,\"signal\":11,\"bytes\":1,\"error\":\"read failed\"}\n" + sentinel, false, true},
		{"partial", good + strings.TrimSuffix(sentinel, "\n"), false, true},
		{"missing sentinel", good, false, true},
		{"wrong target signal", strings.Replace(good, "11", "9", 1) + sentinel, false, true},
		{"duplicate", good + good + sentinel, false, true},
		{"malformed", "garbage\n" + sentinel, false, true},
	} {
		t.Run(row.name, func(t *testing.T) {
			records, err := m2CoreRecords([]byte(row.data), 42, 43)
			if (err != nil) != row.failed || (len(records) > 0) != row.found {
				t.Fatalf("records=%v err=%v", records, err)
			}
		})
	}
}

func TestM2CoreFileWindow(t *testing.T) {
	directory := t.TempDir()
	observer := &m2CoreObserver{directory: directory, pattern: "core.%P.%p"}
	observer.Start(t)
	mark := observer.Mark()
	if observer.Since(mark).Conclusive {
		t.Fatal("unsealed window accepted")
	}
	observer.target = 42
	observer.output = "pid=2\nhostpid=42\n"
	if err := observer.Seal(ProducerSync{Complete: true, Kind: "worker-reaped"}); err != nil {
		t.Fatal(err)
	}
	result := observer.Since(mark)
	if !result.Conclusive || len(result.Records) != 0 {
		t.Fatalf("empty window: %+v", result)
	}
	header := make([]byte, 18)
	copy(header, []byte{0x7f, 'E', 'L', 'F'})
	header[16] = 4
	if err := os.WriteFile(filepath.Join(directory, "core.42.2"), header, 0600); err != nil {
		t.Fatal(err)
	}
	if len(observer.Since(mark).Records) != 0 {
		t.Fatal("sealed snapshot changed")
	}
	mark = observer.Mark()
	observer.target = 42
	if err := observer.Seal(ProducerSync{Complete: true, Kind: "worker-reaped"}); err != nil {
		t.Fatal(err)
	}
	if len(observer.Since(mark).Records) != 1 {
		t.Fatal("core not recorded")
	}
	if err := observer.Stop(); err != nil {
		t.Fatal(err)
	}
}

func TestM2CrashControlWaitStatus(t *testing.T) {
	command := exec.Command("/bin/sh", "-c", "kill -TERM $$")
	if err := command.Run(); err == nil {
		t.Fatal("signal control unexpectedly succeeded")
	}
	if err := m2CrashControlStatus(command.ProcessState, syscall.SIGTERM); err != nil {
		t.Fatal(err)
	}
	if err := m2CrashControlStatus(command.ProcessState, syscall.SIGSEGV); err == nil {
		t.Fatal("accepted wrong signal")
	}
	if err := m2CrashControlStatus(nil, syscall.SIGTERM); err == nil {
		t.Fatal("accepted unavailable status")
	}
}
