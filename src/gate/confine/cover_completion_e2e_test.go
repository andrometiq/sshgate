//go:build linux && jail_e2e

package confine

import (
	"bufio"
	"bytes"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestCoverProbeCompletionFixture(t *testing.T) {
	const good = "COVER-BEGIN fuse-ioctl\nopen=ok\nioctl=ok\nCOVER-END 0\n"
	for _, tc := range []struct {
		name   string
		result jailResult
		count  int
		bad    bool
	}{
		{"effect", jailResult{stdout: good}, 1, false},
		{"denied", jailResult{stdout: "COVER-BEGIN fuse-ioctl\nopen=2\nCOVER-END 1\n"}, 1, false},
		{"crashed-after-effect", jailResult{stdout: strings.Replace(good, "END 0", "END 139", 1)}, 1, true},
		{"killed-before-later-success", jailResult{stdout: strings.Replace(good, "END 0", "END 137", 1) + good}, 2, true},
		{"missing-ioctl", jailResult{stdout: strings.Replace(good, "ioctl=ok\n", "", 1)}, 1, true},
		{"unterminated-report", jailResult{stdout: strings.Replace(good, "ioctl=ok\n", "ioctl=ok", 1)}, 1, true},
		{"missing-completion", jailResult{stdout: "COVER-BEGIN fuse-ioctl\nopen=ok\nioctl=ok\n"}, 1, true},
		{"missing-probe", jailResult{stdout: good}, 2, true},
		{"wrong-status", jailResult{stdout: strings.Replace(good, "END 0", "END 1", 1)}, 1, true},
		{"stderr", jailResult{stdout: good, stderr: "diagnostic\n"}, 1, true},
		{"setup", jailResult{stdout: good, setupErr: errors.New("setup")}, 1, true},
		{"shell-killed", jailResult{stdout: good, exit: -1}, 1, true},
		{"empty-listing", jailResult{}, 0, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := validateCoverReports(tc.result, tc.count)
			if (err != nil) != tc.bad {
				t.Fatalf("validation: %v", err)
			}
		})
	}
}

func TestCoverProbeFramingFixture(t *testing.T) {
	probe := filepath.Join(t.TempDir(), "probe")
	if err := os.WriteFile(probe, []byte("#!/bin/sh\nprintf 'open=ok\\nioctl=ok\\n'\nexit \"$2\"\n"), 0700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("SSHGATE_COVER_PROBE", probe)
	for _, status := range []string{"0", "139"} {
		command := exec.Command("/bin/sh", "-c", coverProbeCommand("fuse-ioctl", status)+"; "+coverProbeCommand("fuse-ioctl", "0"))
		var stdout, stderr bytes.Buffer
		command.Stdout, command.Stderr = &stdout, &stderr
		err := command.Run()
		result := jailResult{stdout: stdout.String(), stderr: stderr.String(), exit: exitCodeOf(err)}
		output, err := validateCoverReports(result, 2)
		if (err != nil) != (status != "0") {
			t.Fatalf("status %s: validation %v, result %+v", status, err, result)
		}
		if err == nil && output != "open=ok\nioctl=ok\nopen=ok\nioctl=ok\n" {
			t.Fatalf("stripped output: %q", output)
		}
	}
}

func TestFuseObserverSealFixture(t *testing.T) {
	log := filepath.Join(t.TempDir(), "records")
	if err := os.WriteFile(log, nil, 0600); err != nil {
		t.Fatal(err)
	}
	command := exec.Command("/bin/sh", "-c", "trap 'sleep 0.02; printf \"IOCTL 42\\nBARRIER\\n\" >> \"$1\"' USR1; trap 'printf \"VERDICT ok\\n\" >> \"$1\"; exit 0' TERM; echo READY; while :; do sleep 0.01; done", "observer", log)
	diagnostic := &coverLogBuffer{}
	command.Stderr = diagnostic
	stdout, err := command.StdoutPipe()
	mutationSetup(t, err)
	mutationSetup(t, command.Start())
	f := &fuseFixture{log: log, command: command, diagnostic: diagnostic}
	t.Cleanup(func() {
		if err := f.Stop(); err != nil {
			t.Error(err)
		}
	})
	ready := make(chan bool, 1)
	go func() { scanner := bufio.NewScanner(stdout); ready <- scanner.Scan() && scanner.Text() == "READY" }()
	select {
	case ok := <-ready:
		if !ok {
			t.Fatal("observer readiness")
		}
	case <-time.After(time.Second):
		t.Fatal("observer readiness timeout")
	}
	f.Start(t)
	mark := f.Mark()
	if records := f.Since(mark); records.Conclusive || records.Err == nil {
		t.Fatal("unsealed observation accepted")
	}
	if err := f.Seal(ProducerSync{Complete: false, Kind: "framed-op-ended"}); err == nil {
		t.Fatal("incomplete producer accepted")
	}
	mutationSetup(t, f.Seal(ProducerSync{Complete: true, Kind: "framed-op-ended"}))
	records := f.Since(mark)
	if !records.Conclusive || !records.Sealed || len(records.Records) != 1 || records.Records[0] != "IOCTL 42" {
		t.Fatalf("delayed effect lost: %+v", records)
	}
	next := f.mark(t)
	if records := f.Since(ObserverMark(next)); records.Conclusive || records.Err == nil {
		t.Fatal("lowercase mark retained the control seal")
	}
	mutationSetup(t, f.Seal(ProducerSync{Complete: true, Kind: "framed-op-ended"}))
	if records := f.Since(ObserverMark(next)); !records.Conclusive {
		t.Fatalf("reseal failed: %+v", records)
	}
}

func TestCoverProbeDeclaredStops(t *testing.T) {
	for _, tc := range []struct {
		name, report string
		allowed      map[string]map[string][]int
		bad          bool
	}{
		{"expected-open", "COVER-BEGIN fuse-ioctl\nopen=2\nCOVER-END 1\n", map[string]map[string][]int{"fuse-ioctl": {"open": {2}}}, false},
		{"unexpected-io", "COVER-BEGIN fuse-ioctl\nopen=5\nCOVER-END 1\n", map[string]map[string][]int{"fuse-ioctl": {"open": {2}}}, true},
		{"wrong-step", "COVER-BEGIN fuse-ioctl\nopen=ok\nioctl=2\nCOVER-END 1\n", map[string]map[string][]int{"fuse-ioctl": {"open": {2}}}, true},
		{"private-write-io", "COVER-BEGIN cover-write\nopen=5\nCOVER-END 1\n", map[string]map[string][]int{"cover-write": {"open": {13, 30}}}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := validateCoverReports(jailResult{stdout: tc.report}, 1, tc.allowed)
			if (err != nil) != tc.bad {
				t.Fatalf("validation %v", err)
			}
		})
	}
}
