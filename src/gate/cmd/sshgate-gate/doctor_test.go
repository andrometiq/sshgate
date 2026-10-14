package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"syscall"
	"testing"

	"github.com/karthikeyan5/sshgate/src/gate"
	"github.com/karthikeyan5/sshgate/src/gate/confine"
)

func doctorOut(t *testing.T, args ...string) (int, string) {
	t.Helper()
	var code int
	out := captureStdout(t, func() { code = runLocalSubcommand(append([]string{"doctor"}, args...)) })
	return code, out
}

func doctorJSON(t *testing.T) doctorReport {
	t.Helper()
	code, out := doctorOut(t, "--json")
	var d doctorReport
	if code != exitOK || json.Unmarshal([]byte(out), &d) != nil {
		t.Fatalf("doctor --json exit = %d, out = %q", code, out)
	}
	return d
}

func withHostFacts(t *testing.T, facts confine.HostFacts) {
	t.Helper()
	previous := hostFactsFn
	hostFactsFn = func() confine.HostFacts { return facts }
	t.Cleanup(func() { hostFactsFn = previous })
}

var capableFacts = confine.HostFacts{MaxUserNS: 100, DevShmDir: true, SeccompFilter: true, LandlockABI: 6, LSMs: []string{"capability", "landlock"}}

func TestDoctorReportsPinStates(t *testing.T) {
	withHostFacts(t, capableFacts)
	for _, tc := range []struct {
		name, pin, reads string
		mode             os.FileMode
		want             doctorReport
	}{
		{name: "absent", reads: "kernel-jailed, no network", want: doctorReport{Pin: "absent"}},
		{name: "valid deny", pin: pinDeny + "accept_fs=autofs\n", mode: 0o644, reads: "kernel-jailed, no network", want: doctorReport{Pin: "valid", PinNet: "deny", AcceptFS: []string{"autofs"}}},
		{name: "valid allow", pin: pinAllow, mode: 0o644, reads: "kernel-jailed, network open", want: doctorReport{Pin: "valid", PinNet: "allow"}},
		{name: "damaged", pin: pinDeny, mode: 0o666, reads: "denied (the jail pin is damaged)", want: doctorReport{Pin: "damaged", PinError: "group- or world-writable"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			withGateDir(t, dir)
			if tc.pin != "" {
				writePin(t, dir, tc.pin, tc.mode)
			}
			withFakeAttempt(t, gate.ExecResult{ExitCode: 0, Jail: &confine.Facts{}}, nil)
			d := doctorJSON(t)
			got := doctorReport{Pin: d.Pin, PinError: d.PinError, PinNet: d.PinNet, AcceptFS: d.AcceptFS}
			if !reflect.DeepEqual(got, tc.want) || d.Reads != tc.reads || d.LandlockABI != 6 || d.MaxUserNS != 100 {
				t.Fatalf("doctor = %+v", d)
			}
		})
	}
}

func TestDoctorReportsAttempt(t *testing.T) {
	clamp := capableFacts
	clamp.AppArmorUsernsClamp = true
	for _, tc := range []struct {
		name, pin      string
		facts          confine.HostFacts
		stage          string
		errno          syscall.Errno
		attempt, reads string
		clampNote      bool
	}{
		{name: "kernel", facts: capableFacts, attempt: "kernel", reads: "kernel-jailed, no network"},
		{name: "clamp absent", facts: clamp, stage: "clone", errno: syscall.EACCES, attempt: "jail:absent:clone:EACCES", reads: "classifier-only (no usable jail)", clampNote: true},
		{name: "clamp absent, pinned", pin: pinDeny, facts: clamp, stage: "clone", errno: syscall.EACCES, attempt: "jail:absent:clone:EACCES", reads: "denied (jail:absent:clone:EACCES)", clampNote: true},
		{name: "unexplained EACCES", facts: capableFacts, stage: "clone", errno: syscall.EACCES, attempt: "jail:failed:clone:EACCES", reads: "denied (jail:failed:clone:EACCES)"},
		{name: "failed", facts: capableFacts, stage: "seccomp", errno: syscall.EIO, attempt: "jail:failed:seccomp:EIO", reads: "denied (jail:failed:seccomp:EIO)"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			withGateDir(t, dir)
			withHostFacts(t, tc.facts)
			if tc.pin != "" {
				writePin(t, dir, tc.pin, 0o644)
			}
			fake := withFakeAttempt(t, gate.ExecResult{ExitCode: 0, Jail: &confine.Facts{}}, nil)
			if tc.stage != "" {
				fake.result, fake.err = setupFailure(tc.stage, tc.errno)
			}
			d := doctorJSON(t)
			hasClampNote := len(d.Notes) == 1 && strings.Contains(d.Notes[0], "AppArmor userns_create denial")
			if d.Attempt != tc.attempt || d.Reads != tc.reads || hasClampNote != tc.clampNote || fake.confined != 1 || fake.fallback != 0 {
				t.Fatalf("doctor = %+v, executor %+v", d, fake)
			}
			if _, err := os.Stat(filepath.Join(dir, "audit.log")); err == nil {
				t.Error("doctor wrote an audit record")
			}
		})
	}
}

func TestDoctorHumanOutput(t *testing.T) {
	withHostFacts(t, capableFacts)
	dir := t.TempDir()
	withGateDir(t, dir)
	writePin(t, dir, pinAllow+"accept_fs=network\n", 0o644)
	withFakeAttempt(t, gate.ExecResult{ExitCode: 0, Jail: &confine.Facts{}}, nil)
	code, out := doctorOut(t)
	for _, want := range []string{
		"pin:                   valid: net=allow accept_fs=network\n", "attempt:               kernel\n",
		"reads:                 kernel-jailed, network open\n", "landlock_abi:          6\n",
		"lsm:                   capability,landlock\n",
	} {
		if code != exitOK || !strings.Contains(out, want) {
			t.Errorf("exit %d, output lacks %q:\n%s", code, want, out)
		}
	}
	if code, _ := doctorOut(t, "--bogus"); code != exitDataErr {
		t.Errorf("unknown flag exit = %d, want %d", code, exitDataErr)
	}
}

// TestDoctorJailFloorNote: a leftover jail-floor gets exactly one note and
// changes nothing: reads on the host are not pinned by it.
func TestDoctorJailFloorNote(t *testing.T) {
	withHostFacts(t, capableFacts)
	dir := t.TempDir()
	withGateDir(t, dir)
	withFakeAttempt(t, gate.ExecResult{ExitCode: 0, Jail: &confine.Facts{}}, nil)
	if d := doctorJSON(t); len(d.Notes) != 0 {
		t.Fatalf("notes without a floor: %v", d.Notes)
	}
	if err := os.WriteFile(filepath.Join(dir, jailFloorFile), []byte("full\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	d := doctorJSON(t)
	if len(d.Notes) != 1 || !strings.Contains(d.Notes[0], "jail-floor is no longer used and is ignored; reads on this host are NOT pinned") || d.Pin != "absent" {
		t.Fatalf("doctor = %+v", d)
	}

	readNamedWriter(t)
	fake := withFakeAttempt(t, gate.ExecResult{}, nil)
	fake.result, fake.err = setupFailure("landlock", syscall.ENOSYS)
	target := seedTarget(t, dir)
	if code, _, stderr := runWith(t, "stat "+target+" edited"); code != exitOK || fake.fallback != 1 {
		t.Fatalf("a read under a leftover floor: exit %d, stderr %q, executor %+v", code, stderr, fake)
	}
	targetIs(t, target, "edited\n")
}

func TestDoctorRejectsPinFlag(t *testing.T) {
	dir := t.TempDir()
	withGateDir(t, dir)
	fake := withFakeAttempt(t, gate.ExecResult{ExitCode: 0, Jail: &confine.Facts{}}, nil)
	var code int
	stderr := captureStderr(t, func() { code, _ = doctorOut(t, "--pin", "--net=deny") })
	if code != exitDataErr || !strings.Contains(stderr, "--pin is not available") {
		t.Fatalf("--pin exit = %d, stderr = %q", code, stderr)
	}
	if entries, _ := os.ReadDir(dir); len(entries) != 0 || fake.confined != 0 {
		t.Fatalf("--pin wrote %v or attempted the jail %d times", entries, fake.confined)
	}
}
