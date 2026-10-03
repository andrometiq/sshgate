package main

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/karthikeyan5/sshgate/src/gate/confine"
)

func doctorOut(t *testing.T, args ...string) (int, string) {
	t.Helper()
	var code int
	out := captureStdout(t, func() { code = runLocalSubcommand(append([]string{"doctor"}, args...)) })
	return code, out
}

func TestDoctorReport(t *testing.T) {
	dir := t.TempDir()
	withGateDir(t, dir)
	withDetect(t, confine.Report{
		Rung: confine.Rung1Full, LandlockABI: 10, Userns: true, Seccomp: true,
		LSMs: []string{"capability", "landlock"}, Notes: []string{"a note"},
	})

	code, out := doctorOut(t)
	if code != exitOK {
		t.Fatalf("doctor exit = %d", code)
	}
	for _, want := range []string{
		"rung:                  full\n", "landlock_abi:          10\n", "userns:                yes\n",
		"seccomp:               yes\n", "lsm:                   capability,landlock\n",
		"apparmor_userns_clamp: no\n", "probe_err:             none\n", "floor:                 none\n",
		"reads:                 jailed:full\n", "notes:                 a note\n",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("human output lacks %q:\n%s", want, out)
		}
	}

	code, out = doctorOut(t, "--json")
	var d doctorReport
	if code != exitOK || json.Unmarshal([]byte(out), &d) != nil {
		t.Fatalf("--json exit = %d, out = %q", code, out)
	}
	if d.Rung != "full" || d.LandlockABI != 10 || !d.Userns || d.Reads != "jailed:full" || d.Floor != "" {
		t.Errorf("--json = %+v", d)
	}

	if code, _ := doctorOut(t, "--bogus"); code != exitDataErr {
		t.Errorf("unknown flag exit = %d, want %d", code, exitDataErr)
	}
}

// TestDoctorReportsDeny: doctor shows the read-path verdict, so a probe error or
// a damaged floor reads as a deny, never as a jail or unconfined.
func TestDoctorReportsDeny(t *testing.T) {
	dir := t.TempDir()
	withGateDir(t, dir)
	withDetect(t, confine.Report{Rung: confine.Rung2Landlock, ProbeErr: errors.New("transient")})
	_, out := doctorOut(t, "--json")
	var d doctorReport
	if err := json.Unmarshal([]byte(out), &d); err != nil {
		t.Fatal(err)
	}
	if d.ProbeErr != "transient" || !strings.HasPrefix(d.Reads, "denied: ") {
		t.Errorf("probe error: %+v", d)
	}

	withDetect(t, confine.Report{Rung: confine.Rung1Full})
	writeFloor(t, dir, "full", 0o666)
	_, out = doctorOut(t, "--json")
	d = doctorReport{}
	if err := json.Unmarshal([]byte(out), &d); err != nil {
		t.Fatal(err)
	}
	if d.FloorErr == "" || !strings.HasPrefix(d.Reads, "denied: ") {
		t.Errorf("damaged floor: %+v", d)
	}
}

// TestDoctorPinEnforced is the real effect of --pin: the floor it writes is the
// one the read path enforces, so a later probe below it denies the read.
func TestDoctorPinEnforced(t *testing.T) {
	dir := t.TempDir()
	withGateDir(t, dir)
	withDetect(t, confine.Report{Rung: confine.Rung1Full})
	if code, out := doctorOut(t, "--pin"); code != exitOK || !strings.Contains(out, "floor:                 full\n") {
		t.Fatalf("--pin exit = %d, out:\n%s", code, out)
	}
	info, err := os.Stat(filepath.Join(dir, jailFloorFile))
	if err != nil || info.Mode().Perm() != 0o644 {
		t.Fatalf("floor file: %v %v", info, err)
	}
	if got, err := readPinnedFloor(dir); err != nil || got != confine.Rung1Full {
		t.Fatalf("readPinnedFloor = %v, %v", got, err)
	}

	withDetect(t, confine.Report{Rung: confine.Rung2Landlock})
	if code, _, stderr := runWith(t, "cat /etc/hostname"); code != exitNoPermVal || !strings.Contains(stderr, "below the pinned floor") {
		t.Errorf("read below the pinned floor: exit = %d, stderr = %q", code, stderr)
	}
}

// TestDoctorPinKeepsOrRaises: re-pinning at the same rung is idempotent, and a
// higher live rung raises the floor.
func TestDoctorPinKeepsOrRaises(t *testing.T) {
	dir := t.TempDir()
	withGateDir(t, dir)
	writeFloor(t, dir, "landlock\n", 0o644)
	for _, rung := range []confine.Rung{confine.Rung2Landlock, confine.Rung1Full} {
		withDetect(t, confine.Report{Rung: rung})
		if code, _ := doctorOut(t, "--pin"); code != exitOK {
			t.Fatalf("--pin at %s exit = %d", rung, code)
		}
		if got, err := readPinnedFloor(dir); err != nil || got != rung {
			t.Errorf("floor after --pin at %s = %v, %v", rung, got, err)
		}
	}
}

// TestDoctorPinRefuses: --pin writes nothing on a probe error, on rung 3, over a
// floor it cannot trust, or when that would lower the existing floor.
func TestDoctorPinRefuses(t *testing.T) {
	for _, tc := range []struct {
		name  string
		rep   confine.Report
		floor string // pre-existing floor content, "" = none
	}{
		{name: "probe error", rep: confine.Report{Rung: confine.Rung1Full, ProbeErr: errors.New("x")}},
		{name: "rung3", rep: confine.Report{Rung: confine.Rung3Unconfined}},
		{name: "would lower a floor", rep: confine.Report{Rung: confine.Rung2Landlock}, floor: "full\n"},
		{name: "damaged floor", rep: confine.Report{Rung: confine.Rung1Full}, floor: "strongest\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			withGateDir(t, dir)
			withDetect(t, tc.rep)
			if tc.floor != "" {
				writeFloor(t, dir, tc.floor, 0o644)
			}
			if code, _ := doctorOut(t, "--pin"); code == exitOK {
				t.Fatalf("--pin succeeded")
			}
			b, err := os.ReadFile(filepath.Join(dir, jailFloorFile))
			switch {
			case tc.floor == "" && !errors.Is(err, os.ErrNotExist):
				t.Errorf("a floor was written: %q, %v", b, err)
			case tc.floor != "" && string(b) != tc.floor:
				t.Errorf("existing floor changed to %q", b)
			}
		})
	}
}
