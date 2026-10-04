package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/karthikeyan5/sshgate/src/gate/confine"
)

// withDetect injects a host probe result for run(), restoring the real probe on
// cleanup.
func withDetect(t *testing.T, rep confine.Report) {
	t.Helper()
	prev := detectFn
	detectFn = func() confine.Report { return rep }
	t.Cleanup(func() { detectFn = prev })
}

func writeFloor(t *testing.T, dir, content string, mode os.FileMode) {
	t.Helper()
	p := filepath.Join(dir, jailFloorFile)
	if err := os.WriteFile(p, []byte(content), mode); err != nil {
		t.Fatalf("write floor: %v", err)
	}
	if err := os.Chmod(p, mode); err != nil {
		t.Fatalf("chmod floor: %v", err)
	}
}

func TestReadPinnedFloor(t *testing.T) {
	for _, tc := range []struct {
		name    string
		content string // "" = no file
		mode    os.FileMode
		want    confine.Rung
		wantErr bool
	}{
		{name: "absent is no floor", want: confine.Rung3Unconfined},
		{name: "full", content: "full\n", mode: 0o644, want: confine.Rung1Full},
		{name: "landlock is damaged", content: " landlock ", mode: 0o600, wantErr: true},
		{name: "unconfined", content: "unconfined", mode: 0o644, want: confine.Rung3Unconfined},
		{name: "garbage", content: "strong", mode: 0o644, wantErr: true},
		{name: "empty", content: "\n", mode: 0o644, wantErr: true},
		{name: "group-writable", content: "full", mode: 0o664, wantErr: true},
		{name: "world-writable", content: "full", mode: 0o646, wantErr: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			if tc.content != "" {
				writeFloor(t, dir, tc.content, tc.mode)
			}
			got, err := readPinnedFloor(dir)
			if (err != nil) != tc.wantErr || (!tc.wantErr && got != tc.want) {
				t.Errorf("readPinnedFloor = %v, %v; want %v, err=%v", got, err, tc.want, tc.wantErr)
			}
		})
	}
}

func TestConfineSpecFor(t *testing.T) {
	full, unconfined := confine.Rung1Full, confine.Rung3Unconfined
	for _, tc := range []struct {
		name     string
		rep      confine.Report
		floor    confine.Rung
		wantSpec bool
		wantDeny bool
	}{
		{name: "full no floor", rep: confine.Report{Rung: full}, floor: unconfined, wantSpec: true},
		{name: "unconfined no floor", rep: confine.Report{Rung: unconfined}, floor: unconfined},
		{name: "full at floor", rep: confine.Report{Rung: full}, floor: full, wantSpec: true},
		{name: "unconfined below floor", rep: confine.Report{Rung: unconfined}, floor: full, wantDeny: true},
		{name: "probe error full", rep: confine.Report{Rung: full, ProbeErr: errors.New("EAGAIN")}, wantDeny: true},
		{name: "probe error unconfined", rep: confine.Report{Rung: unconfined, ProbeErr: errors.New("x")}, wantDeny: true},
		{name: "unknown rung", rep: confine.Report{Rung: confine.Rung(9)}, wantDeny: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			spec, deny := confineSpecFor(tc.rep, tc.floor)
			if (deny != "") != tc.wantDeny {
				t.Fatalf("deny = %q, want deny=%v", deny, tc.wantDeny)
			}
			if !tc.wantSpec {
				if spec != nil {
					t.Errorf("spec = %+v, want nil", spec)
				}
				return
			}
			want := confine.Spec{Profile: confine.ProfileROv1, Net: true}
			if spec == nil || !reflect.DeepEqual(*spec, want) {
				t.Errorf("spec = %+v, want %+v", spec, want)
			}
		})
	}
}

// TestRunReadFailsClosed pins the deny branches on the read path: a probe error,
// a live rung below the pinned floor, or a damaged floor makes the read NOT run
// at all (not jailed, not unconfined), audited as a denied read.
func TestRunReadFailsClosed(t *testing.T) {
	readNamedWriter(t)
	for _, tc := range []struct {
		name  string
		rep   confine.Report
		floor string
		mode  os.FileMode
	}{
		{name: "probe error", rep: confine.Report{Rung: confine.Rung1Full, ProbeErr: errors.New("transient")}},
		{name: "below pinned floor", rep: confine.Report{Rung: confine.Rung3Unconfined}, floor: "full", mode: 0o644},
		{name: "removed landlock floor unconfined", rep: confine.Report{Rung: confine.Rung3Unconfined}, floor: "landlock", mode: 0o644},
		{name: "removed landlock floor full", rep: confine.Report{Rung: confine.Rung1Full}, floor: "landlock", mode: 0o644},
		{name: "insecure floor", rep: confine.Report{Rung: confine.Rung1Full}, floor: "full", mode: 0o666},
		{name: "garbage floor", rep: confine.Report{Rung: confine.Rung1Full}, floor: "maximum", mode: 0o644},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			withGateDir(t, dir)
			if tc.floor != "" {
				writeFloor(t, dir, tc.floor, tc.mode)
			}
			withDetect(t, tc.rep)
			target := filepath.Join(dir, "target")
			if err := os.WriteFile(target, []byte("orig\n"), 0o644); err != nil {
				t.Fatal(err)
			}
			// A read the classifier accepts that leaves a trace if it executes.
			code, out, stderr := runWith(t, "stat "+target+" ran")
			if code != exitNoPermVal {
				t.Errorf("exit = %d, want %d (deny)", code, exitNoPermVal)
			}
			if out != "" || !strings.Contains(stderr, "refusing") || !strings.Contains(stderr, "gate: read jail unavailable") {
				t.Errorf("stdout = %q, stderr = %q; want no output and a refusal", out, stderr)
			}
			if b, _ := os.ReadFile(target); string(b) != "orig\n" {
				t.Errorf("the command ran despite the deny: %q", b)
			}
			recs := auditRecords(t, dir)
			if len(recs) != 1 || recs[0]["classification"] != "read" || recs[0]["approval_status"] != "denied" {
				t.Errorf("audit = %v, want one denied read", recs)
			}
			if _, ok := recs[0]["rung"]; ok {
				t.Errorf("a denied read carries a rung: %v", recs[0])
			}
		})
	}
}

// TestRunReadRung3Unconfined: rung 3 with no floor is today's unconfined /bin/sh
// path, labelled unconfined in the audit.
func TestRunReadRung3Unconfined(t *testing.T) {
	readNamedWriter(t)
	dir := t.TempDir()
	withGateDir(t, dir)
	withDetect(t, confine.Report{Rung: confine.Rung3Unconfined})
	target := filepath.Join(dir, "target")
	if err := os.WriteFile(target, []byte("orig\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	// The test-owned `stat` is a classifier read that edits; unconfined, it really edits.
	code, _, stderr := runWith(t, "stat "+target+" edited")
	if code != exitOK {
		t.Fatalf("exit = %d, stderr = %q", code, stderr)
	}
	if b, _ := os.ReadFile(target); string(b) != "edited\n" {
		t.Errorf("target = %q; rung 3 should be today's unconfined path", b)
	}
	recs := auditRecords(t, dir)
	if len(recs) != 1 || recs[0]["rung"] != "unconfined" {
		t.Errorf("audit = %v, want rung unconfined", recs)
	}
}

// liveRung returns the real host rung, skipping when the host has no jail.
// `make test-jail` runs these tests and fails on any skip.
func liveRung(t *testing.T) confine.Rung {
	t.Helper()
	rep := confine.Detect()
	if rep.ProbeErr != nil {
		t.Fatalf("host probe error: %v", rep.ProbeErr)
	}
	if rep.Rung == confine.Rung3Unconfined {
		t.Skipf("SKIP rung: host has no kernel jail (rung 3)")
	}
	return rep.Rung
}

// TestRunReadJailedRealEffect is the real-effect proof on the live host (rung 1
// here): an unsigned Tier-1 read runs inside the jail — a normal read still
// works, and a classifier-approved read that writes (the test-owned `stat`, see
// readNamedWriter) cannot change the file. A signed read and a signed REVEAL
// read are jailed the same way, while a signed WRITE stays unconfined and lands.
func TestRunReadJailedRealEffect(t *testing.T) {
	readNamedWriter(t)
	rung := liveRung(t)
	seed := func(t *testing.T, dir string) string {
		p := filepath.Join(dir, "target")
		if err := os.WriteFile(p, []byte("orig AKIA1234567890ABCDEF\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		return p
	}
	assertUnchanged := func(t *testing.T, p string) {
		t.Helper()
		if b, _ := os.ReadFile(p); string(b) != "orig AKIA1234567890ABCDEF\n" {
			t.Errorf("jailed read changed the file: %q", b)
		}
	}
	assertAudit := func(t *testing.T, dir, approval, rungWant string, revealed bool) {
		t.Helper()
		recs := auditRecords(t, dir)
		if len(recs) != 1 {
			t.Fatalf("audit = %v, want one record", recs)
		}
		r := recs[0]
		rv, _ := r["revealed"].(bool)
		got, has := r["rung"]
		if r["approval_status"] != approval || rv != revealed || (rungWant == "" && has) || (rungWant != "" && got != rungWant) {
			t.Errorf("audit = %v, want approval %s rung %q revealed %v", r, approval, rungWant, revealed)
		}
	}

	t.Run("tier1 read works jailed", func(t *testing.T) {
		dir := t.TempDir()
		withGateDir(t, dir)
		target := seed(t, dir)
		code, out, stderr := runWith(t, "cat "+target)
		if code != exitOK || !strings.HasPrefix(out, "orig ") || strings.Contains(out, "AKIA1234567890ABCDEF") {
			t.Errorf("exit = %d, stdout = %q, stderr = %q; want the redacted file", code, out, stderr)
		}
		assertAudit(t, dir, "unsigned", rung.String(), false)
	})

	t.Run("tier1 read cannot write", func(t *testing.T) {
		dir := t.TempDir()
		withGateDir(t, dir)
		target := seed(t, dir)
		code, _, _ := runWith(t, "stat "+target+" pwned")
		if code == exitOK {
			t.Errorf("a jailed in-place edit exited 0")
		}
		assertUnchanged(t, target)
		assertAudit(t, dir, "unsigned", rung.String(), false)
	})

	t.Run("signed read cannot write", func(t *testing.T) {
		dir := t.TempDir()
		pub, priv := genKey(t)
		seedPub(t, dir, pub, 0o644)
		withGateDir(t, dir)
		target := seed(t, dir)
		code, _, _ := runWith(t, signedLine(t, priv, freshPayload("stat "+target+" pwned")))
		if code == exitOK {
			t.Errorf("a jailed signed-read in-place edit exited 0")
		}
		assertUnchanged(t, target)
		assertAudit(t, dir, "signed", rung.String(), false)
	})

	t.Run("signed reveal read is raw and still jailed", func(t *testing.T) {
		dir := t.TempDir()
		pub, priv := genKey(t)
		seedPub(t, dir, pub, 0o644)
		withGateDir(t, dir)
		target := seed(t, dir)
		p := freshPayload("cat " + target + " && stat " + target + " pwned")
		p.Reveal = true
		code, out, _ := runWith(t, signedLine(t, priv, p))
		if !strings.Contains(out, "AKIA1234567890ABCDEF") {
			t.Errorf("reveal output = %q, want the raw secret", out)
		}
		if code == exitOK {
			t.Errorf("the revealed read's in-place edit exited 0")
		}
		assertUnchanged(t, target)
		assertAudit(t, dir, "signed", rung.String(), true)
	})

	t.Run("profile read uses private scratch", func(t *testing.T) {
		dir := t.TempDir()
		withGateDir(t, dir)
		withDetect(t, confine.Report{Rung: confine.Rung1Full})
		target := seed(t, dir)
		code, out, stderr := runWith(t, "cat "+target+" && stat "+target+" pwned")
		if !strings.HasPrefix(out, "orig ") || code == exitOK {
			t.Errorf("exit = %d, stdout = %q, stderr = %q; want the read to work and the edit to fail", code, out, stderr)
		}
		assertUnchanged(t, target)
		assertAudit(t, dir, "unsigned", "full", false)

		// A read that must spill to temp files works only if the jail hands it
		// private writable scratch: sort with a 1 KiB buffer over ~200 KiB.
		var big strings.Builder
		for i := 19999; i >= 0; i-- {
			fmt.Fprintf(&big, "line-%05d\n", i)
		}
		bigFile := filepath.Join(dir, "big")
		if err := os.WriteFile(bigFile, []byte(big.String()), 0o644); err != nil {
			t.Fatal(err)
		}
		code, out, stderr = runWith(t, "sort -S 1K "+bigFile+" | tail -1")
		if code != exitOK || out != "line-19999\n" || strings.Contains(stderr, "temporary file") {
			t.Errorf("spilling sort: exit = %d, stdout = %q, stderr = %q; want the last line via the scratch TMPDIR", code, out, stderr)
		}
		left, _ := filepath.Glob(filepath.Join(os.TempDir(), "sshgate-jail-*"))
		if len(left) != 0 {
			t.Errorf("host scratch dirs outlived the command: %v", left)
		}
	})

	t.Run("signed write stays unconfined", func(t *testing.T) {
		dir := t.TempDir()
		pub, priv := genKey(t)
		seedPub(t, dir, pub, 0o644)
		withGateDir(t, dir)
		target := seed(t, dir)
		code, _, stderr := runWith(t, signedLine(t, priv, freshPayload("sed -i 's/orig/edited/' "+target)))
		if code != exitOK {
			t.Fatalf("signed write exit = %d, stderr = %q", code, stderr)
		}
		if b, _ := os.ReadFile(target); !strings.HasPrefix(string(b), "edited ") {
			t.Errorf("signed write did not land: %q", b)
		}
		assertAudit(t, dir, "signed", "", false)
	})
}

// TestRunReadJailSetupFailureDenies: when the jail never reaches the command —
// the worker aborts before execve, or a removed floor is pinned —
// nothing ran, so the gate exits 77 and audits a denial with no rung. It must
// never look like a command that ran and exited 1 (grep with no match).
func TestRunReadJailSetupFailureDenies(t *testing.T) {
	readNamedWriter(t)
	check := func(t *testing.T, dir, target string, code int, out, stderr string) {
		t.Helper()
		// The MCP tells this 77 from a missing signature by this exact line.
		if code != exitNoPermVal || out != "" || !strings.Contains(stderr, "gate: read jail unavailable") {
			t.Errorf("exit = %d, stdout = %q, stderr = %q; want a 77 deny naming the jail", code, out, stderr)
		}
		if b, _ := os.ReadFile(target); string(b) != "orig\n" {
			t.Errorf("the command ran: %q", b)
		}
		recs := auditRecords(t, dir)
		if len(recs) != 1 || recs[0]["approval_status"] != "denied" || recs[0]["classification"] != "read" ||
			recs[0]["exit_code"] != float64(exitNoPermVal) {
			t.Errorf("audit = %v, want one denied read with exit 77", recs)
		}
		if _, ok := recs[0]["rung"]; ok {
			t.Errorf("a read that never ran carries a rung: %v", recs[0])
		}
	}
	seed := func(t *testing.T, dir string) string {
		p := filepath.Join(dir, "target")
		if err := os.WriteFile(p, []byte("orig\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		return p
	}

	t.Run("worker aborts before execve", func(t *testing.T) {
		liveRung(t)
		dir := t.TempDir()
		withGateDir(t, dir)
		target := seed(t, dir)
		plan := execPlan{
			confine: &confine.Spec{Profile: confine.ProfileROv1, Net: true, InjectFailAt: "seccomp"},
			rung:    confine.Rung1Full.String(),
		}
		var code int
		var out string
		stderr := captureStderr(t, func() {
			out = captureStdout(t, func() {
				code = execAndAudit(newAuditLogger(), "stat "+target+" ran", "read", "unsigned", false, plan)
			})
		})
		check(t, dir, target, code, out, stderr)
	})

	t.Run("removed landlock floor denies before execution", func(t *testing.T) {
		dir := t.TempDir()
		withGateDir(t, dir)
		withDetect(t, confine.Report{Rung: confine.Rung3Unconfined})
		target := seed(t, dir)
		writeFloor(t, dir, "landlock\n", 0o644)
		code, out, stderr := runWith(t, "stat "+target+" ran")
		check(t, dir, target, code, out, stderr)
	})
}

// readNamedWriter puts a test-owned `stat` first on PATH that rewrites "orig"
// in its first argument to its second, via sed -i. The classifier calls it a
// read, so it stands in for any read that writes without depending on a real
// classifier bypass staying open.
func readNamedWriter(t *testing.T) {
	t.Helper()
	dir := t.TempDir()
	script := "#!/bin/sh\nexec sed -i \"s/orig/$2/\" \"$1\"\n"
	if err := os.WriteFile(filepath.Join(dir, "stat"), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	withEnv(t, "PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
}
