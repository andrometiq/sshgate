package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/karthikeyan5/sshgate/src/gate"
	"github.com/karthikeyan5/sshgate/src/gate/confine"
)

// requireJail attempts the unpinned read jail with `:` and returns its facts.
// A host without the jail (Absent) skips; `make test-jail` runs these tests
// and fails on any skip. A Failed jail fails the test.
func requireJail(t *testing.T) confine.Facts {
	t.Helper()
	spec := readSpec(pinState{}, false, false)
	res, err := gate.ExecWithRedaction(context.Background(), ":", gate.ExecOpts{Confine: &spec})
	if res.ExitCode == 0 && res.Jail != nil {
		return *res.Jail
	}
	var setup *confine.SetupError
	if !errors.As(err, &setup) {
		t.Fatalf("jail attempt: exit %d, %v", res.ExitCode, err)
	}
	if class := attemptClass(setup, res); class == confine.Absent {
		t.Skipf("SKIP jail: %s", confine.DenyReason(class, setup.Stage, setup.Errno))
	}
	t.Fatalf("jail attempt failed: %v", err)
	return confine.Facts{}
}

// TestRunReadJailedRealEffect is the real-effect proof on the live host: an
// unsigned Tier-1 read on an unpinned host runs inside the jail without network — a normal read still
// works, and a classifier-approved read that writes (the test-owned `stat`, see
// readNamedWriter) cannot change the file. A signed read and a signed REVEAL
// read are jailed the same way, while a signed WRITE stays unconfined and lands.
func TestRunReadJailedRealEffect(t *testing.T) {
	readNamedWriter(t)
	requireJail(t)
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
	assertAudit := func(t *testing.T, dir, approval string, jailed, revealed bool) {
		t.Helper()
		recs := auditRecords(t, dir)
		if len(recs) != 1 {
			t.Fatalf("audit = %v, want one record", recs)
		}
		r := recs[0]
		rv, _ := r["revealed"].(bool)
		if r["approval_status"] != approval || rv != revealed {
			t.Errorf("audit = %v, want approval %s revealed %v", r, approval, revealed)
		}
		if !jailed {
			if _, ok := r["enforcement"]; ok {
				t.Errorf("a signed write has a read block: %v", r)
			}
			return
		}
		if r["enforcement"] != "kernel" || r["profile"] != "ro-v1" || r["pinned"] != false || r["net"] != false ||
			r["requires_confinement"] != false || r["landlock_abi"].(float64) < 1 {
			t.Errorf("audit = %v, want an unpinned kernel read without network", r)
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
		assertAudit(t, dir, "unsigned", true, false)
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
		assertAudit(t, dir, "unsigned", true, false)
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
		assertAudit(t, dir, "signed", true, false)
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
		assertAudit(t, dir, "signed", true, true)
	})

	t.Run("profile read uses private scratch", func(t *testing.T) {
		dir := t.TempDir()
		withGateDir(t, dir)
		target := seed(t, dir)
		code, out, stderr := runWith(t, "cat "+target+" && stat "+target+" pwned")
		if !strings.HasPrefix(out, "orig ") || code == exitOK {
			t.Errorf("exit = %d, stdout = %q, stderr = %q; want the read to work and the edit to fail", code, out, stderr)
		}
		assertUnchanged(t, target)
		assertAudit(t, dir, "unsigned", true, false)

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
		assertAudit(t, dir, "signed", false, false)
	})
}

// TestRunReadJailSetupFailureDenies: on the live jail, a worker that aborts
// before execve never runs the command. A Failed stage denies with 77 on any
// host; an Absent stage denies on a pinned host. It must never look like a
// command that ran and exited 1 (grep with no match).
func TestRunReadJailSetupFailureDenies(t *testing.T) {
	readNamedWriter(t)
	requireJail(t)
	for _, tc := range []struct {
		name, pin, inject, reason, worker, line string
		abi                                     int
	}{
		{name: "worker aborts before execve", inject: "seccomp", reason: "jail:failed:seccomp:EIO", worker: "gate-jail: setup failed at seccomp: input/output error\n", line: "the jail could not be set up (seccomp: input/output error)"},
		{name: "pinned host with an Absent jail", pin: pinDeny, abi: confine.ForceNoLandlock, reason: "jail:absent:landlock:ENOSYS", line: "this host has no usable jail (landlock: function not implemented) and reads are pinned"},
		{name: "pinned host with an Absent mount stage", pin: pinDeny, inject: "setattr:ENOSYS", reason: "jail:absent:setattr:ENOSYS", line: "this host has no usable jail (setattr: function not implemented) and reads are pinned"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			withGateDir(t, dir)
			if tc.pin != "" {
				plantPin(t, dir, tc.pin, 0o644)
			}
			readSpecHook = func(spec *confine.Spec) { spec.InjectFailAt, spec.ForceABI = tc.inject, tc.abi }
			t.Cleanup(func() { readSpecHook = nil })
			target := seedTarget(t, dir)
			code, out, stderr := runWith(t, "stat "+target+" ran")
			// The MCP tells this 77 from a missing signature by this exact line.
			if code != exitNoPermVal || out != "" || stderr != tc.worker+"gate: read jail unavailable: "+tc.line+"; nothing ran\n" {
				t.Errorf("exit = %d, stdout = %q, stderr = %q; want a 77 deny naming the jail", code, out, stderr)
			}
			targetIs(t, target, "orig\n")
			oneDeniedRead(t, dir, tc.reason, exitNoPermVal)
		})
	}
}

// TestRunReadJailAbsentFallsBack: on the live jail, an Absent stage on an
// unpinned host stops before the command, stays quiet (no worker line), and
// the read runs once classifier-only.
func TestRunReadJailAbsentFallsBack(t *testing.T) {
	readNamedWriter(t)
	requireJail(t)
	for _, inject := range []string{"setattr:ENOSYS", "private:EPERM", "seccomp:ENOSYS"} {
		t.Run(inject, func(t *testing.T) {
			dir := t.TempDir()
			withGateDir(t, dir)
			readSpecHook = func(spec *confine.Spec) { spec.InjectFailAt = inject }
			t.Cleanup(func() { readSpecHook = nil })
			target := seedTarget(t, dir)
			code, _, stderr := runWith(t, "stat "+target+" edited")
			if code != exitOK || stderr != "" {
				t.Fatalf("exit = %d, stderr = %q", code, stderr)
			}
			targetIs(t, target, "edited\n")
			recs := auditRecords(t, dir)
			if len(recs) != 1 || recs[0]["enforcement"] != "classifier" || recs[0]["jail_absent"] != inject || recs[0]["net"] != true {
				t.Fatalf("audit = %v", recs)
			}
		})
	}
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
