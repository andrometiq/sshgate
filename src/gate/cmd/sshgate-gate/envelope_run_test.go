package main

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"github.com/karthikeyan5/sshgate/src/gate"
	"github.com/karthikeyan5/sshgate/src/gate/confine"
	"github.com/karthikeyan5/sshgate/src/sigwire"
)

func TestEnvelopeTier1DamagedPub(t *testing.T) {
	dir := t.TempDir()
	withGateDir(t, dir)
	if err := os.WriteFile(filepath.Join(dir, "gate.pub"), []byte("broken"), 0600); err != nil {
		t.Fatal(err)
	}
	fake := withFakeAttempt(t, gate.ExecResult{}, nil)
	code, _, stderr := runWith(t, "SSHGATE_READ1 confined cat /dev/null")
	if code != exitSoftware || !strings.Contains(stderr, "load pubkey") || fake.confined != 0 || fake.fallback != 0 {
		t.Fatalf("code=%d stderr=%q calls=%+v", code, stderr, fake)
	}
}

func TestEnvelopeDispatch(t *testing.T) {
	for _, inner := range []string{"SSHGATE_VERSION", "SSHGATE_JAIL", "SSHGATE_REVOKE", "SSHGATE_SIG:invalid", "touch /must-not-exist", "SSHGATE_READ1 confined cat /dev/null"} {
		t.Run(inner, func(t *testing.T) {
			dir := t.TempDir()
			withGateDir(t, dir)
			fake := withFakeAttempt(t, gate.ExecResult{}, nil)
			code, out, stderr := runWith(t, "SSHGATE_READ1 confined "+inner)
			if code != 77 || out != "" || stderr != "gate: "+sigwire.GateDenyEnvelopeNotRead+"\n" || fake.confined != 0 || fake.fallback != 0 {
				t.Fatalf("code=%d out=%q stderr=%q calls=%+v", code, out, stderr, fake)
			}
			rows := auditRecords(t, dir)
			if len(rows) != 1 || rows[0]["classification"] != "write" || rows[0]["envelope"] != true || rows[0]["deny_reason"] != "envelope:not-a-read" {
				t.Fatalf("audit=%v", rows)
			}
		})
	}
}

func TestAuditNetFields(t *testing.T) {
	for _, source := range []string{"pin", "envelope"} {
		for _, denied := range []bool{false, true} {
			name := source + "/executed"
			if denied {
				name = source + "/denied"
			}
			t.Run(name, func(t *testing.T) {
				dir := t.TempDir()
				withGateDir(t, dir)
				plantPin(t, dir, pinAllow, 0644)
				previous := executeCommand
				executeCommand = func(_ context.Context, _ string, opts gate.ExecOpts) (gate.ExecResult, error) {
					if opts.Confine == nil || !opts.Confine.Net || !opts.Confine.Strict {
						t.Fatalf("unexpected spec: %+v", opts.Confine)
					}
					if denied {
						return setupFailure("landlock", syscall.ENOSYS)
					}
					return gate.ExecResult{Jail: &confine.Facts{Net: true, ABI: 1}}, nil
				}
				t.Cleanup(func() { executeCommand = previous })
				command := "cat /dev/null"
				if source == "envelope" {
					command = "SSHGATE_READ1 confined,net " + command
				}
				code, _, _ := runWith(t, command)
				want := 0
				if denied {
					want = 77
				}
				if code != want {
					t.Fatalf("code=%d want=%d", code, want)
				}
				rows := auditRecords(t, dir)
				if len(rows) != 1 {
					t.Fatalf("audit=%v", rows)
				}
				row := rows[0]
				if _, ok := row["net_grant"]; ok {
					t.Fatalf("unexpected grant: %v", row)
				}
				if source == "envelope" {
					if row["envelope"] != true {
						t.Fatalf("missing envelope: %v", row)
					}
				} else if _, ok := row["envelope"]; ok {
					t.Fatalf("unexpected envelope: %v", row)
				}
				if !denied && (row["net"] != true || row["requires_confinement"] != true) {
					t.Fatalf("read fields: %v", row)
				}
				if denied && (row["deny_reason"] != "jail:absent:landlock:ENOSYS" || row["approval_status"] != "denied") {
					t.Fatalf("denial fields: %v", row)
				}
			})
		}
	}
}

func TestEnvelopePinSnapshot(t *testing.T) {
	for _, when := range []string{"before", "after"} {
		for _, change := range []string{"remove", "deny"} {
			t.Run(when+"/"+change, func(t *testing.T) {
				dir := t.TempDir()
				withGateDir(t, dir)
				plantPin(t, dir, pinAllow, 0644)
				oldParse, oldAdmit, oldPin, oldExec := envelopeParsedHook, readAdmittedHook, jailPinFn, executeCommand
				t.Cleanup(func() {
					envelopeParsedHook, readAdmittedHook, jailPinFn, executeCommand = oldParse, oldAdmit, oldPin, oldExec
				})
				reads, calls := 0, 0
				jailPinFn = func() pinState { reads++; return readJailPin() }
				alter := func() {
					if change == "deny" {
						plantPin(t, dir, pinDeny, 0644)
					} else if err := os.Remove(filepath.Join(dir, confine.PinFile)); err != nil {
						t.Fatal(err)
					}
				}
				if when == "before" {
					envelopeParsedHook = alter
				} else {
					readAdmittedHook = func(pinState) { alter() }
				}
				executeCommand = func(_ context.Context, _ string, opts gate.ExecOpts) (gate.ExecResult, error) {
					calls++
					if opts.Confine == nil || !opts.Confine.Net || !opts.Confine.Strict {
						t.Fatalf("lost admitted network: %+v", opts.Confine)
					}
					return gate.ExecResult{Jail: &confine.Facts{Net: true, ABI: 1}}, nil
				}
				code, _, stderr := runWith(t, "SSHGATE_READ1 confined,net cat /dev/null")
				if reads != 1 {
					t.Fatalf("pin snapshots=%d", reads)
				}
				if when == "before" {
					if code != 77 || calls != 0 || stderr != "gate: "+sigwire.GateDenyNetNotPermitted+"\n" {
						t.Fatalf("code=%d calls=%d stderr=%q", code, calls, stderr)
					}
				} else if code != 0 || calls != 1 {
					t.Fatalf("code=%d calls=%d stderr=%q", code, calls, stderr)
				}
			})
		}
	}
}
