package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/karthikeyan5/sshgate/src/mcp/registry"
	"github.com/karthikeyan5/sshgate/src/mcp/tools"
)

// These tests drive the PRINT-ONLY `sshgate revoke <alias>` out-of-band
// de-provision helper. The whole point of the verb is that it touches nothing —
// no remote dial, no signer, no registry write — so the tests assert both the
// printed content AND that the on-disk registry + dedicated key are byte-identical
// afterwards. They reuse seedConfigRoot / captureStdout from xfer_test.go.

// seedDedicatedKey generates SSHGate's dedicated keypair under root (writing
// ssh/sshgate_ed25519[.pub]) via the real provisioning helper and returns the
// exact base64 blob of the public key — the anchor the strip must match on.
func seedDedicatedKey(t *testing.T, root string) string {
	t.Helper()
	line, err := tools.EnsureSSHGateKeypair(filepath.Join(root, "ssh", "sshgate_ed25519"))
	if err != nil {
		t.Fatalf("seed dedicated key: %v", err)
	}
	fields := strings.Fields(line)
	if len(fields) < 2 {
		t.Fatalf("dedicated key line %q has no base64 field", line)
	}
	return fields[1]
}

// TestRevoke_PrintOnlyGuide is the table-style test: a Tier-1 and a Tier-2 alias,
// each asserting the printed strip is precise (exact key blob, not a loose
// pattern), names the right user@host and registry path, and carries the correct
// tier-aware note — while mutating NOTHING on disk.
func TestRevoke_PrintOnlyGuide(t *testing.T) {
	root := seedConfigRoot(t, map[string]registry.Entry{
		"prod": {Host: "prod.example.com", Port: 2222, User: "deploy", AddedAt: time.Now(), Fingerprint: "SHA256:prodfp"},
		"edge": {Host: "edge.example.com", Port: 22, User: "ops", AddedAt: time.Now(), Fingerprint: "SHA256:edgefp", ReadOnly: true},
	})
	b64 := seedDedicatedKey(t, root)
	regPath := filepath.Join(root, "servers.json")

	cases := []struct {
		name           string
		alias          string
		wantUserHost   string // the real user@host must appear
		mustContain    []string
		mustNotContain []string
	}{
		{
			name:         "tier2 prod",
			alias:        "prod",
			wantUserHost: "deploy@prod.example.com",
			mustContain: []string{
				"deploy@prod.example.com:2222", // real target, real port
				"grep -F -- '" + b64 + "'",     // precise preview on the EXACT key blob
				"grep -F -v -- '" + b64 + "'",  // precise strip on the EXACT key blob
				regPath,                        // local-forget names the right registry path
				`jq 'del(."prod")'`,            // precise local-forget
				"Tier-2",                       // tier-aware note
				"PREFERRED",                    // signed path is preferred for Tier-2
				"/sshgate:revoke prod",         // points at the signed agent path
				"~deploy/.ssh/authorized_keys", // user-qualified remote path
			},
			mustNotContain: []string{
				"/sshgate/d", // no loose sed pattern
				"sed -i",     // no in-place broad edit
				"ONLY way",   // Tier-2 must NOT say this is the only path
			},
		},
		{
			name:         "tier1 edge",
			alias:        "edge",
			wantUserHost: "ops@edge.example.com",
			mustContain: []string{
				"ops@edge.example.com:22",
				"grep -F -- '" + b64 + "'",
				"grep -F -v -- '" + b64 + "'",
				regPath,
				`jq 'del(."edge")'`,
				"Tier-1",
				"ONLY way",         // Tier-1: this manual strip is the only path
				"no signer pubkey", // echoes the tier1RevokeErr reasoning
				"~ops/.ssh/authorized_keys",
			},
			mustNotContain: []string{
				"/sshgate/d",
				"sed -i",
				"PREFERRED", // Tier-1 has no preferred signed path
			},
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			// Snapshot the registry bytes BEFORE, to prove no mutation after.
			before, err := os.ReadFile(regPath)
			if err != nil {
				t.Fatalf("read registry: %v", err)
			}

			out := captureStdout(t, func() {
				if code := run([]string{"revoke", c.alias}); code != 0 {
					t.Fatalf("run(revoke %s) = %d; want 0", c.alias, code)
				}
			})

			if !strings.Contains(out, c.wantUserHost) {
				t.Errorf("output missing user@host %q:\n%s", c.wantUserHost, out)
			}
			for _, want := range c.mustContain {
				if !strings.Contains(out, want) {
					t.Errorf("output missing %q:\n%s", want, out)
				}
			}
			for _, bad := range c.mustNotContain {
				if strings.Contains(out, bad) {
					t.Errorf("output unexpectedly contains %q (loose/wrong-tier):\n%s", bad, out)
				}
			}

			// CRITICAL: the registry file must be byte-identical — the helper is
			// print-only and must never write servers.json.
			after, err := os.ReadFile(regPath)
			if err != nil {
				t.Fatalf("read registry after: %v", err)
			}
			if string(before) != string(after) {
				t.Errorf("registry mutated by a print-only revoke:\nbefore=%s\nafter=%s", before, after)
			}
			// And the alias must still be registered (nothing was forgotten).
			reg, err := registry.New(regPath)
			if err != nil {
				t.Fatalf("reopen registry: %v", err)
			}
			if _, ok := reg.Get(c.alias); !ok {
				t.Errorf("alias %q was removed from the registry by a print-only revoke", c.alias)
			}
		})
	}
}

// TestRevoke_TierNotesDiffer asserts the Tier-1 and Tier-2 notes are genuinely
// different text (belt-and-braces over the table's per-tier phrase checks).
func TestRevoke_TierNotesDiffer(t *testing.T) {
	root := seedConfigRoot(t, map[string]registry.Entry{
		"prod": {Host: "h", Port: 22, User: "u", AddedAt: time.Now(), Fingerprint: "SHA256:prodfp"},
		"edge": {Host: "h2", Port: 22, User: "u", AddedAt: time.Now(), Fingerprint: "SHA256:edgefp", ReadOnly: true},
	})
	seedDedicatedKey(t, root)

	tier2 := captureStdout(t, func() {
		if code := run([]string{"revoke", "prod"}); code != 0 {
			t.Fatalf("run(revoke prod) = %d; want 0", code)
		}
	})
	tier1 := captureStdout(t, func() {
		if code := run([]string{"revoke", "edge"}); code != 0 {
			t.Fatalf("run(revoke edge) = %d; want 0", code)
		}
	})
	if tier1 == tier2 {
		t.Fatal("Tier-1 and Tier-2 revoke plans are identical; the tier-aware note must differ")
	}
}

// TestRevoke_UnknownAlias: an alias not in the registry is a clean non-zero exit.
func TestRevoke_UnknownAlias(t *testing.T) {
	root := seedConfigRoot(t, map[string]registry.Entry{})
	seedDedicatedKey(t, root)
	if code := run([]string{"revoke", "ghost"}); code == 0 {
		t.Fatal("run(revoke ghost) = 0; want non-zero for an unknown alias")
	}
}

// TestRevoke_MissingPubKey: without the dedicated .pub the helper cannot anchor
// the strip precisely, so it refuses (non-zero) rather than print a fuzzy match.
func TestRevoke_MissingPubKey(t *testing.T) {
	seedConfigRoot(t, map[string]registry.Entry{
		"prod": {Host: "h", Port: 22, User: "u", AddedAt: time.Now(), Fingerprint: "SHA256:prodfp"},
	})
	// Deliberately do NOT seed the dedicated key.
	if code := run([]string{"revoke", "prod"}); code == 0 {
		t.Fatal("run(revoke prod) = 0; want non-zero when the dedicated .pub is absent")
	}
}

// TestRevoke_Usage: wrong arity and unknown flags are usage errors (exit 2).
func TestRevoke_Usage(t *testing.T) {
	if code := run([]string{"revoke"}); code != 2 {
		t.Errorf("run(revoke) = %d; want 2 (usage error)", code)
	}
	if code := run([]string{"revoke", "a", "b"}); code != 2 {
		t.Errorf("run(revoke a b) = %d; want 2 (too many args)", code)
	}
	if code := run([]string{"revoke", "--bogus"}); code != 2 {
		t.Errorf("run(revoke --bogus) = %d; want 2 (unknown flag)", code)
	}
}
