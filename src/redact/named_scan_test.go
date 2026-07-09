package redact

import (
	"strings"
	"testing"
)

// containsRule reports whether ms holds a match emitted by ruleID.
func containsRule(ms []match, ruleID string) bool {
	for _, m := range ms {
		if m.RuleID == ruleID {
			return true
		}
	}
	return false
}

// TestFindNamedMatchesExcludesGenericNet pins the W4-8 invariant that the
// completed non-private PEM path relies on: findNamedMatches runs the named
// regex ruleset ONLY and never emits the generic default-deny net's output,
// whereas findMatches (the full pipeline) does. A certificate body is a
// benign high-entropy blob; routing it through the generic net would
// re-redact it and defeat `cat server.crt`.
func TestFindNamedMatchesExcludesGenericNet(t *testing.T) {
	var salt [32]byte
	// A trivial named rule so neither method hits the len(rules)==0 early
	// return; it also gives us a NAMED hit to prove named rules still fire.
	akiaRule := CompileRule(
		"test-akia", "aws-shaped",
		`\b(AKIA[0-9A-Z]{16})\b`, []string{"AKIA"}, 1, 20, 20,
	)
	s := newScanner(salt, []Rule{akiaRule})

	genRun := mixed3(40) // 3-class, >= genericMinLen, high entropy -> generic net fires
	akia := "AKIA" + strings.Repeat("Q", 16)
	buf := []byte("blob " + genRun + " AKIA-key " + akia + "\n")

	full := s.findMatches(buf)
	named := s.findNamedMatches(buf)

	// The full pipeline sees the generic run; the named-only path must not.
	if !containsRule(full, genericEntropyRuleID) {
		t.Fatalf("findMatches should include the generic-net hit; got %+v", full)
	}
	if containsRule(named, genericEntropyRuleID) {
		t.Errorf("findNamedMatches must EXCLUDE generic-net output; got %+v", named)
	}
	// A named hit must still be caught by the named-only path.
	if !containsRule(named, "test-akia") {
		t.Errorf("findNamedMatches dropped the named AKIA hit; got %+v", named)
	}
}

// TestHasSSHPubkeyBodyPrefix pins the anti-spoof discriminator for the
// twitter-bearer veto: only a real SSH wire-format body earns the pass; an
// `AAAAAAAA…`-style bearer body does not.
func TestHasSSHPubkeyBodyPrefix(t *testing.T) {
	positives := []string{
		"AAAAB3NzaC1yc2EAAAADAQAB",   // ssh-rsa
		"AAAAC3NzaC1lZDI1NTE5AAAAII", // ssh-ed25519
		"AAAAE2VjZHNhLXNoYTItbmlzdH", // ecdsa-sha2-*
	}
	for _, p := range positives {
		if !hasSSHPubkeyBodyPrefix([]byte(p)) {
			t.Errorf("expected %q to be recognised as an SSH pubkey body", p)
		}
	}
	negatives := []string{
		"AAAAAAAAAAAAAAAAAAAAAM1234", // real twitter/x bearer shape
		"AAAAf00barbazqux",           // synthetic AAAA run, not a wire prefix
		"BBBBC3NzaC1lZDI1NTE5",       // does not start AAAA
		"AAA",                        // too short
	}
	for _, n := range negatives {
		if hasSSHPubkeyBodyPrefix([]byte(n)) {
			t.Errorf("expected %q NOT to be recognised as an SSH pubkey body", n)
		}
	}
}
