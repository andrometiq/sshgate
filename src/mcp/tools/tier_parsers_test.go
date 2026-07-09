package tools

import (
	"context"
	"testing"
)

// TestParseProbedTier pins the additive tier= extraction (#62): a recognised
// ro/rw value is returned, and anything else (absent token = old gate, empty or
// unrecognised value) reports "" so a garbled/forward-incompatible value is
// treated as "no signal" rather than mis-reconciled. It keys on the tier= token
// independently of the frozen rev= key and tolerates surrounding/trailing tokens.
func TestParseProbedTier(t *testing.T) {
	t.Parallel()
	cases := []struct{ in, want string }{
		{"SSHGATE_VERSION rev=v1.4.0 tier=ro\n", "ro"},
		{"SSHGATE_VERSION rev=v1.4.0 tier=rw\n", "rw"},
		{"SSHGATE_VERSION rev=v1.4.0\n", ""},               // old gate: no tier token
		{"SSHGATE_VERSION rev=dev tier=bogus\n", ""},       // unrecognised value
		{"SSHGATE_VERSION rev=dev tier=\n", ""},            // empty value
		{"", ""},                                           // empty reply
		{"SSHGATE_VERSION rev=v1 tier=rw extra=1\n", "rw"}, // tolerant of trailing tokens
	}
	for _, c := range cases {
		if got := parseProbedTier(c.in); got != c.want {
			t.Errorf("parseProbedTier(%q) = %q; want %q", c.in, got, c.want)
		}
	}
}

// TestProbeRunningRev_TolerantOfTierToken proves the FROZEN rev= consumer
// probeRunningRev returns the same rev value whether or not the additive tier=
// token trails the SSHGATE_VERSION line (#62 additive-safety).
func TestProbeRunningRev_TolerantOfTierToken(t *testing.T) {
	t.Parallel()
	withTier := &internalProbeSSH{out: []byte("SSHGATE_VERSION rev=v1.4.0 tier=ro\n"), exit: 0}
	if got := probeRunningRev(context.TODO(), withTier, "h", "u", 22); got != "v1.4.0" {
		t.Errorf("with trailing tier= token: runningRev = %q; want v1.4.0", got)
	}
	without := &internalProbeSSH{out: []byte("SSHGATE_VERSION rev=v1.4.0\n"), exit: 0}
	if got := probeRunningRev(context.TODO(), without, "h", "u", 22); got != "v1.4.0" {
		t.Errorf("without tier=: runningRev = %q; want v1.4.0", got)
	}
}

// TestParseUpdatedMarker_TolerantOfTrailingToken proves the FROZEN SSHGATE_UPDATED
// rev= consumer still parses correctly with an unknown trailing token present.
// Production only appends tier= to SSHGATE_VERSION (never to the UPDATED marker),
// but the parser must be additive-safe like the other two frozen consumers.
func TestParseUpdatedMarker_TolerantOfTrailingToken(t *testing.T) {
	t.Parallel()
	h, n, rev, ok := parseUpdatedMarker("SSHGATE_UPDATED sha256=deadbeef size=4096 rev=abc1234 tier=rw\n")
	if !ok || h != "deadbeef" || n != 4096 || rev != "abc1234" {
		t.Errorf("with trailing token = (%q,%d,%q,%v); want (deadbeef,4096,abc1234,true)", h, n, rev, ok)
	}
	h, n, rev, ok = parseUpdatedMarker("SSHGATE_UPDATED sha256=deadbeef size=4096 rev=abc1234\n")
	if !ok || h != "deadbeef" || n != 4096 || rev != "abc1234" {
		t.Errorf("without trailing token = (%q,%d,%q,%v); want (deadbeef,4096,abc1234,true)", h, n, rev, ok)
	}
}
