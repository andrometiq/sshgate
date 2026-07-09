package tools

import (
	"fmt"
	"strings"
	"testing"

	signpkg "github.com/karthikeyan5/sshgate/src/mcp/sign"
)

// TestTier1RefusalStrings_NoCircularRevokeAdvice is the regression guard for the
// honest-strings sweep (W1-2d). Every Tier-1-path refusal message must describe
// the manual de-provision + re-add that actually works, and must NOT tell the
// user to run /sshgate:revoke — that command wraps revoke_server, which is itself
// refused on a Tier-1 host (its gate has no signer pubkey to verify the signed
// SSHGATE_REVOKE), so the advice would be circular and unrunnable.
func TestTier1RefusalStrings_NoCircularRevokeAdvice(t *testing.T) {
	t.Parallel()

	// A zero Runner has an empty SignerSockPath, so signerSocketPresent() is
	// false and the ErrUnreachable branches take the Tier-1 (no-signer) path.
	var r Runner
	unreachable := fmt.Errorf("dial failed: %w", signpkg.ErrUnreachable)

	strs := map[string]string{
		"readOnlyWriteErr":      readOnlyWriteErr("db").Error(),
		"gateDenyNote(77)":      gateDenyNote(77),
		"retierManualPath":      retierManualPath("db"),
		"tier1RevokeErr":        tier1RevokeErr("db").Error(),
		"remediateSignErr/T1":   r.remediateSignErr(unreachable).Error(),
		"classifySignErrReason": r.classifySignErrReason(unreachable),
	}

	for name, s := range strs {
		if strings.Contains(s, "/sshgate:revoke") {
			t.Errorf("%s contains circular /sshgate:revoke advice: %q", name, s)
		}
		// Every one of these must point at the real re-provision entry point.
		if !strings.Contains(s, "sshgate add") {
			t.Errorf("%s does not mention the `sshgate add` re-provision path: %q", name, s)
		}
	}

	// The canonical helper must name the concrete manual steps (host file + the
	// registry) so the advice is actually actionable, and must interpolate the
	// alias into both the drop-from-registry and re-add instructions.
	got := retierManualPath("db")
	for _, sub := range []string{"authorized_keys", "servers.json", `"db"`, "sshgate add db"} {
		if !strings.Contains(got, sub) {
			t.Errorf("retierManualPath is missing %q: %q", sub, got)
		}
	}
}
