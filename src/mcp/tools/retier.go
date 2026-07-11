package tools

import "fmt"

// retierManualPath returns the factual, code-grounded guidance for changing a
// read-only (Tier-1) server's tier. It is the single source of truth for the
// tier-change wording, reused by every Tier-1 write-refusal message so they can
// never drift apart or regress to circular advice.
//
// Why the manual path is the only one that exists today (verified against
// provision.go): a Tier-1 gate has NO signer pubkey on the host, so it cannot
// verify a signed SSHGATE_REVOKE — the agent's revoke_server (and the
// /sshgate:revoke command that wraps it) is refused before it can tear a Tier-1
// gate down. There is also no in-place read-only→write flip (rejected for
// security, roadmap #17 — any unsigned tier-flip path the CLI could exercise the
// agent could emulate). So re-tiering is a human de-provision + re-add:
//
//  1. On the host, over the operator's own admin access, replace SSHGate's
//     forced command="..." line in ~/.ssh/authorized_keys with `sshgate
//     pubkey`'s plain line (this re-opens the brief full-shell window and stops
//     the gate answering).
//  2. Drop the stale alias from the local registry
//     (~/.config/sshgate/servers.json) — `sshgate add` refuses an
//     already-registered alias (provision.go), and no working revoke exists for
//     a Tier-1 host.
//  3. Re-run `sshgate add <alias> <user@host>` at the desired tier; because the
//     idempotency probe no longer sees a gate, full provisioning re-runs and
//     re-locks the key at that tier.
//
// alias may be a concrete alias or the literal "<alias>" placeholder for
// contexts with no specific server in hand (e.g. the generic exit-77 note).
func retierManualPath(alias string) string {
	return fmt.Sprintf(
		"To change its tier, a human de-provisions it by hand and re-adds it — there is no in-place read-only→write flip (rejected for security, roadmap #17) and no signed remote revoke works on a Tier-1 gate (it has no signer pubkey): on the host, using your own admin access, replace SSHGate's forced command=\"...\" line in ~/.ssh/authorized_keys with `sshgate pubkey`'s plain line, drop the %q entry from the local registry (~/.config/sshgate/servers.json), then re-run `sshgate add %s <user@host>` at the desired tier (run /sshgate:setup first if no signer is configured yet) — full provisioning re-runs once the gate no longer answers. Run `sshgate revoke %s` for the exact copy-pasteable strip + local-forget steps (print-only; it changes nothing).",
		alias, alias, alias)
}

// tier1RevokeErr is the actionable refusal for revoke_server against a server
// registered read-only (Tier-1). A Tier-1 gate has no signer pubkey, so the
// signed SSHGATE_REVOKE it would send can never be verified — the gate denies it
// (exit 77) and the alias is never removed, yet soliciting the signature first
// burns a real human Telegram tap on a guaranteed no-op. So revoke_server
// refuses BEFORE signing and describes the manual de-provision that actually
// works. It deliberately does NOT tell the user to run /sshgate:revoke (that is
// this very path — circular).
func tier1RevokeErr(alias string) error {
	return fmt.Errorf(
		"tools: server %q is registered read-only (Tier-1) — its gate has no signer pubkey, so a signed SSHGATE_REVOKE cannot be verified and the agent cannot tear a Tier-1 gate down remotely (it would be denied at the gate, exit 77, after burning a Telegram tap). Remove it by hand instead: on the host, using your own admin access, delete SSHGate's forced command=\"...\" line from ~/.ssh/authorized_keys and remove the ~/.sshgate-gate directory, then drop the %q entry from the local registry (~/.config/sshgate/servers.json). To re-add it, re-paste `sshgate pubkey`'s plain line and run `sshgate add %s <user@host>` at the tier you want. Run `sshgate revoke %s` for the exact copy-pasteable strip + local-forget steps (print-only; it changes nothing).",
		alias, alias, alias, alias)
}
