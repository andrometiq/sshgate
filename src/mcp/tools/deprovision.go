package tools

import (
	"fmt"
	"strings"
)

// This file renders the PRINT-ONLY, out-of-band de-provision guidance for the
// human-only `sshgate revoke <alias>` CLI verb (D2). It is the single source of
// truth for the strip wording, kept HERE next to the values it must stay exact
// against — commandForcingFmt, remoteGateBin, remoteGateDir, remoteAuthKeys (the
// same constants provisioning writes) — so the printed strip can never drift from
// the line rewriteAuthorizedKeys actually installs.
//
// SECURITY / SAFETY invariants this renderer upholds:
//   - It performs NO I/O, NO network, NO ssh, NO mutation. It only formats a
//     string from values the caller already holds. The strip it prints is run by
//     the OPERATOR over their OWN pre-existing admin access to the host — never by
//     SSHGate's gate. A Tier-1 host holds no signer pubkey by construction, so the
//     gate can never be handed a self-modifying unauthenticated revoke; the strip
//     therefore MUST be out-of-band. This helper just makes that strip precise.
//   - The strip anchors on the dedicated key's exact base64 blob (globally unique
//     to this key), NOT a loose `/sshgate/` substring. Precision is the whole
//     value: a broad match could delete an unrelated authorized_keys line and lock
//     the operator out, or leave a stray plain duplicate of the key (a full-shell
//     credential) behind. Matching the exact blob removes SSHGate's key (restricted
//     line AND any stray plain duplicate) while preserving every other key.

// RevokeGuideInput carries everything RevokeGuide needs. Every field is a value
// the caller (the CLI) already holds from the local registry + the dedicated
// public-key file; RevokeGuide reads nothing itself.
type RevokeGuideInput struct {
	Alias string
	User  string
	Host  string
	Port  int
	// ReadOnly is the alias's registered tier (true = Tier-1 read-only). It only
	// selects which tier-aware note is printed; it changes no step.
	ReadOnly bool
	// Base64Key is the exact base64 blob of SSHGate's dedicated public key — the
	// second whitespace field of the .pub line (e.g. "AAAAC3NzaC1lZDI1NTE5AAAA...").
	// It anchors the strip on the precise key, never a fuzzy pattern.
	Base64Key string
	// ServersPath is the absolute path to the local registry (servers.json) whose
	// alias entry the operator drops in the local-forget step.
	ServersPath string
}

// RevokeGuide renders the copy-pasteable de-provision plan for
// `sshgate revoke <alias>`. It is PRINT-ONLY: zero network/ssh calls, zero
// mutations. The returned string ends with a trailing newline.
func RevokeGuide(in RevokeGuideInput) string {
	port := in.Port
	if port == 0 {
		port = 22
	}

	// Build the target-user-qualified remote paths from the SAME constants
	// provisioning uses, replacing the leading "~" (which would expand to the
	// home of whoever runs the strip — root, say) with "~<user>" so the commands
	// target the SSHGate login user's files regardless of which admin account the
	// operator connects as.
	authKeys := "~" + in.User + strings.TrimPrefix(remoteAuthKeys, "~")
	gateDir := "~" + in.User + strings.TrimPrefix(remoteGateDir, "~")

	// The exact authorized_keys line rewriteAuthorizedKeys installs for this key:
	// the forcing-option prefix (with the real gate path) + the OpenSSH pubkey.
	forcedLine := fmt.Sprintf(commandForcingFmt, remoteGateBin) + "ssh-ed25519 " + in.Base64Key

	tier := "signed-write (Tier-2)"
	if in.ReadOnly {
		tier = "read-only (Tier-1)"
	}

	var b strings.Builder
	fmt.Fprintf(&b, "sshgate revoke %s — PRINT-ONLY out-of-band de-provision plan (nothing was changed)\n\n", in.Alias)
	fmt.Fprintf(&b, "  alias:  %s\n", in.Alias)
	fmt.Fprintf(&b, "  target: %s@%s:%d\n", in.User, in.Host, port)
	fmt.Fprintf(&b, "  tier:   %s\n\n", tier)
	fmt.Fprintf(&b, "This helper connected to NOTHING and edited NOTHING. It prints the exact steps for\n")
	fmt.Fprintf(&b, "YOU to run over your OWN pre-existing admin access to %s. SSHGate's gate cannot do\n", in.Host)
	fmt.Fprintf(&b, "this itself — a Tier-1 host holds no signer pubkey by construction, precisely so the\n")
	fmt.Fprintf(&b, "gate can never be told to do anything privileged — so the strip must happen over\n")
	fmt.Fprintf(&b, "your admin access, never the gate's.\n\n")

	// STEP 1 — precise remote strip.
	fmt.Fprintf(&b, "STEP 1 — on %s, over your admin access, remove SSHGate's dedicated key.\n", in.Host)
	fmt.Fprintf(&b, "SSHGate's access is exactly this one line in %s:\n\n", authKeys)
	fmt.Fprintf(&b, "    %s\n\n", forcedLine)
	fmt.Fprintf(&b, "Match it by SSHGate's dedicated key blob below — unique to this key — never by a\n")
	fmt.Fprintf(&b, "loose \"sshgate\" word/comment match: matching on text could strip an unrelated line\n")
	fmt.Fprintf(&b, "and lock you out, or leave a stray plain copy of the key (a full-shell credential).\n\n")
	fmt.Fprintf(&b, "  1a. Preview EXACTLY what will be removed — expect SSHGate's gate line (and any stray\n")
	fmt.Fprintf(&b, "      plain duplicate of the same key), and NOTHING you rely on to log in. If you see\n")
	fmt.Fprintf(&b, "      your own admin key here, STOP:\n\n")
	fmt.Fprintf(&b, "        grep -F -- '%s' %s\n\n", in.Base64Key, authKeys)
	fmt.Fprintf(&b, "  1b. Back up, then remove exactly those line(s). Idempotent (safe to run twice),\n")
	fmt.Fprintf(&b, "      safe if the line is already gone, and it preserves every OTHER key — so your\n")
	fmt.Fprintf(&b, "      own admin key is untouched:\n\n")
	fmt.Fprintf(&b, "        cp -p %s %s.sshgate-bak && \\\n", authKeys, authKeys)
	fmt.Fprintf(&b, "          grep -F -v -- '%s' %s.sshgate-bak > %s\n\n", in.Base64Key, authKeys, authKeys)
	fmt.Fprintf(&b, "      (The backup at %s.sshgate-bak lets you restore instantly if anything looks\n", authKeys)
	fmt.Fprintf(&b, "      wrong: mv %s.sshgate-bak %s)\n\n", authKeys, authKeys)
	fmt.Fprintf(&b, "  1c. Remove the gate payload directory:\n\n")
	fmt.Fprintf(&b, "        rm -rf %s\n\n", gateDir)

	// STEP 2 — local forget.
	fmt.Fprintf(&b, "STEP 2 — on THIS machine (the SSHGate control host, NOT the remote), forget the\n")
	fmt.Fprintf(&b, "alias locally. Drop the %q entry from the local registry:\n\n", in.Alias)
	fmt.Fprintf(&b, "    %s\n\n", in.ServersPath)
	fmt.Fprintf(&b, "  With jq (idempotent — a no-op if the alias is already absent; keeps mode 0600):\n\n")
	fmt.Fprintf(&b, "        jq 'del(.\"%s\")' %s > %s.sshgate-tmp && \\\n", in.Alias, in.ServersPath, in.ServersPath)
	fmt.Fprintf(&b, "          mv %s.sshgate-tmp %s && chmod 600 %s\n\n", in.ServersPath, in.ServersPath, in.ServersPath)
	fmt.Fprintf(&b, "  Or edit %s by hand and delete the top-level \"%s\": { ... } object (the registry\n", in.ServersPath, in.Alias)
	fmt.Fprintf(&b, "  is a bare alias->server JSON map; leave the surrounding braces well-formed).\n\n")

	// STEP 3 — tier-aware note.
	if in.ReadOnly {
		fmt.Fprintf(&b, "NOTE (Tier-1): this manual strip is the ONLY way to de-provision %q. Its gate has\n", in.Alias)
		fmt.Fprintf(&b, "no signer pubkey, so a signed SSHGATE_REVOKE can never be verified — the agent's\n")
		fmt.Fprintf(&b, "`revoke_server` tool and `/sshgate:revoke %s` refuse a Tier-1 host before any tap\n", in.Alias)
		fmt.Fprintf(&b, "(it would be denied at the gate, exit 77). There is no agent path; do the above.\n\n")
	} else {
		fmt.Fprintf(&b, "NOTE (Tier-2): the SIGNED agent path still exists and is PREFERRED — the\n")
		fmt.Fprintf(&b, "`revoke_server` MCP tool / `/sshgate:revoke %s` tears the gate down remotely and\n", in.Alias)
		fmt.Fprintf(&b, "drops the alias in one Telegram-approved step, doing STEP 1 and STEP 2 for you.\n")
		fmt.Fprintf(&b, "Use THIS manual strip only as the out-of-band FALLBACK — e.g. the signer is down,\n")
		fmt.Fprintf(&b, "or the host is unreachable through the gate.\n\n")
	}

	reAddFlag := ""
	if in.ReadOnly {
		reAddFlag = " --read-only"
	}
	fmt.Fprintf(&b, "To re-add later: re-paste `sshgate pubkey`'s plain line into %s, then run\n", authKeys)
	fmt.Fprintf(&b, "`sshgate add %s %s@%s:%d%s` — full provisioning re-runs once the gate no longer answers.\n",
		in.Alias, in.User, in.Host, port, reAddFlag)

	return b.String()
}
