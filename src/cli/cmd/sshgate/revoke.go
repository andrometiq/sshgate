package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/karthikeyan5/sshgate/src/mcp/tools"
)

// runRevoke implements the PRINT-ONLY `sshgate revoke <alias>` out-of-band
// de-provision helper (D2). It reads the local registry + SSHGate's dedicated
// public key and PRINTS a precise, copy-pasteable strip + local-forget procedure.
//
// It changes NOTHING: no remote connection, no ssh, no signer call, no write to
// servers.json. It is deliberately DISTINCT from the signed teardown — the
// `revoke_server` MCP tool / `/sshgate:revoke` — which is the preferred path for a
// Tier-2 host but cannot run on a Tier-1 host (no signer pubkey there to verify a
// signed SSHGATE_REVOKE). This helper is the out-of-band fallback (Tier-2) and the
// ONLY de-provision path (Tier-1), and its whole value is making the manual strip
// precise so it can never lock the operator out.
func runRevoke(args []string) int {
	var positional []string
	for _, a := range args {
		switch a {
		case "-h", "--help":
			fmt.Fprintln(os.Stdout, "usage: sshgate revoke <alias>")
			return 0
		default:
			if len(a) > 0 && a[0] == '-' {
				fmt.Fprintf(os.Stderr, "sshgate revoke: unknown flag %q\n", a)
				return 2
			}
			positional = append(positional, a)
		}
	}
	if len(positional) != 1 {
		fmt.Fprintln(os.Stderr, "usage: sshgate revoke <alias>")
		return 2
	}
	alias := positional[0]

	root, err := configRoot()
	if err != nil {
		fmt.Fprintf(os.Stderr, "sshgate: %v\n", err)
		return 1
	}
	e, err := lookupServer(root, alias)
	if err != nil {
		fmt.Fprintf(os.Stderr, "sshgate revoke: %v\n", err)
		return 1
	}

	// The dedicated key's base64 blob anchors the strip on the EXACT key. Read it
	// (never regenerate — this path mutates nothing) from the .pub provisioning
	// wrote next to the private key.
	pubPath := filepath.Join(root, "ssh", "sshgate_ed25519.pub")
	b64, err := readDedicatedKeyBase64(pubPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "sshgate revoke: %v\n", err)
		return 1
	}

	guide := tools.RevokeGuide(tools.RevokeGuideInput{
		Alias:       alias,
		User:        e.User,
		Host:        e.Host,
		Port:        e.Port,
		ReadOnly:    e.ReadOnly,
		Base64Key:   b64,
		ServersPath: serversPath(root),
	})
	fmt.Fprint(os.Stdout, guide)
	return 0
}

// readDedicatedKeyBase64 reads SSHGate's dedicated public-key file and returns the
// exact base64 key blob (the second whitespace field of "ssh-ed25519 <b64>
// [comment]"), which anchors the printed strip on the precise key rather than a
// loose pattern. It is read-only.
func readDedicatedKeyBase64(pubPath string) (string, error) {
	body, err := os.ReadFile(pubPath)
	if err != nil {
		if os.IsNotExist(err) {
			return "", fmt.Errorf("SSHGate dedicated public key not found at %s — run `sshgate pubkey` to (re)generate it, then retry", pubPath)
		}
		return "", fmt.Errorf("read %s: %w", pubPath, err)
	}
	// SSHGate's dedicated .pub is ALWAYS exactly one ed25519 line. Refuse a file
	// with more than one non-empty key line: a bare strings.Fields would silently
	// take the FIRST key's blob, so the printed strip would anchor on the wrong key
	// (and could leave a second, unstripped key behind, or miss the real one).
	var keyLines []string
	for _, ln := range strings.Split(string(body), "\n") {
		if strings.TrimSpace(ln) != "" {
			keyLines = append(keyLines, ln)
		}
	}
	if len(keyLines) > 1 {
		return "", fmt.Errorf("SSHGate dedicated public key in %s has %d key lines; expected exactly one ed25519 line — refusing rather than guess which key to strip", pubPath, len(keyLines))
	}
	fields := strings.Fields(string(body))
	if len(fields) < 2 || !strings.HasPrefix(fields[0], "ssh-") {
		return "", fmt.Errorf("malformed SSHGate public key in %s (expected an \"ssh-... <base64>\" line)", pubPath)
	}
	return fields[1], nil
}
