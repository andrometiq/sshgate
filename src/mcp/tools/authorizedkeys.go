package tools

import (
	"bufio"
	"bytes"
	"fmt"
	"strings"

	"golang.org/x/crypto/ssh"
)

// commandForcing is the option list prepended to the SSHGate dedicated
// key in authorized_keys. The command field is templated with the
// remote path to the gate binary; the other restrictions are static.
// Spec §"SSH key management":
//
//	restrict,command="~/.sshgate-gate/gate",no-pty,no-port-forwarding,no-X11-forwarding,no-agent-forwarding <key>
//
// restrict (OpenSSH ≥ 7.2, 2016) is the deny-all catch-all: it disables PTY
// allocation, agent/port/X11 forwarding, AND ~/.ssh/rc execution, and
// auto-includes any future restriction OpenSSH adds. It closes the one gap the
// explicit list left open — no-user-rc: with a forced command sshd still runs a
// pre-existing ~/.ssh/rc as a full shell *before* the forced command unless
// restrict/no-user-rc is set, so an agent that ever lands a write to ~/.ssh/rc
// would get a shell outside the gate on the next connection. The explicit no-*
// options are kept as belt-and-braces (redundant under restrict, but greppable
// and independently golden-pinned). no-pty in particular: without it a
// third-party SSH client holding the SSHGate key could request a TTY and turn a
// classified-read pager (less/man/git log/systemctl status) interactive,
// escaping the gate via !sh / v-to-editor (docs/security-readonly-bypass.md B9).
// The gate's own client never asks for a PTY, so none of this affects SSHGate's
// own traffic.
//
// NOTE: restrict requires OpenSSH ≥ 7.2 on the target; a pre-7.2 sshd rejects
// the whole line (the key stops working). SSHGate targets modern hosts, so 7.2
// is a safe floor.
const commandForcingFmt = `restrict,command="%s",no-pty,no-port-forwarding,no-X11-forwarding,no-agent-forwarding `

// rewriteAuthorizedKeys returns the new contents of authorized_keys
// after:
//
//  1. Removing any existing line whose key bytes match pubkey
//     (regardless of options or comment — idempotent re-add).
//  2. Appending a single line with the command="..." forcing prefix
//     followed by the OpenSSH-formatted pubkey.
//
// Other lines (comments, blank lines, unrelated keys) are preserved
// verbatim and in order. The returned buffer always ends with a
// trailing newline so concatenation is well-defined.
//
// commandPath is the remote path to the gate binary (e.g.
// "~/.sshgate-gate/gate"). It is embedded verbatim into the
// command="..." field; callers MUST keep it free of shell
// metacharacters and double-quotes.
func rewriteAuthorizedKeys(existing []byte, pubkey ssh.PublicKey, commandPath string) ([]byte, error) {
	if pubkey == nil {
		return nil, fmt.Errorf("rewriteAuthorizedKeys: pubkey is nil")
	}
	if strings.ContainsAny(commandPath, "\"\n") {
		return nil, fmt.Errorf("rewriteAuthorizedKeys: commandPath %q contains forbidden characters", commandPath)
	}
	wantBytes := pubkey.Marshal()

	var out bytes.Buffer
	sc := bufio.NewScanner(bytes.NewReader(existing))
	// Allow long authorized_keys lines (RSA 8192 + options can exceed
	// the default 64 KiB token buffer on some platforms; bump generously).
	buf := make([]byte, 0, 256*1024)
	sc.Buffer(buf, 1024*1024)
	for sc.Scan() {
		line := sc.Text()
		if lineMatchesKey(line, wantBytes) {
			// Drop this line (we will re-emit it as the restricted entry).
			continue
		}
		out.WriteString(line)
		out.WriteByte('\n')
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("rewriteAuthorizedKeys: scan: %w", err)
	}

	// OpenSSH-format pubkey is "ssh-<type> <b64> [comment]\n" — exactly
	// what we want to append after the forcing options.
	pubLine := bytes.TrimRight(ssh.MarshalAuthorizedKey(pubkey), "\n")
	fmt.Fprintf(&out, commandForcingFmt, commandPath)
	out.Write(pubLine)
	out.WriteByte('\n')
	return out.Bytes(), nil
}

// lineMatchesKey reports whether line contains an authorized_keys
// entry whose key bytes equal want. The line may carry options
// (command="...", environment="...", etc.), the key type ("ssh-ed25519"
// or "ssh-rsa"), the base64 key, and an optional comment.
//
// We use ssh.ParseAuthorizedKey, which correctly handles all the
// option-string quoting rules of OpenSSH's authorized_keys format.
// A non-key line (comment, blank, malformed) is reported as no match.
func lineMatchesKey(line string, want []byte) bool {
	trimmed := strings.TrimSpace(line)
	if trimmed == "" || strings.HasPrefix(trimmed, "#") {
		return false
	}
	parsed, _, _, _, err := ssh.ParseAuthorizedKey([]byte(line))
	if err != nil {
		return false
	}
	return bytes.Equal(parsed.Marshal(), want)
}

// hasRestrictedEntryForKey reports whether existing already contains a
// line with the exact command-forcing prefix (commandPath) AND the
// given pubkey. This is the idempotency probe: when true, the auto-
// setup tool can skip the rewrite step and just verify.
//
// The match is conservative: we require the line to start with the
// exact commandForcing prefix (commandPath in the command= option) and
// to carry the pubkey. Any difference in options (e.g. an extra
// "from=10.0.0.0/8" clause) is treated as "not the entry we'd write,"
// which forces a rewrite — that's the safe default.
func hasRestrictedEntryForKey(existing []byte, pubkey ssh.PublicKey, commandPath string) bool {
	if pubkey == nil {
		return false
	}
	wantBytes := pubkey.Marshal()
	wantPrefix := fmt.Sprintf(commandForcingFmt, commandPath)

	sc := bufio.NewScanner(bytes.NewReader(existing))
	buf := make([]byte, 0, 256*1024)
	sc.Buffer(buf, 1024*1024)
	for sc.Scan() {
		line := sc.Text()
		if !strings.HasPrefix(line, wantPrefix) {
			continue
		}
		if lineMatchesKey(line, wantBytes) {
			return true
		}
	}
	return false
}
