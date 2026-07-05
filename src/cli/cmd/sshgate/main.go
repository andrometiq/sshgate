// Command sshgate is the HUMAN-ONLY provisioning CLI. It is deliberately
// kept OUT of the agent/MCP surface so an AI agent can never expand its own
// reach by onboarding new machines: only a human at a terminal runs it.
//
// Bootstrap model (different from the legacy MCP add_server, which borrowed
// the operator's personal SSH key):
//
//  1. `sshgate pubkey` prints SSHGate's OWN dedicated public-key line.
//  2. The human MANUALLY pastes that line (plain, unrestricted) into the
//     target server's ~/.ssh/authorized_keys (they already administer it).
//  3. `sshgate add <alias> <user@host>[:port] [--read-only]` connects to the
//     target USING SSHGate's own key (which now has plain shell access),
//     installs the gate, and rewrites the pasted plain line into the
//     restricted command="~/.sshgate-gate/gate" forced-command line — locking
//     the key down. From then on the key is gated.
//
// The ONLY credential involved is SSHGate's own sshgate_ed25519. The brief
// window between the human's paste and the rewrite (where the key has full
// shell) is accepted and human-controlled.
//
// Configuration (all paths in $XDG_CONFIG_HOME/sshgate/, default
// ~/.config/sshgate/):
//
//	servers.json                      — alias → host/port/user registry
//	ssh/sshgate_ed25519[.pub]         — SSHGate dedicated SSH keypair
//	known_hosts                       — TOFU host-key store
//	bin/sshgate-gate-linux-amd64      — cross-compiled gate binary
//	pubkey-distrib/gate.pub           — signer public key (tier-2 writes)
package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/karthikeyan5/sshgate/src/mcp/tools"
)

func main() {
	os.Exit(run(os.Args[1:]))
}

func run(args []string) int {
	if len(args) == 0 {
		usage(os.Stderr)
		return 2
	}
	switch args[0] {
	case "pubkey":
		return runPubkey(args[1:])
	case "add":
		return runAdd(args[1:])
	case "xfer-register":
		return runXferRegister(args[1:])
	case "xfer-rotate":
		return runXferRotate(args[1:])
	case "xfer-status":
		return runXferStatus(args[1:])
	case "-h", "--help", "help":
		usage(os.Stdout)
		return 0
	default:
		fmt.Fprintf(os.Stderr, "sshgate: unknown subcommand %q\n\n", args[0])
		usage(os.Stderr)
		return 2
	}
}

func usage(w *os.File) {
	fmt.Fprint(w, `sshgate — human-only SSHGate provisioning CLI

Usage:
  sshgate pubkey
        Print SSHGate's dedicated public-key line (generating the keypair if
        absent). Paste this line into the target server's
        ~/.ssh/authorized_keys, then run "sshgate add".

  sshgate add <alias> <user@host>[:port] [--read-only|--ro]
        Connect to the target with SSHGate's key, install the gate, and lock
        the pasted key down behind a forced-command entry. Registers <alias>.
        --read-only (--ro): tier-1 install (no signer pubkey; writes denied
        at the gate).

  sshgate xfer-register <alias> --box-pub '<line>' --id-pub '<line>' [--label <s>]
        (Re)register a server's box→box transfer keys with the signer, under the
        fingerprint recorded in servers.json. Human-approved (Telegram tap). The
        recovery/standalone path — no host contact.

  sshgate xfer-rotate <alias> [user@host[:port]]
        Rotate a provisioned Tier-2 host's transfer keys and re-register them.
        Requires the plain bootstrap window re-opened first (see the printed hint).

  sshgate xfer-status [<alias>]
        Show transfer readiness per server: tier, keys-on-host (best-effort),
        and fingerprint.

  sshgate help
        Show this help.
`)
}

// runPubkey implements `sshgate pubkey`.
func runPubkey(args []string) int {
	if len(args) != 0 {
		fmt.Fprintln(os.Stderr, "sshgate pubkey: takes no arguments")
		return 2
	}
	root, err := configRoot()
	if err != nil {
		fmt.Fprintf(os.Stderr, "sshgate: %v\n", err)
		return 1
	}
	keyPath := filepath.Join(root, "ssh", "sshgate_ed25519")
	line, err := tools.EnsureSSHGateKeypair(keyPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "sshgate: %v\n", err)
		return 1
	}
	// The bare key line goes to stdout so it can be piped/copied cleanly.
	fmt.Fprintln(os.Stdout, line)
	// The next-step hint goes to stderr so it never contaminates a pipe.
	fmt.Fprintln(os.Stderr, "")
	fmt.Fprintln(os.Stderr, "Next steps:")
	fmt.Fprintln(os.Stderr, "  1. Paste the line above into the TARGET server's ~/.ssh/authorized_keys")
	fmt.Fprintln(os.Stderr, "     (plain, on its own line — you administer that box out-of-band).")
	fmt.Fprintln(os.Stderr, "  2. Run: sshgate add <alias> <user@host>[:port] [--read-only]")
	fmt.Fprintln(os.Stderr, "     SSHGate will install the gate and lock this key down.")
	return 0
}

// runAdd implements `sshgate add <alias> <user@host>[:port] [--read-only|--ro]`.
func runAdd(args []string) int {
	var (
		positional []string
		readOnly   bool
	)
	for _, a := range args {
		switch a {
		case "--read-only", "--ro":
			readOnly = true
		case "-h", "--help":
			fmt.Fprintln(os.Stdout, "usage: sshgate add <alias> <user@host>[:port] [--read-only|--ro]")
			return 0
		default:
			if strings.HasPrefix(a, "-") {
				fmt.Fprintf(os.Stderr, "sshgate add: unknown flag %q\n", a)
				return 2
			}
			positional = append(positional, a)
		}
	}
	if len(positional) != 2 {
		fmt.Fprintln(os.Stderr, "usage: sshgate add <alias> <user@host>[:port] [--read-only|--ro]")
		return 2
	}
	alias := positional[0]
	user, host, port, err := parseUserHostPort(positional[1])
	if err != nil {
		fmt.Fprintf(os.Stderr, "sshgate add: %v\n", err)
		return 2
	}

	root, err := configRoot()
	if err != nil {
		fmt.Fprintf(os.Stderr, "sshgate: %v\n", err)
		return 1
	}
	cfg := provisionConfig(root)

	out, err := tools.Provision(context.Background(), cfg, tools.ProvisionInput{
		Alias:    alias,
		Host:     host,
		Port:     port,
		User:     user,
		ReadOnly: readOnly,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "sshgate add: %v\n", err)
		return 1
	}

	mode := "signed-write (tier-2)"
	if out.ReadOnlyMode {
		mode = "read-only (tier-1)"
	}
	fmt.Fprintf(os.Stdout, "added %q\n", out.Alias)
	fmt.Fprintf(os.Stdout, "  host:        %s\n", out.Host)
	fmt.Fprintf(os.Stdout, "  port:        %d\n", out.Port)
	fmt.Fprintf(os.Stdout, "  user:        %s\n", out.User)
	fmt.Fprintf(os.Stdout, "  fingerprint: %s\n", out.Fingerprint)
	fmt.Fprintf(os.Stdout, "  gate:        %s\n", out.BinaryPath)
	fmt.Fprintf(os.Stdout, "  verified:    %t\n", out.VerifiedOK)
	fmt.Fprintf(os.Stdout, "  mode:        %s\n", mode)
	if out.Idempotent {
		fmt.Fprintf(os.Stdout, "  idempotent:  true (restricted entry already present; verify + register only)\n")
		if !out.ReadOnlyMode {
			// Spec §2.4: on an idempotent Tier-2 re-add genkeys is deliberately
			// skipped (no clobber) — tell the operator how to (re)key.
			fmt.Fprintf(os.Stdout, "  transfer:    keys were NOT (re)generated on the already-gated host; run `sshgate xfer-rotate %s` to (re)key for transfers\n", out.Alias)
		}
	}

	// Transfer-key registration leg (Tier-2 fresh add only — XferBoxPub is "" on a
	// Tier-1 or idempotent add). The keys were generated on the host by genkeys;
	// register their PUBLIC halves with the signer under the SAME fingerprint the
	// legs bind to. A denied/timed-out/lost tap must NOT orphan a correctly-added
	// server — surface an actionable retry and still return 0.
	if !out.ReadOnlyMode && out.XferBoxPub != "" {
		fmt.Fprintln(os.Stdout, "transfer keys generated on host; registering with the signer…")
		fmt.Fprintf(os.Stdout, "  box: %s\n", out.XferBoxPub)
		fmt.Fprintf(os.Stdout, "  id:  %s\n", out.XferIDPub)
		// Default label = alias, clamped to the friendly CLI cap so a long alias
		// can't bounce off the daemon's authoritative 64-byte label check
		// (mirrors runXferRegister; the label is display-only).
		label := out.Alias
		if len(label) > maxXferLabelLen {
			label = label[:maxXferLabelLen]
		}
		if rerr := registerWithSigner(context.Background(), out.Fingerprint, label, out.XferBoxPub, out.XferIDPub); rerr != nil {
			fmt.Fprintf(os.Stdout, "  transfer:    NOT registered (%s)\n", describeSignerError(rerr))
			fmt.Fprintln(os.Stdout, "The server is added; to enable transfers, re-run:")
			fmt.Fprintf(os.Stdout, "  sshgate xfer-register %s --box-pub '%s' --id-pub '%s'\n", out.Alias, out.XferBoxPub, out.XferIDPub)
			return 0
		}
		fmt.Fprintf(os.Stdout, "  transfer:    registered (label %q)\n", label)
	}
	return 0
}

// parseUserHostPort parses "user@host[:port]" into its parts. Port defaults to
// 22. IPv6 literals are not bracket-handled here (the registry/host validator
// accepts bare IPv6, but ":port" parsing on a bare IPv6 is ambiguous — use a
// hostname or IPv4 for now, matching the MCP add surface).
func parseUserHostPort(s string) (user, host string, port int, err error) {
	at := strings.IndexByte(s, '@')
	if at <= 0 || at == len(s)-1 {
		return "", "", 0, fmt.Errorf("target %q is not user@host[:port]", s)
	}
	user = s[:at]
	hostPort := s[at+1:]
	port = 22
	if colon := strings.LastIndexByte(hostPort, ':'); colon != -1 {
		host = hostPort[:colon]
		portStr := hostPort[colon+1:]
		p, perr := strconv.Atoi(portStr)
		if perr != nil || p < 1 || p > 65535 {
			return "", "", 0, fmt.Errorf("invalid port %q in target %q", portStr, s)
		}
		port = p
	} else {
		host = hostPort
	}
	if host == "" {
		return "", "", 0, fmt.Errorf("target %q has an empty host", s)
	}
	return user, host, port, nil
}

// gateBinaryPath resolves the cross-compiled gate binary, honouring the same
// $SSHGATE_GATE_BIN override the MCP resolver uses, then falling back to the
// stable <configRoot>/bin/ location `make install-local` writes to.
func gateBinaryPath(root string) string {
	if env := os.Getenv("SSHGATE_GATE_BIN"); env != "" {
		return env
	}
	return filepath.Join(root, "bin", "sshgate-gate-linux-amd64")
}

// configRoot returns the sshgate config root, honouring $XDG_CONFIG_HOME
// (default ~/.config), mirroring sshgate-mcp/main.go and the tools package.
func configRoot() (string, error) {
	if root := os.Getenv("XDG_CONFIG_HOME"); root != "" {
		return filepath.Join(root, "sshgate"), nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("resolve home dir: %w", err)
	}
	return filepath.Join(home, ".config", "sshgate"), nil
}
