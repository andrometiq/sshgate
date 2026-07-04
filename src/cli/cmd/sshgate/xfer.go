package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"

	"github.com/karthikeyan5/sshgate/src/mcp/registry"
	"github.com/karthikeyan5/sshgate/src/mcp/sign"
	"github.com/karthikeyan5/sshgate/src/mcp/tools"
	"github.com/karthikeyan5/sshgate/src/sigwire"
	"github.com/karthikeyan5/sshgate/src/xfer"
)

// This file holds the human-only box→box transfer CLI verbs: xfer-register,
// xfer-rotate, xfer-status. They live in the same human-only `sshgate` binary as
// `add` — deliberately OFF the agent/MCP surface, so an AI agent can never
// register a transfer key, rotate keys, or expand the transfer trust anchor.
//
// SECURITY invariants this file upholds:
//   - The fingerprint a key is registered under is read ONLY from provisioning
//     state (servers.json Entry.Fingerprint) — never re-derived, never
//     operator-supplied. That string is the registry key AND the leg Host binding.
//   - Registration ALWAYS prompts a human (the signer routes register_xfer_key
//     through a Telegram tap); the CLI interprets a denied/timeout/lost verdict
//     HONESTLY and never claims success, and never silently orphans a server.
//   - Private key material never appears here — the CLI handles only the two
//     PUBLIC lines and the fingerprint.

// maxXferLabelLen is the friendly CLI-side label cap. The daemon enforces the
// authoritative cap (signer.maxXferLabelLen = 64); this rejects an over-long
// label before spending a round-trip / human tap. Keep the two in lockstep.
const maxXferLabelLen = 64

// registerXferKey is the signer-registration seam. Production dials a real
// sign.Client; tests inject a fake so runAdd / runXferRegister never touch a real
// socket. Mirrors the newBootstrapSession seam pattern in tools. Timeout matches
// the MCP's (it must exceed the daemon's human-approval budget — register blocks
// on a Telegram tap).
var registerXferKey = func(ctx context.Context, sockPath, reqID string, req sign.RegisterXferKeyReq) error {
	client := sign.Client{SocketPath: sockPath, Timeout: sigwire.ClientSignTimeout}
	return client.RegisterXferKey(ctx, reqID, req)
}

// xferKeysOnHost is the host-probe seam for xfer-status (tests inject a fake to
// avoid a real dial). Production probes the live gate over SSH.
var xferKeysOnHost = tools.XferKeysOnHost

// signerSockPath resolves the signer socket path, honouring $SSHGATE_SIGNER_SOCK
// (mirrors the MCP resolver) then falling back to the packaged default.
func signerSockPath() string {
	if s := os.Getenv("SSHGATE_SIGNER_SOCK"); s != "" {
		return s
	}
	return "/run/sshgatesigner/sock"
}

// newRequestID mints a fresh correlation id (16 random bytes hex). The signer
// only requires it non-empty + unique for correlation.
func newRequestID() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", fmt.Errorf("generate request id: %w", err)
	}
	return hex.EncodeToString(b[:]), nil
}

// provisionConfig builds the shared path set the provisioning + transfer verbs
// consult from the config root.
func provisionConfig(root string) tools.ProvisionConfig {
	return tools.ProvisionConfig{
		GateBinaryPath: gateBinaryPath(root),
		GatePubPath:    filepath.Join(root, "pubkey-distrib", "gate.pub"),
		SSHGateKeyPath: filepath.Join(root, "ssh", "sshgate_ed25519"),
		SSHGatePubPath: filepath.Join(root, "ssh", "sshgate_ed25519.pub"),
		KnownHostsPath: filepath.Join(root, "known_hosts"),
		ServersPath:    filepath.Join(root, "servers.json"),
	}
}

// serversPath returns the registry path under the config root.
func serversPath(root string) string { return filepath.Join(root, "servers.json") }

// lookupServer loads the registry and returns the entry for alias.
func lookupServer(root, alias string) (registry.Entry, error) {
	reg, err := registry.New(serversPath(root))
	if err != nil {
		return registry.Entry{}, fmt.Errorf("registry: %w", err)
	}
	e, ok := reg.Get(alias)
	if !ok {
		return registry.Entry{}, fmt.Errorf("alias %q is not registered", alias)
	}
	return e, nil
}

// describeSignerError maps a signer/dial error to an actionable one-liner. The
// two dial conditions match what the MCP already documents.
func describeSignerError(err error) string {
	switch {
	case errors.Is(err, sign.ErrSignerPermission):
		return "cannot reach the signer socket (permission denied) — your shell is not in the sshgatesigner group; log out/in and retry, or run this on the machine where the signer is installed"
	case errors.Is(err, sign.ErrUnreachable):
		return fmt.Sprintf("signer socket not reachable at %s — is the signer installed on this machine? (transfers require a Tier-2 signer)", signerSockPath())
	case errors.Is(err, sign.ErrVerdictUnknown):
		return "the signer decided but the response did not arrive — a human may have DENIED it; check the Telegram thread before retrying (do NOT assume success)"
	case errors.Is(err, sign.ErrDenied):
		return "registration DENIED by the operator"
	case errors.Is(err, sign.ErrTimeout):
		return "registration timed out waiting for the operator's approval"
	default:
		return err.Error()
	}
}

// registerWithSigner dials the signer (via the seam) and requests a
// register_xfer_key for fp/label/boxPub/idPub. It returns the raw sign error so
// the caller can interpret approved/denied/etc. honestly.
func registerWithSigner(ctx context.Context, fp, label, boxPub, idPub string) error {
	reqID, err := newRequestID()
	if err != nil {
		return err
	}
	return registerXferKey(ctx, signerSockPath(), reqID, sign.RegisterXferKeyReq{
		HostFP: fp, Label: label, BoxPub: boxPub, IDPub: idPub,
	})
}

// runXferRegister implements
// `sshgate xfer-register <alias> --box-pub '<line>' --id-pub '<line>' [--label <s>]`.
// It (re)sends register_xfer_key to the signer under the fp from servers.json —
// the standalone / recovery path (no host contact).
func runXferRegister(args []string) int {
	var (
		positional    []string
		boxPub, idPub string
		label         string
		labelSet      bool
	)
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch a {
		case "--box-pub":
			if i+1 >= len(args) {
				fmt.Fprintln(os.Stderr, "sshgate xfer-register: --box-pub requires a value")
				return 2
			}
			i++
			boxPub = args[i]
		case "--id-pub":
			if i+1 >= len(args) {
				fmt.Fprintln(os.Stderr, "sshgate xfer-register: --id-pub requires a value")
				return 2
			}
			i++
			idPub = args[i]
		case "--label":
			if i+1 >= len(args) {
				fmt.Fprintln(os.Stderr, "sshgate xfer-register: --label requires a value")
				return 2
			}
			i++
			label = args[i]
			labelSet = true
		case "-h", "--help":
			fmt.Fprintln(os.Stdout, "usage: sshgate xfer-register <alias> --box-pub '<line>' --id-pub '<line>' [--label <s>]")
			return 0
		default:
			if len(a) > 0 && a[0] == '-' {
				fmt.Fprintf(os.Stderr, "sshgate xfer-register: unknown flag %q\n", a)
				return 2
			}
			positional = append(positional, a)
		}
	}
	if len(positional) != 1 {
		fmt.Fprintln(os.Stderr, "usage: sshgate xfer-register <alias> --box-pub '<line>' --id-pub '<line>' [--label <s>]")
		return 2
	}
	if boxPub == "" || idPub == "" {
		fmt.Fprintln(os.Stderr, "sshgate xfer-register: both --box-pub and --id-pub are required")
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
		fmt.Fprintf(os.Stderr, "sshgate xfer-register: %v\n", err)
		return 1
	}
	if e.ReadOnly {
		fmt.Fprintf(os.Stderr, "sshgate xfer-register: server %q is read-only (Tier-1); transfers need a Tier-2 server\n", alias)
		return 1
	}
	// Validate the two lines locally BEFORE dialing — never spend a human tap on
	// a malformed line (mirrors the daemon's pre-prompt validation).
	if _, perr := xfer.ParseBoxPublicText(boxPub); perr != nil {
		fmt.Fprintf(os.Stderr, "sshgate xfer-register: invalid --box-pub line\n")
		return 2
	}
	if _, perr := xfer.ParseIDPublicText(idPub); perr != nil {
		fmt.Fprintf(os.Stderr, "sshgate xfer-register: invalid --id-pub line\n")
		return 2
	}
	if !labelSet || label == "" {
		label = alias
	}
	if len(label) > maxXferLabelLen {
		fmt.Fprintf(os.Stderr, "sshgate xfer-register: --label too long (max %d bytes)\n", maxXferLabelLen)
		return 2
	}

	fmt.Fprintf(os.Stdout, "registering transfer keys for %q (fp %s) with the signer…\n", alias, e.Fingerprint)
	if err := registerWithSigner(context.Background(), e.Fingerprint, label, boxPub, idPub); err != nil {
		fmt.Fprintf(os.Stderr, "sshgate xfer-register: %s\n", describeSignerError(err))
		return 1
	}
	fmt.Fprintf(os.Stdout, "registered (label %q)\n", label)
	return 0
}

// runXferRotate implements `sshgate xfer-rotate <alias> [user@host[:port]]`. It
// regenerates the host's transfer keys (over a re-opened plain bootstrap window)
// and re-registers them under the SAME fingerprint.
func runXferRotate(args []string) int {
	var positional []string
	for _, a := range args {
		switch a {
		case "-h", "--help":
			fmt.Fprintln(os.Stdout, "usage: sshgate xfer-rotate <alias> [user@host[:port]]")
			return 0
		default:
			if len(a) > 0 && a[0] == '-' {
				fmt.Fprintf(os.Stderr, "sshgate xfer-rotate: unknown flag %q\n", a)
				return 2
			}
			positional = append(positional, a)
		}
	}
	if len(positional) < 1 || len(positional) > 2 {
		fmt.Fprintln(os.Stderr, "usage: sshgate xfer-rotate <alias> [user@host[:port]]")
		return 2
	}
	alias := positional[0]
	in := tools.RotateInput{Alias: alias}
	if len(positional) == 2 {
		user, host, port, err := parseUserHostPort(positional[1])
		if err != nil {
			fmt.Fprintf(os.Stderr, "sshgate xfer-rotate: %v\n", err)
			return 2
		}
		in.User, in.Host, in.Port = user, host, port
	}

	root, err := configRoot()
	if err != nil {
		fmt.Fprintf(os.Stderr, "sshgate: %v\n", err)
		return 1
	}
	cfg := provisionConfig(root)

	fmt.Fprintf(os.Stdout, "Rotating transfer keys for %q.\n", alias)
	fmt.Fprintln(os.Stdout, "  If the server is still locked, first remove the existing command=\"...\" line")
	fmt.Fprintln(os.Stdout, "  for the SSHGate key from its ~/.ssh/authorized_keys and paste `sshgate pubkey`'s")
	fmt.Fprintln(os.Stdout, "  plain line back (this re-opens the brief full-shell window), then re-run this.")

	out, err := tools.RotateXferKeys(context.Background(), cfg, in)
	if err != nil {
		fmt.Fprintf(os.Stderr, "sshgate xfer-rotate: %v\n", err)
		return 1
	}
	fmt.Fprintf(os.Stdout, "transfer keys regenerated on host; re-registering with the signer…\n")
	fmt.Fprintf(os.Stdout, "  box: %s\n", out.XferBoxPub)
	fmt.Fprintf(os.Stdout, "  id:  %s\n", out.XferIDPub)
	if err := registerWithSigner(context.Background(), out.Fingerprint, alias, out.XferBoxPub, out.XferIDPub); err != nil {
		fmt.Fprintf(os.Stderr, "sshgate xfer-rotate: keys rotated on host but registration NOT completed (%s).\n", describeSignerError(err))
		fmt.Fprintf(os.Stderr, "To finish, re-run:\n  sshgate xfer-register %s --box-pub '%s' --id-pub '%s'\n", alias, out.XferBoxPub, out.XferIDPub)
		return 1
	}
	fmt.Fprintf(os.Stdout, "  transfer:    re-registered (label %q)\n", alias)
	return 0
}

// runXferStatus implements `sshgate xfer-status [<alias>]`. It reports transfer
// readiness where the OPERATOR looks (the CLI), honouring "no new MCP surface".
// Per the P4 spec (MAJOR-1) it does NOT query the signer: it reports tier +
// fingerprint + a best-effort host key-presence probe, and states that
// registration is confirmed at register time (re-run xfer-register to re-confirm).
func runXferStatus(args []string) int {
	var positional []string
	for _, a := range args {
		switch a {
		case "-h", "--help":
			fmt.Fprintln(os.Stdout, "usage: sshgate xfer-status [<alias>]")
			return 0
		default:
			if len(a) > 0 && a[0] == '-' {
				fmt.Fprintf(os.Stderr, "sshgate xfer-status: unknown flag %q\n", a)
				return 2
			}
			positional = append(positional, a)
		}
	}
	if len(positional) > 1 {
		fmt.Fprintln(os.Stderr, "usage: sshgate xfer-status [<alias>]")
		return 2
	}

	root, err := configRoot()
	if err != nil {
		fmt.Fprintf(os.Stderr, "sshgate: %v\n", err)
		return 1
	}
	reg, err := registry.New(serversPath(root))
	if err != nil {
		fmt.Fprintf(os.Stderr, "sshgate xfer-status: registry: %v\n", err)
		return 1
	}

	var aliases []string
	if len(positional) == 1 {
		if _, ok := reg.Get(positional[0]); !ok {
			fmt.Fprintf(os.Stderr, "sshgate xfer-status: alias %q is not registered\n", positional[0])
			return 1
		}
		aliases = []string{positional[0]}
	} else {
		for a := range reg.List() {
			aliases = append(aliases, a)
		}
		sort.Strings(aliases)
	}

	cfg := provisionConfig(root)
	fmt.Fprintf(os.Stdout, "%-14s %-8s %-14s %s\n", "alias", "tier", "keys-on-host", "fingerprint")
	for _, alias := range aliases {
		e, ok := reg.Get(alias)
		if !ok {
			continue
		}
		tier := "tier-2"
		keys := "unknown"
		if e.ReadOnly {
			tier = "tier-1"
			keys = "n/a" // a read-only gate never holds transfer keys
		} else {
			present, reachable := xferKeysOnHost(context.Background(), cfg, alias)
			switch {
			case !reachable:
				keys = "unknown"
			case present:
				keys = "yes"
			default:
				keys = "no"
			}
		}
		fmt.Fprintf(os.Stdout, "%-14s %-8s %-14s %s\n", alias, tier, keys, e.Fingerprint)
	}
	fmt.Fprintln(os.Stdout, "")
	fmt.Fprintln(os.Stdout, "registered: confirmed at registration time — re-run `sshgate xfer-register <alias>`")
	fmt.Fprintln(os.Stdout, "            (or `sshgate xfer-rotate <alias>`) to re-confirm; overwrite is safe.")
	return 0
}
