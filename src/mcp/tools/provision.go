package tools

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/karthikeyan5/sshgate/src/mcp/registry"
	sshpkg "github.com/karthikeyan5/sshgate/src/mcp/ssh"
	"github.com/karthikeyan5/sshgate/src/xfer"
)

// This file implements the HUMAN-ONLY CLI provisioning path (the `sshgate`
// binary's `pubkey` and `add` subcommands). It lives in the tools package so
// it can reuse the shared auto-setup machinery — runAutoSetup,
// rewriteAuthorizedKeys, hasRestrictedEntryForKey, the backup + rollback, and
// the bootstrapSession seam — rather than duplicating any of it.
//
// Provision dials with the SSHGate dedicated key itself — the human has
// already pasted its PLAIN public key into the target's authorized_keys
// out-of-band — and the rewrite REPLACES that same key's plain line with the
// restricted forced-command line, locking the key down. From then on the key
// is gated. rewriteAuthorizedKeys removes ANY line matching the key (plain or
// restricted) and re-emits exactly one restricted line, so the
// plain→restricted replacement falls out for free.

// EnsureSSHGateKeypair makes sure the SSHGate dedicated ed25519 keypair exists
// at keyPath (private, mode 0600) and keyPath+".pub" (mode 0644), generating
// it if absent. The parent directory is created mode 0700. It returns the
// bare authorized_keys public-key LINE (e.g. "ssh-ed25519 AAAA... sshgate-dedicated")
// with no trailing newline — this is exactly what the human pastes into a
// target server's ~/.ssh/authorized_keys.
//
// Idempotent: if the private key already exists, it is parsed (not
// regenerated) and its public half is returned; a missing or stale .pub is
// re-derived from the private key. No sudo, no key rotation.
func EnsureSSHGateKeypair(keyPath string) (string, error) {
	dir := filepath.Dir(keyPath)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", fmt.Errorf("mkdir %s: %w", dir, err)
	}

	// Existing key: parse and return its public half (idempotent).
	if body, err := os.ReadFile(keyPath); err == nil {
		signer, perr := ssh.ParsePrivateKey(body)
		if perr != nil {
			return "", fmt.Errorf("parse existing key %s: %w", keyPath, perr)
		}
		return ensurePubFile(keyPath, signer.PublicKey())
	} else if !errors.Is(err, fs.ErrNotExist) {
		return "", fmt.Errorf("read %s: %w", keyPath, err)
	}

	// Generate a fresh ed25519 keypair (matches `ssh-keygen -t ed25519 -C
	// sshgate-dedicated` the setup flow used to shell out to).
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return "", fmt.Errorf("generate ed25519 key: %w", err)
	}
	block, err := ssh.MarshalPrivateKey(priv, "sshgate-dedicated")
	if err != nil {
		return "", fmt.Errorf("marshal private key: %w", err)
	}
	// Write the private key with 0600 from creation (O_EXCL so we never
	// clobber a key that appeared between the stat and the write).
	f, err := os.OpenFile(keyPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return "", fmt.Errorf("create %s: %w", keyPath, err)
	}
	if _, err := f.Write(pem.EncodeToMemory(block)); err != nil {
		f.Close()
		return "", fmt.Errorf("write %s: %w", keyPath, err)
	}
	if err := f.Close(); err != nil {
		return "", fmt.Errorf("close %s: %w", keyPath, err)
	}

	sshPub, err := ssh.NewPublicKey(pub)
	if err != nil {
		return "", fmt.Errorf("derive public key: %w", err)
	}
	return ensurePubFile(keyPath, sshPub)
}

// ensurePubFile writes the OpenSSH-format public-key line for pub to
// keyPath+".pub" (mode 0644) with the canonical "sshgate-dedicated" comment,
// and returns the line (trimmed of the trailing newline).
func ensurePubFile(keyPath string, pub ssh.PublicKey) (string, error) {
	// MarshalAuthorizedKey emits "ssh-ed25519 AAAA...\n" with no comment;
	// append the canonical comment so the pasted line is self-describing.
	raw := strings.TrimRight(string(ssh.MarshalAuthorizedKey(pub)), "\n")
	line := raw + " sshgate-dedicated"
	if err := os.WriteFile(keyPath+".pub", []byte(line+"\n"), 0o644); err != nil {
		return "", fmt.Errorf("write %s.pub: %w", keyPath, err)
	}
	return line, nil
}

// hasPlainLineForKey reports whether existing contains a line for pubkey that
// is NOT the canonical restricted forced-command entry — i.e. a plain
// (unrestricted) duplicate of the SSHGate key that the rewrite must remove.
// Used by Provision's tests to assert the plain line is gone after the
// rewrite, and a useful internal invariant.
func hasPlainLineForKey(existing []byte, pubkey ssh.PublicKey) bool {
	if pubkey == nil {
		return false
	}
	wantBytes := pubkey.Marshal()
	wantPrefix := fmt.Sprintf(commandForcingFmt, remoteGateBin)

	sc := bufio.NewScanner(bytes.NewReader(existing))
	buf := make([]byte, 0, 256*1024)
	sc.Buffer(buf, 1024*1024)
	for sc.Scan() {
		line := sc.Text()
		if !lineMatchesKey(line, wantBytes) {
			continue
		}
		if !strings.HasPrefix(line, wantPrefix) {
			return true
		}
	}
	return false
}

// provisionCfg gathers the local paths the CLI consults. Unlike addServerCfg
// (which leans on the Runner's wired SSH client + registry), Provision is a
// standalone entry point invoked by the `sshgate` binary, so it carries every
// path it needs explicitly. The binary's command layer fills these from
// configRoot()/$XDG_CONFIG_HOME before calling Provision.
type provisionCfg struct {
	// GateBinaryPath is the local cross-compiled gate binary
	// (sshgate-gate-linux-amd64).
	GateBinaryPath string
	// GatePubPath is the local signer public key (pubkey-distrib/gate.pub).
	// Required for write (tier-2) adds; ignored for --read-only.
	GatePubPath string
	// SSHGateKeyPath is the SSHGate dedicated PRIVATE key — the credential
	// the CLI dials with (mode 0600).
	SSHGateKeyPath string
	// SSHGatePubPath is the SSHGate dedicated PUBLIC key, used to locate +
	// rewrite the pasted plain line into the restricted line.
	SSHGatePubPath string
	// KnownHostsPath is the TOFU known_hosts store (shared with the MCP).
	KnownHostsPath string
	// ServersPath is the registry the CLI writes (the SAME servers.json the
	// MCP reads).
	ServersPath string
}

// ProvisionConfig is the exported alias the binary uses to build a provisionCfg.
type ProvisionConfig = provisionCfg

// ProvisionInput is the parsed `sshgate add` request.
type ProvisionInput struct {
	Alias    string
	Host     string
	Port     int
	User     string
	ReadOnly bool
}

// ProvisionOutput summarises a successful `sshgate add`.
type ProvisionOutput struct {
	Alias        string
	Host         string
	Port         int
	User         string
	Fingerprint  string
	BinaryPath   string
	VerifiedOK   bool
	Idempotent   bool
	ReadOnlyMode bool
	// XferBoxPub / XferIDPub are the canonical box/id transfer PublicText lines
	// generated on the host by `gate genkeys` during a fresh Tier-2 add (parsed +
	// validated from the readback). Both are "" on a Tier-1 or idempotent add
	// (genkeys is skipped there). The CLI reads them off this struct and registers
	// them with the signer under Fingerprint. Additive fields (keyed literals) —
	// no breakage.
	XferBoxPub string
	XferIDPub  string
	// TierNote is a loud, human-facing NOTE set ONLY on an idempotent re-add
	// whose --read-only flag disagreed with the gate's self-reported tier (#62):
	// the registry was reconciled to host truth and the note explains the
	// override + how to actually change the tier. Empty on every other add
	// (fresh, or idempotent with matching/absent tier). The CLI prints it.
	TierNote string
}

// Provision is the human-only CLI add. It dials the target with the SSHGate
// dedicated key (the human pasted its plain public key first), installs the
// gate, rewrites the pasted plain line into the restricted forced-command
// line (locking the key down), verifies, and registers the alias.
//
// The auto-setup + rollback machinery is invoked via a throwaway Runner
// (runAutoSetup / rollback / rollbackPartial are methods on Runner that touch
// no Runner state). The flow:
//
//  1. Validate (alias regex, not-already-registered).
//  2. Read local materials (gate binary; gate.pub for tier-2; sshgate pubkey).
//  3. Dial the target using the SSHGate PRIVATE key (same TOFU known_hosts).
//  4. If the restricted entry already exists → idempotent (verify+register).
//  5. Else upload gate (+gate.pub for tier-2), back up authorized_keys, and
//     rewrite the plain sshgate line → restricted line.
//  6. Verify by RE-DIALING (the key is now gated → empty cmd → SSHGATE_OK).
//  7. Register the alias in servers.json.
//
// Any failure after authorized_keys is modified rolls back to the backup.
func Provision(ctx context.Context, cfg provisionCfg, in ProvisionInput) (ProvisionOutput, error) {
	if !aliasPattern.MatchString(in.Alias) {
		return ProvisionOutput{}, fmt.Errorf("invalid alias %q (must match %s)", in.Alias, aliasPattern)
	}
	if err := validateHost(in.Host); err != nil {
		return ProvisionOutput{}, err
	}
	if err := validateUser(in.User); err != nil {
		return ProvisionOutput{}, err
	}
	port := in.Port
	if port == 0 {
		port = 22
	}

	servers, err := registry.New(cfg.ServersPath)
	if err != nil {
		return ProvisionOutput{}, fmt.Errorf("registry: %w", err)
	}
	if _, exists := servers.Get(in.Alias); exists {
		return ProvisionOutput{}, fmt.Errorf("alias %q already registered — de-provision it first: for a signed-write (Tier-2) server the agent can tear it down with /sshgate:revoke %s; a read-only (Tier-1) gate has no signer pubkey so a signed remote revoke cannot run — remove its entry from the local registry (%s) by hand (and strip SSHGate's forced command=\"...\" line from the host's ~/.ssh/authorized_keys) before re-adding. Run `sshgate revoke %s` for the exact copy-pasteable strip + local-forget steps (print-only; it changes nothing)", in.Alias, in.Alias, cfg.ServersPath, in.Alias)
	}

	// Read local materials before touching the remote so we fail fast.
	gateBin, err := readLocalFile(cfg.GateBinaryPath, "gate binary",
		"run `make install-local` to install the committed, CI-verified sshgate-gate-linux-amd64 (copied from dist/gate/, never rebuilt) into ~/.config/sshgate/bin/")
	if err != nil {
		return ProvisionOutput{}, err
	}
	var gatePubBytes []byte
	if !in.ReadOnly {
		gatePubBytes, err = readLocalFile(cfg.GatePubPath, "gate signing public key",
			"no signer pubkey found; run /sshgate:setup tier-2 to generate it, or pass --read-only")
		if err != nil {
			return ProvisionOutput{}, err
		}
	}
	sshgatePubBytes, err := readLocalFile(cfg.SSHGatePubPath, "SSHGate dedicated SSH public key",
		"run `sshgate pubkey` first to generate it")
	if err != nil {
		return ProvisionOutput{}, err
	}
	sshgatePub, _, _, _, err := ssh.ParseAuthorizedKey(sshgatePubBytes)
	if err != nil {
		return ProvisionOutput{}, fmt.Errorf("parse %s: %w", cfg.SSHGatePubPath, err)
	}

	// Dial using the SSHGate dedicated key. We reuse bootstrapAuthMethod's
	// key-file branch (it enforces 0600) and the SAME TOFU known_hosts the
	// MCP uses, so the host-key pin is shared.
	auth, err := bootstrapAuthMethod(AddServerInput{BootstrapKeyPath: cfg.SSHGateKeyPath})
	if err != nil {
		return ProvisionOutput{}, fmt.Errorf("load SSHGate key %s: %w", cfg.SSHGateKeyPath, err)
	}
	if cfg.KnownHostsPath == "" {
		return ProvisionOutput{}, errors.New("known_hosts path is empty; cannot pin host key")
	}
	bootCfg := &ssh.ClientConfig{
		User:            in.User,
		Auth:            []ssh.AuthMethod{auth},
		HostKeyCallback: sshpkg.TOFU(cfg.KnownHostsPath),
		Timeout:         bootstrapDialTimeout,
	}

	dialCtx, cancel := context.WithTimeout(ctx, bootstrapDialTimeout)
	defer cancel()
	bootSess, hostFingerprint, err := newBootstrapSession(dialCtx, in.Host, port, bootCfg)
	if err != nil {
		// The human probably hasn't pasted `sshgate pubkey`'s output into
		// the target's authorized_keys yet — or the line is already locked
		// down / wrong. Surface that rather than the bare SSH error.
		if strings.Contains(err.Error(), "unable to authenticate") {
			return ProvisionOutput{}, fmt.Errorf(
				"SSH auth to %s@%s:%d with the SSHGate key failed — paste the `sshgate pubkey` output into %s's ~/.ssh/authorized_keys first (or the line is already locked down / wrong): %w",
				in.User, in.Host, port, in.Host, err)
		}
		return ProvisionOutput{}, fmt.Errorf("dial %s@%s:%d with the SSHGate key: %w", in.User, in.Host, port, err)
	}
	defer bootSess.Close()

	// Idempotency, probe FIRST: send the unsigned SSHGATE_VERSION verb on the
	// dedicated-key connection we just authenticated. If a live gate answers,
	// the host is by construction already provisioned for THIS key — the only
	// way the verb reaches a gate is through the forced-command line bound to
	// the key we dialed with — so skip install/rewrite and just verify +
	// register (a lost servers.json is the main reason a human re-adds).
	//
	// Reading authorized_keys THROUGH the gate can never detect this case:
	// the read's `2>/dev/null` redirect classifies as an unsigned write (gate
	// exit 77 — the bug this closes), and even as a pure read the gate's
	// output redactor scrubs the key base64 that hasRestrictedEntryForKey
	// matches on. "A gate answered on this key" is a strictly stronger signal
	// than parsing authorized_keys, with no classifier/redactor in the loop.
	//
	// A stray PLAIN duplicate of the key cannot hide behind this probe: sshd
	// uses the FIRST authorized_keys line matching the offered key, so either
	// the restricted line wins (the plain duplicate is unreachable for this
	// key) or the plain line wins (a bare shell fails the verb) and the
	// fallback below forces the rewrite that removes it.
	idempotent, probedTier := probeGateVersion(ctx, bootSess)

	// No gate answered → not already provisioned for this key (plain shell),
	// or a half-provisioned/broken gate — which deliberately falls through so
	// the fresh flow surfaces its error unchanged. The authorized_keys read
	// below runs on a PLAIN shell in the fresh case (no classifier/redactor
	// in play). Skip the rewrite ONLY when the canonical restricted entry
	// is present AND there is no stray PLAIN duplicate of the same key. If a
	// plain line coexists with the restricted one (the human pasted twice, or
	// a prior partial run left both), treating the host as "already set up"
	// would leave that plain line live — a FULL-SHELL credential — while the
	// server registers as verified. Forcing the rewrite path in that case
	// removes ALL lines matching the key (plain and restricted) and re-emits
	// exactly one restricted line, closing the gap.
	var existing []byte
	if !idempotent {
		existing, _, err = bootSess.Run(ctx, "cat "+remoteAuthKeys+" 2>/dev/null || true")
		if err != nil {
			return ProvisionOutput{}, fmt.Errorf("read authorized_keys: %w", err)
		}
		idempotent = hasRestrictedEntryForKey(existing, sshgatePub, remoteGateBin) &&
			!hasPlainLineForKey(existing, sshgatePub)
	}

	// runAutoSetup / rollback are methods on Runner but touch no Runner
	// state — a zero Runner is a safe shared host for them.
	var r Runner
	if !idempotent {
		if err := r.runAutoSetup(ctx, bootSess, gateBin, gatePubBytes, sshgatePub, existing); err != nil {
			return ProvisionOutput{}, err
		}
	}

	// On-host transfer-key generation (Tier-2 fresh add only). The gate binary is
	// now installed and bootSess is STILL the plain shell (authenticated by the
	// pre-rewrite pasted line — sshd does not re-evaluate authorized_keys
	// mid-session), so `gate genkeys` reaches the human-only ARGV subcommand. Only
	// the two PUBLIC lines cross the wire; the private halves are Saved 0600 on the
	// host and never leave it. Tier-1 skips this (a read-only gate can never run
	// the signed SEND/RECV legs, so transfer keys would be dead weight); the
	// idempotent path skips it too (the host is already gated — no plain shell, and
	// clobbering live keys is wrong; `sshgate xfer-rotate` handles re-keying).
	var boxPubLine, idPubLine string
	if !idempotent && !in.ReadOnly {
		out, _, gerr := bootSess.Run(ctx, remoteGateBin+" genkeys")
		if gerr != nil {
			return ProvisionOutput{}, provisionRollback(ctx, &r, bootSess, existing, in.User, in.Host,
				fmt.Errorf("generate transfer keys: %w", gerr))
		}
		boxPubLine, idPubLine, gerr = parseGenKeysReadback(out)
		if gerr != nil {
			return ProvisionOutput{}, provisionRollback(ctx, &r, bootSess, existing, in.User, in.Host, gerr)
		}
	}

	// Verify by RE-DIALING with the (now gated) SSHGate key. The MCP routes
	// this through r.SSH; the CLI re-dials via the same seam. An empty cmd
	// triggers gate's SSHGATE_OK probe path.
	if err := verifyProvision(ctx, in.Host, port, bootCfg); err != nil {
		if !idempotent {
			return ProvisionOutput{}, provisionRollback(ctx, &r, bootSess, existing, in.User, in.Host, err)
		}
		return ProvisionOutput{}, err
	}

	// #62 tier-reconcile. On an idempotent (already-gated) re-add where the gate
	// answered SSHGATE_VERSION with a tier= token, the HOST is the source of truth
	// for the tier: gate.pub presence is what the gate actually enforces, and it
	// may have been changed out-of-band since the alias was first registered.
	// Follow it — register the probed tier — and if the caller's --read-only flag
	// disagreed, carry a loud NOTE (printed by the CLI) that the flag was
	// overridden. An old gate that omits tier= (probedTier=="") keeps the current
	// faith-based behavior: the caller's flag stands (backward-compat). A fresh
	// (non-idempotent) add has no host tier to reconcile against yet, so its flag
	// also stands.
	effectiveReadOnly := in.ReadOnly
	var tierNote string
	if idempotent && probedTier != "" {
		hostReadOnly := probedTier == "ro"
		if hostReadOnly != in.ReadOnly {
			tierNote = tierReconcileNote(in.Alias, hostReadOnly, in.ReadOnly)
			effectiveReadOnly = hostReadOnly
		}
	}

	if err := servers.Add(in.Alias, registry.Entry{
		Host:    in.Host,
		Port:    port,
		User:    in.User,
		AddedAt: time.Now().UTC(),
		// Persist the TOFU-pinned host-key fingerprint captured on the dial so
		// the MCP can later bind sign requests to this exact host (the gate
		// enforces the binding). Sourced here, in provisioning, never from the
		// agent.
		Fingerprint: hostFingerprint,
		ReadOnly:    effectiveReadOnly,
	}); err != nil {
		if !idempotent {
			return ProvisionOutput{}, provisionRollback(ctx, &r, bootSess, existing, in.User, in.Host,
				fmt.Errorf("registry add: %w", err))
		}
		return ProvisionOutput{}, fmt.Errorf("registry add: %w", err)
	}

	return ProvisionOutput{
		Alias:        in.Alias,
		Host:         in.Host,
		Port:         port,
		User:         in.User,
		Fingerprint:  hostFingerprint,
		BinaryPath:   remoteGateBin,
		VerifiedOK:   true,
		Idempotent:   idempotent,
		ReadOnlyMode: effectiveReadOnly,
		XferBoxPub:   boxPubLine,
		XferIDPub:    idPubLine,
		TierNote:     tierNote,
	}, nil
}

// tierReconcileNote is the loud NOTE surfaced (and printed by the CLI) on an
// idempotent re-add whose --read-only flag disagreed with the gate's
// self-reported tier (#62). The registry follows host truth — gate.pub presence
// is the enforcement point, not the registry flag — so the note tells the
// operator the flag was overridden and how to actually change the tier if that
// was the intent.
func tierReconcileNote(alias string, hostReadOnly, flagReadOnly bool) string {
	tierName := func(ro bool) string {
		if ro {
			return "read-only (Tier-1)"
		}
		return "signed-write (Tier-2)"
	}
	flagDesc := "you did not pass --read-only"
	if flagReadOnly {
		flagDesc = "you passed --read-only"
	}
	return fmt.Sprintf(
		"NOTE: %q is already provisioned %s on the host, but %s. Registering it as %s to match host truth — the gate (gate.pub presence) is the enforcement point, not the registry flag. %s",
		alias, tierName(hostReadOnly), flagDesc, tierName(hostReadOnly), retierManualPath(alias))
}

// parseGenKeysReadback extracts the two canonical PUBLIC transfer-key lines from
// a `gate genkeys` stdout readback. It tolerates motd/banner noise BEFORE the
// BEGIN marker, requires exactly one box line and one id line between the
// markers, and VALIDATES each through xfer.ParseBoxPublicText/ParseIDPublicText
// so a malformed line is a hard error (the CLI never registers an unvalidated
// line). It returns the raw canonical text lines (the signer re-parses them).
//
// It lives in tools (next to Provision) so the genkeys bootSess.Run stays private
// to this package; the CLI reads the parsed lines off ProvisionOutput. It depends
// only on src/xfer (stdlib + x/crypto), so there is no import cycle.
func parseGenKeysReadback(stdout []byte) (boxLine, idLine string, err error) {
	const (
		beginMarker  = "SSHGATE_XFER_PUBKEYS_BEGIN"
		endMarker    = "SSHGATE_XFER_PUBKEYS_END"
		boxTagPrefix = "sshgate-xfer-box-x25519 "
		idTagPrefix  = "sshgate-xfer-id-ed25519 "
	)
	lines := strings.Split(string(stdout), "\n")
	begin := -1
	for i, l := range lines {
		if strings.TrimRight(l, "\r") == beginMarker {
			begin = i
			break
		}
	}
	if begin == -1 {
		return "", "", errors.New("gate did not return transfer pubkeys (is this an older gate?)")
	}
	end := -1
	for i := begin + 1; i < len(lines); i++ {
		if strings.TrimRight(lines[i], "\r") == endMarker {
			end = i
			break
		}
	}
	if end == -1 {
		return "", "", errors.New("gate did not return transfer pubkeys (is this an older gate?)")
	}
	for i := begin + 1; i < end; i++ {
		line := strings.TrimRight(lines[i], "\r")
		if line == "" {
			continue
		}
		switch {
		case strings.HasPrefix(line, boxTagPrefix):
			if boxLine != "" {
				return "", "", errors.New("gate returned more than one box transfer pubkey")
			}
			boxLine = line
		case strings.HasPrefix(line, idTagPrefix):
			if idLine != "" {
				return "", "", errors.New("gate returned more than one id transfer pubkey")
			}
			idLine = line
		default:
			return "", "", errors.New("unexpected line in transfer pubkey block")
		}
	}
	if boxLine == "" || idLine == "" {
		return "", "", errors.New("gate did not return both transfer pubkeys")
	}
	// Validate BEFORE returning — never register an unvalidated line.
	if _, perr := xfer.ParseBoxPublicText(boxLine); perr != nil {
		return "", "", fmt.Errorf("invalid box transfer pubkey: %w", perr)
	}
	if _, perr := xfer.ParseIDPublicText(idLine); perr != nil {
		return "", "", fmt.Errorf("invalid id transfer pubkey: %w", perr)
	}
	return boxLine, idLine, nil
}

// RotateInput is the parsed `sshgate xfer-rotate` request. Alias is required;
// User/Host/Port optionally override the registry (empty = use servers.json).
type RotateInput struct {
	Alias string
	User  string
	Host  string
	Port  int
}

// RotateOutput carries the fingerprint the caller must re-register under (the
// SAME servers.json fingerprint — rotation never changes host identity) and the
// two freshly-generated PUBLIC transfer lines.
type RotateOutput struct {
	Alias       string
	Fingerprint string
	XferBoxPub  string
	XferIDPub   string
}

// RotateXferKeys rotates an already-provisioned Tier-2 host's box→box transfer
// keys and returns the two new PUBLIC lines for the CLI to re-register. Because a
// provisioned host is gated (no plain shell), rotation REQUIRES the operator to
// have re-opened the plain bootstrap window first (remove the old forced-command
// line for the SSHGate key and re-paste `sshgate pubkey`'s plain line), exactly
// like the accepted window of a fresh add. This function refuses to proceed if a
// gate still answers (the forced command is active → `gate genkeys` argv is
// unreachable), telling the operator how to open the window — it never silently
// rotates against a gated shell. It does NOT mutate servers.json (fp unchanged).
//
// SECURITY: the captured host fingerprint is asserted equal to the stored one —
// a mismatch means the host key changed and rotation aborts (never rotate
// against a new identity). The private halves are Saved 0600 on the host by
// `gate genkeys --rotate`; only the two PUBLIC lines cross the wire.
func RotateXferKeys(ctx context.Context, cfg provisionCfg, in RotateInput) (RotateOutput, error) {
	servers, err := registry.New(cfg.ServersPath)
	if err != nil {
		return RotateOutput{}, fmt.Errorf("registry: %w", err)
	}
	e, ok := servers.Get(in.Alias)
	if !ok {
		return RotateOutput{}, fmt.Errorf("alias %q is not registered", in.Alias)
	}
	if e.ReadOnly {
		return RotateOutput{}, fmt.Errorf("server %q is read-only (Tier-1); it has no transfer keys to rotate", in.Alias)
	}
	host := e.Host
	user := e.User
	port := e.Port
	if in.Host != "" {
		host = in.Host
	}
	if in.User != "" {
		user = in.User
	}
	if in.Port != 0 {
		port = in.Port
	}
	if port == 0 {
		port = 22
	}

	// Local materials (Tier-2 always needs gate.pub for the re-lock).
	gateBin, err := readLocalFile(cfg.GateBinaryPath, "gate binary",
		"run `make install-local` to install the committed sshgate-gate-linux-amd64 into ~/.config/sshgate/bin/")
	if err != nil {
		return RotateOutput{}, err
	}
	gatePubBytes, err := readLocalFile(cfg.GatePubPath, "gate signing public key",
		"no signer pubkey found; run /sshgate:setup tier-2 to generate it")
	if err != nil {
		return RotateOutput{}, err
	}
	sshgatePubBytes, err := readLocalFile(cfg.SSHGatePubPath, "SSHGate dedicated SSH public key",
		"run `sshgate pubkey` first to generate it")
	if err != nil {
		return RotateOutput{}, err
	}
	sshgatePub, _, _, _, err := ssh.ParseAuthorizedKey(sshgatePubBytes)
	if err != nil {
		return RotateOutput{}, fmt.Errorf("parse %s: %w", cfg.SSHGatePubPath, err)
	}

	auth, err := bootstrapAuthMethod(AddServerInput{BootstrapKeyPath: cfg.SSHGateKeyPath})
	if err != nil {
		return RotateOutput{}, fmt.Errorf("load SSHGate key %s: %w", cfg.SSHGateKeyPath, err)
	}
	if cfg.KnownHostsPath == "" {
		return RotateOutput{}, errors.New("known_hosts path is empty; cannot pin host key")
	}
	bootCfg := &ssh.ClientConfig{
		User:            user,
		Auth:            []ssh.AuthMethod{auth},
		HostKeyCallback: sshpkg.TOFU(cfg.KnownHostsPath),
		Timeout:         bootstrapDialTimeout,
	}
	dialCtx, cancel := context.WithTimeout(ctx, bootstrapDialTimeout)
	defer cancel()
	bootSess, hostFingerprint, err := newBootstrapSession(dialCtx, host, port, bootCfg)
	if err != nil {
		return RotateOutput{}, fmt.Errorf("dial %s@%s:%d with the SSHGate key: %w", user, host, port, err)
	}
	defer bootSess.Close()

	// Fail CLOSED on a host-key change — never rotate against a new identity.
	if hostFingerprint != e.Fingerprint {
		return RotateOutput{}, fmt.Errorf(
			"host key for %q changed (registered %s, dialed %s) — aborting rotation; investigate the host before re-provisioning",
			in.Alias, e.Fingerprint, hostFingerprint)
	}

	// The rotate window REQUIRES a plain shell. If a gate answers, the forced
	// command is still active and `gate genkeys` (argv) is unreachable — refuse
	// with the exact remediation rather than silently doing nothing.
	if probeGateAnswers(ctx, bootSess) {
		return RotateOutput{}, fmt.Errorf(
			"server %q is still locked (its gate answered) — to rotate, remove the existing command=\"...\" line for the SSHGate key from %s:~/.ssh/authorized_keys, paste `sshgate pubkey`'s plain line back (this re-opens the brief full-shell window), then re-run `sshgate xfer-rotate %s`",
			in.Alias, host, in.Alias)
	}

	// Plain shell: read authorized_keys so runAutoSetup can back it up + rewrite.
	existing, _, err := bootSess.Run(ctx, "cat "+remoteAuthKeys+" 2>/dev/null || true")
	if err != nil {
		return RotateOutput{}, fmt.Errorf("read authorized_keys: %w", err)
	}

	// Re-lock: re-upload the gate + rewrite the pasted plain line into the
	// restricted forced-command line (same path fresh add uses).
	var r Runner
	if err := r.runAutoSetup(ctx, bootSess, gateBin, gatePubBytes, sshgatePub, existing); err != nil {
		return RotateOutput{}, err
	}

	// Regenerate the transfer keys on the host (overwrite) over the still-plain
	// shell, then parse + validate the readback.
	out, _, gerr := bootSess.Run(ctx, remoteGateBin+" genkeys --rotate")
	if gerr != nil {
		return RotateOutput{}, provisionRollback(ctx, &r, bootSess, existing, user, host,
			fmt.Errorf("rotate transfer keys: %w", gerr))
	}
	boxPubLine, idPubLine, gerr := parseGenKeysReadback(out)
	if gerr != nil {
		return RotateOutput{}, provisionRollback(ctx, &r, bootSess, existing, user, host, gerr)
	}

	// Verify the re-locked gate answers on a fresh dial.
	if err := verifyProvision(ctx, host, port, bootCfg); err != nil {
		return RotateOutput{}, provisionRollback(ctx, &r, bootSess, existing, user, host, err)
	}

	return RotateOutput{
		Alias:       in.Alias,
		Fingerprint: e.Fingerprint,
		XferBoxPub:  boxPubLine,
		XferIDPub:   idPubLine,
	}, nil
}

// XferKeysOnHost is a best-effort, read-only probe of whether both transfer key
// files are present in the remote gate dir. It dials the (gated) host with the
// SSHGate key and runs a plain `ls ~/.sshgate-gate` — which the gate classifies
// as a READ, so it runs with no approval tap and no new verb. It never writes and
// never reveals key CONTENT (only filenames). reachable is false when the host
// cannot be dialed (the caller renders "unknown"); present is true only when both
// xfer-box.key and xfer-id.key appear in the listing.
func XferKeysOnHost(ctx context.Context, cfg provisionCfg, alias string) (present, reachable bool) {
	servers, err := registry.New(cfg.ServersPath)
	if err != nil {
		return false, false
	}
	e, ok := servers.Get(alias)
	if !ok {
		return false, false
	}
	auth, err := bootstrapAuthMethod(AddServerInput{BootstrapKeyPath: cfg.SSHGateKeyPath})
	if err != nil {
		return false, false
	}
	if cfg.KnownHostsPath == "" {
		return false, false
	}
	port := e.Port
	if port == 0 {
		port = 22
	}
	bootCfg := &ssh.ClientConfig{
		User:            e.User,
		Auth:            []ssh.AuthMethod{auth},
		HostKeyCallback: sshpkg.TOFU(cfg.KnownHostsPath),
		Timeout:         bootstrapDialTimeout,
	}
	dialCtx, cancel := context.WithTimeout(ctx, bootstrapDialTimeout)
	defer cancel()
	sess, _, err := newBootstrapSession(dialCtx, e.Host, port, bootCfg)
	if err != nil {
		return false, false
	}
	defer sess.Close()
	out, _, err := sess.Run(ctx, "ls "+remoteGateDir)
	if err != nil {
		// Reachable, but the listing failed (e.g. the dir is absent) — treat as
		// "not present" rather than "unknown".
		return false, true
	}
	listing := string(out)
	present = strings.Contains(listing, "xfer-box.key") && strings.Contains(listing, "xfer-id.key")
	return present, true
}

// provisionRollback runs the shared rollback after a Provision failure that
// occurred AFTER authorized_keys was modified, then wraps cause in an
// actionable, security-explicit error. Provision's backup is the human's
// PLAIN pasted line — so a rollback restores the SSHGate key to FULL SHELL.
// The human must be told that explicitly:
//
//   - On a clean restore: tell them the key is back to the plain full-shell
//     line they pasted and how to remediate (remove it or re-run `sshgate add`).
//   - On a FAILED restore: escalate — the host may now hold an un-restricted
//     SSHGate key in an indeterminate state, so they must inspect it manually.
//
// host/user are included so the message names the exact file to fix.
func provisionRollback(ctx context.Context, r *Runner, bootSess bootstrapSession, existing []byte, user, host string, cause error) error {
	restoreErr := r.rollback(ctx, bootSess, existing != nil)
	if restoreErr != nil {
		return fmt.Errorf(
			"provisioning failed (%w); ROLLBACK ALSO FAILED (%v) — manually inspect %s:~/.ssh/authorized_keys; it may contain an un-restricted SSHGate key (FULL SHELL) for %s@%s",
			cause, restoreErr, host, user, host)
	}
	return fmt.Errorf(
		"provisioning failed (%w); the SSHGate key on %s@%s has been rolled back to the PLAIN line you pasted, which grants FULL SHELL — remove that line from %s:~/.ssh/authorized_keys now, or re-run `sshgate add` to complete the lockdown",
		cause, user, host, host)
}

// probeGateAnswers reports whether a live gate answered the unsigned
// SSHGATE_VERSION verb (a plain shell fails it and reports false). It is the
// bool-only wrapper over probeGateVersion for callers that don't need the tier
// (RotateXferKeys).
func probeGateAnswers(ctx context.Context, sess bootstrapSession) bool {
	answered, _ := probeGateVersion(ctx, sess)
	return answered
}

// probeGateVersion sends the unsigned SSHGATE_VERSION verb over the already-
// dialed dedicated-key session and reports whether a live gate answered — the
// gate prints "SSHGATE_VERSION rev=<rev>" and exits 0 (the same mechanism
// probeRunningRev uses in update_gate.go) — plus the gate's self-reported tier
// when present. A plain shell fails the verb ("command not found", exit 127 →
// bootstrapSession.Run surfaces the non-zero exit as an error) and a broken or
// pre-verb gate errors or prints no marker; all of those report answered=false,
// sending Provision down the fresh-provision flow unchanged. tier is "ro"/"rw"
// when the reply carries the additive tier= token (#62), or "" for an OLD gate
// that omits it (the caller then keeps its faith-based tier). Best-effort by
// design: a probe failure is never surfaced.
func probeGateVersion(ctx context.Context, sess bootstrapSession) (answered bool, tier string) {
	stdout, _, err := sess.Run(ctx, "SSHGATE_VERSION")
	if err != nil {
		return false, ""
	}
	s := string(stdout)
	if !strings.Contains(s, "SSHGATE_VERSION rev=") {
		return false, ""
	}
	return true, parseProbedTier(s)
}

// parseProbedTier extracts the additive tier= token from a SSHGATE_VERSION reply
// ("SSHGATE_VERSION rev=<v> tier=ro|rw"). It returns "ro" or "rw" for a
// recognised value, or "" when the token is absent (old gate) or unrecognised —
// so a garbled or forward-incompatible value is treated as "no signal" rather
// than mis-reconciled. Whitespace-split, so it tolerates any surrounding/trailing
// tokens; it keys on the tier= token independently of the frozen rev= key.
func parseProbedTier(stdout string) string {
	for _, f := range strings.Fields(stdout) {
		if strings.HasPrefix(f, "tier=") {
			switch strings.TrimPrefix(f, "tier=") {
			case "ro":
				return "ro"
			case "rw":
				return "rw"
			}
		}
	}
	return ""
}

// verifyProvision re-dials the target with the (now gated) SSHGate key and
// runs the empty-command SSHGATE_OK probe. It opens a FRESH connection so the
// gate's forced command is exercised on a new session (the pre-rewrite
// connection is still authenticated by the old plain entry). Returns nil on
// SSHGATE_OK, an error otherwise.
func verifyProvision(ctx context.Context, host string, port int, bootCfg *ssh.ClientConfig) error {
	dialCtx, cancel := context.WithTimeout(ctx, bootstrapDialTimeout)
	defer cancel()
	// Dial on a COPY of the config. dialBootstrap (add_server.go) wraps and
	// REPLACES cfg.HostKeyCallback in place to capture the fingerprint, so the
	// caller's bootCfg has already been mutated by the first dial. Passing a
	// shallow copy keeps the verify dial from depending on — or further
	// mutating — that shared callback state. (HostKeyCallback is the only
	// field dialBootstrap touches; the TOFU store it points at is the durable
	// pin and is unaffected by the copy.)
	cfgCopy := *bootCfg
	sess, _, err := newBootstrapSession(dialCtx, host, port, &cfgCopy)
	if err != nil {
		return fmt.Errorf("verify re-dial: %w", err)
	}
	defer sess.Close()
	probe, _, err := sess.Run(ctx, "")
	if err != nil {
		return fmt.Errorf("verify probe: %w (stdout=%q)", err, string(probe))
	}
	if !strings.Contains(string(probe), "SSHGATE_OK") {
		return fmt.Errorf("verify probe did not return SSHGATE_OK (got %q)", string(probe))
	}
	return nil
}
