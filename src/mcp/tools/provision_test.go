package tools

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/karthikeyan5/sshgate/src/mcp/registry"
	"github.com/karthikeyan5/sshgate/src/xfer"
	"golang.org/x/crypto/ssh"
)

// errSSHUnableToAuthenticate returns a representative golang.org/x/crypto/ssh
// handshake error so the dial-auth-failure remediation branch is exercised
// without a live sshd.
func errSSHUnableToAuthenticate() error {
	return errors.New("tools: bootstrap dial: ssh handshake: ssh: handshake failed: ssh: unable to authenticate, attempted methods [none publickey]")
}

// White-box tests for the human-only CLI provisioning path. They reuse the
// fakeBootstrapSession / khSSH / installFakeBootstrapSession seams defined in
// add_server_bootstrap_test.go so the dial-upload-rewrite-rollback flow is
// reachable without a live sshd or sudo.
//
// The ONE behavioural delta from AddServer is that Provision dials with the
// SSHGate dedicated PRIVATE key (the human pasted the plain public key first),
// and the rewrite REPLACES that same key's plain line with the restricted
// forced-command line. We test that delta carefully.

// ---------------------------------------------------------------------
// EnsureSSHGateKeypair
// ---------------------------------------------------------------------

// TestEnsureSSHGateKeypair_GeneratesWhenAbsent: a fresh key path gets a new
// ed25519 keypair with the right perms (priv 0600, pub 0644, dir 0700), and
// the returned line is the bare ssh-ed25519 public-key line.
func TestEnsureSSHGateKeypair_GeneratesWhenAbsent(t *testing.T) {
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "ssh", "sshgate_ed25519")

	line, err := EnsureSSHGateKeypair(keyPath)
	if err != nil {
		t.Fatalf("EnsureSSHGateKeypair: %v", err)
	}
	if !strings.HasPrefix(line, "ssh-ed25519 ") {
		t.Errorf("public-key line = %q; want an ssh-ed25519 line", line)
	}
	if strings.Contains(line, "command=") {
		t.Errorf("public-key line %q must be the BARE key, not the restricted line", line)
	}
	if strings.Contains(line, "\n") {
		t.Errorf("public-key line %q must be a single line (no trailing newline)", line)
	}

	// Private key perms 0600.
	pi, err := os.Stat(keyPath)
	if err != nil {
		t.Fatalf("stat private key: %v", err)
	}
	if pi.Mode().Perm() != 0o600 {
		t.Errorf("private key mode = %#o; want 0600", pi.Mode().Perm())
	}
	// Public key perms 0644.
	pubInfo, err := os.Stat(keyPath + ".pub")
	if err != nil {
		t.Fatalf("stat public key: %v", err)
	}
	if pubInfo.Mode().Perm() != 0o644 {
		t.Errorf("public key mode = %#o; want 0644", pubInfo.Mode().Perm())
	}
	// Dir perms 0700.
	di, err := os.Stat(filepath.Dir(keyPath))
	if err != nil {
		t.Fatalf("stat ssh dir: %v", err)
	}
	if di.Mode().Perm() != 0o700 {
		t.Errorf("ssh dir mode = %#o; want 0700", di.Mode().Perm())
	}

	// The private key must parse as a valid OpenSSH ed25519 key, and its
	// public half must match the printed line.
	body, err := os.ReadFile(keyPath)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.ParsePrivateKey(body)
	if err != nil {
		t.Fatalf("private key does not parse: %v", err)
	}
	wantKey := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(signer.PublicKey())))
	// The printed line is the bare key plus the canonical comment.
	if line != wantKey+" sshgate-dedicated" {
		t.Errorf("printed line %q does not match the private key's public half %q (+comment)", line, wantKey)
	}
}

// TestEnsureSSHGateKeypair_Idempotent: a second call must NOT regenerate the
// key (same bytes returned), so re-running `sshgate pubkey` is safe.
func TestEnsureSSHGateKeypair_Idempotent(t *testing.T) {
	keyPath := filepath.Join(t.TempDir(), "ssh", "sshgate_ed25519")

	first, err := EnsureSSHGateKeypair(keyPath)
	if err != nil {
		t.Fatalf("first EnsureSSHGateKeypair: %v", err)
	}
	privBefore, err := os.ReadFile(keyPath)
	if err != nil {
		t.Fatal(err)
	}

	second, err := EnsureSSHGateKeypair(keyPath)
	if err != nil {
		t.Fatalf("second EnsureSSHGateKeypair: %v", err)
	}
	if first != second {
		t.Errorf("idempotent call returned a different line:\n first=%q\nsecond=%q", first, second)
	}
	privAfter, err := os.ReadFile(keyPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(privBefore) != string(privAfter) {
		t.Error("private key was regenerated on the second call; must be idempotent")
	}
}

// ---------------------------------------------------------------------
// Provision — helper to write a real SSHGate private key
// ---------------------------------------------------------------------

// writeSSHGateKeypair writes a real 0600 OpenSSH ed25519 private key plus its
// 0644 .pub at <dir>/ssh/sshgate_ed25519[.pub] and returns the private path
// and the parsed public key (so tests can seed the pasted plain line / the
// canonical restricted line).
func writeSSHGateKeypair(t *testing.T) (privPath string, pub ssh.PublicKey) {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "ssh")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	pubKey, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	block, err := ssh.MarshalPrivateKey(priv, "")
	if err != nil {
		t.Fatal(err)
	}
	privPath = filepath.Join(dir, "sshgate_ed25519")
	if err := os.WriteFile(privPath, pem.EncodeToMemory(block), 0o600); err != nil {
		t.Fatal(err)
	}
	sshPub, err := ssh.NewPublicKey(pubKey)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(privPath+".pub", ssh.MarshalAuthorizedKey(sshPub), 0o644); err != nil {
		t.Fatal(err)
	}
	return privPath, sshPub
}

// provisionMaterials writes the gate binary + gate.pub locally and returns a
// provisionCfg pointing the gate-material paths and the SSHGate private key
// path at real files.
func provisionMaterials(t *testing.T) (provisionCfg, ssh.PublicKey) {
	t.Helper()
	dir := t.TempDir()
	gateBin := filepath.Join(dir, "sshgate-gate-linux-amd64")
	if err := os.WriteFile(gateBin, []byte("#!/bin/true\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	gatePub := filepath.Join(dir, "gate.pub")
	if err := os.WriteFile(gatePub, []byte("gate-signing-pubkey-bytes\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	privPath, pub := writeSSHGateKeypair(t)
	cfg := provisionCfg{
		GateBinaryPath: gateBin,
		GatePubPath:    gatePub,
		SSHGateKeyPath: privPath,
		SSHGatePubPath: privPath + ".pub",
		KnownHostsPath: filepath.Join(t.TempDir(), "known_hosts"),
		ServersPath:    filepath.Join(t.TempDir(), "servers.json"),
	}
	return cfg, pub
}

// plainPastedLine builds the bare (unrestricted) authorized_keys line a human
// would paste from `sshgate pubkey`, optionally surrounded by other keys.
func plainPastedLine(t *testing.T, pub ssh.PublicKey) []byte {
	t.Helper()
	return ssh.MarshalAuthorizedKey(pub) // ssh-ed25519 AAAA... comment\n
}

// ---------------------------------------------------------------------
// Provision — happy paths
// ---------------------------------------------------------------------

// TestProvision_ReadOnlyHappyPath drives the tier-1 CLI add: dial with the
// SSHGate key, upload gate (NO gate.pub), rewrite the pasted plain line into
// the restricted line, verify, register read_only=true.
func TestProvision_ReadOnlyHappyPath(t *testing.T) {
	cfg, pub := provisionMaterials(t)
	// Point gate.pub at a nonexistent file to PROVE tier-1 never reads it.
	cfg.GatePubPath = filepath.Join(t.TempDir(), "absent-gate-pub")

	sess := &fakeBootstrapSession{catAuthKeys: plainPastedLine(t, pub), probeOut: []byte("SSHGATE_OK\n")}
	cap := installFakeBootstrapSession(t, sess, "SHA256:ro")

	out, err := Provision(context.Background(), cfg, ProvisionInput{
		Alias:    "ro1",
		Host:     "ro.example.com",
		User:     "u",
		ReadOnly: true,
	})
	if err != nil {
		t.Fatalf("Provision (read-only): %v", err)
	}
	if !out.ReadOnlyMode {
		t.Error("ReadOnlyMode = false; want true for tier-1")
	}
	if out.Fingerprint != "SHA256:ro" {
		t.Errorf("Fingerprint = %q; want the captured dial fingerprint", out.Fingerprint)
	}
	if !out.VerifiedOK {
		t.Error("VerifiedOK = false; want true")
	}
	// gate.pub must NOT have been uploaded.
	if _, ok := sess.uploadedTo(remoteGatePub); ok {
		t.Error("gate.pub was uploaded in tier-1 read-only mode; it must be skipped")
	}
	// gate binary + authorized_keys rewrite still happen.
	if _, ok := sess.uploadedTo(remoteGateBin); !ok {
		t.Error("gate binary not uploaded in tier-1")
	}
	au, ok := sess.uploadedTo(remoteAuthKeys)
	if !ok {
		t.Fatal("authorized_keys rewrite missing in tier-1")
	}
	// The rewritten file must carry the restricted entry for our key and NOT
	// the plain duplicate.
	if !hasRestrictedEntryForKey(au.body, pub, remoteGateBin) {
		t.Error("rewritten authorized_keys lacks the canonical forced-command entry")
	}
	if hasPlainLineForKey(au.body, pub) {
		t.Error("rewritten authorized_keys still has a PLAIN (unrestricted) line for the sshgate key")
	}

	// The dial must have used the SSHGate private key (cfg threaded the user).
	if cap.cfg == nil || cap.cfg.User != "u" {
		t.Errorf("dial cfg user = %v; want the target user threaded in", cap.cfg)
	}

	// Registry on disk holds the read-only entry.
	reg, err := registry.New(cfg.ServersPath)
	if err != nil {
		t.Fatalf("reload registry: %v", err)
	}
	if e, ok := reg.Get("ro1"); !ok {
		t.Error("registry missing tier-1 alias")
	} else if !e.ReadOnly {
		t.Error("registry entry not marked read-only for tier-1 add")
	} else if e.Fingerprint != "SHA256:ro" {
		t.Errorf("registry entry Fingerprint = %q; want the pinned dial fingerprint SHA256:ro", e.Fingerprint)
	}
}

// genKeysReadbackBlock builds a valid SSHGATE_XFER_PUBKEYS_BEGIN/END readback
// block (with a leading motd line, to prove the parser tolerates banner noise)
// from a fresh box+id keypair, returning the block bytes plus the two canonical
// public lines so a test can assert the parsed ProvisionOutput fields.
func genKeysReadbackBlock(t *testing.T) (block []byte, boxLine, idLine string) {
	t.Helper()
	bk, err := xfer.GenerateBoxKey()
	if err != nil {
		t.Fatalf("gen box: %v", err)
	}
	ik, err := xfer.GenerateIDKey()
	if err != nil {
		t.Fatalf("gen id: %v", err)
	}
	boxLine = bk.PublicText()
	idLine = ik.PublicText()
	block = []byte("Welcome to the host (motd noise)\n" +
		"SSHGATE_XFER_PUBKEYS_BEGIN\n" + boxLine + "\n" + idLine + "\n" + "SSHGATE_XFER_PUBKEYS_END\n")
	return block, boxLine, idLine
}

// TestProvision_WriteHappyPath drives the tier-2 CLI add: gate.pub IS uploaded
// and read_only=false, and the genkeys leg's readback populates the transfer
// pubkey fields.
func TestProvision_WriteHappyPath(t *testing.T) {
	cfg, pub := provisionMaterials(t)
	block, wantBox, wantID := genKeysReadbackBlock(t)
	sess := &fakeBootstrapSession{catAuthKeys: plainPastedLine(t, pub), probeOut: []byte("SSHGATE_OK\n"), genkeysOut: block}
	installFakeBootstrapSession(t, sess, "SHA256:rw")

	out, err := Provision(context.Background(), cfg, ProvisionInput{
		Alias: "prod",
		Host:  "h.example.com",
		Port:  2222,
		User:  "deploy",
	})
	if err != nil {
		t.Fatalf("Provision (write): %v", err)
	}
	if out.ReadOnlyMode {
		t.Error("ReadOnlyMode = true; want false for tier-2")
	}
	// The genkeys readback populated the transfer pubkey fields with the parsed,
	// validated canonical lines.
	if out.XferBoxPub != wantBox {
		t.Errorf("XferBoxPub = %q; want %q", out.XferBoxPub, wantBox)
	}
	if out.XferIDPub != wantID {
		t.Errorf("XferIDPub = %q; want %q", out.XferIDPub, wantID)
	}
	// The gate genkeys command actually ran on the plain shell.
	if !sess.ranContaining(remoteGateBin + " genkeys") {
		t.Error("genkeys leg did not run on the plain shell for a Tier-2 add")
	}
	if u, ok := sess.uploadedTo(remoteGatePub); !ok {
		t.Error("gate.pub was not uploaded (tier-2 must push it)")
	} else if u.mode != "644" {
		t.Errorf("gate.pub mode = %q; want 644", u.mode)
	}
	if out.Port != 2222 {
		t.Errorf("output Port = %d; want 2222", out.Port)
	}
	reg, err := registry.New(cfg.ServersPath)
	if err != nil {
		t.Fatal(err)
	}
	if e, ok := reg.Get("prod"); !ok {
		t.Error("registry missing alias")
	} else if e.ReadOnly {
		t.Error("registry entry marked read-only for a tier-2 add")
	} else if e.Port != 2222 || e.User != "deploy" || e.Host != "h.example.com" {
		t.Errorf("registry entry fields wrong: %+v", e)
	} else if e.Fingerprint != "SHA256:rw" {
		// The pinned host-key fingerprint must be stored so the MCP can later
		// bind sign requests to this host.
		t.Errorf("registry entry Fingerprint = %q; want the pinned dial fingerprint SHA256:rw", e.Fingerprint)
	}
	if out.Fingerprint != "SHA256:rw" {
		t.Errorf("output Fingerprint = %q; want SHA256:rw", out.Fingerprint)
	}
}

// TestProvision_WriteRequiresGatePub: tier-2 (write) with the local gate.pub
// absent must error clearly before touching the remote.
func TestProvision_WriteRequiresGatePub(t *testing.T) {
	cfg, _ := provisionMaterials(t)
	cfg.GatePubPath = filepath.Join(t.TempDir(), "absent-gate-pub")

	sess := &fakeBootstrapSession{}
	installFakeBootstrapSession(t, sess, "SHA256:nogatepub")

	_, err := Provision(context.Background(), cfg, ProvisionInput{
		Alias: "needpub",
		Host:  "h.example.com",
		User:  "u",
		// ReadOnly false => tier-2 => requires gate.pub.
	})
	if err == nil {
		t.Fatal("Provision = nil; want an error for missing gate.pub in write mode")
	}
	if !strings.Contains(err.Error(), "gate signing public key") && !strings.Contains(err.Error(), "read-only") {
		t.Errorf("err = %v; want a clear missing-gate.pub / pass-read-only message", err)
	}
	// Nothing should have been uploaded.
	if len(sess.uploads) != 0 {
		t.Errorf("uploaded %d file(s) despite the missing gate.pub fail-fast", len(sess.uploads))
	}
}

// ---------------------------------------------------------------------
// Provision — rewrite correctness (plain -> restricted, others untouched)
// ---------------------------------------------------------------------

// TestProvision_RewriteReplacesPlainKeepsOthers: an authorized_keys containing
// the pasted PLAIN sshgate line PLUS an unrelated key must come out with the
// sshgate key restricted, the plain duplicate gone, and the unrelated key
// verbatim.
func TestProvision_RewriteReplacesPlainKeepsOthers(t *testing.T) {
	cfg, pub := provisionMaterials(t)

	// An unrelated key the human already had in authorized_keys.
	otherPubRaw, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	otherPub, err := ssh.NewPublicKey(otherPubRaw)
	if err != nil {
		t.Fatal(err)
	}
	otherLine := ssh.MarshalAuthorizedKey(otherPub) // ssh-ed25519 AAAA...\n

	existing := append(append([]byte(nil), otherLine...), plainPastedLine(t, pub)...)

	sess := &fakeBootstrapSession{catAuthKeys: existing, probeOut: []byte("SSHGATE_OK\n")}
	installFakeBootstrapSession(t, sess, "SHA256:rewrite")

	cfg.GatePubPath = filepath.Join(t.TempDir(), "absent") // tier-1 for simplicity
	_, err = Provision(context.Background(), cfg, ProvisionInput{
		Alias:    "rw",
		Host:     "h.example.com",
		User:     "u",
		ReadOnly: true,
	})
	if err != nil {
		t.Fatalf("Provision: %v", err)
	}

	au, ok := sess.uploadedTo(remoteAuthKeys)
	if !ok {
		t.Fatal("authorized_keys was not rewritten")
	}
	if !hasRestrictedEntryForKey(au.body, pub, remoteGateBin) {
		t.Error("sshgate key is not restricted in the rewritten file")
	}
	if hasPlainLineForKey(au.body, pub) {
		t.Error("plain sshgate line survived the rewrite")
	}
	// The unrelated key's exact line must be preserved.
	if !strings.Contains(string(au.body), strings.TrimRight(string(otherLine), "\n")) {
		t.Error("unrelated authorized_keys line was not preserved verbatim")
	}
}

// TestProvision_Idempotent: re-running against a host whose authorized_keys
// ALREADY has the restricted entry must skip the rewrite (no uploads of the
// gate / authorized_keys) and just verify + register.
func TestProvision_Idempotent(t *testing.T) {
	cfg, pub := provisionMaterials(t)
	existing := canonicalAuthKeysLine(t, pub)

	sess := &fakeBootstrapSession{catAuthKeys: existing, probeOut: []byte("SSHGATE_OK\n")}
	installFakeBootstrapSession(t, sess, "SHA256:idem")

	out, err := Provision(context.Background(), cfg, ProvisionInput{
		Alias: "again",
		Host:  "h.example.com",
		User:  "u",
	})
	if err != nil {
		t.Fatalf("Provision (idempotent): %v", err)
	}
	if !out.Idempotent {
		t.Error("Idempotent = false; want true when the restricted entry already exists")
	}
	if len(sess.uploads) != 0 {
		t.Errorf("idempotent re-run uploaded %d file(s); want 0", len(sess.uploads))
	}
	if sess.ranContaining("mkdir -p " + remoteGateDir) {
		t.Error("idempotent re-run ran mkdir; setup must be skipped")
	}
	reg, err := registry.New(cfg.ServersPath)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := reg.Get("again"); !ok {
		t.Error("registry missing alias after idempotent re-run")
	}
}

// TestProvision_ProbeIdempotent_GateAnswers: when the SSHGATE_VERSION probe on
// the dedicated-key dial is answered by a live gate, Provision must take the
// idempotent path WITHOUT ever reading authorized_keys — on an already-gated
// host that read routes through the gate, where its `2>/dev/null` redirect
// classifies as an unsigned write (exit 77) and the gate's redactor scrubs the
// key base64 the fallback detection matches on. It must skip install/rewrite,
// verify, and (re)register the alias with the TOFU fingerprint (a lost
// servers.json is the main reason a human re-adds).
func TestProvision_ProbeIdempotent_GateAnswers(t *testing.T) {
	cfg, _ := provisionMaterials(t)

	sess := &fakeBootstrapSession{
		// A live gate answers the version probe...
		versionProbeOut: []byte("SSHGATE_VERSION rev=abc123def456\n"),
		// ...and the SSHGATE_OK verify re-dial succeeds.
		probeOut: []byte("SSHGATE_OK\n"),
		// What a REAL gated host would return for the cat: the redactor has
		// scrubbed the key base64, so the fallback detection could never match
		// it. The probe-first path must not even issue the cat.
		catAuthKeys: []byte(`command="~/.sshgate-gate/gate",no-port-forwarding ssh-ed25519 [SSHGATE_REDACTED key=deadbeef] sshgate-dedicated` + "\n"),
	}
	installFakeBootstrapSession(t, sess, "SHA256:probeidem")

	out, err := Provision(context.Background(), cfg, ProvisionInput{
		Alias: "readd",
		Host:  "h.example.com",
		User:  "u",
	})
	if err != nil {
		t.Fatalf("Provision (probe-idempotent): %v", err)
	}
	if !out.Idempotent {
		t.Error("Idempotent = false; want true when a gate answers the version probe")
	}
	// The authorized_keys read must NOT have run — through the gate it would
	// exit 77 (the very failure the probe-first design closes).
	if sess.ranContaining("cat " + remoteAuthKeys) {
		t.Error("probe-idempotent path read authorized_keys; the probe must short-circuit it")
	}
	// No install/rewrite of any kind.
	if len(sess.uploads) != 0 {
		t.Errorf("probe-idempotent re-run uploaded %d file(s); want 0", len(sess.uploads))
	}
	if sess.ranContaining("mkdir -p " + remoteGateDir) {
		t.Error("probe-idempotent re-run ran mkdir; setup must be skipped")
	}
	// The alias is registered with the freshly pinned fingerprint, exactly
	// like a fresh provision would record it.
	reg, err := registry.New(cfg.ServersPath)
	if err != nil {
		t.Fatal(err)
	}
	if e, ok := reg.Get("readd"); !ok {
		t.Error("registry missing alias after probe-idempotent re-run")
	} else if e.Fingerprint != "SHA256:probeidem" {
		t.Errorf("registry entry Fingerprint = %q; want the pinned dial fingerprint SHA256:probeidem", e.Fingerprint)
	}
	if out.Fingerprint != "SHA256:probeidem" {
		t.Errorf("output Fingerprint = %q; want SHA256:probeidem", out.Fingerprint)
	}
}

// TestProvision_ReconcileTierToHost is the #62 tier-reconcile. On an idempotent
// re-add where the gate self-reports its tier via the additive tier= token, the
// registry must follow HOST truth (gate.pub presence is the enforcement point),
// and a --read-only flag that disagreed must be overridden with a loud NOTE. An
// old gate that omits tier= keeps the caller's flag (faith-based, backward-compat).
func TestProvision_ReconcileTierToHost(t *testing.T) {
	cases := []struct {
		name         string
		versionOut   string
		flagReadOnly bool
		wantReadOnly bool // what should land in the registry / output
		wantNote     bool
		noteContains string
	}{
		{
			name:         "host ro overrides absent flag",
			versionOut:   "SSHGATE_VERSION rev=v1.4.0 tier=ro\n",
			flagReadOnly: false,
			wantReadOnly: true,
			wantNote:     true,
			noteContains: "read-only (Tier-1)",
		},
		{
			name:         "host rw overrides --read-only",
			versionOut:   "SSHGATE_VERSION rev=v1.4.0 tier=rw\n",
			flagReadOnly: true,
			wantReadOnly: false,
			wantNote:     true,
			noteContains: "signed-write (Tier-2)",
		},
		{
			name:         "matching tier: no note, no override",
			versionOut:   "SSHGATE_VERSION rev=v1.4.0 tier=ro\n",
			flagReadOnly: true,
			wantReadOnly: true,
			wantNote:     false,
		},
		{
			name:         "old gate omits tier=: faith-based, no reconcile",
			versionOut:   "SSHGATE_VERSION rev=v1.4.0\n",
			flagReadOnly: false,
			wantReadOnly: false,
			wantNote:     false,
		},
	}
	for _, c := range cases {
		c := c
		t.Run(c.name, func(t *testing.T) {
			cfg, _ := provisionMaterials(t)
			sess := &fakeBootstrapSession{
				versionProbeOut: []byte(c.versionOut),
				probeOut:        []byte("SSHGATE_OK\n"),
			}
			installFakeBootstrapSession(t, sess, "SHA256:reconcile")

			out, err := Provision(context.Background(), cfg, ProvisionInput{
				Alias:    "recon",
				Host:     "h.example.com",
				User:     "u",
				ReadOnly: c.flagReadOnly,
			})
			if err != nil {
				t.Fatalf("Provision: %v", err)
			}
			if !out.Idempotent {
				t.Fatal("Idempotent = false; want true (gate answered the probe)")
			}
			if out.ReadOnlyMode != c.wantReadOnly {
				t.Errorf("out.ReadOnlyMode = %v; want %v", out.ReadOnlyMode, c.wantReadOnly)
			}
			reg, err := registry.New(cfg.ServersPath)
			if err != nil {
				t.Fatal(err)
			}
			e, ok := reg.Get("recon")
			if !ok {
				t.Fatal("registry missing alias after reconcile re-add")
			}
			if e.ReadOnly != c.wantReadOnly {
				t.Errorf("registered ReadOnly = %v; want %v (host truth)", e.ReadOnly, c.wantReadOnly)
			}
			if c.wantNote {
				if out.TierNote == "" {
					t.Fatal("TierNote is empty; want a loud override NOTE")
				}
				if !strings.Contains(out.TierNote, "recon") {
					t.Errorf("TierNote %q does not name the alias", out.TierNote)
				}
				if c.noteContains != "" && !strings.Contains(out.TierNote, c.noteContains) {
					t.Errorf("TierNote %q missing %q", out.TierNote, c.noteContains)
				}
				if strings.Contains(out.TierNote, "/sshgate:revoke") {
					t.Errorf("TierNote %q gives circular /sshgate:revoke advice", out.TierNote)
				}
			} else if out.TierNote != "" {
				t.Errorf("TierNote = %q; want empty (tiers matched or no tier token)", out.TierNote)
			}
		})
	}
}

// TestProvision_ProbeFails_FreshFlowUnchanged: when the SSHGATE_VERSION probe
// hard-fails (a plain shell runs it — "command not found", exit 127), Provision
// must swallow the probe error and proceed with the fresh-provision flow
// exactly as before: plain-shell authorized_keys read, install, rewrite,
// verify, register.
func TestProvision_ProbeFails_FreshFlowUnchanged(t *testing.T) {
	cfg, pub := provisionMaterials(t)

	block, _, _ := genKeysReadbackBlock(t)
	sess := &fakeBootstrapSession{
		// The probe errors like a plain shell's exit 127.
		failRunSub:  "SSHGATE_VERSION",
		catAuthKeys: plainPastedLine(t, pub),
		probeOut:    []byte("SSHGATE_OK\n"),
		genkeysOut:  block,
	}
	installFakeBootstrapSession(t, sess, "SHA256:fresh")

	out, err := Provision(context.Background(), cfg, ProvisionInput{
		Alias: "fresh",
		Host:  "h.example.com",
		User:  "u",
	})
	if err != nil {
		t.Fatalf("Provision (probe fails → fresh flow): %v", err)
	}
	if out.Idempotent {
		t.Error("Idempotent = true; want false on a fresh host (probe failed)")
	}
	// The fallback authorized_keys read ran on the plain shell.
	if !sess.ranContaining("cat " + remoteAuthKeys) {
		t.Error("fresh flow skipped the authorized_keys read; the fallback detection must still run")
	}
	// Full install happened: gate uploaded + authorized_keys rewritten.
	if _, ok := sess.uploadedTo(remoteGateBin); !ok {
		t.Error("gate binary not uploaded on the fresh flow")
	}
	au, ok := sess.uploadedTo(remoteAuthKeys)
	if !ok {
		t.Fatal("authorized_keys was not rewritten on the fresh flow")
	}
	if !hasRestrictedEntryForKey(au.body, pub, remoteGateBin) {
		t.Error("rewritten authorized_keys lacks the canonical forced-command entry")
	}
	reg, err := registry.New(cfg.ServersPath)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := reg.Get("fresh"); !ok {
		t.Error("registry missing alias after fresh provision")
	}
}

// ---------------------------------------------------------------------
// Provision — rollback
// ---------------------------------------------------------------------

// TestProvision_VerifyFailureRollsBack: setup completes but the verify probe
// does not return SSHGATE_OK; Provision must roll back authorized_keys from
// the backup and remove the gate dir, and must NOT register.
func TestProvision_VerifyFailureRollsBack(t *testing.T) {
	cfg, pub := provisionMaterials(t)
	cfg.GatePubPath = filepath.Join(t.TempDir(), "absent") // tier-1

	sess := &fakeBootstrapSession{
		catAuthKeys: plainPastedLine(t, pub),
		probeOut:    []byte("nope\n"), // gate probe (via re-dial) returns junk
	}
	installFakeBootstrapSession(t, sess, "SHA256:verifyfail")

	_, err := Provision(context.Background(), cfg, ProvisionInput{
		Alias:    "bad",
		Host:     "h.example.com",
		User:     "u",
		ReadOnly: true,
	})
	if err == nil {
		t.Fatal("Provision = nil; want a verify-probe failure")
	}
	if !strings.Contains(err.Error(), "SSHGATE_OK") {
		t.Errorf("err = %v; want a verify-probe SSHGATE_OK failure", err)
	}
	if !sess.ranContaining(remoteAuthKeysBackup) {
		t.Error("rollback did not restore authorized_keys from backup")
	}
	if !sess.ranContaining("rm -rf " + remoteGateDir) {
		t.Error("rollback did not remove the gate dir")
	}
	reg, err := registry.New(cfg.ServersPath)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := reg.Get("bad"); ok {
		t.Error("registry holds the alias after a failed verify; it must be untouched")
	}
}

// ---------------------------------------------------------------------
// Provision — bad-bootstrap (did you paste the key?)
// ---------------------------------------------------------------------

// TestProvision_DialAuthFailureActionable: a dial/auth failure must surface the
// "did you paste the sshgate pubkey into the host's authorized_keys" hint
// rather than a bare SSH error.
func TestProvision_DialAuthFailureActionable(t *testing.T) {
	cfg, _ := provisionMaterials(t)
	installFailingBootstrapDial(t, errSSHUnableToAuthenticate())

	_, err := Provision(context.Background(), cfg, ProvisionInput{
		Alias:    "authfail",
		Host:     "h.example.com",
		User:     "deploy",
		ReadOnly: true,
	})
	if err == nil {
		t.Fatal("Provision = nil; want an actionable dial-auth failure")
	}
	if !strings.Contains(err.Error(), "authorized_keys") {
		t.Errorf("err = %v; want the 'paste the key into authorized_keys' hint", err)
	}
	if !strings.Contains(err.Error(), "sshgate pubkey") {
		t.Errorf("err = %v; want a reference to `sshgate pubkey`", err)
	}
	reg, err := registry.New(cfg.ServersPath)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := reg.Get("authfail"); ok {
		t.Error("registry holds the alias after a dial failure")
	}
}

// ---------------------------------------------------------------------
// Provision — validation + already-registered
// ---------------------------------------------------------------------

func TestProvision_BadAlias(t *testing.T) {
	cfg, _ := provisionMaterials(t)
	for _, bad := range []string{"", "1abc", "Abc", "has space", "way-too-long-alias-name-exceeding-the-cap-x"} {
		_, err := Provision(context.Background(), cfg, ProvisionInput{
			Alias:    bad,
			Host:     "h.example.com",
			User:     "u",
			ReadOnly: true,
		})
		if err == nil {
			t.Errorf("Provision(alias=%q) = nil; want an alias validation error", bad)
		}
	}
}

func TestProvision_AlreadyRegistered(t *testing.T) {
	cfg, _ := provisionMaterials(t)
	// Pre-seed the registry on disk.
	reg, err := registry.New(cfg.ServersPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := reg.Add("dup", registry.Entry{Host: "old", Port: 22, User: "u"}); err != nil {
		t.Fatal(err)
	}

	_, err = Provision(context.Background(), cfg, ProvisionInput{
		Alias:    "dup",
		Host:     "h.example.com",
		User:     "u",
		ReadOnly: true,
	})
	if err == nil {
		t.Fatal("Provision = nil; want an already-registered refusal")
	}
	if !strings.Contains(err.Error(), "already registered") {
		t.Errorf("err = %v; want an 'already registered' refusal", err)
	}
}

// ---------------------------------------------------------------------
// Adversarial security regressions (review findings)
// ---------------------------------------------------------------------

// countRestrictedEntries returns how many lines in authorized_keys carry the
// canonical forced-command prefix for pub. The rewrite must always leave
// EXACTLY one — never zero (key unusable) and never more (duplicate gate lines).
func countRestrictedEntries(t *testing.T, authKeys []byte, pub ssh.PublicKey) int {
	t.Helper()
	wantBytes := pub.Marshal()
	wantPrefix := fmtCommandPrefix()
	n := 0
	for _, line := range strings.Split(string(authKeys), "\n") {
		if !strings.HasPrefix(line, wantPrefix) {
			continue
		}
		if lineMatchesKey(line, wantBytes) {
			n++
		}
	}
	return n
}

// fmtCommandPrefix mirrors the exact restricted-line prefix the rewrite emits.
func fmtCommandPrefix() string {
	return strings.Replace(commandForcingFmt, "%s", remoteGateBin, 1)
}

// TestProvision_HIGH1_RestrictedPlusPlainForcesRewrite is the HIGH-1
// regression. authorized_keys contains BOTH the canonical restricted line AND
// a stray PLAIN duplicate of the SAME sshgate key (the human pasted twice, or
// a prior partial run left both). The old idempotency probe (restricted-entry
// present => skip) would treat this as "already set up" and leave the plain
// line LIVE — a full-shell credential — while registering the server verified.
//
// Provision MUST instead force the rewrite, producing authorized_keys with NO
// plain line for the key and EXACTLY ONE restricted entry.
func TestProvision_HIGH1_RestrictedPlusPlainForcesRewrite(t *testing.T) {
	cfg, pub := provisionMaterials(t)
	cfg.GatePubPath = filepath.Join(t.TempDir(), "absent") // tier-1 for simplicity

	// Seed BOTH: the canonical restricted line AND a stray plain duplicate.
	restricted := canonicalAuthKeysLine(t, pub)
	plain := plainPastedLine(t, pub)
	existing := append(append([]byte(nil), restricted...), plain...)

	// Sanity: the pre-condition the bug relies on actually holds.
	if !hasRestrictedEntryForKey(existing, pub, remoteGateBin) {
		t.Fatal("test seed lacks the restricted entry")
	}
	if !hasPlainLineForKey(existing, pub) {
		t.Fatal("test seed lacks the coexisting plain duplicate")
	}

	sess := &fakeBootstrapSession{catAuthKeys: existing, probeOut: []byte("SSHGATE_OK\n")}
	installFakeBootstrapSession(t, sess, "SHA256:high1")

	out, err := Provision(context.Background(), cfg, ProvisionInput{
		Alias:    "high1",
		Host:     "h.example.com",
		User:     "u",
		ReadOnly: true,
	})
	if err != nil {
		t.Fatalf("Provision: %v", err)
	}
	// The host must NOT be treated as idempotent — the rewrite has to run.
	if out.Idempotent {
		t.Fatal("Idempotent = true despite a coexisting PLAIN line; the rewrite was skipped and the full-shell key survives (HIGH-1)")
	}
	au, ok := sess.uploadedTo(remoteAuthKeys)
	if !ok {
		t.Fatal("authorized_keys was not rewritten; the coexisting plain line was left live (HIGH-1)")
	}
	if hasPlainLineForKey(au.body, pub) {
		t.Error("PLAIN (full-shell) sshgate line survived; HIGH-1 not fixed")
	}
	if !hasRestrictedEntryForKey(au.body, pub, remoteGateBin) {
		t.Error("restricted entry missing after the forced rewrite")
	}
	if n := countRestrictedEntries(t, au.body, pub); n != 1 {
		t.Errorf("restricted entries = %d; want exactly 1 after the rewrite", n)
	}
}

// TestProvision_HIGH2_VerifyFailureSurfacesPlainKeyRemediation is the HIGH-2
// regression. When verify fails after authorized_keys was modified, the
// shared rollback restores the backup — which for Provision is the human's
// PLAIN pasted line, i.e. the key is back to FULL SHELL. The returned error
// MUST tell the human that explicitly and name the host so it is actionable.
func TestProvision_HIGH2_VerifyFailureSurfacesPlainKeyRemediation(t *testing.T) {
	cfg, pub := provisionMaterials(t)
	cfg.GatePubPath = filepath.Join(t.TempDir(), "absent") // tier-1

	sess := &fakeBootstrapSession{
		catAuthKeys: plainPastedLine(t, pub),
		probeOut:    []byte("nope\n"), // verify re-dial returns junk => verify fails
	}
	installFakeBootstrapSession(t, sess, "SHA256:high2verify")

	_, err := Provision(context.Background(), cfg, ProvisionInput{
		Alias:    "high2",
		Host:     "target.example.com",
		User:     "deploy",
		ReadOnly: true,
	})
	if err == nil {
		t.Fatal("Provision = nil; want a verify failure with remediation")
	}
	msg := err.Error()
	// Names the host so the human knows exactly which file to fix.
	if !strings.Contains(msg, "target.example.com") {
		t.Errorf("err = %v; want the host named for actionability", err)
	}
	// Spells out the danger and the fix.
	if !strings.Contains(msg, "FULL SHELL") {
		t.Errorf("err = %v; want the explicit FULL SHELL warning", err)
	}
	if !strings.Contains(msg, "PLAIN") {
		t.Errorf("err = %v; want the PLAIN pasted-line remediation", err)
	}
	if !strings.Contains(msg, "authorized_keys") {
		t.Errorf("err = %v; want the authorized_keys file referenced", err)
	}
	// The underlying cause must still be wrapped in.
	if !strings.Contains(msg, "SSHGATE_OK") {
		t.Errorf("err = %v; want the underlying verify cause preserved", err)
	}
}

// TestProvision_HIGH2_RollbackRestoreFailureEscalates is the second half of
// HIGH-2: when the rollback's authorized_keys RESTORE itself fails, the host
// may be left holding an un-restricted SSHGate key in an indeterminate state.
// The error must ESCALATE to the "ROLLBACK ALSO FAILED — manually inspect"
// message rather than the (now misleading) "rolled back to the plain line".
func TestProvision_HIGH2_RollbackRestoreFailureEscalates(t *testing.T) {
	cfg, pub := provisionMaterials(t)
	cfg.GatePubPath = filepath.Join(t.TempDir(), "absent") // tier-1

	sess := &fakeBootstrapSession{
		catAuthKeys: plainPastedLine(t, pub),
		probeOut:    []byte("nope\n"), // force verify failure -> rollback
		// Fail ONLY the rollback restore (cp FROM backup TO authorized_keys).
		// The setup backup step copies the other direction (authkeys -> backup)
		// so it is NOT matched and setup still completes.
		failRunSub: "cp " + remoteAuthKeysBackup + " " + remoteAuthKeys,
	}
	installFakeBootstrapSession(t, sess, "SHA256:high2restore")

	_, err := Provision(context.Background(), cfg, ProvisionInput{
		Alias:    "high2b",
		Host:     "danger.example.com",
		User:     "deploy",
		ReadOnly: true,
	})
	if err == nil {
		t.Fatal("Provision = nil; want an escalated rollback-failure error")
	}
	msg := err.Error()
	if !strings.Contains(msg, "ROLLBACK ALSO FAILED") {
		t.Errorf("err = %v; want the escalated 'ROLLBACK ALSO FAILED' message", err)
	}
	if !strings.Contains(msg, "manually inspect") {
		t.Errorf("err = %v; want the 'manually inspect' instruction", err)
	}
	if !strings.Contains(msg, "danger.example.com") {
		t.Errorf("err = %v; want the host named for actionability", err)
	}
	if !strings.Contains(msg, "un-restricted") {
		t.Errorf("err = %v; want the un-restricted-key warning", err)
	}
}

// TestProvision_RewriteRobustness_CRLFOptionsDuplicate exercises the
// Provision-level rewrite against a gnarly seed: the pasted plain line carries
// CRLF line endings AND leading options (from="..."), a SECOND duplicate paste
// of the same key, and an UNRELATED other key. After Provision, authorized_keys
// must have exactly one restricted line, no surviving plain line for the key,
// and the unrelated key preserved.
func TestProvision_RewriteRobustness_CRLFOptionsDuplicate(t *testing.T) {
	cfg, pub := provisionMaterials(t)
	cfg.GatePubPath = filepath.Join(t.TempDir(), "absent") // tier-1

	// An unrelated key already present in authorized_keys.
	otherRaw, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	otherPub, err := ssh.NewPublicKey(otherRaw)
	if err != nil {
		t.Fatal(err)
	}
	otherLine := strings.TrimRight(string(ssh.MarshalAuthorizedKey(otherPub)), "\n")

	// Bare key (no comment), to compose option-prefixed / CRLF variants.
	bare := strings.TrimRight(string(ssh.MarshalAuthorizedKey(pub)), "\n")

	// Seed: CRLF endings throughout; first sshgate paste carries leading
	// options; a second duplicate paste is plain; an unrelated key sits in
	// between.
	withOptions := `from="10.0.0.0/8" ` + bare
	seed := withOptions + "\r\n" +
		otherLine + "\r\n" +
		bare + "\r\n"
	existing := []byte(seed)

	// Pre-conditions the rewrite must clean up.
	if !hasPlainLineForKey(existing, pub) {
		t.Fatal("seed should contain at least one plain sshgate line")
	}

	sess := &fakeBootstrapSession{catAuthKeys: existing, probeOut: []byte("SSHGATE_OK\n")}
	installFakeBootstrapSession(t, sess, "SHA256:robust")

	_, err = Provision(context.Background(), cfg, ProvisionInput{
		Alias:    "robust",
		Host:     "h.example.com",
		User:     "u",
		ReadOnly: true,
	})
	if err != nil {
		t.Fatalf("Provision: %v", err)
	}

	au, ok := sess.uploadedTo(remoteAuthKeys)
	if !ok {
		t.Fatal("authorized_keys was not rewritten")
	}
	if hasPlainLineForKey(au.body, pub) {
		t.Error("a PLAIN sshgate line (CRLF / options / duplicate) survived the rewrite")
	}
	if !hasRestrictedEntryForKey(au.body, pub, remoteGateBin) {
		t.Error("restricted entry missing after the rewrite")
	}
	if n := countRestrictedEntries(t, au.body, pub); n != 1 {
		t.Errorf("restricted entries = %d; want exactly 1 (both pastes collapse to one)", n)
	}
	// The unrelated key must still be present.
	if !lineSetHasKey(au.body, otherPub) {
		t.Error("unrelated authorized_keys key was not preserved")
	}
}

// lineSetHasKey reports whether any line in authKeys parses to otherPub.
func lineSetHasKey(authKeys []byte, otherPub ssh.PublicKey) bool {
	want := otherPub.Marshal()
	for _, line := range strings.Split(string(authKeys), "\n") {
		if lineMatchesKey(line, want) {
			return true
		}
	}
	return false
}
