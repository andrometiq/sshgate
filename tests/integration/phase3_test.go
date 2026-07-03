//go:build integration

// Phase-3 end-to-end test for SSHGate (task 3.4 / lock criterion for
// task 3.1).
//
// Boots a FRESH linuxserver/openssh-server container with NO gate
// pre-installed, then exercises the human-only CLI provisioning path
// (tools.Provision — the engine behind `sshgate add`):
//
//  1. Success path. The human pastes SSHGate's dedicated PLAIN public
//     key into the target's authorized_keys out-of-band (pasteSSHGate-
//     PlainLine, using the bootstrap key the linuxserver image baked in).
//     Provision then dials with the dedicated key ITSELF, uploads gate +
//     signing pubkey, rewrites the pasted plain line into the restricted
//     command="..." forced-command line (locking the key down), verifies
//     via the SSHGATE_OK probe, and registers the alias. Then a plain
//     `df -h` Runner.Run goes through and works.
//  2. Verify failure → rollback. Point Provision's SSHGatePubPath at a
//     DIFFERENT pubkey than the key it dials with: the rewrite gates the
//     WRONG key and leaves the dedicated key's plain line in place, so the
//     verify re-dial gets a bare shell (no SSHGATE_OK) and fails. Rollback
//     restores authorized_keys from the backup (the bootstrap key still
//     works) AND removes ~/.sshgate-gate/.
//  3. Idempotent re-add (different alias, already-restricted state) →
//     skip rewrite, return Idempotent=true, register the new alias.
//  4. Re-adding the same alias → "already registered" error (fires before
//     any dial, so this subtest needs no container).
//  5. Read-only (tier-1) provision: no gate.pub pushed; reads execute,
//     writes are denied at the gate.
//
// Goroutine leak check at the end mirrors Phases 1-2.
package integration_test

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"go.uber.org/goleak"
	sshlib "golang.org/x/crypto/ssh"

	"github.com/karthikeyan5/sshgate/src/mcp/registry"
	signpkg "github.com/karthikeyan5/sshgate/src/mcp/sign"
	sshpkg "github.com/karthikeyan5/sshgate/src/mcp/ssh"
	"github.com/karthikeyan5/sshgate/src/mcp/tools"
)

func TestPhase3Provision_Success(t *testing.T) {
	// The linuxserver image bakes ONE pubkey into authorized_keys at
	// boot — call that the "bootstrap key" (operator's normal access).
	bootstrapPriv, _ := generateSSHKey(t)
	cleanup := bootContainer(t)
	t.Cleanup(cleanup)

	// SSHGate-dedicated key (separate from bootstrap). The human pastes
	// its PLAIN line first; Provision dials with it and rewrites that line.
	dedicatedPriv, dedicatedPub := generateStandaloneSSHKey(t)
	pasteSSHGatePlainLine(t, dedicatedPub)

	// Cross-compile gate + generate signing keypair.
	gateBin := buildGateLinux(t)
	_, gatePub := generateGateKeyPair(t)

	regPath := filepath.Join(t.TempDir(), "servers.json")
	khPath := filepath.Join(t.TempDir(), "known_hosts")

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	out, err := tools.Provision(ctx, tools.ProvisionConfig{
		GateBinaryPath: gateBin,
		GatePubPath:    gatePub,
		SSHGateKeyPath: dedicatedPriv,
		SSHGatePubPath: dedicatedPub,
		KnownHostsPath: khPath,
		ServersPath:    regPath,
	}, tools.ProvisionInput{
		Alias: "test",
		Host:  "127.0.0.1",
		Port:  sshContainerPort,
		User:  remoteUser,
	})
	if err != nil {
		t.Fatalf("Provision: %v", err)
	}
	if !out.VerifiedOK {
		t.Errorf("VerifiedOK=false; want true")
	}
	if out.Fingerprint == "" {
		t.Errorf("Fingerprint is empty; want a SHA256 capture")
	}
	if !strings.HasPrefix(out.Fingerprint, "SHA256:") {
		t.Errorf("Fingerprint=%q; want SHA256: prefix", out.Fingerprint)
	}
	if out.BinaryPath != "~/.sshgate-gate/gate" {
		t.Errorf("BinaryPath=%q; want ~/.sshgate-gate/gate", out.BinaryPath)
	}
	if out.Idempotent {
		t.Errorf("Idempotent=true on first add; want false")
	}

	// Registry on disk holds the alias. Open it fresh (Provision wrote it
	// via its own *registry.Servers).
	servers, err := registry.New(regPath)
	if err != nil {
		t.Fatalf("registry.New: %v", err)
	}
	if _, ok := servers.Get("test"); !ok {
		t.Errorf("registry does not have 'test' after Provision")
	}

	// Now run a read via the (now gated) dedicated key — confirm gate is
	// in the loop and routes the read through to /bin/sh -c successfully.
	sshClient := &sshpkg.Client{
		KeyPath:        dedicatedPriv,
		KnownHostsPath: khPath,
		Timeout:        15 * time.Second,
	}
	runner := &tools.Runner{
		Servers: servers,
		Sign:    &noopSign{}, // not used by reads
		SSH:     sshClient,
	}
	rdOut, err := runner.Run(ctx, tools.RunInput{Alias: "test", Command: "df -h"})
	if err != nil {
		t.Fatalf("Runner.Run(df -h) after provision: %v", err)
	}
	if rdOut.ExitCode != 0 {
		t.Errorf("df -h exit=%d; want 0 (stderr=%q)", rdOut.ExitCode, rdOut.Stderr)
	}
	if rdOut.Kind != "read" {
		t.Errorf("Kind=%q; want read", rdOut.Kind)
	}

	// Captured fingerprint should match what's now in known_hosts.
	if got := fingerprintFromKnownHosts(t, khPath); got != out.Fingerprint {
		t.Errorf("captured fingerprint=%q; known_hosts has %q", out.Fingerprint, got)
	}

	_ = bootstrapPriv // bootstrap key is only the paste credential here.
}

func TestPhase3Provision_VerifyFailureRollsBack(t *testing.T) {
	bootstrapPriv, _ := generateSSHKey(t)
	cleanup := bootContainer(t)
	t.Cleanup(cleanup)

	// The dedicated key whose PLAIN line we paste and whose PRIVATE half
	// Provision dials with.
	dedicatedPriv, dedicatedPub := generateStandaloneSSHKey(t)
	pasteSSHGatePlainLine(t, dedicatedPub)

	// DELIBERATELY hand Provision a DIFFERENT pubkey via SSHGatePubPath.
	// rewriteAuthorizedKeys then gates the WRONG key and leaves the
	// dedicated key's PLAIN line untouched — so the verify re-dial (with the
	// dedicated key) lands on a bare shell, the empty-command probe returns
	// no SSHGATE_OK, and Provision rolls back.
	_, wrongPub := generateStandaloneSSHKey(t)

	gateBin := buildGateLinux(t)
	_, gatePub := generateGateKeyPair(t)

	regPath := filepath.Join(t.TempDir(), "servers.json")
	khPath := filepath.Join(t.TempDir(), "known_hosts")

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	_, err := tools.Provision(ctx, tools.ProvisionConfig{
		GateBinaryPath: gateBin,
		GatePubPath:    gatePub,
		SSHGateKeyPath: dedicatedPriv,
		// Rewrite locks down THIS (wrong) key; the dial key's plain line
		// survives, so the gated probe never runs → verify fails.
		SSHGatePubPath: wrongPub,
		KnownHostsPath: khPath,
		ServersPath:    regPath,
	}, tools.ProvisionInput{
		Alias: "test",
		Host:  "127.0.0.1",
		Port:  sshContainerPort,
		User:  remoteUser,
	})
	if err == nil {
		t.Fatalf("Provision: nil err; expected verify failure")
	}
	if !strings.Contains(err.Error(), "verify") && !strings.Contains(err.Error(), "SSHGATE_OK") {
		t.Errorf("err=%v; expected message mentioning verify / SSHGATE_OK", err)
	}

	// Registry must NOT have been touched.
	servers, err := registry.New(regPath)
	if err != nil {
		t.Fatalf("registry.New: %v", err)
	}
	if _, ok := servers.Get("test"); ok {
		t.Errorf("registry has 'test' after rollback; should be empty")
	}

	// authorized_keys must have been restored — the BOOTSTRAP key
	// should still work. (If rollback failed, the rewritten file would
	// reject the bootstrap key.)
	stdout, _, exit, err := directUnsignedSSH(t, bootstrapPriv,
		"127.0.0.1", sshContainerPort, remoteUser, "echo BOOTSTRAP_OK")
	if err != nil {
		t.Fatalf("post-rollback bootstrap SSH: %v", err)
	}
	if exit != 0 || !strings.Contains(string(stdout), "BOOTSTRAP_OK") {
		t.Errorf("post-rollback bootstrap SSH exit=%d stdout=%q; bootstrap key was locked out",
			exit, stdout)
	}

	// ~/.sshgate-gate/ must have been removed.
	dirCheck, _, exit, err := directUnsignedSSH(t, bootstrapPriv,
		"127.0.0.1", sshContainerPort, remoteUser, "test -d ~/.sshgate-gate && echo PRESENT || echo ABSENT")
	if err != nil {
		t.Fatalf("post-rollback dir probe: %v", err)
	}
	if !strings.Contains(string(dirCheck), "ABSENT") {
		t.Errorf("~/.sshgate-gate still present after rollback (exit=%d, stdout=%q)", exit, dirCheck)
	}
}

func TestPhase3Provision_AliasAlreadyRegistered(t *testing.T) {
	// Provision's already-registered guard fires BEFORE it reads any local
	// material or dials the remote, so this subtest needs no container.
	regPath := filepath.Join(t.TempDir(), "servers.json")
	servers, err := registry.New(regPath)
	if err != nil {
		t.Fatalf("registry.New: %v", err)
	}
	if err := servers.Add("dup", registry.Entry{
		Host: "h", Port: 22, User: "u", AddedAt: time.Now(),
	}); err != nil {
		t.Fatalf("seed: %v", err)
	}

	_, err = tools.Provision(context.Background(), tools.ProvisionConfig{
		GateBinaryPath: "/nonexistent",
		GatePubPath:    "/nonexistent",
		SSHGateKeyPath: "/nonexistent",
		SSHGatePubPath: "/nonexistent",
		KnownHostsPath: filepath.Join(t.TempDir(), "known_hosts"),
		ServersPath:    regPath,
	}, tools.ProvisionInput{
		Alias: "dup",
		Host:  "127.0.0.1",
		User:  "anyone",
	})
	if err == nil {
		t.Fatalf("Provision: nil err; expected 'already registered'")
	}
	if !strings.Contains(err.Error(), "already registered") {
		t.Errorf("err=%v; expected 'already registered'", err)
	}
}

func TestPhase3Provision_IdempotentReAdd(t *testing.T) {
	bootstrapPriv, _ := generateSSHKey(t)
	cleanup := bootContainer(t)
	t.Cleanup(cleanup)

	dedicatedPriv, dedicatedPub := generateStandaloneSSHKey(t)
	pasteSSHGatePlainLine(t, dedicatedPub)

	gateBin := buildGateLinux(t)
	_, gatePub := generateGateKeyPair(t)

	regPath := filepath.Join(t.TempDir(), "servers.json")
	khPath := filepath.Join(t.TempDir(), "known_hosts")
	cfg := tools.ProvisionConfig{
		GateBinaryPath: gateBin,
		GatePubPath:    gatePub,
		SSHGateKeyPath: dedicatedPriv,
		SSHGatePubPath: dedicatedPub,
		KnownHostsPath: khPath,
		ServersPath:    regPath,
	}

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	out, err := tools.Provision(ctx, cfg, tools.ProvisionInput{
		Alias: "first",
		Host:  "127.0.0.1",
		Port:  sshContainerPort,
		User:  remoteUser,
	})
	if err != nil {
		t.Fatalf("first Provision: %v", err)
	}
	if out.Idempotent {
		t.Errorf("Idempotent=true on first add; want false")
	}

	// Re-provision with a DIFFERENT alias against the same host. The
	// dedicated key is already gated by the restricted entry (and the plain
	// line was rewritten away in the first provision), so Provision detects
	// the canonical restricted entry, skips the rewrite, and just verifies +
	// registers the new alias.
	out2, err := tools.Provision(ctx, cfg, tools.ProvisionInput{
		Alias: "second",
		Host:  "127.0.0.1",
		Port:  sshContainerPort,
		User:  remoteUser,
	})
	if err != nil {
		t.Fatalf("second Provision (idempotent): %v", err)
	}
	if !out2.Idempotent {
		t.Errorf("Idempotent=false on the re-add; want true (restricted entry already present)")
	}

	servers, err := registry.New(regPath)
	if err != nil {
		t.Fatalf("registry.New: %v", err)
	}
	if _, ok := servers.Get("second"); !ok {
		t.Errorf("second alias not registered after idempotent re-add")
	}

	_ = bootstrapPriv // only the paste credential here.
}

// TestPhase3Provision_ReadOnly covers the tier-1 install path: deploy
// gate WITHOUT uploading gate.pub. Reads should still execute
// through the gate (gate's keystore returns (nil, nil) for the
// missing pubkey and treats reads as allowed); writes must be denied
// with the read-only-mode error message and exit code 77.
func TestPhase3Provision_ReadOnly(t *testing.T) {
	bootstrapPriv, _ := generateSSHKey(t)
	cleanup := bootContainer(t)
	t.Cleanup(cleanup)

	dedicatedPriv, dedicatedPub := generateStandaloneSSHKey(t)
	pasteSSHGatePlainLine(t, dedicatedPub)

	gateBin := buildGateLinux(t)
	// GatePubPath points at a non-existent file — Provision in ReadOnly
	// mode must not read it. The tier-1 flow doesn't have it on disk yet.
	gatePubPath := filepath.Join(t.TempDir(), "definitely-not-here.pub")

	regPath := filepath.Join(t.TempDir(), "servers.json")
	khPath := filepath.Join(t.TempDir(), "known_hosts")

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	out, err := tools.Provision(ctx, tools.ProvisionConfig{
		GateBinaryPath: gateBin,
		GatePubPath:    gatePubPath,
		SSHGateKeyPath: dedicatedPriv,
		SSHGatePubPath: dedicatedPub,
		KnownHostsPath: khPath,
		ServersPath:    regPath,
	}, tools.ProvisionInput{
		Alias:    "ro",
		Host:     "127.0.0.1",
		Port:     sshContainerPort,
		User:     remoteUser,
		ReadOnly: true,
	})
	if err != nil {
		t.Fatalf("Provision (read-only): %v", err)
	}
	if !out.ReadOnlyMode {
		t.Errorf("ReadOnlyMode=false on read-only add; want true")
	}
	if !out.VerifiedOK {
		t.Errorf("VerifiedOK=false; want true (probe works regardless of pubkey)")
	}

	// Confirm gate.pub is NOT on the remote.
	probe, _, exit, err := directUnsignedSSH(t, bootstrapPriv,
		"127.0.0.1", sshContainerPort, remoteUser,
		"test -f ~/.sshgate-gate/gate.pub && echo PRESENT || echo ABSENT")
	if err != nil {
		t.Fatalf("pubkey probe: %v", err)
	}
	if !strings.Contains(string(probe), "ABSENT") {
		t.Errorf("gate.pub present on remote in tier-1 (exit=%d, stdout=%q)", exit, probe)
	}

	servers, err := registry.New(regPath)
	if err != nil {
		t.Fatalf("registry.New: %v", err)
	}
	sshClient := &sshpkg.Client{
		KeyPath:        dedicatedPriv,
		KnownHostsPath: khPath,
		Timeout:        15 * time.Second,
	}
	runner := &tools.Runner{
		Servers: servers,
		Sign:    &noopSign{},
		SSH:     sshClient,
	}

	// Read goes through.
	rdOut, err := runner.Run(ctx, tools.RunInput{Alias: "ro", Command: "df -h"})
	if err != nil {
		t.Fatalf("Runner.Run(df -h) on tier-1 server: %v", err)
	}
	if rdOut.ExitCode != 0 {
		t.Errorf("df -h exit=%d; want 0 (stderr=%q)", rdOut.ExitCode, rdOut.Stderr)
	}

	// A write straight over SSH on the gated dedicated key must be denied
	// at the gate (tier-1 has no signer pubkey). SSH_ORIGINAL_COMMAND is
	// set to "rm /tmp/x" by the SSH client; the gate classifies it write
	// and refuses with the read-only-mode message and exit 77.
	_, stderr, exit, err := sshClient.Run(ctx, "127.0.0.1", remoteUser, sshContainerPort, "rm /tmp/x")
	if err == nil && exit == 0 {
		t.Fatalf("write executed on tier-1 server (exit=0, stderr=%q); want denial", stderr)
	}
	if exit != 77 {
		t.Errorf("write exit=%d; want 77 (EX_NOPERM)", exit)
	}
	if !strings.Contains(string(stderr), "no signing key configured") {
		t.Errorf("stderr=%q; want substring %q", stderr, "no signing key configured")
	}
	if !strings.Contains(string(stderr), "/sshgate:setup") {
		t.Errorf("stderr=%q; want substring %q", stderr, "/sshgate:setup")
	}
}

func TestPhase3Provision_NoGoroutineLeaks(t *testing.T) {
	// The other Phase-3 subtests own the heavy lifetimes via t.Cleanup;
	// goleak here is a final sanity check that any docker/SSH goroutines
	// have unwound.
	goleak.VerifyNone(t,
		goleak.IgnoreTopFunction("os/exec.(*Cmd).watchCtx"),
		goleak.IgnoreTopFunction("internal/poll.runtime_pollWait"),
		goleak.IgnoreTopFunction("net/http.(*persistConn).readLoop"),
		goleak.IgnoreTopFunction("net/http.(*persistConn).writeLoop"),
	)
}

// noopSign is a Sign stub that errors if invoked. The Provision path must
// not call Sign at any point; reads after the add must not call Sign
// either (the read path is direct).
type noopSign struct{}

func (noopSign) Sign(_ context.Context, _ string, _ []signpkg.CmdReq) (signpkg.SignResult, error) {
	return signpkg.SignResult{}, errors.New("noopSign: Sign should not be invoked in Phase 3 tests")
}

// The grant methods below exist only so noopSign satisfies the current
// tools.SignClient interface (it grew RequestGrant/RevokeGrant/ListGrants with
// the standing-grants work). No Phase-3 test path mints or lists a grant, so
// each errors if invoked — same fail-if-called posture as Sign.
func (noopSign) RequestGrant(_ context.Context, _, _, _ string, _ []string, _ int64) (string, int64, error) {
	return "", 0, errors.New("noopSign: RequestGrant should not be invoked in Phase 3 tests")
}

func (noopSign) RevokeGrant(_ context.Context, _, _ string) error {
	return errors.New("noopSign: RevokeGrant should not be invoked in Phase 3 tests")
}

func (noopSign) ListGrants(_ context.Context, _, _ string) ([]signpkg.GrantInfo, error) {
	return nil, errors.New("noopSign: ListGrants should not be invoked in Phase 3 tests")
}

// fingerprintFromKnownHosts reads the first host-key line out of path
// and returns its SHA256 fingerprint in "SHA256:..." form.
func fingerprintFromKnownHosts(t *testing.T, path string) string {
	t.Helper()
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read known_hosts %s: %v", path, err)
	}
	for _, line := range strings.Split(string(body), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		// known_hosts line: "host keytype b64"
		parts := strings.Fields(line)
		if len(parts) < 3 {
			continue
		}
		keyBytes, err := base64.StdEncoding.DecodeString(parts[2])
		if err != nil {
			continue
		}
		key, err := sshlib.ParsePublicKey(keyBytes)
		if err != nil {
			continue
		}
		sum := sha256.Sum256(key.Marshal())
		return "SHA256:" + base64.RawStdEncoding.EncodeToString(sum[:])
	}
	t.Fatalf("no host-key line in %s", path)
	return ""
}
