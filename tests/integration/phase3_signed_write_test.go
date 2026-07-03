//go:build integration

// Phase-3 SIGNED-WRITE end-to-end test.
//
// The other Phase-3 tests deliberately stub the signer (noopSign) and so
// only prove the gate's write-DENIAL path over real SSH. Phase-4 proves
// the full signer -> sign -> gate-verify -> execute pipeline, but via the
// SSHGATE_REVOKE *admin verb*. This test closes the remaining gap the operator
// flagged for the server-migration dress rehearsal: a *regular signed
// write* (a redirect run under /bin/sh -c — the shape of useradd /
// systemctl / file-edit migration steps) actually EXECUTING over real SSH
// against the live Tier-2 gate, through the full MCP write path:
//
//   Runner.Run(write) -> sign.Client -> real signer.Daemon (signs
//   locally with the master key on approval) -> SSHGATE_SIG envelope over
//   real SSH -> gate VerifySigned -> /bin/sh -c executes it.
//
// The ONLY substitution vs. production is the approval backend: a real
// deployment routes approval through Telegram + a human tap; here the
// shared auto-approve backend (startSignerAutoApprove, defined in
// phase4_test.go) stands in for that tap, so the daemon's real
// local-signing path runs unchanged. This is the most faithful
// signed-write check possible without a live Telegram round-trip.
package integration_test

import (
	"context"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/karthikeyan5/sshgate/src/mcp/registry"
	signpkg "github.com/karthikeyan5/sshgate/src/mcp/sign"
	sshpkg "github.com/karthikeyan5/sshgate/src/mcp/ssh"
	"github.com/karthikeyan5/sshgate/src/mcp/tools"
)

// TestPhase3SignedWrite_Executes proves the full signed-write path end to
// end over real SSH against a live Tier-2 gate.
func TestPhase3SignedWrite_Executes(t *testing.T) {
	// Baked SSH key (the linuxserver image installs its .pub into
	// authorized_keys) — this becomes the gate-forced key.
	sshPriv, _ := generateSSHKey(t)
	cleanupC := bootContainer(t)
	t.Cleanup(cleanupC)

	// Master signing keypair. gatePub becomes the gate's trust anchor;
	// gatePriv backs the signer daemon.
	gatePriv, gatePub := generateGateKeyPair(t)

	// Install gate + gate.pub and force the gate on the baked key (Tier-2).
	deployGateBinary(t, gatePub)

	// Real signer daemon that auto-approves (stands in for the Telegram
	// tap) — shared helper from phase4_test.go.
	socket, cleanupS := startSignerAutoApprove(t, gatePriv)
	t.Cleanup(cleanupS)

	// Real MCP Runner: registry entry (Tier-2, ReadOnly=false) + live
	// sign.Client + ssh.Client. WriteTTLSec keeps exp-ts within the
	// gate's 5-minute cap.
	regPath := filepath.Join(t.TempDir(), "servers.json")
	servers, err := registry.New(regPath)
	if err != nil {
		t.Fatalf("registry.New: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()

	// The gate fails CLOSED on an empty/mismatched host binding (verify.go —
	// ErrHostMismatch), so the signed write's payload MUST bind to THIS gate's
	// real host-key fingerprint. Production records it at provision time via
	// TOFU; here we pin it the same way (a SSHGATE_VERSION read populates
	// known_hosts) and store it in Entry.Fingerprint, which Runner.Run copies
	// into the signed payload's Host.
	khPath := filepath.Join(t.TempDir(), "known_hosts")
	sshClient := &sshpkg.Client{
		KeyPath:        sshPriv,
		KnownHostsPath: khPath,
		Timeout:        15 * time.Second,
	}
	fp := pinContainerHostFP(ctx, t, sshClient, khPath)

	if err := servers.Add("mig", registry.Entry{
		Host: "127.0.0.1", Port: sshContainerPort, User: remoteUser, AddedAt: time.Now(), Fingerprint: fp,
	}); err != nil {
		t.Fatalf("registry.Add: %v", err)
	}
	runner := &tools.Runner{
		Servers:     servers,
		Sign:        &signpkg.Client{SocketPath: socket, Timeout: 15 * time.Second},
		SSH:         sshClient,
		WriteTTLSec: 60,
	}

	const marker = "signed-write-works"
	const remoteFile = "/tmp/sshgate_signed_ok"

	// 1) Signed write EXECUTES. A redirect makes this unambiguously a
	//    write; the gate must classify it write, require a signature, and
	//    (with one) run it under /bin/sh -c.
	wOut, err := runner.Run(ctx, tools.RunInput{
		Alias:   "mig",
		Command: "echo " + marker + " > " + remoteFile,
	})
	if err != nil {
		t.Fatalf("signed write Run: %v", err)
	}
	if wOut.ExitCode != 0 {
		t.Fatalf("signed write exit=%d; want 0 (stderr=%q)", wOut.ExitCode, wOut.Stderr)
	}
	if wOut.Kind != "write" {
		t.Errorf("Kind=%q; want write", wOut.Kind)
	}
	if !wOut.Approved {
		t.Errorf("Approved=false on a signed write; want true")
	}

	// 2) Read it back through the gate — proves the write actually
	//    persisted on the remote filesystem.
	rOut, err := runner.Run(ctx, tools.RunInput{Alias: "mig", Command: "cat " + remoteFile})
	if err != nil {
		t.Fatalf("read-back Run: %v", err)
	}
	if rOut.ExitCode != 0 {
		t.Fatalf("read-back exit=%d; want 0 (stderr=%q)", rOut.ExitCode, rOut.Stderr)
	}
	if got := trimAll(rOut.Stdout); got != marker {
		t.Errorf("read-back stdout=%q; want %q (the signed write did not take effect)", got, marker)
	}

	// 3) Negative control: an UNSIGNED write straight over SSH (bypassing
	//    the signer) must still be denied with EX_NOPERM (77) on this
	//    Tier-2 gate, and must NOT create a file.
	const bypassFile = "/tmp/sshgate_bypass_should_not_exist"
	_, stderr, exit, err := directUnsignedSSH(t, sshPriv, "127.0.0.1", sshContainerPort, remoteUser,
		"echo nope > "+bypassFile)
	if err == nil && exit == 0 {
		t.Fatalf("unsigned write executed on Tier-2 gate (exit=0); want denial. stderr=%q", stderr)
	}
	if exit != 77 {
		t.Errorf("unsigned write exit=%d; want 77 (EX_NOPERM)", exit)
	}
	if !strings.Contains(string(stderr), "SSHGATE_SIG") {
		t.Errorf("unsigned-write stderr=%q; want the needs-signature message", stderr)
	}
	// Confirm the file was NEVER created — via a PURE READ the gate runs
	// unsigned (`ls` is read-allowlisted). A compound `test -f && echo`
	// would itself be classified write and denied, so use bare `ls`:
	// absent ⇒ ls exits non-zero with "No such file".
	lsOut, lsErr, lsExit, _ := directUnsignedSSH(t, sshPriv, "127.0.0.1", sshContainerPort, remoteUser,
		"ls "+bypassFile)
	if lsExit == 0 {
		t.Errorf("unsigned write created %s on a Tier-2 gate; bypass! (ls stdout=%q)", bypassFile, lsOut)
	}
	if !strings.Contains(string(lsErr), "No such file") {
		t.Errorf("ls probe stderr=%q; want 'No such file' (file should be absent)", lsErr)
	}
}
