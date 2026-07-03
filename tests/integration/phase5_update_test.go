//go:build integration

// Phase-5 SSHGATE_UPDATE end-to-end tests (spec §9 "Integration").
//
// These prove the signed in-place gate self-update over REAL SSH against a
// live Tier-2 gate, exercising the one path the unit tests can only fake: the
// new gate binary streaming on the SSH session's channel stdin, the gate
// re-hashing what it receives, and an atomic in-place replace of its own
// binary inode.
//
//   Runner.UpdateGate(alias)
//     -> reads the operator's locally-staged gate binary ONCE (hash+bytes)
//     -> sign.Client -> real signer.Daemon (auto-approve backend stands in
//        for the Telegram tap) mints a signature committing to that SHA-256
//     -> RunWithStdin streams the exact approved bytes over real SSH
//     -> gate handleUpdate re-hashes, ELF/arch/size-checks, backs up to
//        gate.bak, atomically replaces ~/.sshgate-gate/gate, prints the
//        SSHGATE_UPDATED marker.
//
// The ONLY substitution vs. production is the approval backend (auto-approve
// instead of a live Telegram round-trip) — the daemon's real local-signing
// path and the gate's real handler run unchanged.
//
// HOST-KEY BINDING. The gate fails CLOSED on an empty/mismatched host binding
// (verify.go:107 — "empty Host on a signed write -> ErrHostMismatch"), so the
// signed payload MUST bind to the container's real SSH host-key fingerprint.
// We derive it from a TOFU-populated known_hosts via fingerprintFromKnownHosts
// and pin it in the registry Entry.Fingerprint / CmdReq.Host — exactly what
// production's provisioning records. (An earlier draft left Fingerprint empty
// on the assumption the gate accepts it; the gate does not.)
//
// Test 1 (happy path) proves the binary is actually replaced, gate.bak holds
// the old binary, the trust anchor (gate.pub) is untouched, and the replaced
// gate is functional (a follow-up signed write executes on it).
//
// Test 2 (tampered stream) proves the gate refuses a stream whose bytes do
// not match the signed hash — over real SSH — and leaves the old gate intact.
// The honest UpdateGate tool always streams what it hashed, so Test 2 bypasses
// it and constructs the wire command by hand (mirroring update_gate.go). It
// asserts the refusal is the HASH-mismatch path (not a host-binding artifact)
// by checking the gate's stderr.
package integration_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/karthikeyan5/sshgate/src/mcp/registry"
	signpkg "github.com/karthikeyan5/sshgate/src/mcp/sign"
	sshpkg "github.com/karthikeyan5/sshgate/src/mcp/ssh"
	"github.com/karthikeyan5/sshgate/src/mcp/tools"
)

// buildGateLinuxTagged cross-compiles the gate for linux/amd64 EXACTLY like
// buildGateLinux, but injects a distinct Go build id via -ldflags "-buildid=".
// buildGateLinux is deterministic, so building it twice yields byte-identical
// output — that would not prove a replacement actually happened. -buildid only
// changes the embedded ELF build-id note (never execution), so the result is a
// fully valid, runnable amd64 gate whose bytes (and thus SHA-256) differ from
// the deployed old gate. It writes to a distinct path so it never clobbers the
// buildGateLinux output the old gate was deployed from.
func buildGateLinuxTagged(t *testing.T, buildid string) string {
	t.Helper()
	root := repoRoot(t)
	out := filepath.Join(root, "bin", "gate-linux-amd64-updated")
	if err := os.MkdirAll(filepath.Dir(out), 0o755); err != nil {
		t.Fatalf("mkdir bin: %v", err)
	}
	cmd := exec.Command("go", "build",
		"-trimpath",
		"-ldflags", "-s -w -buildid="+buildid,
		"-o", out,
		"./src/gate/cmd/sshgate-gate",
	)
	cmd.Dir = root
	cmd.Env = append(os.Environ(), "CGO_ENABLED=0", "GOOS=linux", "GOARCH=amd64")
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("build tagged gate-linux: %v\n%s", err, output)
	}
	return out
}

// sha256File returns the lowercase-hex SHA-256 of a host file's contents —
// the same encoding (hex.EncodeToString of sha256.Sum256) the MCP and gate
// use, so it compares directly against out.NewHash and the gate marker.
func sha256File(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// containerSha256 runs `sha256sum <path>` inside the container and returns the
// leading hex field, so a caller can assert what bytes are actually installed
// on the remote (busybox sha256sum prints "<hex>  <path>").
func containerSha256(t *testing.T, containerPath string) string {
	t.Helper()
	out, err := dockerExec(t, nil, "sha256sum "+containerPath)
	if err != nil {
		t.Fatalf("sha256sum %s in container: %v\n%s", containerPath, err, out)
	}
	fields := strings.Fields(string(out))
	if len(fields) == 0 {
		t.Fatalf("empty sha256sum output for %s", containerPath)
	}
	return fields[0]
}

// pinContainerHostFP does a TOFU read over sshClient to populate known_hosts,
// then returns the container's SSH host-key fingerprint in the exact
// "SHA256:<base64>" form the gate self-derives from /etc/ssh/ssh_host_*.pub and
// enforces on the signed payload. SSHGATE_VERSION is an unsigned read the gate
// always answers with exit 0, so it is a clean way to trigger the TOFU pin.
func pinContainerHostFP(ctx context.Context, t *testing.T, sshClient *sshpkg.Client, khPath string) string {
	t.Helper()
	if _, _, _, err := sshClient.Run(ctx, "127.0.0.1", remoteUser, sshContainerPort, "SSHGATE_VERSION"); err != nil {
		t.Fatalf("TOFU read to pin host key: %v", err)
	}
	return fingerprintFromKnownHosts(t, khPath)
}

// TestUpdateGate_Integration_HappyPath drives Runner.UpdateGate end to end and
// proves the container's gate binary is actually replaced by the streamed
// bytes, that gate.bak holds the old binary, that gate.pub (the trust anchor)
// is untouched, and that the replaced gate is functional.
func TestUpdateGate_Integration_HappyPath(t *testing.T) {
	// Baked SSH key (the linuxserver image installs its .pub into
	// authorized_keys) — this becomes the gate-forced key.
	sshPriv, _ := generateSSHKey(t)
	cleanupC := bootContainer(t)
	t.Cleanup(cleanupC)

	// Master signing keypair: gatePub is the gate's trust anchor; gatePriv
	// backs the signer daemon.
	gatePriv, gatePub := generateGateKeyPair(t)

	// Deploy the OLD gate (deployGateBinary installs the buildGateLinux bytes
	// as a Tier-2 gate). buildGateLinux is deterministic, so hashing its output
	// on the host gives the exact bytes now on the container.
	deployGateBinary(t, gatePub)
	oldHash := sha256File(t, buildGateLinux(t))

	// Real signer daemon that auto-approves (stands in for the Telegram tap).
	socket, cleanupS := startSignerAutoApprove(t, gatePriv)
	t.Cleanup(cleanupS)

	// Stage the NEW gate: byte-different from the old one via -buildid, so a
	// successful replace is provable by a hash change (not a no-op).
	newBin := buildGateLinuxTagged(t, "sshgate-update-integration")
	newBytes, err := os.ReadFile(newBin)
	if err != nil {
		t.Fatalf("read staged new gate: %v", err)
	}
	newHash := sha256File(t, newBin)
	if newHash == oldHash {
		t.Fatalf("staged new gate is byte-identical to the deployed old gate (hash=%s) — the -buildid trick failed and this test would be vacuous", newHash)
	}

	// Trust anchor hash BEFORE the update (must be identical after — R7).
	pubBefore := containerSha256(t, containerHome+"/.sshgate-gate/gate.pub")

	// Generous window: UpdateGate streams a multi-MB binary and the two
	// follow-up writes each do a full SSH round trip.
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()

	// SSH and SSHStdin are the SAME *ssh.Client instance, exactly as production
	// wires them. Pin the container's host-key fingerprint (the gate fails
	// closed on an empty/mismatched Host — see the file header).
	khPath := filepath.Join(t.TempDir(), "known_hosts")
	sshClient := &sshpkg.Client{
		KeyPath:        sshPriv,
		KnownHostsPath: khPath,
		Timeout:        15 * time.Second,
	}
	fp := pinContainerHostFP(ctx, t, sshClient, khPath)

	regPath := filepath.Join(t.TempDir(), "servers.json")
	servers, err := registry.New(regPath)
	if err != nil {
		t.Fatalf("registry.New: %v", err)
	}
	if err := servers.Add("upd", registry.Entry{
		Host: "127.0.0.1", Port: sshContainerPort, User: remoteUser, AddedAt: time.Now(), Fingerprint: fp,
	}); err != nil {
		t.Fatalf("registry.Add: %v", err)
	}
	runner := &tools.Runner{
		Servers:        servers,
		Sign:           &signpkg.Client{SocketPath: socket, Timeout: 15 * time.Second},
		SSH:            sshClient,
		SSHStdin:       sshClient, // same *ssh.Client as SSH (production wires both)
		StagedGatePath: newBin,
		WriteTTLSec:    60,
	}

	out, err := runner.UpdateGate(ctx, tools.UpdateGateInput{Alias: "upd"})
	if err != nil {
		t.Fatalf("UpdateGate: %v", err)
	}
	if out.NewHash != newHash {
		t.Errorf("out.NewHash=%q; want %q (the approved/confirmed hash)", out.NewHash, newHash)
	}
	if !out.VerifiedAlive {
		t.Errorf("out.VerifiedAlive=false; want true (the new gate should answer the liveness re-probe)")
	}
	if out.Size != int64(len(newBytes)) {
		t.Errorf("out.Size=%d; want %d (len of the streamed binary)", out.Size, len(newBytes))
	}

	// The whole point: the container's gate binary is now the streamed bytes.
	// This proves the stdin binary transport works end to end over real SSH.
	if got := containerSha256(t, containerHome+"/.sshgate-gate/gate"); got != newHash {
		t.Errorf("container gate hash=%q; want new %q (the stdin binary transport did NOT replace the gate)", got, newHash)
	}
	// gate.bak holds the OLD binary (out-of-band recovery aid).
	if got := containerSha256(t, containerHome+"/.sshgate-gate/gate.bak"); got != oldHash {
		t.Errorf("container gate.bak hash=%q; want old %q", got, oldHash)
	}
	// gate.pub (trust anchor) untouched across the update.
	pubAfter := containerSha256(t, containerHome+"/.sshgate-gate/gate.pub")
	if pubAfter != pubBefore {
		t.Errorf("gate.pub changed across the update (before=%q after=%q); the trust anchor must be untouched", pubBefore, pubAfter)
	}

	// A follow-up signed write must execute on the NEW gate — proving the
	// replaced binary is a functional Tier-2 gate.
	const marker = "new-gate-works"
	const remoteFile = "/tmp/new_gate_ok"
	wOut, err := runner.Run(ctx, tools.RunInput{Alias: "upd", Command: "echo " + marker + " > " + remoteFile})
	if err != nil {
		t.Fatalf("post-update signed write Run: %v", err)
	}
	if wOut.ExitCode != 0 {
		t.Fatalf("post-update write exit=%d; want 0 (stderr=%q) — new gate not functional", wOut.ExitCode, wOut.Stderr)
	}
	if !wOut.Approved {
		t.Errorf("post-update write Approved=false; want true")
	}
	rOut, err := runner.Run(ctx, tools.RunInput{Alias: "upd", Command: "cat " + remoteFile})
	if err != nil {
		t.Fatalf("post-update read-back Run: %v", err)
	}
	if rOut.ExitCode != 0 {
		t.Fatalf("post-update read-back exit=%d; want 0 (stderr=%q)", rOut.ExitCode, rOut.Stderr)
	}
	if got := trimAll(rOut.Stdout); got != marker {
		t.Errorf("post-update read-back stdout=%q; want %q (new gate did not execute the write)", got, marker)
	}
}

// TestUpdateGate_Integration_TamperedStreamRefused proves the gate refuses a
// stream whose bytes do NOT match the signed hash (R4), over real SSH, writing
// nothing. The honest UpdateGate always streams what it hashed, so we bypass it
// and build the wire by hand: sign a commitment to hash(A) but stream bytes of
// B (B != A). The gate re-hashes B, finds a mismatch, and refuses with exit 65
// before any backup/replace — so the old gate stays intact and no .bak exists.
func TestUpdateGate_Integration_TamperedStreamRefused(t *testing.T) {
	sshPriv, _ := generateSSHKey(t)
	cleanupC := bootContainer(t)
	t.Cleanup(cleanupC)

	gatePriv, gatePub := generateGateKeyPair(t)
	deployGateBinary(t, gatePub)
	oldHash := sha256File(t, buildGateLinux(t))

	socket, cleanupS := startSignerAutoApprove(t, gatePriv)
	t.Cleanup(cleanupS)

	// A = the NEW (tagged) gate; we sign a commitment to hash(A) = Ha ...
	newBin := buildGateLinuxTagged(t, "sshgate-tamper-integration")
	aHash := sha256File(t, newBin) // Ha
	// ... but STREAM B = the OLD gate bytes (a valid gate whose hash != Ha).
	bBytes, err := os.ReadFile(buildGateLinux(t))
	if err != nil {
		t.Fatalf("read old gate bytes for the tampered stream: %v", err)
	}
	if aHash == oldHash {
		t.Fatalf("Ha == hash(streamed B) (%s) — the tampered test would be vacuous; the -buildid trick failed", aHash)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	// Pin the container's host-key fingerprint so the signature VERIFIES and the
	// gate actually reaches handleUpdate — otherwise a host-binding failure would
	// also exit 65 and the test would pass for the WRONG reason.
	khPath := filepath.Join(t.TempDir(), "known_hosts")
	sshClient := &sshpkg.Client{KeyPath: sshPriv, KnownHostsPath: khPath, Timeout: 15 * time.Second}
	fp := pinContainerHostFP(ctx, t, sshClient, khPath)

	// Sign the commitment to Ha via a real sign.Client. No grant is configured,
	// so the auto-approve backend stands in for the human tap and mints it.
	signClient := &signpkg.Client{SocketPath: socket, Timeout: 15 * time.Second}
	cmd := "SSHGATE_UPDATE " + aHash
	res, err := signClient.Sign(ctx, "r_tamper_integration", []signpkg.CmdReq{{
		Server: "upd", Cmd: cmd, TTLSec: 300, Host: fp,
	}})
	if err != nil {
		t.Fatalf("Sign the update commitment: %v", err)
	}
	if len(res.Signed) != 1 {
		t.Fatalf("expected 1 signature; got %d", len(res.Signed))
	}
	// Mirror update_gate.go's wireCmd = sig + " " + cmd.
	wire := res.Signed[0].Sig + " " + cmd

	// Stream B with a signature that commits to Ha, over real SSH. NOTE the
	// RunWithStdin arg order is (ctx, host, user, port, cmd, stdin).
	stdout, stderr, exit, err := sshClient.RunWithStdin(ctx, "127.0.0.1", remoteUser, sshContainerPort, wire, bytes.NewReader(bBytes))
	if err != nil {
		t.Fatalf("RunWithStdin: %v (stderr=%q)", err, strings.TrimSpace(string(stderr)))
	}
	// The gate refuses a hash mismatch with EX_DATAERR (65), writing nothing.
	if exit != 65 {
		t.Errorf("gate exit=%d; want 65 (EX_DATAERR hash-mismatch refusal). stdout=%q stderr=%q",
			exit, strings.TrimSpace(string(stdout)), strings.TrimSpace(string(stderr)))
	}
	// Prove the refusal is the HASH check (the signature verified and the gate
	// reached handleUpdate), not a host-binding artifact that also exits 65.
	if !strings.Contains(string(stderr), "hash mismatch") {
		t.Errorf("gate stderr=%q; want it to mention a hash mismatch (proving handleUpdate ran and refused on the hash, not on host binding)", strings.TrimSpace(string(stderr)))
	}

	// The refusal wrote nothing: the container gate is still the OLD binary.
	if got := containerSha256(t, containerHome+"/.sshgate-gate/gate"); got != oldHash {
		t.Errorf("container gate hash=%q; want old %q — a refused (hash-mismatch) update must NOT replace the binary", got, oldHash)
	}
	// And no backup was created (the refusal short-circuits before the backup).
	bakOut, _ := dockerExec(t, nil,
		"test -f "+containerHome+"/.sshgate-gate/gate.bak && echo PRESENT || echo ABSENT")
	if !strings.Contains(string(bakOut), "ABSENT") {
		t.Errorf("gate.bak present after a refused update (stdout=%q); a hash-mismatch refusal writes nothing", bakOut)
	}
}
