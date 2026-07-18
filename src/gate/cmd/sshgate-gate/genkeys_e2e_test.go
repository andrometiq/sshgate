package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/karthikeyan5/sshgate/pkg/signerkit"
)

// This file is the PROVISIONING-LEVEL end-to-end gate (P4 spec §8). It differs
// from the P3 grep-the-logs e2e in one load-bearing way: the two gates' transfer
// keys are created by the REAL `gate genkeys` ARGV subcommand (not pre-seeded),
// registered into a REAL signer XferRegistry via the REAL register_xfer_key
// handler (human-approved through MockBackend), and the two legs are minted by
// the REAL signer transfer handler. It then runs SEND→RECV against the
// genkeys-provisioned key files and greps every accountability surface for the
// plaintext. This proves the PROVISIONED keys work end-to-end and never leak.

// gkConn is a tiny in-memory read/write conn for driving the daemon.
type gkConn struct {
	in  *bytes.Reader
	out *bytes.Buffer
}

func (c *gkConn) Read(p []byte) (int, error)  { return c.in.Read(p) }
func (c *gkConn) Write(p []byte) (int, error) { return c.out.Write(p) }

// genKeysOnGate runs the REAL `runGenKeys(args)` against dir (via the gateDirFn
// seam), writing the key files into dir and returning the two PUBLIC lines.
func genKeysOnGate(t *testing.T, dir string, args ...string) (boxLine, idLine string) {
	t.Helper()
	prev := gateDirFn
	gateDirFn = func() (string, string, error) { return dir, filepath.Join(dir, "gate"), nil }
	defer func() { gateDirFn = prev }()
	out := captureStdout(t, func() {
		if rc := runGenKeys(args); rc != exitOK {
			t.Fatalf("runGenKeys(%v) rc=%d", args, rc)
		}
	})
	for _, l := range strings.Split(out, "\n") {
		switch {
		case strings.HasPrefix(l, "sshgate-xfer-box-x25519 "):
			boxLine = l
		case strings.HasPrefix(l, "sshgate-xfer-id-ed25519 "):
			idLine = l
		}
	}
	if boxLine == "" || idLine == "" {
		t.Fatalf("genkeys readback missing lines:\n%s", out)
	}
	return boxLine, idLine
}

// buildSignerDaemon builds a real Daemon with an on-disk XferRegistry + audit log
// and a MockBackend the caller drives with Approve.
func buildSignerDaemon(t *testing.T, priv ed25519.PrivateKey, auditPath, regPath string) (*signerkit.Daemon, *signerkit.MockBackend) {
	t.Helper()
	reg, err := signerkit.LoadXferRegistry(regPath)
	if err != nil {
		t.Fatalf("load registry: %v", err)
	}
	audit, err := signerkit.OpenAuditLog(auditPath)
	if err != nil {
		t.Fatalf("open audit: %v", err)
	}
	t.Cleanup(func() { _ = audit.Close() })
	mock := signerkit.NewMockBackend()
	return &signerkit.Daemon{Key: priv, Backend: mock, Audit: audit, XferRegistry: reg}, mock
}

func registerViaDaemon(t *testing.T, d *signerkit.Daemon, mock *signerkit.MockBackend, reqID, fp, label, box, id string) {
	t.Helper()
	mock.Approve(reqID, "operator")
	body := map[string]any{
		"kind": "register_xfer_key", "request_id": reqID, "host_fp": fp,
		"label": label, "box_pub": box, "id_pub": id,
	}
	raw, _ := json.Marshal(body)
	conn := &gkConn{in: bytes.NewReader(append(raw, '\n')), out: &bytes.Buffer{}}
	if err := d.HandleSignRequest(context.Background(), conn); err != nil {
		t.Fatalf("register HandleSignRequest: %v", err)
	}
	var resp struct {
		Status string `json:"status"`
		Error  string `json:"error"`
	}
	_ = json.Unmarshal(bytes.TrimRight(conn.out.Bytes(), "\n"), &resp)
	if resp.Status != "approved" {
		t.Fatalf("register %s: status=%q err=%q", fp, resp.Status, resp.Error)
	}
}

func mintTransferLegs(t *testing.T, d *signerkit.Daemon, mock *signerkit.MockBackend, reqID, srcFP, srcPath, destFP, destPath string) (sendSig, recvSig, xferID string) {
	t.Helper()
	mock.Approve(reqID, "operator")
	body := map[string]any{
		"kind": "transfer", "request_id": reqID,
		"src_alias": "src", "src_fp": srcFP, "src_path": srcPath,
		"dest_alias": "dst", "dest_fp": destFP, "dest_path": destPath,
		"mode": "0600", "ttl_seconds": 60,
	}
	raw, _ := json.Marshal(body)
	conn := &gkConn{in: bytes.NewReader(append(raw, '\n')), out: &bytes.Buffer{}}
	if err := d.HandleSignRequest(context.Background(), conn); err != nil {
		t.Fatalf("transfer HandleSignRequest: %v", err)
	}
	var resp struct {
		Status string `json:"status"`
		XferID string `json:"xfer_id"`
		Send   *struct {
			Cmd string `json:"cmd"`
			Sig string `json:"sig"`
		} `json:"send"`
		Recv *struct {
			Cmd string `json:"cmd"`
			Sig string `json:"sig"`
		} `json:"recv"`
		Error string `json:"error"`
	}
	_ = json.Unmarshal(bytes.TrimRight(conn.out.Bytes(), "\n"), &resp)
	if resp.Status != "approved" || resp.Send == nil || resp.Recv == nil {
		t.Fatalf("mint legs: status=%q err=%q", resp.Status, resp.Error)
	}
	return resp.Send.Sig, resp.Recv.Sig, resp.XferID
}

func assertKeyFile0600(t *testing.T, path string) {
	t.Helper()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat %s: %v", path, err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Errorf("%s mode = %#o; want 0600", path, info.Mode().Perm())
	}
}

const (
	provFPA = "SHA256:provE2EhostA-aaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	provFPB = "SHA256:provE2EhostB-bbbbbbbbbbbbbbbbbbbbbbbbbbbb"
)

// TestProvisioningE2E_GenkeysRegisterTransfer is the headline P4 gate.
func TestProvisioningE2E_GenkeysRegisterTransfer(t *testing.T) {
	const sentinel = "XFERSECRET-provisioning-e2e-9x8y7z0q1w2e"
	signerPub, signerPriv := genKey(t)

	dirA := t.TempDir()
	seedPub(t, dirA, signerPub, 0o644)
	seedAuditAllFull(t, dirA)
	dirB := t.TempDir()
	seedPub(t, dirB, signerPub, 0o644)
	seedAuditAllFull(t, dirB)

	// PROVISION transfer keys on each host with genkeys (argv) — not pre-seeded.
	boxA, idA := genKeysOnGate(t, dirA)
	boxB, idB := genKeysOnGate(t, dirB)
	assertKeyFile0600(t, filepath.Join(dirA, "xfer-box.key"))
	assertKeyFile0600(t, filepath.Join(dirA, "xfer-id.key"))
	assertKeyFile0600(t, filepath.Join(dirB, "xfer-box.key"))
	assertKeyFile0600(t, filepath.Join(dirB, "xfer-id.key"))

	signerAudit := filepath.Join(t.TempDir(), "signer-audit.log")
	regPath := filepath.Join(t.TempDir(), "xfer-registry.json")
	d, mock := buildSignerDaemon(t, signerPriv, signerAudit, regPath)

	// REGISTER each host's genkeys-produced public lines (human-approved).
	registerViaDaemon(t, d, mock, "regA", provFPA, "host-a", boxA, idA)
	registerViaDaemon(t, d, mock, "regB", provFPB, "host-b", boxB, idB)

	srcPath := filepath.Join(t.TempDir(), "secret.env")
	if err := os.WriteFile(srcPath, []byte(sentinel), 0o600); err != nil {
		t.Fatal(err)
	}
	destPath := filepath.Join(t.TempDir(), "delivered.env")

	sendSig, recvSig, xferID := mintTransferLegs(t, d, mock, "xfer1", provFPA, srcPath, provFPB, destPath)

	// SEND on gate A → envelope (ciphertext) to stdout.
	envelope, stderrA, codeA := driveGate(t, dirA, provFPA, sendSig, nil)
	if codeA != 0 {
		t.Fatalf("SEND rc=%d stderr=%q", codeA, stderrA)
	}
	if envelope == "" {
		t.Fatal("SEND produced no envelope")
	}
	// RECV on gate B (envelope on stdin) → marker to stdout, plaintext to dest.
	marker, stderrB, codeB := driveGate(t, dirB, provFPB, recvSig, []byte(envelope))
	if codeB != 0 {
		t.Fatalf("RECV rc=%d stderr=%q", codeB, stderrB)
	}

	// Positive control: the transfer delivered the sentinel to the dest.
	got, err := os.ReadFile(destPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != sentinel {
		t.Fatalf("dest = %q; want the sentinel", got)
	}

	// Grep-the-logs: the sentinel must be ABSENT from every surface.
	surfaces := map[string]string{
		"gate A audit":          readFileOrEmpty(filepath.Join(dirA, "audit.log")),
		"gate B audit":          readFileOrEmpty(filepath.Join(dirB, "audit.log")),
		"signer audit":          readFileOrEmpty(signerAudit),
		"SEND stderr":           stderrA,
		"RECV stderr":           stderrB,
		"RECV marker (stdout)":  marker,
		"envelope (ciphertext)": envelope,
	}
	for name, body := range surfaces {
		if strings.Contains(body, sentinel) {
			t.Errorf("CONFIDENTIALITY: sentinel leaked into %s:\n%s", name, body)
		}
	}
	if !strings.Contains(marker, xferID) {
		t.Errorf("RECV marker missing the xferID metadata %q: %q", xferID, marker)
	}
}

// TestRotationFailClosedAndLiveness proves §4.2: after gate B rotates its keys,
// a STALE envelope sealed to the pre-rotation box key fails RECV open (exit 65,
// dest untouched), and a FRESH transfer after re-registration succeeds.
func TestRotationFailClosedAndLiveness(t *testing.T) {
	const sentinel = "XFERSECRET-rotation-live-7z6y5x4w3v2u"
	signerPub, signerPriv := genKey(t)

	dirA := t.TempDir()
	seedPub(t, dirA, signerPub, 0o644)
	seedAuditAllFull(t, dirA)
	dirB := t.TempDir()
	seedPub(t, dirB, signerPub, 0o644)
	seedAuditAllFull(t, dirB)

	boxA, idA := genKeysOnGate(t, dirA)
	boxB, idB := genKeysOnGate(t, dirB)

	regPath := filepath.Join(t.TempDir(), "xfer-registry.json")
	d, mock := buildSignerDaemon(t, signerPriv, filepath.Join(t.TempDir(), "signer-audit.log"), regPath)
	registerViaDaemon(t, d, mock, "regA", provFPA, "host-a", boxA, idA)
	registerViaDaemon(t, d, mock, "regB", provFPB, "host-b", boxB, idB)

	srcPath := filepath.Join(t.TempDir(), "secret.env")
	if err := os.WriteFile(srcPath, []byte(sentinel), 0o600); err != nil {
		t.Fatal(err)
	}
	destPath := filepath.Join(t.TempDir(), "delivered.env")

	// Mint + run a transfer that seals to the OLD box key, capturing the envelope
	// and the RECV leg (bound to the pre-rotation keys).
	sendSig, staleRecvSig, _ := mintTransferLegs(t, d, mock, "pre", provFPA, srcPath, provFPB, destPath)
	staleEnvelope, _, codeSend := driveGate(t, dirA, provFPA, sendSig, nil)
	if codeSend != 0 || staleEnvelope == "" {
		t.Fatalf("pre-rotation SEND failed rc=%d", codeSend)
	}

	// ROTATE gate B's keys on the host (overwrite), capturing the NEW public lines.
	newBoxB, newIDB := genKeysOnGate(t, dirB, "--rotate")

	// Replay the STALE envelope + stale RECV leg against the rotated box key →
	// open must fail closed (exit 65), dest untouched.
	_, _, codeStale := driveGate(t, dirB, provFPB, staleRecvSig, []byte(staleEnvelope))
	if codeStale != exitDataErr {
		t.Errorf("stale envelope after rotation: rc=%d; want %d (fail-closed open)", codeStale, exitDataErr)
	}
	if _, err := os.Stat(destPath); err == nil {
		t.Error("stale envelope wrote the dest file after rotation; must fail closed with nothing written")
	}

	// Re-register gate B under the SAME fp with its NEW public lines, then a FRESH
	// transfer must succeed against the rotated keys (liveness).
	registerViaDaemon(t, d, mock, "regB2", provFPB, "host-b", newBoxB, newIDB)

	freshDest := filepath.Join(t.TempDir(), "fresh.env")
	sendSig2, recvSig2, _ := mintTransferLegs(t, d, mock, "post", provFPA, srcPath, provFPB, freshDest)
	env2, _, codeSend2 := driveGate(t, dirA, provFPA, sendSig2, nil)
	if codeSend2 != 0 {
		t.Fatalf("post-rotation SEND rc=%d", codeSend2)
	}
	_, stderr2, codeRecv2 := driveGate(t, dirB, provFPB, recvSig2, []byte(env2))
	if codeRecv2 != 0 {
		t.Fatalf("post-rotation RECV rc=%d stderr=%q", codeRecv2, stderr2)
	}
	got, err := os.ReadFile(freshDest)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != sentinel {
		t.Errorf("post-rotation dest = %q; want the sentinel (rotation liveness)", got)
	}
}
