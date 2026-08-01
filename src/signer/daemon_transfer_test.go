package signer_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"path/filepath"
	"testing"
	"time"

	"github.com/karthikeyan5/sshgate/pkg/signerkit"
	"github.com/karthikeyan5/sshgate/src/gate"
	"github.com/karthikeyan5/sshgate/src/xfer"
	"github.com/karthikeyan5/sshgate/src/xferwire"
)

// transferRespDecoded is the decoded "transfer" response shape.
type transferRespDecoded struct {
	RequestID string `json:"request_id"`
	Status    string `json:"status"`
	AuthMode  string `json:"auth_mode"`
	XferID    string `json:"xfer_id"`
	Send      *struct {
		Cmd string `json:"cmd"`
		Sig string `json:"sig"`
	} `json:"send"`
	Recv *struct {
		Cmd string `json:"cmd"`
		Sig string `json:"sig"`
	} `json:"recv"`
	Error string `json:"error"`
}

// registerHostResp is the decoded "register_xfer_key" response shape.
type registerHostResp struct {
	RequestID string `json:"request_id"`
	Status    string `json:"status"`
	Error     string `json:"error"`
}

// newXferDaemon builds a Daemon wired with a fresh (empty) on-disk transfer
// registry plus the given backend and a fixed clock. Returns the daemon, its
// master public key, the audit-log path, and the registry so a test can
// pre-register peers.
func newXferDaemon(t *testing.T, bk signerkit.Backend, base time.Time) (*signerkit.Daemon, ed25519.PublicKey, string, *signerkit.XferRegistry) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("genkey: %v", err)
	}
	auditPath := filepath.Join(t.TempDir(), "audit.log")
	audit, err := signerkit.OpenAuditLog(auditPath)
	if err != nil {
		t.Fatalf("open audit: %v", err)
	}
	t.Cleanup(func() { audit.Close() })
	reg, err := signerkit.LoadXferRegistry(filepath.Join(t.TempDir(), "xfer-registry.json"))
	if err != nil {
		t.Fatalf("load registry: %v", err)
	}
	d := &signerkit.Daemon{
		Key:          priv,
		Backend:      bk,
		Audit:        audit,
		NowFunc:      func() time.Time { return base },
		XferRegistry: reg,
	}
	return d, pub, auditPath, reg
}

// registerHost generates a fresh box+id keypair, registers it under fp, and
// returns the box public key and id public key for later assertions.
func registerHost(t *testing.T, reg *signerkit.XferRegistry, fp, label string) (*[32]byte, ed25519.PublicKey) {
	t.Helper()
	bk, err := xfer.GenerateBoxKey()
	if err != nil {
		t.Fatalf("gen box: %v", err)
	}
	ik, err := xfer.GenerateIDKey()
	if err != nil {
		t.Fatalf("gen id: %v", err)
	}
	if err := reg.Register(fp, label, bk.PublicText(), ik.PublicText()); err != nil {
		t.Fatalf("register %s: %v", fp, err)
	}
	return bk.Public(), ik.Public()
}

// driveTransfer sends a "transfer" request through the daemon and returns the
// decoded response. The mock approval for reqID must be pre-armed by the caller.
func driveTransfer(t *testing.T, d *signerkit.Daemon, reqID, srcFP, srcPath, destFP, destPath, mode string, ttl int64) transferRespDecoded {
	t.Helper()
	body := map[string]any{
		"kind":        "transfer",
		"request_id":  reqID,
		"src_alias":   "src-alias",
		"src_fp":      srcFP,
		"src_path":    srcPath,
		"dest_alias":  "dest-alias",
		"dest_fp":     destFP,
		"dest_path":   destPath,
		"mode":        mode,
		"ttl_seconds": ttl,
	}
	raw, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("marshal transfer req: %v", err)
	}
	conn := &memConn{in: bytes.NewReader(append(raw, '\n')), out: &bytes.Buffer{}}
	if err := d.HandleSignRequest(context.Background(), conn); err != nil {
		t.Fatalf("HandleSignRequest(transfer): %v", err)
	}
	var resp transferRespDecoded
	if err := json.Unmarshal(bytes.TrimRight(conn.out.Bytes(), "\n"), &resp); err != nil {
		t.Fatalf("decode transfer resp: %v\nraw=%q", err, conn.out.String())
	}
	return resp
}

// TestTransfer_ApprovedTwoLegs is the core test: one approval yields two legs
// with the correct per-leg Host binding, a fresh xferID, and box/id pubkeys
// sourced FROM THE REGISTRY (never the request). Each leg verifies through
// gate.VerifySigned with the master pubkey and the right self-host set.
func TestTransfer_ApprovedTwoLegs(t *testing.T) {
	t.Parallel()
	base := time.Unix(1000, 0)
	mock := signerkit.NewMockBackend()
	d, pub, _, reg := newXferDaemon(t, mock, base)

	srcFP := "SHA256:src-fp-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	destFP := "SHA256:dst-fp-bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	_, srcIDPub := registerHost(t, reg, srcFP, "src-host")
	destBoxPub, _ := registerHost(t, reg, destFP, "dest-host")

	mock.Approve("t_ok", "operator")
	resp := driveTransfer(t, d, "t_ok", srcFP, "/etc/secret.env", destFP, "/etc/dest.env", "0600", 60)

	if resp.Status != "approved" {
		t.Fatalf("status = %q (err=%q); want approved", resp.Status, resp.Error)
	}
	if resp.AuthMode != "human" {
		t.Errorf("auth_mode = %q; want human", resp.AuthMode)
	}
	if !xferwire.ValidXferID(resp.XferID) {
		t.Errorf("xfer_id %q is not a valid minted id", resp.XferID)
	}
	if resp.Send == nil || resp.Recv == nil {
		t.Fatal("approved but a leg is missing")
	}

	// SEND leg: verifies only against the SOURCE gate's host set.
	sendInner, _, err := gate.VerifySigned(resp.Send.Sig, pub, base, []string{srcFP})
	if err != nil {
		t.Fatalf("verify SEND leg (src host set): %v", err)
	}
	if sendInner != resp.Send.Cmd {
		t.Errorf("SEND inner cmd mismatch")
	}
	// Cross-host un-replayability: the SEND leg must NOT verify on the dest gate.
	if _, _, err := gate.VerifySigned(resp.Send.Sig, pub, base, []string{destFP}); err == nil {
		t.Error("SEND leg verified on the DEST gate — host binding broken")
	}

	// RECV leg: verifies only against the DEST gate's host set.
	recvInner, _, err := gate.VerifySigned(resp.Recv.Sig, pub, base, []string{destFP})
	if err != nil {
		t.Fatalf("verify RECV leg (dest host set): %v", err)
	}
	if recvInner != resp.Recv.Cmd {
		t.Errorf("RECV inner cmd mismatch")
	}
	if _, _, err := gate.VerifySigned(resp.Recv.Sig, pub, base, []string{srcFP}); err == nil {
		t.Error("RECV leg verified on the SRC gate — host binding broken")
	}

	// Decode both legs and prove the pubkeys came from the REGISTRY.
	sendLeg, err := xferwire.ParseSend(resp.Send.Cmd)
	if err != nil {
		t.Fatalf("ParseSend: %v", err)
	}
	if *sendLeg.BoxPub != *destBoxPub {
		t.Error("SEND leg box key is not the DEST's registered box key")
	}
	if sendLeg.DestID != destFP || sendLeg.SrcPath != "/etc/secret.env" {
		t.Errorf("SEND fields wrong: %+v", sendLeg)
	}
	if sendLeg.XferID != resp.XferID {
		t.Error("SEND xferID != response xferID")
	}

	recvLeg, err := xferwire.ParseRecv(resp.Recv.Cmd)
	if err != nil {
		t.Fatalf("ParseRecv: %v", err)
	}
	if !bytes.Equal(recvLeg.IDPub, srcIDPub) {
		t.Error("RECV leg id key is not the SRC's registered id key")
	}
	if recvLeg.SrcID != srcFP || recvLeg.DestID != destFP || recvLeg.Mode != "0600" || recvLeg.DestPath != "/etc/dest.env" {
		t.Errorf("RECV fields wrong: %+v", recvLeg)
	}
	if recvLeg.XferID != resp.XferID {
		t.Error("RECV xferID != response xferID")
	}
}

// TestTransfer_FreshXferIDPerApproval: two transfers mint distinct xferIDs.
func TestTransfer_FreshXferIDPerApproval(t *testing.T) {
	t.Parallel()
	mock := signerkit.NewMockBackend()
	d, _, _, reg := newXferDaemon(t, mock, time.Unix(1000, 0))
	srcFP := "SHA256:src-fp-cccccccccccccccccccccccccccccccc"
	destFP := "SHA256:dst-fp-dddddddddddddddddddddddddddddddd"
	registerHost(t, reg, srcFP, "s")
	registerHost(t, reg, destFP, "d")

	mock.Approve("t1", "k")
	r1 := driveTransfer(t, d, "t1", srcFP, "/a", destFP, "/b", "0600", 60)
	mock.Approve("t2", "k")
	r2 := driveTransfer(t, d, "t2", srcFP, "/a", destFP, "/b", "0600", 60)
	if r1.XferID == "" || r1.XferID == r2.XferID {
		t.Errorf("xferIDs not fresh per approval: %q vs %q", r1.XferID, r2.XferID)
	}
}

// TestTransfer_UnregisteredFails: an unregistered src or dest fp fails at the
// registry lookup — no signing, error status.
func TestTransfer_UnregisteredFails(t *testing.T) {
	t.Parallel()
	mock := signerkit.NewMockBackend()
	d, _, _, reg := newXferDaemon(t, mock, time.Unix(1000, 0))
	srcFP := "SHA256:src-fp-eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"
	destFP := "SHA256:dst-fp-ffffffffffffffffffffffffffffffff"
	registerHost(t, reg, srcFP, "s") // only src registered

	// dest unregistered.
	resp := driveTransfer(t, d, "t_nodst", srcFP, "/a", destFP, "/b", "0600", 60)
	if resp.Status != "error" || resp.Send != nil {
		t.Errorf("unregistered dest: status=%q send=%v; want error/no-leg", resp.Status, resp.Send)
	}

	// src unregistered (register only dest).
	d2, _, _, reg2 := newXferDaemon(t, signerkit.NewMockBackend(), time.Unix(1000, 0))
	registerHost(t, reg2, destFP, "d")
	resp2 := driveTransfer(t, d2, "t_nosrc", srcFP, "/a", destFP, "/b", "0600", 60)
	if resp2.Status != "error" || resp2.Send != nil {
		t.Errorf("unregistered src: status=%q; want error", resp2.Status)
	}
}

// TestTransfer_SelfTransferRejected: src_fp == dest_fp is refused.
func TestTransfer_SelfTransferRejected(t *testing.T) {
	t.Parallel()
	mock := signerkit.NewMockBackend()
	d, _, _, reg := newXferDaemon(t, mock, time.Unix(1000, 0))
	fp := "SHA256:same-fp-11111111111111111111111111111111"
	registerHost(t, reg, fp, "x")
	resp := driveTransfer(t, d, "t_self", fp, "/a", fp, "/b", "0600", 60)
	if resp.Status != "error" {
		t.Errorf("self-transfer: status=%q; want error", resp.Status)
	}
}

// TestTransfer_BadModeRejected: a mode outside the P2 allowlist is refused.
func TestTransfer_BadModeRejected(t *testing.T) {
	t.Parallel()
	mock := signerkit.NewMockBackend()
	d, _, _, reg := newXferDaemon(t, mock, time.Unix(1000, 0))
	srcFP := "SHA256:src-fp-22222222222222222222222222222222"
	destFP := "SHA256:dst-fp-33333333333333333333333333333333"
	registerHost(t, reg, srcFP, "s")
	registerHost(t, reg, destFP, "d")
	resp := driveTransfer(t, d, "t_mode", srcFP, "/a", destFP, "/b", "0755", 60)
	if resp.Status != "error" {
		t.Errorf("bad mode: status=%q; want error", resp.Status)
	}
}

// TestTransfer_NilRegistryFailsClosed: a daemon built without a registry
// refuses transfers with a clear error rather than nil-panicking.
func TestTransfer_NilRegistryFailsClosed(t *testing.T) {
	t.Parallel()
	d, _, _, _ := newXferDaemon(t, signerkit.NewMockBackend(), time.Unix(1000, 0))
	d.XferRegistry = nil
	resp := driveTransfer(t, d, "t_noreg", "SHA256:a-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "/a", "SHA256:b-bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", "/b", "0600", 60)
	if resp.Status != "error" {
		t.Errorf("nil registry: status=%q; want error", resp.Status)
	}
}

// TestSignPath_RejectsTransferVerb is the confused-deputy guard: a generic sign
// request whose command is SSHGATE_XFER_SEND is REJECTED — transfers cannot ride
// the sign path (where the recipient key would come from the request), even with
// a live scope=all grant that would otherwise auto-sign.
func TestSignPath_RejectsTransferVerb(t *testing.T) {
	t.Parallel()
	base := time.Unix(1000, 0)
	mock := signerkit.NewMockBackend()
	d, _, auditPath, _ := newXferDaemon(t, mock, base)

	// Even with a standing grant covering ALL commands on the alias, the sign
	// path must reject the transfer verb before matchGrant.
	mock.Approve("g_all", "operator")
	createGrant(t, d, "g_all", "prod", "all", nil, 3600)

	xferCmd := "SSHGATE_XFER_SEND c3NoZ2F0ZS14ZmVyLWJveA aaaa bbbb cccc"
	req := map[string]any{
		"kind":       "sign",
		"request_id": "s_xfer",
		"commands":   []map[string]any{{"server": "prod", "cmd": xferCmd, "ttl_seconds": 60}},
	}
	raw, _ := json.Marshal(req)
	conn := &memConn{in: bytes.NewReader(append(raw, '\n')), out: &bytes.Buffer{}}
	if err := d.HandleSignRequest(context.Background(), conn); err != nil {
		t.Fatalf("HandleSignRequest: %v", err)
	}
	var resp grantSignResp
	if err := json.Unmarshal(bytes.TrimRight(conn.out.Bytes(), "\n"), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.Status != "error" {
		t.Fatalf("transfer verb on sign path: status=%q; want error (grant must NOT auto-sign it)", resp.Status)
	}
	if len(resp.Signatures) != 0 {
		t.Error("transfer verb produced signatures on the sign path")
	}
	// Audited as an error, not a signed write.
	if got := authModeFor(t, auditPath, "s_xfer"); got != "" {
		t.Errorf("rejected transfer verb recorded auth_mode=%q; want empty", got)
	}
}

// TestRegisterXferKey_ApprovedWrites: register_xfer_key always prompts the
// backend and writes the registry ONLY on approval.
func TestRegisterXferKey_ApprovedWrites(t *testing.T) {
	t.Parallel()
	mock := signerkit.NewMockBackend()
	d, _, _, reg := newXferDaemon(t, mock, time.Unix(1000, 0))
	bk, _ := xfer.GenerateBoxKey()
	ik, _ := xfer.GenerateIDKey()
	fp := "SHA256:reg-host-44444444444444444444444444444444"

	mock.Approve("reg1", "operator")
	resp := driveRegister(t, d, "reg1", fp, "new-host", bk.PublicText(), ik.PublicText())
	if resp.Status != "approved" {
		t.Fatalf("register status=%q (err=%q); want approved", resp.Status, resp.Error)
	}
	if _, _, label, ok := reg.Lookup(fp); !ok || label != "new-host" {
		t.Error("approved register did not land in the registry")
	}
}

// TestRegisterXferKey_DeniedNoWrite: a denied registration leaves the registry
// unchanged (and still routes through the backend — no auto path).
func TestRegisterXferKey_DeniedNoWrite(t *testing.T) {
	t.Parallel()
	mock := signerkit.NewMockBackend()
	d, _, _, reg := newXferDaemon(t, mock, time.Unix(1000, 0))
	bk, _ := xfer.GenerateBoxKey()
	ik, _ := xfer.GenerateIDKey()
	fp := "SHA256:reg-host-55555555555555555555555555555555"

	mock.Deny("reg_deny")
	resp := driveRegister(t, d, "reg_deny", fp, "nope", bk.PublicText(), ik.PublicText())
	if resp.Status != "denied" {
		t.Fatalf("register status=%q; want denied", resp.Status)
	}
	if _, _, _, ok := reg.Lookup(fp); ok {
		t.Error("denied register still wrote the registry")
	}
}

// driveRegister sends a register_xfer_key request and returns the decoded
// response.
func driveRegister(t *testing.T, d *signerkit.Daemon, reqID, fp, label, boxText, idText string) registerHostResp {
	t.Helper()
	body := map[string]any{
		"kind":       "register_xfer_key",
		"request_id": reqID,
		"host_fp":    fp,
		"label":      label,
		"box_pub":    boxText,
		"id_pub":     idText,
	}
	raw, _ := json.Marshal(body)
	conn := &memConn{in: bytes.NewReader(append(raw, '\n')), out: &bytes.Buffer{}}
	if err := d.HandleSignRequest(context.Background(), conn); err != nil {
		t.Fatalf("HandleSignRequest(register): %v", err)
	}
	var resp registerHostResp
	if err := json.Unmarshal(bytes.TrimRight(conn.out.Bytes(), "\n"), &resp); err != nil {
		t.Fatalf("decode register resp: %v\nraw=%q", err, conn.out.String())
	}
	return resp
}
