package tools_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/karthikeyan5/sshgate/src/mcp/registry"
	signpkg "github.com/karthikeyan5/sshgate/src/mcp/sign"
	"github.com/karthikeyan5/sshgate/src/mcp/tools"
	"github.com/karthikeyan5/sshgate/src/xfer"
	"github.com/karthikeyan5/sshgate/src/xferwire"
)

// xferHarness is a single test double that plays THREE roles at once: the
// signer's TransferClient (it returns two REAL parseable legs + a minted
// xferID), the source gate (SSHRunner: it runs the REAL SEND crypto and returns
// the envelope), and the destination gate (StdinRunner: it runs the REAL RECV
// crypto over the relayed envelope and returns the marker). Wiring the same
// value into Runner.Xfer / SSH / SSHStdin exercises the full relay path
// (SEND stdout → RECV stdin) with REAL ciphertext, without a daemon or SSH.
type xferHarness struct {
	destBox *xfer.BoxKey // recipient (dest gate) box key — shared by signer + dest gate
	srcID   *xfer.IDKey  // sender (src gate) id key — shared by signer + src gate
	secret  []byte       // the plaintext "at src_path"

	// Transfer controls + capture.
	xferErr    error
	xferCalled bool
	gotReq     signpkg.TransferReq

	// SEND controls + capture.
	sendCalled bool
	sendExit   int
	sendRunErr error

	// RECV controls + capture.
	recvCalled        bool
	recvExit          int
	recvRunErr        error
	suppressMarker    bool
	forceMarkerXferID string
	recvGotPlaintext  []byte
	lastEnvelope      []byte

	mintedXferID string
}

func newXferHarness(t *testing.T, secret string) *xferHarness {
	t.Helper()
	bk, err := xfer.GenerateBoxKey()
	if err != nil {
		t.Fatal(err)
	}
	ik, err := xfer.GenerateIDKey()
	if err != nil {
		t.Fatal(err)
	}
	return &xferHarness{destBox: bk, srcID: ik, secret: []byte(secret), mintedXferID: "XFERtestid1234567890"}
}

func (h *xferHarness) Transfer(_ context.Context, _ string, req signpkg.TransferReq) (signpkg.TransferResult, error) {
	h.xferCalled = true
	h.gotReq = req
	if h.xferErr != nil {
		return signpkg.TransferResult{}, h.xferErr
	}
	sendCmd, err := xferwire.EncodeSend(h.destBox.Public(), h.mintedXferID, req.DestFP, req.SrcPath)
	if err != nil {
		return signpkg.TransferResult{}, fmt.Errorf("harness encode send: %w", err)
	}
	recvCmd, err := xferwire.EncodeRecv(h.srcID.Public(), h.mintedXferID, req.SrcFP, req.DestFP, req.Mode, req.DestPath)
	if err != nil {
		return signpkg.TransferResult{}, fmt.Errorf("harness encode recv: %w", err)
	}
	return signpkg.TransferResult{
		XferID:   h.mintedXferID,
		Send:     signpkg.Signed{Cmd: sendCmd, Sig: "SSHGATE_SIG:fakesig:send"},
		Recv:     signpkg.Signed{Cmd: recvCmd, Sig: "SSHGATE_SIG:fakesig:recv"},
		AuthMode: "human",
	}, nil
}

// Run is the SEND leg on the source gate: parse the leg, seal the secret to the
// leg's box pub, return the envelope as stdout (real ciphertext).
func (h *xferHarness) Run(_ context.Context, _, _ string, _ int, cmd string) ([]byte, []byte, int, error) {
	h.sendCalled = true
	if h.sendRunErr != nil {
		return nil, nil, h.sendExit, h.sendRunErr
	}
	if h.sendExit != 0 {
		return nil, []byte("gate: xfer send: refused"), h.sendExit, nil
	}
	leg, err := xferwire.ParseSend(legFromWire(cmd))
	if err != nil {
		return nil, []byte("gate: parse send"), 65, nil
	}
	env, err := xfer.Seal(h.secret, leg.BoxPub, h.srcID.Private(), leg.XferID, leg.DestID)
	if err != nil {
		return nil, []byte("gate: seal"), 65, nil
	}
	out, err := env.Marshal()
	if err != nil {
		return nil, []byte("gate: marshal"), 65, nil
	}
	h.lastEnvelope = out
	return out, nil, 0, nil
}

// RunWithStdin is the RECV leg on the destination gate: read the relayed
// envelope, open it, record the recovered plaintext, and return the marker.
func (h *xferHarness) RunWithStdin(_ context.Context, _, _ string, _ int, cmd string, stdin io.Reader) ([]byte, []byte, int, error) {
	h.recvCalled = true
	if h.recvRunErr != nil {
		return nil, nil, h.recvExit, h.recvRunErr
	}
	if h.recvExit != 0 {
		return nil, []byte("gate: xfer recv: refused"), h.recvExit, nil
	}
	leg, err := xferwire.ParseRecv(legFromWire(cmd))
	if err != nil {
		return nil, []byte("gate: parse recv"), 65, nil
	}
	body, err := io.ReadAll(stdin)
	if err != nil {
		return nil, []byte("gate: read stdin"), 65, nil
	}
	env, err := xfer.Unmarshal(body)
	if err != nil {
		return nil, []byte("gate: unmarshal"), 65, nil
	}
	pt, err := xfer.Open(env, h.destBox.Public(), h.destBox.Private(), leg.IDPub, leg.XferID, leg.DestID, 1<<20)
	if err != nil {
		return nil, []byte("gate: open"), 65, nil
	}
	h.recvGotPlaintext = pt
	if h.suppressMarker {
		return []byte("done, but no marker\n"), nil, 0, nil
	}
	id := leg.XferID
	if h.forceMarkerXferID != "" {
		id = h.forceMarkerXferID
	}
	return []byte(fmt.Sprintf("SSHGATE_XFER_RECEIVED xfer=%s bytes=%d\n", id, len(pt))), nil, 0, nil
}

// legFromWire strips the leading "SSHGATE_SIG:…:… " envelope the tool prepends
// (Sig + " " + Cmd) and returns the inner leg command. The SIG token carries no
// space, so the first space cleanly delimits it.
func legFromWire(wire string) string {
	if i := strings.IndexByte(wire, ' '); i >= 0 {
		return wire[i+1:]
	}
	return wire
}

func newXferRegistry(t *testing.T) *registry.Servers {
	t.Helper()
	r := newRegistryWith(t, "src", registry.Entry{
		Host: "10.0.0.1", Port: 22, User: "ops", AddedAt: time.Now(), Fingerprint: "SHA256:srcHostFP",
	})
	if err := r.Add("dst", registry.Entry{
		Host: "10.0.0.2", Port: 2222, User: "ops", AddedAt: time.Now(), Fingerprint: "SHA256:dstHostFP",
	}); err != nil {
		t.Fatal(err)
	}
	return r
}

// TestTransfer_HappyPath: metadata-only output, dest received the exact secret,
// and the relay carried REAL ciphertext (SEND stdout → RECV stdin).
func TestTransfer_HappyPath(t *testing.T) {
	t.Parallel()
	const secret = "botToken-XYZ-do-not-leak"
	h := newXferHarness(t, secret)
	r := newXferRegistry(t)
	runner := &tools.Runner{Servers: r, Xfer: h, SSH: h, SSHStdin: h}

	out, err := runner.Transfer(context.Background(), tools.TransferInput{
		SrcAlias: "src", SrcPath: "/etc/secret", DestAlias: "dst", DestPath: "/etc/out",
	})
	if err != nil {
		t.Fatalf("Transfer: %v", err)
	}
	if out.XferID != h.mintedXferID {
		t.Errorf("XferID = %q; want %q", out.XferID, h.mintedXferID)
	}
	if out.Bytes != int64(len(secret)) {
		t.Errorf("Bytes = %d; want %d", out.Bytes, len(secret))
	}
	if out.Mode != "0600" {
		t.Errorf("Mode = %q; want default 0600", out.Mode)
	}
	if out.AuthMode != "human" {
		t.Errorf("AuthMode = %q; want human", out.AuthMode)
	}
	if string(h.recvGotPlaintext) != secret {
		t.Errorf("dest received %q; want the exact secret", h.recvGotPlaintext)
	}
	// Confidentiality at the tool boundary: the secret must not appear anywhere
	// in the marshaled TransferOutput.
	blob, _ := json.Marshal(out)
	if strings.Contains(string(blob), secret) {
		t.Errorf("CONFIDENTIALITY: secret leaked into TransferOutput JSON: %s", blob)
	}
	if strings.Contains(string(blob), string(h.lastEnvelope)) {
		t.Errorf("CONFIDENTIALITY: envelope leaked into TransferOutput JSON")
	}
}

// TestTransfer_FingerprintsFromRegistryNotInput: the input carries no fp; the
// tool must source both fingerprints from the trusted registry entries.
func TestTransfer_FingerprintsFromRegistryNotInput(t *testing.T) {
	t.Parallel()
	h := newXferHarness(t, "s3cr3t")
	r := newXferRegistry(t)
	runner := &tools.Runner{Servers: r, Xfer: h, SSH: h, SSHStdin: h}

	if _, err := runner.Transfer(context.Background(), tools.TransferInput{
		SrcAlias: "src", SrcPath: "/a", DestAlias: "dst", DestPath: "/b",
	}); err != nil {
		t.Fatalf("Transfer: %v", err)
	}
	if h.gotReq.SrcFP != "SHA256:srcHostFP" {
		t.Errorf("SrcFP = %q; want the src registry fingerprint (not agent input)", h.gotReq.SrcFP)
	}
	if h.gotReq.DestFP != "SHA256:dstHostFP" {
		t.Errorf("DestFP = %q; want the dest registry fingerprint (not agent input)", h.gotReq.DestFP)
	}
	if h.gotReq.TTLSec != tools.TransferTTLSec {
		t.Errorf("TTLSec = %d; want %d", h.gotReq.TTLSec, tools.TransferTTLSec)
	}
}

// TestTransfer_InputSchemaHasNoKeysOrFPs: TransferInput exposes ONLY aliases +
// paths + mode — never a pubkey, fingerprint, or xferID field.
func TestTransfer_InputSchemaHasNoKeysOrFPs(t *testing.T) {
	t.Parallel()
	allowed := map[string]bool{
		"src_alias": true, "src_path": true, "dest_alias": true, "dest_path": true, "mode": true,
	}
	tp := reflect.TypeOf(tools.TransferInput{})
	for i := 0; i < tp.NumField(); i++ {
		tag := tp.Field(i).Tag.Get("json")
		name := strings.Split(tag, ",")[0]
		if !allowed[name] {
			t.Errorf("TransferInput exposes an unexpected field %q — the agent must never supply keys/fps/xferID", name)
		}
	}
}

// TestTransfer_ReadOnlySrcShortCircuits: a read-only source is refused BEFORE
// any approval (no tap wasted); the signer is never called.
func TestTransfer_ReadOnlySrcShortCircuits(t *testing.T) {
	t.Parallel()
	h := newXferHarness(t, "x")
	r := newRegistryWith(t, "src", registry.Entry{Host: "h", Port: 22, User: "u", AddedAt: time.Now(), ReadOnly: true})
	if err := r.Add("dst", registry.Entry{Host: "h2", Port: 22, User: "u", AddedAt: time.Now(), Fingerprint: "SHA256:dst"}); err != nil {
		t.Fatal(err)
	}
	runner := &tools.Runner{Servers: r, Xfer: h, SSH: h, SSHStdin: h}

	_, err := runner.Transfer(context.Background(), tools.TransferInput{SrcAlias: "src", SrcPath: "/a", DestAlias: "dst", DestPath: "/b"})
	if err == nil || !strings.Contains(err.Error(), "read-only") {
		t.Fatalf("err = %v; want a read-only remediation", err)
	}
	if h.xferCalled {
		t.Error("signer was called for a read-only source — must short-circuit before any tap")
	}
}

// TestTransfer_ReadOnlyDestShortCircuits: a read-only destination is refused
// before any approval.
func TestTransfer_ReadOnlyDestShortCircuits(t *testing.T) {
	t.Parallel()
	h := newXferHarness(t, "x")
	r := newRegistryWith(t, "src", registry.Entry{Host: "h", Port: 22, User: "u", AddedAt: time.Now(), Fingerprint: "SHA256:src"})
	if err := r.Add("dst", registry.Entry{Host: "h2", Port: 22, User: "u", AddedAt: time.Now(), ReadOnly: true}); err != nil {
		t.Fatal(err)
	}
	runner := &tools.Runner{Servers: r, Xfer: h, SSH: h, SSHStdin: h}

	_, err := runner.Transfer(context.Background(), tools.TransferInput{SrcAlias: "src", SrcPath: "/a", DestAlias: "dst", DestPath: "/b"})
	if err == nil || !strings.Contains(err.Error(), "read-only") {
		t.Fatalf("err = %v; want a read-only remediation", err)
	}
	if h.xferCalled {
		t.Error("signer was called for a read-only destination — must short-circuit")
	}
}

// TestTransfer_UnknownAlias: an unregistered alias yields a friendly error and
// no approval.
func TestTransfer_UnknownAlias(t *testing.T) {
	t.Parallel()
	h := newXferHarness(t, "x")
	r := newXferRegistry(t)
	runner := &tools.Runner{Servers: r, Xfer: h, SSH: h, SSHStdin: h}

	_, err := runner.Transfer(context.Background(), tools.TransferInput{SrcAlias: "nope", SrcPath: "/a", DestAlias: "dst", DestPath: "/b"})
	if err == nil || !strings.Contains(err.Error(), "unknown source server alias") {
		t.Fatalf("err = %v; want an unknown-alias error", err)
	}
	if h.xferCalled {
		t.Error("signer was called for an unknown alias")
	}
}

// TestTransfer_SignerDeniedNoSSH: a denial from the signer is surfaced with the
// sentinel preserved, and no SSH leg runs.
func TestTransfer_SignerDeniedNoSSH(t *testing.T) {
	t.Parallel()
	h := newXferHarness(t, "x")
	h.xferErr = signpkg.ErrDenied
	r := newXferRegistry(t)
	runner := &tools.Runner{Servers: r, Xfer: h, SSH: h, SSHStdin: h}

	_, err := runner.Transfer(context.Background(), tools.TransferInput{SrcAlias: "src", SrcPath: "/a", DestAlias: "dst", DestPath: "/b"})
	if !errors.Is(err, signpkg.ErrDenied) {
		t.Fatalf("err = %v; want ErrDenied preserved", err)
	}
	if h.sendCalled || h.recvCalled {
		t.Error("an SSH leg ran despite a signer denial")
	}
}

// TestTransfer_SignerTimeoutNoSSH: a timeout is likewise surfaced, no SSH.
func TestTransfer_SignerTimeoutNoSSH(t *testing.T) {
	t.Parallel()
	h := newXferHarness(t, "x")
	h.xferErr = signpkg.ErrTimeout
	r := newXferRegistry(t)
	runner := &tools.Runner{Servers: r, Xfer: h, SSH: h, SSHStdin: h}

	_, err := runner.Transfer(context.Background(), tools.TransferInput{SrcAlias: "src", SrcPath: "/a", DestAlias: "dst", DestPath: "/b"})
	if !errors.Is(err, signpkg.ErrTimeout) {
		t.Fatalf("err = %v; want ErrTimeout preserved", err)
	}
	if h.sendCalled {
		t.Error("SEND ran despite a signer timeout")
	}
}

// TestTransfer_SendGateDenyNoRecv: a non-zero SEND exit is annotated and the
// RECV leg is NOT run; the error carries no envelope.
func TestTransfer_SendGateDenyNoRecv(t *testing.T) {
	t.Parallel()
	for _, exit := range []int{65, 70, 77} {
		h := newXferHarness(t, "secretvalue")
		h.sendExit = exit
		r := newXferRegistry(t)
		runner := &tools.Runner{Servers: r, Xfer: h, SSH: h, SSHStdin: h}

		_, err := runner.Transfer(context.Background(), tools.TransferInput{SrcAlias: "src", SrcPath: "/a", DestAlias: "dst", DestPath: "/b"})
		if err == nil {
			t.Fatalf("exit %d: expected an error", exit)
		}
		if !strings.Contains(err.Error(), "source gate") {
			t.Errorf("exit %d: err = %v; want a SEND-leg (source gate) annotation", exit, err)
		}
		if h.recvCalled {
			t.Errorf("exit %d: RECV ran despite a failed SEND", exit)
		}
	}
}

// TestTransfer_RecvMarkerMissing: a RECV that returns no marker errors out.
func TestTransfer_RecvMarkerMissing(t *testing.T) {
	t.Parallel()
	h := newXferHarness(t, "secretvalue")
	h.suppressMarker = true
	r := newXferRegistry(t)
	runner := &tools.Runner{Servers: r, Xfer: h, SSH: h, SSHStdin: h}

	_, err := runner.Transfer(context.Background(), tools.TransferInput{SrcAlias: "src", SrcPath: "/a", DestAlias: "dst", DestPath: "/b"})
	if err == nil || !strings.Contains(err.Error(), "did not confirm") {
		t.Fatalf("err = %v; want a missing-marker error", err)
	}
}

// TestTransfer_RecvXferIDMismatch: a marker whose xferID differs from the
// approved one is rejected.
func TestTransfer_RecvXferIDMismatch(t *testing.T) {
	t.Parallel()
	h := newXferHarness(t, "secretvalue")
	h.forceMarkerXferID = "SOMEOTHERID"
	r := newXferRegistry(t)
	runner := &tools.Runner{Servers: r, Xfer: h, SSH: h, SSHStdin: h}

	_, err := runner.Transfer(context.Background(), tools.TransferInput{SrcAlias: "src", SrcPath: "/a", DestAlias: "dst", DestPath: "/b"})
	if err == nil || !strings.Contains(err.Error(), "DIFFERENT transfer id") {
		t.Fatalf("err = %v; want an xferID-mismatch error", err)
	}
}

// TestTransfer_CustomModeForwarded: a supplied mode rides into the signer
// request (and the output).
func TestTransfer_CustomModeForwarded(t *testing.T) {
	t.Parallel()
	h := newXferHarness(t, "secretvalue")
	r := newXferRegistry(t)
	runner := &tools.Runner{Servers: r, Xfer: h, SSH: h, SSHStdin: h}

	out, err := runner.Transfer(context.Background(), tools.TransferInput{
		SrcAlias: "src", SrcPath: "/a", DestAlias: "dst", DestPath: "/b", Mode: "0600",
	})
	if err != nil {
		t.Fatalf("Transfer: %v", err)
	}
	if h.gotReq.Mode != "0600" || out.Mode != "0600" {
		t.Errorf("mode not forwarded: req=%q out=%q", h.gotReq.Mode, out.Mode)
	}
}

// TestTransfer_NilXferErrors: a nil Xfer dependency is a clean infrastructure
// error, not a panic (existing Runner literals without Xfer stay safe).
func TestTransfer_NilXferErrors(t *testing.T) {
	t.Parallel()
	r := newXferRegistry(t)
	runner := &tools.Runner{Servers: r, SSH: &fakeSSH{}, SSHStdin: &fakeStdinSSH{}}
	_, err := runner.Transfer(context.Background(), tools.TransferInput{SrcAlias: "src", SrcPath: "/a", DestAlias: "dst", DestPath: "/b"})
	if err == nil || !strings.Contains(err.Error(), "Xfer is nil") {
		t.Fatalf("err = %v; want a nil-Xfer error", err)
	}
}
