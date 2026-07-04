package main

import (
	"bytes"
	"crypto/ed25519"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/karthikeyan5/sshgate/src/sigwire"
	"github.com/karthikeyan5/sshgate/src/xfer"
	"github.com/karthikeyan5/sshgate/src/xferwire"
)

// This file drives the gate's SSHGATE_XFER_SEND / SSHGATE_XFER_RECV dispatch
// end-to-end through run() using the same gateDirFn / hostKeyFPsFn / os.Stdin /
// os.Stdout seams the update tests use. It builds real signed legs (via the
// in-test signer key seeded as gate.pub) and real envelopes (via src/xfer), and
// asserts the documented exit codes AND — the load-bearing property — that a
// signed XFER leg is treated as DATA, never shell-executed, and that no
// plaintext ever reaches stdout / the audit log.

const (
	// testXferID is a valid b64url-nopad xferID (the shape base64.RawURLEncoding
	// mints). testSrcFP / testDestFP are valid "SHA256:" fingerprints for the
	// leg's srcID/destID fields (audit/binding metadata).
	testXferID  = "AQ4bKDVCT1xpdoOQnaq3xA"
	testSrcFP   = "SHA256:kQ4jRxfersourcefp000000000000000000000000ab"
	testDestFP  = "SHA256:9Zt7Xxferdestfp1111111111111111111111111111cd"
	testXferPT  = "XFERSECRET-a1b2c3d4e5" // the sentinel plaintext for grep tests
	testXferPT2 = "botToken-9c1f-super-secret-value"
)

// genXferKeys makes a fresh (box, id) xfer keypair.
func genXferKeys(t *testing.T) (*xfer.BoxKey, *xfer.IDKey) {
	t.Helper()
	bk, err := xfer.GenerateBoxKey()
	if err != nil {
		t.Fatalf("generate box key: %v", err)
	}
	ik, err := xfer.GenerateIDKey()
	if err != nil {
		t.Fatalf("generate id key: %v", err)
	}
	return bk, ik
}

// seedXferKeyFiles writes the gate's own xfer-box.key + xfer-id.key (0600) into
// dir. These are the keys the gate LOADS at rest (RECV uses box, SEND uses id).
func seedXferKeyFiles(t *testing.T, dir string, bk *xfer.BoxKey, ik *xfer.IDKey) {
	t.Helper()
	if err := bk.Save(filepath.Join(dir, "xfer-box.key")); err != nil {
		t.Fatalf("save box key: %v", err)
	}
	if err := ik.Save(filepath.Join(dir, "xfer-id.key")); err != nil {
		t.Fatalf("save id key: %v", err)
	}
}

// payloadHost is freshPayload with an explicit Host, so a test can bind a leg
// to a specific gate fingerprint (or a wrong one, for the cross-host rejection).
func payloadHost(cmd, host string) sigwire.SigPayload {
	now := time.Now()
	return sigwire.SigPayload{
		Cmd:   cmd,
		TS:    now.Add(-1 * time.Second).Unix(),
		Exp:   now.Add(4 * time.Minute).Unix(),
		Nonce: "nonce-xfer-test",
		Host:  host,
	}
}

// writeSource writes content to a temp source file and returns its ABSOLUTE
// path (ValidPath requires filepath.IsAbs).
func writeSource(t *testing.T, content string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "src.secret")
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatalf("write source: %v", err)
	}
	return p
}

// ---------------------------------------------------------------------------
// SEND golden (§5.1)
// ---------------------------------------------------------------------------

// TestXferSend_Golden signs a SEND leg whose BoxPub is B's box pub and whose
// SrcPath holds a known secret, drives run(), then Unmarshal+Open the captured
// stdout with B's box priv + A's id pub + the leg's xferID/destID — recovering
// the exact secret. Exit 0; the audit row is metadata-only (no plaintext).
func TestXferSend_Golden(t *testing.T) {
	dir := t.TempDir()
	pub, priv := genKey(t)
	seedPub(t, dir, pub, 0o644)
	boxA, idA := genXferKeys(t) // gate A's own keys; idA attests
	seedXferKeyFiles(t, dir, boxA, idA)
	withGateDir(t, dir)
	seedAuditAllFull(t, dir)

	boxB, _ := genXferKeys(t) // the recipient (gate B) box key
	src := writeSource(t, testXferPT)

	sendCmd, err := xferwire.EncodeSend(boxB.Public(), testXferID, testDestFP, src)
	if err != nil {
		t.Fatalf("encode send: %v", err)
	}
	line := signedLine(t, priv, payloadHost(sendCmd, testGateHostFP))

	code, out, stderr := runWith(t, line)
	if code != exitOK {
		t.Fatalf("exit = %d; want 0 (stderr=%q)", code, stderr)
	}
	// The captured stdout is the opaque envelope. It must decrypt back to the
	// exact plaintext with the recipient's box key + the sender's id pub.
	env, err := xfer.Unmarshal([]byte(out))
	if err != nil {
		t.Fatalf("unmarshal captured envelope: %v", err)
	}
	got, err := xfer.Open(env, boxB.Public(), boxB.Private(), idA.Public(), testXferID, testDestFP, 1<<20)
	if err != nil {
		t.Fatalf("open captured envelope: %v", err)
	}
	if string(got) != testXferPT {
		t.Errorf("recovered plaintext = %q; want %q", got, testXferPT)
	}
	// CONFIDENTIALITY: the sentinel plaintext must NOT be in stdout (envelope),
	// stderr, or the gate's all+full audit log.
	assertSentinelAbsent(t, "SEND", out, stderr, dir)
}

// ---------------------------------------------------------------------------
// RECV golden (§5.1)
// ---------------------------------------------------------------------------

// TestXferRecv_Golden pre-builds an envelope (Seal the secret to B's box pub,
// attest with A's id priv), signs a RECV leg (IDPub = A id pub, mode 0600),
// feeds the envelope on stdin, drives run(), and asserts the dest file holds the
// secret at 0600, the stdout marker is present, and exit is 0.
func TestXferRecv_Golden(t *testing.T) {
	dir := t.TempDir()
	pub, priv := genKey(t)
	seedPub(t, dir, pub, 0o644)
	boxB, idB := genXferKeys(t) // gate B's own keys; boxB opens
	seedXferKeyFiles(t, dir, boxB, idB)
	withGateDir(t, dir)
	seedAuditAllFull(t, dir)

	_, idA := genXferKeys(t) // the sender (gate A) id key attests
	env, err := xfer.Seal([]byte(testXferPT), boxB.Public(), idA.Private(), testXferID, testDestFP)
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	envBytes, err := env.Marshal()
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	dest := filepath.Join(t.TempDir(), "out.secret")
	recvCmd, err := xferwire.EncodeRecv(idA.Public(), testXferID, testSrcFP, testDestFP, "0600", dest)
	if err != nil {
		t.Fatalf("encode recv: %v", err)
	}
	line := signedLine(t, priv, payloadHost(recvCmd, testGateHostFP))

	code, out, stderr := runWithStdin(t, line, envBytes)
	if code != exitOK {
		t.Fatalf("exit = %d; want 0 (stderr=%q)", code, stderr)
	}
	body, err := os.ReadFile(dest)
	if err != nil {
		t.Fatalf("read dest: %v", err)
	}
	if string(body) != testXferPT {
		t.Errorf("dest file = %q; want %q", body, testXferPT)
	}
	if info, _ := os.Stat(dest); info.Mode().Perm() != 0o600 {
		t.Errorf("dest mode = %#o; want 0600", info.Mode().Perm())
	}
	if !strings.Contains(out, "SSHGATE_XFER_RECEIVED xfer="+testXferID) {
		t.Errorf("stdout = %q; want the RECEIVED marker with the xferID", out)
	}
	assertSentinelAbsent(t, "RECV", out, stderr, dir)
}

// TestXferRoundTrip_GateSurfaceGrep is the host-side half of the acceptance
// gate (§5.4): a real SEND on "gate A" produces an envelope, which a real RECV
// on "gate B" opens and writes — and the sentinel plaintext appears on NEITHER
// gate's stdout/stderr NOR either gate's all+full audit log.
func TestXferRoundTrip_GateSurfaceGrep(t *testing.T) {
	// Gate A (sender).
	dirA := t.TempDir()
	pubA, privA := genKey(t)
	seedPub(t, dirA, pubA, 0o644)
	boxA, idA := genXferKeys(t)
	seedXferKeyFiles(t, dirA, boxA, idA)
	seedAuditAllFull(t, dirA)

	// Gate B (recipient).
	dirB := t.TempDir()
	pubB, privB := genKey(t)
	seedPub(t, dirB, pubB, 0o644)
	boxB, idB := genXferKeys(t)
	seedXferKeyFiles(t, dirB, boxB, idB)
	seedAuditAllFull(t, dirB)

	src := writeSource(t, testXferPT2)
	dest := filepath.Join(t.TempDir(), "out.secret")

	// --- SEND on gate A ---
	sendCmd, err := xferwire.EncodeSend(boxB.Public(), testXferID, testDestFP, src)
	if err != nil {
		t.Fatalf("encode send: %v", err)
	}
	withGateDir(t, dirA)
	sendLine := signedLine(t, privA, payloadHost(sendCmd, testGateHostFP))
	codeA, envOut, stderrA := runWith(t, sendLine)
	if codeA != exitOK {
		t.Fatalf("SEND exit = %d; want 0 (stderr=%q)", codeA, stderrA)
	}
	assertSentinelAbsentVal(t, "gate A stdout (envelope)", envOut, testXferPT2)
	assertSentinelAbsentVal(t, "gate A stderr", stderrA, testXferPT2)
	assertSentinelAbsentVal(t, "gate A audit", readAudit(t, dirA), testXferPT2)

	// --- RECV on gate B (relay the exact envelope bytes on stdin) ---
	recvCmd, err := xferwire.EncodeRecv(idA.Public(), testXferID, testSrcFP, testDestFP, "0600", dest)
	if err != nil {
		t.Fatalf("encode recv: %v", err)
	}
	withGateDir(t, dirB)
	recvLine := signedLine(t, privB, payloadHost(recvCmd, testGateHostFP))
	codeB, markerOut, stderrB := runWithStdin(t, recvLine, []byte(envOut))
	if codeB != exitOK {
		t.Fatalf("RECV exit = %d; want 0 (stderr=%q)", codeB, stderrB)
	}
	// Positive control: the transfer really happened.
	if body, _ := os.ReadFile(dest); string(body) != testXferPT2 {
		t.Fatalf("dest file = %q; want %q (transfer must have delivered)", body, testXferPT2)
	}
	assertSentinelAbsentVal(t, "gate B stdout (marker)", markerOut, testXferPT2)
	assertSentinelAbsentVal(t, "gate B stderr", stderrB, testXferPT2)
	assertSentinelAbsentVal(t, "gate B audit", readAudit(t, dirB), testXferPT2)
}

// ---------------------------------------------------------------------------
// Injection / tamper cases (§5.1)
// ---------------------------------------------------------------------------

// TestXferSend_WrongHostRejected: a SEND leg bound to a DIFFERENT host is
// rejected by VerifySigned (ErrHostMismatch) → exit 65, dispatch never reached.
func TestXferSend_WrongHostRejected(t *testing.T) {
	dir := t.TempDir()
	pub, priv := genKey(t)
	seedPub(t, dir, pub, 0o644)
	boxA, idA := genXferKeys(t)
	seedXferKeyFiles(t, dir, boxA, idA)
	withGateDir(t, dir)

	boxB, _ := genXferKeys(t)
	src := writeSource(t, testXferPT)
	sendCmd, _ := xferwire.EncodeSend(boxB.Public(), testXferID, testDestFP, src)
	// Bind the leg to some OTHER host fp; the gate self-set is testGateHostFP.
	line := signedLine(t, priv, payloadHost(sendCmd, "SHA256:someOtherHostFingerprintZZZZZZZZZZZZZZZZ"))

	if code, _, _ := runWith(t, line); code != exitDataErr {
		t.Fatalf("exit = %d; want 65 on host mismatch", code)
	}
}

// TestXferSend_ExpiredRejected: an expired leg is rejected → exit 65.
func TestXferSend_ExpiredRejected(t *testing.T) {
	dir := t.TempDir()
	pub, priv := genKey(t)
	seedPub(t, dir, pub, 0o644)
	boxA, idA := genXferKeys(t)
	seedXferKeyFiles(t, dir, boxA, idA)
	withGateDir(t, dir)

	boxB, _ := genXferKeys(t)
	src := writeSource(t, testXferPT)
	sendCmd, _ := xferwire.EncodeSend(boxB.Public(), testXferID, testDestFP, src)
	now := time.Now()
	expired := sigwire.SigPayload{
		Cmd:   sendCmd,
		TS:    now.Add(-10 * time.Minute).Unix(),
		Exp:   now.Add(-5 * time.Minute).Unix(), // already expired
		Nonce: "nonce-expired",
		Host:  testGateHostFP,
	}
	line := signedLine(t, priv, expired)

	if code, _, _ := runWith(t, line); code != exitDataErr {
		t.Fatalf("exit = %d; want 65 on expired leg", code)
	}
}

// TestXferSend_UnsignedDeniedByClassify: a raw (unsigned) SSHGATE_XFER_SEND is
// classified KindWrite and denied at exit 77 — it never reaches handleXfer.
func TestXferSend_UnsignedDeniedByClassify(t *testing.T) {
	dir := t.TempDir()
	pub, _ := genKey(t)
	seedPub(t, dir, pub, 0o644)
	boxA, idA := genXferKeys(t)
	seedXferKeyFiles(t, dir, boxA, idA)
	withGateDir(t, dir)

	boxB, _ := genXferKeys(t)
	src := writeSource(t, testXferPT)
	sendCmd, _ := xferwire.EncodeSend(boxB.Public(), testXferID, testDestFP, src)

	// No SSHGATE_SIG prefix → unsigned → classify → KindWrite → exit 77.
	code, _, stderr := runWith(t, sendCmd)
	if code != exitNoPermVal {
		t.Fatalf("exit = %d; want 77 for an unsigned XFER line (stderr=%q)", code, stderr)
	}
}

// TestXfer_SignedUnknownVerb: a SIGNED but unknown SSHGATE_XFER_* verb hits
// handleXfer's default → exit 65 (never falls through to classify/exec).
func TestXfer_SignedUnknownVerb(t *testing.T) {
	dir := t.TempDir()
	pub, priv := genKey(t)
	seedPub(t, dir, pub, 0o644)
	boxA, idA := genXferKeys(t)
	seedXferKeyFiles(t, dir, boxA, idA)
	withGateDir(t, dir)

	line := signedLine(t, priv, payloadHost("SSHGATE_XFER_BOGUS deadbeef", testGateHostFP))
	if code, _, _ := runWith(t, line); code != exitDataErr {
		t.Fatalf("exit = %d; want 65 on an unknown signed XFER verb", code)
	}
}

// recvFixture builds gate B (box+id keys, gate.pub) and returns the dir, signer
// priv, gate box/id keys, and the sender id key so RECV tamper tests can craft
// mismatched envelopes/legs.
func recvFixture(t *testing.T) (signerPriv ed25519.PrivateKey, boxB *xfer.BoxKey, idA *xfer.IDKey) {
	t.Helper()
	dir := t.TempDir()
	pub, priv := genKey(t)
	seedPub(t, dir, pub, 0o644)
	var idB *xfer.IDKey
	boxB, idB = genXferKeys(t)
	seedXferKeyFiles(t, dir, boxB, idB)
	withGateDir(t, dir)
	_, idA = genXferKeys(t)
	return priv, boxB, idA
}

// TestXferRecv_WrongXferID: an envelope whose xferID differs from the leg's is
// rejected by Open (binding mismatch) → exit 65, dest file NOT created.
func TestXferRecv_WrongXferID(t *testing.T) {
	priv, boxB, idA := recvFixture(t)
	// Envelope sealed with a DIFFERENT xferID than the leg carries.
	env, _ := xfer.Seal([]byte(testXferPT), boxB.Public(), idA.Private(), "DIFFERENTxferID_00000", testDestFP)
	envBytes, _ := env.Marshal()
	dest := filepath.Join(t.TempDir(), "out.secret")
	recvCmd, _ := xferwire.EncodeRecv(idA.Public(), testXferID, testSrcFP, testDestFP, "0600", dest)
	line := signedLine(t, priv, payloadHost(recvCmd, testGateHostFP))

	if code, _, _ := runWithStdin(t, line, envBytes); code != exitDataErr {
		t.Fatalf("exit = %d; want 65 on xferID mismatch", code)
	}
	if _, err := os.Stat(dest); err == nil {
		t.Errorf("dest file created despite a binding mismatch")
	}
}

// TestXferRecv_WrongDestID: an envelope whose destID differs from the leg's is
// rejected → exit 65, no dest file.
func TestXferRecv_WrongDestID(t *testing.T) {
	priv, boxB, idA := recvFixture(t)
	env, _ := xfer.Seal([]byte(testXferPT), boxB.Public(), idA.Private(), testXferID, "SHA256:aDifferentDestFPqqqqqqqqqqqqqqqqqqqqqqqqqq")
	envBytes, _ := env.Marshal()
	dest := filepath.Join(t.TempDir(), "out.secret")
	recvCmd, _ := xferwire.EncodeRecv(idA.Public(), testXferID, testSrcFP, testDestFP, "0600", dest)
	line := signedLine(t, priv, payloadHost(recvCmd, testGateHostFP))

	if code, _, _ := runWithStdin(t, line, envBytes); code != exitDataErr {
		t.Fatalf("exit = %d; want 65 on destID mismatch", code)
	}
	if _, err := os.Stat(dest); err == nil {
		t.Errorf("dest file created despite a destID mismatch")
	}
}

// TestXferRecv_TamperedEnvelope: flipping a Sealed byte breaks the AEAD open →
// exit 65, no dest file.
func TestXferRecv_TamperedEnvelope(t *testing.T) {
	priv, boxB, idA := recvFixture(t)
	env, _ := xfer.Seal([]byte(testXferPT), boxB.Public(), idA.Private(), testXferID, testDestFP)
	env.Sealed[0] ^= 0xFF // corrupt the ciphertext
	envBytes, _ := env.Marshal()
	dest := filepath.Join(t.TempDir(), "out.secret")
	recvCmd, _ := xferwire.EncodeRecv(idA.Public(), testXferID, testSrcFP, testDestFP, "0600", dest)
	line := signedLine(t, priv, payloadHost(recvCmd, testGateHostFP))

	if code, _, _ := runWithStdin(t, line, envBytes); code != exitDataErr {
		t.Fatalf("exit = %d; want 65 on a tampered envelope", code)
	}
	if _, err := os.Stat(dest); err == nil {
		t.Errorf("dest file created despite AEAD failure")
	}
}

// TestXferRecv_WrongSenderID: the leg names an IDPub that did NOT attest the
// envelope → attestation invalid → exit 65.
func TestXferRecv_WrongSenderID(t *testing.T) {
	priv, boxB, idA := recvFixture(t)
	env, _ := xfer.Seal([]byte(testXferPT), boxB.Public(), idA.Private(), testXferID, testDestFP)
	envBytes, _ := env.Marshal()
	// The RECV leg names a DIFFERENT sender id key than the one that attested.
	_, wrongID := genXferKeys(t)
	dest := filepath.Join(t.TempDir(), "out.secret")
	recvCmd, _ := xferwire.EncodeRecv(wrongID.Public(), testXferID, testSrcFP, testDestFP, "0600", dest)
	line := signedLine(t, priv, payloadHost(recvCmd, testGateHostFP))

	if code, _, _ := runWithStdin(t, line, envBytes); code != exitDataErr {
		t.Fatalf("exit = %d; want 65 on a wrong sender id", code)
	}
	if _, err := os.Stat(dest); err == nil {
		t.Errorf("dest file created despite an attestation failure")
	}
}

// TestXferRecv_OversizeStdin: an envelope larger than the (shrunk) cap is
// refused by the bounded read → exit 65, nothing written.
func TestXferRecv_OversizeStdin(t *testing.T) {
	saved := maxXferEnvelopeBytes
	maxXferEnvelopeBytes = 16
	t.Cleanup(func() { maxXferEnvelopeBytes = saved })

	priv, _, idA := recvFixture(t)
	dest := filepath.Join(t.TempDir(), "out.secret")
	recvCmd, _ := xferwire.EncodeRecv(idA.Public(), testXferID, testSrcFP, testDestFP, "0600", dest)
	line := signedLine(t, priv, payloadHost(recvCmd, testGateHostFP))

	if code, _, _ := runWithStdin(t, line, bytes.Repeat([]byte("A"), 64)); code != exitDataErr {
		t.Fatalf("exit = %d; want 65 on oversize stdin", code)
	}
	if _, err := os.Stat(dest); err == nil {
		t.Errorf("dest file created despite an oversize envelope")
	}
}

// TestXferRecv_EmptyStdin: an empty envelope stream is refused → exit 65.
func TestXferRecv_EmptyStdin(t *testing.T) {
	priv, _, idA := recvFixture(t)
	dest := filepath.Join(t.TempDir(), "out.secret")
	recvCmd, _ := xferwire.EncodeRecv(idA.Public(), testXferID, testSrcFP, testDestFP, "0600", dest)
	line := signedLine(t, priv, payloadHost(recvCmd, testGateHostFP))

	if code, _, _ := runWithStdin(t, line, nil); code != exitDataErr {
		t.Fatalf("exit = %d; want 65 on empty stdin", code)
	}
}

// TestXferSend_MissingKeyExit70: SEND with no xfer-id.key present → exit 70.
func TestXferSend_MissingKeyExit70(t *testing.T) {
	dir := t.TempDir()
	pub, priv := genKey(t)
	seedPub(t, dir, pub, 0o644)
	withGateDir(t, dir) // NO seedXferKeyFiles → keys absent

	boxB, _ := genXferKeys(t)
	src := writeSource(t, testXferPT)
	sendCmd, _ := xferwire.EncodeSend(boxB.Public(), testXferID, testDestFP, src)
	line := signedLine(t, priv, payloadHost(sendCmd, testGateHostFP))

	if code, _, _ := runWith(t, line); code != exitSoftware {
		t.Fatalf("exit = %d; want 70 on a missing send key", code)
	}
}

// TestXferRecv_MissingKeyExit70: RECV with no xfer-box.key present → exit 70.
func TestXferRecv_MissingKeyExit70(t *testing.T) {
	dir := t.TempDir()
	pub, priv := genKey(t)
	seedPub(t, dir, pub, 0o644)
	withGateDir(t, dir) // NO seedXferKeyFiles

	_, idA := genXferKeys(t)
	boxB, _ := genXferKeys(t)
	env, _ := xfer.Seal([]byte(testXferPT), boxB.Public(), idA.Private(), testXferID, testDestFP)
	envBytes, _ := env.Marshal()
	dest := filepath.Join(t.TempDir(), "out.secret")
	recvCmd, _ := xferwire.EncodeRecv(idA.Public(), testXferID, testSrcFP, testDestFP, "0600", dest)
	line := signedLine(t, priv, payloadHost(recvCmd, testGateHostFP))

	if code, _, _ := runWithStdin(t, line, envBytes); code != exitSoftware {
		t.Fatalf("exit = %d; want 70 on a missing recv key", code)
	}
	if _, err := os.Stat(dest); err == nil {
		t.Errorf("dest file created despite a missing box key")
	}
}

// TestXferSend_InsecureKeyModeExit70: a group-readable xfer-id.key is rejected
// by the loader (0o077) → exit 70.
func TestXferSend_InsecureKeyModeExit70(t *testing.T) {
	dir := t.TempDir()
	pub, priv := genKey(t)
	seedPub(t, dir, pub, 0o644)
	boxA, idA := genXferKeys(t)
	seedXferKeyFiles(t, dir, boxA, idA)
	if err := os.Chmod(filepath.Join(dir, "xfer-id.key"), 0o644); err != nil {
		t.Fatalf("chmod: %v", err)
	}
	withGateDir(t, dir)

	boxB, _ := genXferKeys(t)
	src := writeSource(t, testXferPT)
	sendCmd, _ := xferwire.EncodeSend(boxB.Public(), testXferID, testDestFP, src)
	line := signedLine(t, priv, payloadHost(sendCmd, testGateHostFP))

	if code, _, _ := runWith(t, line); code != exitSoftware {
		t.Fatalf("exit = %d; want 70 on an insecure-mode key", code)
	}
}

// TestXferSend_MissingSourceExit70: SEND whose SrcPath does not exist → exit 70.
func TestXferSend_MissingSourceExit70(t *testing.T) {
	dir := t.TempDir()
	pub, priv := genKey(t)
	seedPub(t, dir, pub, 0o644)
	boxA, idA := genXferKeys(t)
	seedXferKeyFiles(t, dir, boxA, idA)
	withGateDir(t, dir)

	boxB, _ := genXferKeys(t)
	missing := filepath.Join(t.TempDir(), "does-not-exist.secret")
	sendCmd, _ := xferwire.EncodeSend(boxB.Public(), testXferID, testDestFP, missing)
	line := signedLine(t, priv, payloadHost(sendCmd, testGateHostFP))

	if code, _, _ := runWith(t, line); code != exitSoftware {
		t.Fatalf("exit = %d; want 70 on a missing source file", code)
	}
}

// TestXferSend_EmptySourceExit65: SEND whose SrcPath is an empty file → exit 65.
func TestXferSend_EmptySourceExit65(t *testing.T) {
	dir := t.TempDir()
	pub, priv := genKey(t)
	seedPub(t, dir, pub, 0o644)
	boxA, idA := genXferKeys(t)
	seedXferKeyFiles(t, dir, boxA, idA)
	withGateDir(t, dir)

	boxB, _ := genXferKeys(t)
	src := writeSource(t, "") // empty
	sendCmd, _ := xferwire.EncodeSend(boxB.Public(), testXferID, testDestFP, src)
	line := signedLine(t, priv, payloadHost(sendCmd, testGateHostFP))

	if code, _, _ := runWith(t, line); code != exitDataErr {
		t.Fatalf("exit = %d; want 65 on an empty source file", code)
	}
}

// TestXferSend_OversizeSourceExit65: SEND whose source exceeds the (shrunk) cap
// → exit 65 via the bounded read.
func TestXferSend_OversizeSourceExit65(t *testing.T) {
	saved := maxXferPlaintextBytes
	maxXferPlaintextBytes = 32
	t.Cleanup(func() { maxXferPlaintextBytes = saved })

	dir := t.TempDir()
	pub, priv := genKey(t)
	seedPub(t, dir, pub, 0o644)
	boxA, idA := genXferKeys(t)
	seedXferKeyFiles(t, dir, boxA, idA)
	withGateDir(t, dir)

	boxB, _ := genXferKeys(t)
	src := writeSource(t, strings.Repeat("A", 128)) // > 32-byte cap
	sendCmd, _ := xferwire.EncodeSend(boxB.Public(), testXferID, testDestFP, src)
	line := signedLine(t, priv, payloadHost(sendCmd, testGateHostFP))

	if code, _, _ := runWith(t, line); code != exitDataErr {
		t.Fatalf("exit = %d; want 65 on an oversize source file", code)
	}
}

// TestXferSend_NeverExecTreatedAsData is the load-bearing "never-exec" proof: a
// source file whose bytes are a shell-metachar string is sealed as DATA — no
// side effect occurs (the sentinel file is never created) and the bytes
// round-trip verbatim through Open, proving the leg was never shell-executed.
func TestXferSend_NeverExecTreatedAsData(t *testing.T) {
	dir := t.TempDir()
	pub, priv := genKey(t)
	seedPub(t, dir, pub, 0o644)
	boxA, idA := genXferKeys(t)
	seedXferKeyFiles(t, dir, boxA, idA)
	withGateDir(t, dir)

	boxB, _ := genXferKeys(t)
	pwned := filepath.Join(t.TempDir(), "pwned")
	// The source CONTENT is a shell-injection payload. If any layer shell-exec'd
	// it, `touch <pwned>` would fire.
	payload := "; touch " + pwned + " #"
	src := writeSource(t, payload)
	sendCmd, _ := xferwire.EncodeSend(boxB.Public(), testXferID, testDestFP, src)
	line := signedLine(t, priv, payloadHost(sendCmd, testGateHostFP))

	code, out, stderr := runWith(t, line)
	if code != exitOK {
		t.Fatalf("exit = %d; want 0 (stderr=%q)", code, stderr)
	}
	// (a) NO side effect — the payload was never executed.
	if _, err := os.Stat(pwned); err == nil {
		t.Fatalf("SIDE EFFECT: %s was created — the source content was shell-executed!", pwned)
	}
	// (b) The bytes round-trip as sealed DATA, verbatim.
	env, err := xfer.Unmarshal([]byte(out))
	if err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	got, err := xfer.Open(env, boxB.Public(), boxB.Private(), idA.Public(), testXferID, testDestFP, 1<<20)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if string(got) != payload {
		t.Errorf("round-tripped bytes = %q; want the exact payload %q (treated as data)", got, payload)
	}
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

// seedAuditAllFull writes an audit-level=all+full config into the gate dir so
// the gate writes its authoritative audit log at max verbosity (the worst case
// for a leak) to gateDir/audit.log.
func seedAuditAllFull(t *testing.T, dir string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, "audit-level"), []byte("all+full"), 0o644); err != nil {
		t.Fatalf("write audit-level: %v", err)
	}
}

// readAudit returns the gate's audit-log contents (empty string if absent).
func readAudit(t *testing.T, dir string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(dir, "audit.log"))
	if err != nil {
		return ""
	}
	return string(b)
}

// assertSentinelAbsent greps stdout, stderr, and the gate audit log for the
// default sentinel plaintext and requires it ABSENT from every surface.
func assertSentinelAbsent(t *testing.T, leg, stdout, stderr, dir string) {
	t.Helper()
	assertSentinelAbsentVal(t, leg+" stdout", stdout, testXferPT)
	assertSentinelAbsentVal(t, leg+" stderr", stderr, testXferPT)
	assertSentinelAbsentVal(t, leg+" audit", readAudit(t, dir), testXferPT)
}

func assertSentinelAbsentVal(t *testing.T, surface, haystack, sentinel string) {
	t.Helper()
	if strings.Contains(haystack, sentinel) {
		t.Errorf("CONFIDENTIALITY: sentinel %q leaked into %s: %q", sentinel, surface, haystack)
	}
}
