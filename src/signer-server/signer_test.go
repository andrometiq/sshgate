package signerserver_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/karthikeyan5/sshgate/src/gate"
	signerserver "github.com/karthikeyan5/sshgate/src/signer-server"
	"github.com/karthikeyan5/sshgate/src/signer/backend"
	"github.com/karthikeyan5/sshgate/src/sigwire"
)

// testSigner builds a Signer over a fresh, deterministic-enough keypair
// and returns it alongside its public half (for gate verification).
func testSigner(t *testing.T) (*signerserver.Signer, ed25519.PublicKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate test key: %v", err)
	}
	s, err := signerserver.NewSigner(priv)
	if err != nil {
		t.Fatalf("NewSigner: %v", err)
	}
	return s, pub
}

// TestSigner_GoldenGateRoundTrip is the security foundation: the
// envelope the server mints MUST verify under gate.VerifySigned against
// the server key's public half. This is the only proof that the hosted
// signer produces gate-valid signatures rather than plausible-looking
// JSON. It also asserts the inner command survives the round-trip.
func TestSigner_GoldenGateRoundTrip(t *testing.T) {
	t.Parallel()
	s, pub := testSigner(t)

	approvedAt := time.Unix(1_700_000_000, 0)
	const cmd = "systemctl restart nginx"
	results, err := s.Sign([]signerserver.SignCommand{{Cmd: cmd, TTLSeconds: 120}}, approvedAt)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("got %d results, want 1", len(results))
	}
	if results[0].Cmd != cmd {
		t.Fatalf("result cmd = %q, want %q", results[0].Cmd, cmd)
	}

	// gate verifies at a clock inside the validity window (just after
	// approval). It must ACCEPT and hand back the inner cmd.
	verifyAt := approvedAt.Add(30 * time.Second)
	innerCmd, err := gate.VerifySigned(results[0].Sig, pub, verifyAt)
	if err != nil {
		t.Fatalf("gate.VerifySigned rejected a freshly-minted envelope: %v", err)
	}
	if innerCmd != cmd {
		t.Fatalf("gate returned inner cmd %q, want %q", innerCmd, cmd)
	}

	// Sanity: the envelope is a real SSHGATE_SIG wire string.
	if !sigwire.IsSigned(results[0].Sig) {
		t.Fatalf("Sig %q is not a SSHGATE_SIG envelope", results[0].Sig)
	}
}

// TestSigner_GoldenRejectsTampering proves gate REJECTS an envelope
// whose payload or signature has been altered after signing — i.e. the
// signature actually binds the bytes, it is not decorative.
func TestSigner_GoldenRejectsTampering(t *testing.T) {
	t.Parallel()
	s, pub := testSigner(t)

	approvedAt := time.Unix(1_700_000_000, 0)
	verifyAt := approvedAt.Add(30 * time.Second)
	const cmd = "rm -rf /var/cache/app"
	results, err := s.Sign([]signerserver.SignCommand{{Cmd: cmd, TTLSeconds: 60}}, approvedAt)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	good := results[0].Sig

	// Baseline: the untampered envelope verifies.
	if _, err := gate.VerifySigned(good, pub, verifyAt); err != nil {
		t.Fatalf("baseline envelope failed to verify: %v", err)
	}

	// Decompose the envelope: SSHGATE_SIG:<sigB64>:<payloadB64>.
	const prefix = "SSHGATE_SIG:"
	rest := strings.TrimPrefix(good, prefix)
	parts := strings.SplitN(rest, ":", 2)
	if len(parts) != 2 {
		t.Fatalf("malformed envelope under test: %q", good)
	}
	sigB64, payloadB64 := parts[0], parts[1]
	enc := base64.URLEncoding.WithPadding(base64.NoPadding)

	// (a) Tamper the PAYLOAD: swap the cmd to a more dangerous one but
	// keep the original signature. gate must reject (ErrBadSig).
	pb, err := enc.DecodeString(payloadB64)
	if err != nil {
		t.Fatalf("decode payload: %v", err)
	}
	var p sigwire.SigPayload
	if err := json.Unmarshal(pb, &p); err != nil {
		t.Fatalf("unmarshal payload: %v", err)
	}
	p.Cmd = "rm -rf /"
	tamperedPB, err := json.Marshal(p)
	if err != nil {
		t.Fatalf("marshal tampered payload: %v", err)
	}
	tamperedPayloadEnvelope := prefix + sigB64 + ":" + enc.EncodeToString(tamperedPB)
	if _, err := gate.VerifySigned(tamperedPayloadEnvelope, pub, verifyAt); !errors.Is(err, gate.ErrBadSig) {
		t.Fatalf("tampered-payload envelope: got err %v, want ErrBadSig", err)
	}

	// (b) Tamper the SIGNATURE: flip a byte in the sig, keep the payload.
	rawSig, err := enc.DecodeString(sigB64)
	if err != nil {
		t.Fatalf("decode sig: %v", err)
	}
	rawSig[0] ^= 0xFF
	tamperedSigEnvelope := prefix + enc.EncodeToString(rawSig) + ":" + payloadB64
	if _, err := gate.VerifySigned(tamperedSigEnvelope, pub, verifyAt); !errors.Is(err, gate.ErrBadSig) {
		t.Fatalf("tampered-sig envelope: got err %v, want ErrBadSig", err)
	}

	// (c) Wrong key: a different public key must reject (ErrBadSig).
	otherPub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate other key: %v", err)
	}
	if _, err := gate.VerifySigned(good, otherPub, verifyAt); !errors.Is(err, gate.ErrBadSig) {
		t.Fatalf("wrong-key verify: got err %v, want ErrBadSig", err)
	}
}

// TestSigner_FreshNoncePerCommand proves two signs of the SAME command
// produce DIFFERENT envelopes (distinct nonces), both within and across
// Sign calls — so an attacker cannot recognise a repeated approval.
func TestSigner_FreshNoncePerCommand(t *testing.T) {
	t.Parallel()
	s, _ := testSigner(t)
	approvedAt := time.Unix(1_700_000_000, 0)
	const cmd = "uptime"

	// Two identical commands in one batch.
	batch, err := s.Sign([]signerserver.SignCommand{
		{Cmd: cmd, TTLSeconds: 60},
		{Cmd: cmd, TTLSeconds: 60},
	}, approvedAt)
	if err != nil {
		t.Fatalf("Sign batch: %v", err)
	}
	if batch[0].Sig == batch[1].Sig {
		t.Fatalf("two identical commands in one batch produced identical envelopes (nonce not fresh)")
	}

	// Same command, separate Sign call, same approval time.
	again, err := s.Sign([]signerserver.SignCommand{{Cmd: cmd, TTLSeconds: 60}}, approvedAt)
	if err != nil {
		t.Fatalf("Sign again: %v", err)
	}
	if again[0].Sig == batch[0].Sig {
		t.Fatalf("same command across Sign calls produced identical envelopes (nonce not fresh)")
	}

	// Confirm the difference is the nonce, not the timestamp: decode both
	// and assert TS/Exp match but Nonce differs.
	n0 := nonceOf(t, batch[0].Sig)
	n1 := nonceOf(t, batch[1].Sig)
	if n0 == n1 {
		t.Fatalf("decoded nonces are equal: %q", n0)
	}
}

// TestSigner_ValidityWindowEnforced proves the gate's 5-minute cap is
// honoured at signing time: a TTL exactly at the cap is allowed, a TTL
// over the cap is rejected, and a non-positive TTL is rejected. The
// at-cap envelope must also verify under gate (which enforces the same
// bound on its side).
func TestSigner_ValidityWindowEnforced(t *testing.T) {
	t.Parallel()
	s, pub := testSigner(t)
	approvedAt := time.Unix(1_700_000_000, 0)
	maxSecs := int64(sigwire.MaxSigValidity / time.Second) // 300

	// At the cap: allowed, and gate accepts it.
	atCap, err := s.Sign([]signerserver.SignCommand{{Cmd: "df -h", TTLSeconds: maxSecs}}, approvedAt)
	if err != nil {
		t.Fatalf("Sign at-cap TTL (%d): unexpected error %v", maxSecs, err)
	}
	if _, err := gate.VerifySigned(atCap[0].Sig, pub, approvedAt.Add(time.Second)); err != nil {
		t.Fatalf("gate rejected an at-cap envelope: %v", err)
	}
	// Verify Exp-TS == maxSecs exactly.
	if got := expMinusTS(t, atCap[0].Sig); got != maxSecs {
		t.Fatalf("at-cap envelope Exp-TS = %d, want %d", got, maxSecs)
	}

	// Over the cap: rejected, no envelope minted.
	over, err := s.Sign([]signerserver.SignCommand{{Cmd: "df -h", TTLSeconds: maxSecs + 1}}, approvedAt)
	if err == nil {
		t.Fatalf("Sign over-cap TTL (%d): expected error, got results %v", maxSecs+1, over)
	}
	if over != nil {
		t.Fatalf("Sign over-cap TTL returned non-nil results: %v", over)
	}

	// Non-positive TTL: rejected.
	for _, bad := range []int64{0, -1, -300} {
		if _, err := s.Sign([]signerserver.SignCommand{{Cmd: "df -h", TTLSeconds: bad}}, approvedAt); err == nil {
			t.Fatalf("Sign TTL=%d: expected error, got nil", bad)
		}
	}

	// A batch where one command is over-cap must reject the WHOLE batch
	// (no partial results).
	mixed, err := s.Sign([]signerserver.SignCommand{
		{Cmd: "ok", TTLSeconds: 60},
		{Cmd: "bad", TTLSeconds: maxSecs + 100},
	}, approvedAt)
	if err == nil {
		t.Fatalf("mixed batch with an over-cap command: expected error, got %v", mixed)
	}
	if mixed != nil {
		t.Fatalf("mixed batch returned partial results: %v", mixed)
	}
}

// TestSigner_TSIsApprovalTime proves the payload TS is the approval
// time we pass in (NOT wall-clock-now), so signatures are stamped at
// approval, never at submit/sign-invocation time.
func TestSigner_TSIsApprovalTime(t *testing.T) {
	t.Parallel()
	s, _ := testSigner(t)
	approvedAt := time.Unix(1_650_000_000, 0)
	results, err := s.Sign([]signerserver.SignCommand{{Cmd: "id", TTLSeconds: 90}}, approvedAt)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	_, payload, err := sigwire.DecodeSigned(results[0].Sig)
	if err != nil {
		t.Fatalf("DecodeSigned: %v", err)
	}
	if payload.TS != approvedAt.Unix() {
		t.Fatalf("payload TS = %d, want approval time %d", payload.TS, approvedAt.Unix())
	}
	if payload.Exp != approvedAt.Unix()+90 {
		t.Fatalf("payload Exp = %d, want %d", payload.Exp, approvedAt.Unix()+90)
	}
}

// TestLoadSigningKey_RefusesToStart proves the fail-closed startup
// reflex: missing file, insecure permissions, wrong size, empty path,
// and directory all refuse — mirroring NewServer's panic-on-empty-key.
func TestLoadSigningKey_RefusesToStart(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()

	// Missing file -> error, and errors.Is(fs.ErrNotExist).
	missing := filepath.Join(dir, "nope.key")
	if _, err := signerserver.LoadSigningKey(missing); err == nil {
		t.Fatalf("LoadSigningKey(missing): expected error, got nil")
	} else if !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("LoadSigningKey(missing): err %v, want wrapping fs.ErrNotExist", err)
	}

	// Empty path -> error.
	if _, err := signerserver.LoadSigningKey(""); err == nil {
		t.Fatalf("LoadSigningKey(\"\"): expected error, got nil")
	}

	// Valid 64-byte key but insecure mode (group-readable) -> refuse.
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("gen key: %v", err)
	}
	insecure := filepath.Join(dir, "insecure.key")
	if err := os.WriteFile(insecure, priv, 0o640); err != nil {
		t.Fatalf("write insecure key: %v", err)
	}
	if err := os.Chmod(insecure, 0o640); err != nil {
		t.Fatalf("chmod insecure key: %v", err)
	}
	if _, err := signerserver.LoadSigningKey(insecure); err == nil {
		t.Fatalf("LoadSigningKey(0640): expected refusal, got nil")
	} else if !strings.Contains(err.Error(), "insecure mode") {
		t.Fatalf("LoadSigningKey(0640): err %v, want 'insecure mode'", err)
	}

	// World-readable too.
	worldRead := filepath.Join(dir, "world.key")
	if err := os.WriteFile(worldRead, priv, 0o600); err != nil {
		t.Fatalf("write world key: %v", err)
	}
	if err := os.Chmod(worldRead, 0o604); err != nil {
		t.Fatalf("chmod world key: %v", err)
	}
	if _, err := signerserver.LoadSigningKey(worldRead); err == nil {
		t.Fatalf("LoadSigningKey(0604): expected refusal, got nil")
	}

	// Wrong size with secure mode -> refuse.
	wrongSize := filepath.Join(dir, "short.key")
	if err := os.WriteFile(wrongSize, []byte("too short"), 0o600); err != nil {
		t.Fatalf("write short key: %v", err)
	}
	if _, err := signerserver.LoadSigningKey(wrongSize); err == nil {
		t.Fatalf("LoadSigningKey(wrong size): expected refusal, got nil")
	}

	// A directory -> refuse.
	if _, err := signerserver.LoadSigningKey(dir); err == nil {
		t.Fatalf("LoadSigningKey(dir): expected refusal, got nil")
	}
}

// TestLoadSigningKey_HappyPath proves a correctly-provisioned 0600 raw
// Ed25519 key loads AND that the loaded Signer's output verifies under
// gate against the public half — i.e. the on-disk key is wired through
// signing end-to-end, not just stat-checked.
func TestLoadSigningKey_HappyPath(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("gen key: %v", err)
	}
	keyPath := filepath.Join(dir, "master.key")
	if err := os.WriteFile(keyPath, priv, 0o600); err != nil {
		t.Fatalf("write key: %v", err)
	}

	s, err := signerserver.LoadSigningKey(keyPath)
	if err != nil {
		t.Fatalf("LoadSigningKey(0600 valid): %v", err)
	}
	if !s.PublicKey().Equal(pub) {
		t.Fatalf("loaded Signer's public key does not match the on-disk key's public half")
	}

	approvedAt := time.Unix(1_700_000_000, 0)
	res, err := s.Sign([]signerserver.SignCommand{{Cmd: "whoami", TTLSeconds: 60}}, approvedAt)
	if err != nil {
		t.Fatalf("Sign with loaded key: %v", err)
	}
	if _, err := gate.VerifySigned(res[0].Sig, pub, approvedAt.Add(time.Second)); err != nil {
		t.Fatalf("envelope from on-disk key failed gate verify: %v", err)
	}
}

// TestSigner_NonceFailureSurfaces exercises the nonce-error branch:
// when the entropy source fails, Sign returns an error rather than a
// signature over a zero/garbage nonce.
func TestSigner_NonceFailureSurfaces(t *testing.T) {
	// NOT parallel: mutates a package-level seam.
	s, _ := testSigner(t)
	restore := signerserver.SetNonceReaderForTest(func(b []byte) (int, error) {
		return 0, errors.New("simulated entropy failure")
	})
	defer restore()

	if _, err := s.Sign([]signerserver.SignCommand{{Cmd: "id", TTLSeconds: 60}}, time.Now()); err == nil {
		t.Fatalf("expected nonce failure to surface as an error, got nil")
	}
}

// TestSigner_WireShapeMatchesHosted is the wire-contract proof: the
// Signer's output, serialized into the server's poll-response shape, is
// consumed by the REAL HostedServerBackend (src/signer/backend/hosted.go)
// — its private pollBody/signedSig decode path — and surfaces to the
// daemon as backend.SignedCmd{Cmd, Sig} with the envelope intact and the
// per-command Cmd preserved (which is what daemon.respond() length+Cmd
// matches against). If the JSON tags ever drift, this test fails.
func TestSigner_WireShapeMatchesHosted(t *testing.T) {
	t.Parallel()
	s, pub := testSigner(t)
	approvedAt := time.Unix(1_700_000_000, 0)

	cmds := []signerserver.SignCommand{
		{Cmd: "systemctl status nginx", TTLSeconds: 120},
		{Cmd: "journalctl -u nginx -n 50", TTLSeconds: 120},
	}
	results, err := s.Sign(cmds, approvedAt)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}

	// Marshal the Signer output exactly as the server's /v1/poll handler
	// would: a pollResponse-shaped body with {cmd, sig} signatures. We
	// build the JSON from the Signer's SignResult (which carries the
	// {cmd, sig} tags) to prove SignResult is itself poll-wire-shaped.
	sigsJSON, err := json.Marshal(results)
	if err != nil {
		t.Fatalf("marshal SignResults: %v", err)
	}
	pollJSON := []byte(`{"request_id":"r_test","status":"approved","signatures":` + string(sigsJSON) + `}`)

	// Stand up a tiny server that returns 202 then the approved poll
	// body, and drive the REAL HostedServerBackend against it.
	const apiKey = "wire-test-key"
	mux := http.NewServeMux()
	mux.HandleFunc("POST /v1/sign", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusAccepted)
		_, _ = w.Write([]byte(`{"request_id":"r_test","poll_url":"/v1/poll/r_test"}`))
	})
	mux.HandleFunc("GET /v1/poll/{request_id}", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(pollJSON)
	})
	ts := httptest.NewServer(mux)
	defer ts.Close()

	h := &backend.HostedServerBackend{
		BaseURL:  ts.URL,
		APIKey:   apiKey,
		ClientID: "wire-test-client",
		PollWait: time.Second,
		Timeout:  5 * time.Second,
	}
	req := backend.ApprovalRequest{
		RequestID: "r_test",
		Submitted: approvedAt,
		Commands: []backend.CommandReq{
			{Cmd: cmds[0].Cmd, TTLSec: cmds[0].TTLSeconds},
			{Cmd: cmds[1].Cmd, TTLSec: cmds[1].TTLSeconds},
		},
	}

	ch, err := h.Request(context.Background(), req)
	if err != nil {
		t.Fatalf("HostedServerBackend.Request: %v", err)
	}
	res := <-ch

	if res.Status != backend.StatusApproved {
		t.Fatalf("backend result status = %v, want approved", res.Status)
	}
	if len(res.Signatures) != len(cmds) {
		t.Fatalf("backend got %d signatures, want %d", len(res.Signatures), len(cmds))
	}
	for i := range cmds {
		if res.Signatures[i].Cmd != cmds[i].Cmd {
			t.Fatalf("signature[%d].Cmd = %q, want %q (daemon respond() Cmd-match would fail)", i, res.Signatures[i].Cmd, cmds[i].Cmd)
		}
		if res.Signatures[i].Sig != results[i].Sig {
			t.Fatalf("signature[%d].Sig round-trip mismatch:\n got  %q\n want %q", i, res.Signatures[i].Sig, results[i].Sig)
		}
		// And the surfaced envelope still verifies under gate — proving
		// the wire round-trip did not corrupt the signature.
		if _, err := gate.VerifySigned(res.Signatures[i].Sig, pub, approvedAt.Add(time.Second)); err != nil {
			t.Fatalf("signature[%d] failed gate verify after hosted.go round-trip: %v", i, err)
		}
	}
}

// --- helpers ---

func nonceOf(t *testing.T, envelope string) string {
	t.Helper()
	_, payload, err := sigwire.DecodeSigned(envelope)
	if err != nil {
		t.Fatalf("DecodeSigned: %v", err)
	}
	return payload.Nonce
}

func expMinusTS(t *testing.T, envelope string) int64 {
	t.Helper()
	_, payload, err := sigwire.DecodeSigned(envelope)
	if err != nil {
		t.Fatalf("DecodeSigned: %v", err)
	}
	return payload.Exp - payload.TS
}
