package hosted_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/karthikeyan5/sshgate/pkg/signerkit"
	"github.com/karthikeyan5/sshgate/src/gate"
	"github.com/karthikeyan5/sshgate/src/sigwire"
)

// These tests were the branch's Phase-A signing-engine proofs against its own
// signerserver.Signer. The phase-5 one-codebase port DELETED that type; sign-
// at-approval now routes through the shared signerkit core (Service.
// SignApproved -> signBytes). The assertions are UNCHANGED — gate-valid round
// trip, tamper rejection, fresh nonce, validity cap, approval-time TS, and the
// hosted wire-shape — they simply prove the shared core produces gate-valid
// envelopes rather than the deleted branch engine. The file-key-load + nonce-
// seam proofs moved with the code: signerkit.LoadKey is covered by the
// keystore tests, and the newNonce/randRead failure path by the in-package
// signerkit tests (TestSignAll_NonceFailure + TestSignApproved_NonceFailure).

// testSigner builds the shared signerkit core over a fresh keypair and returns
// it alongside its public half (for gate verification). Audit is an inert
// append-only sink to io.Discard — SignApproved does not touch it.
func testSigner(t *testing.T) (*signerkit.Service, ed25519.PublicKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate test key: %v", err)
	}
	svc, err := signerkit.New(signerkit.Config{
		Signer: priv,
		Audit:  signerkit.NewAppendOnlySink(io.Discard),
	})
	if err != nil {
		t.Fatalf("signerkit.New: %v", err)
	}
	return svc, pub
}

// TestSigner_GoldenGateRoundTrip is the security foundation: the envelope the
// core mints MUST verify under gate.VerifySigned against the signing key's
// public half. This is the only proof that the hosted signer produces gate-
// valid signatures rather than plausible-looking JSON. It also asserts the
// inner command survives the round-trip.
func TestSigner_GoldenGateRoundTrip(t *testing.T) {
	t.Parallel()
	s, pub := testSigner(t)

	approvedAt := time.Unix(1_700_000_000, 0)
	const cmd = "systemctl restart nginx"
	results, err := s.SignApproved([]signerkit.HostedSignCommand{{Cmd: cmd, TTLSeconds: 120, HostKeyFP: testHostFP}}, approvedAt)
	if err != nil {
		t.Fatalf("SignApproved: %v", err)
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
	innerCmd, _, err := gate.VerifySigned(results[0].Sig, pub, verifyAt, []string{testHostFP})
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

// TestSigner_GoldenRejectsTampering proves gate REJECTS an envelope whose
// payload or signature has been altered after signing — i.e. the signature
// actually binds the bytes, it is not decorative.
func TestSigner_GoldenRejectsTampering(t *testing.T) {
	t.Parallel()
	s, pub := testSigner(t)

	approvedAt := time.Unix(1_700_000_000, 0)
	verifyAt := approvedAt.Add(30 * time.Second)
	const cmd = "rm -rf /var/cache/app"
	results, err := s.SignApproved([]signerkit.HostedSignCommand{{Cmd: cmd, TTLSeconds: 60, HostKeyFP: testHostFP}}, approvedAt)
	if err != nil {
		t.Fatalf("SignApproved: %v", err)
	}
	good := results[0].Sig

	// Baseline: the untampered envelope verifies.
	if _, _, err := gate.VerifySigned(good, pub, verifyAt, []string{testHostFP}); err != nil {
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

	// (a) Tamper the PAYLOAD: swap the cmd to a more dangerous one but keep the
	// original signature. gate must reject (ErrBadSig).
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
	if _, _, err := gate.VerifySigned(tamperedPayloadEnvelope, pub, verifyAt, []string{testHostFP}); !errors.Is(err, gate.ErrBadSig) {
		t.Fatalf("tampered-payload envelope: got err %v, want ErrBadSig", err)
	}

	// (b) Tamper the SIGNATURE: flip a byte in the sig, keep the payload.
	rawSig, err := enc.DecodeString(sigB64)
	if err != nil {
		t.Fatalf("decode sig: %v", err)
	}
	rawSig[0] ^= 0xFF
	tamperedSigEnvelope := prefix + enc.EncodeToString(rawSig) + ":" + payloadB64
	if _, _, err := gate.VerifySigned(tamperedSigEnvelope, pub, verifyAt, []string{testHostFP}); !errors.Is(err, gate.ErrBadSig) {
		t.Fatalf("tampered-sig envelope: got err %v, want ErrBadSig", err)
	}

	// (c) Wrong key: a different public key must reject (ErrBadSig).
	otherPub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate other key: %v", err)
	}
	if _, _, err := gate.VerifySigned(good, otherPub, verifyAt, []string{testHostFP}); !errors.Is(err, gate.ErrBadSig) {
		t.Fatalf("wrong-key verify: got err %v, want ErrBadSig", err)
	}
}

// TestSigner_FreshNoncePerCommand proves two signs of the SAME command produce
// DIFFERENT envelopes (distinct nonces), both within and across SignApproved
// calls — so an attacker cannot recognise a repeated approval.
func TestSigner_FreshNoncePerCommand(t *testing.T) {
	t.Parallel()
	s, _ := testSigner(t)
	approvedAt := time.Unix(1_700_000_000, 0)
	const cmd = "uptime"

	// Two identical commands in one batch.
	batch, err := s.SignApproved([]signerkit.HostedSignCommand{
		{Cmd: cmd, TTLSeconds: 60, HostKeyFP: testHostFP},
		{Cmd: cmd, TTLSeconds: 60, HostKeyFP: testHostFP},
	}, approvedAt)
	if err != nil {
		t.Fatalf("SignApproved batch: %v", err)
	}
	if batch[0].Sig == batch[1].Sig {
		t.Fatalf("two identical commands in one batch produced identical envelopes (nonce not fresh)")
	}

	// Same command, separate SignApproved call, same approval time.
	again, err := s.SignApproved([]signerkit.HostedSignCommand{{Cmd: cmd, TTLSeconds: 60, HostKeyFP: testHostFP}}, approvedAt)
	if err != nil {
		t.Fatalf("SignApproved again: %v", err)
	}
	if again[0].Sig == batch[0].Sig {
		t.Fatalf("same command across SignApproved calls produced identical envelopes (nonce not fresh)")
	}

	// Confirm the difference is the nonce, not the timestamp: decode both and
	// assert TS/Exp match but Nonce differs.
	n0 := nonceOf(t, batch[0].Sig)
	n1 := nonceOf(t, batch[1].Sig)
	if n0 == n1 {
		t.Fatalf("decoded nonces are equal: %q", n0)
	}
}

// TestSigner_ValidityWindowEnforced proves the gate's 5-minute cap is honoured
// at signing time: a TTL exactly at the cap is allowed, a TTL over the cap is
// rejected, and a non-positive TTL is rejected. The at-cap envelope must also
// verify under gate (which enforces the same bound on its side).
func TestSigner_ValidityWindowEnforced(t *testing.T) {
	t.Parallel()
	s, pub := testSigner(t)
	approvedAt := time.Unix(1_700_000_000, 0)
	maxSecs := int64(sigwire.MaxSigValidity / time.Second) // 300

	// At the cap: allowed, and gate accepts it.
	atCap, err := s.SignApproved([]signerkit.HostedSignCommand{{Cmd: "df -h", TTLSeconds: maxSecs, HostKeyFP: testHostFP}}, approvedAt)
	if err != nil {
		t.Fatalf("SignApproved at-cap TTL (%d): unexpected error %v", maxSecs, err)
	}
	if _, _, err := gate.VerifySigned(atCap[0].Sig, pub, approvedAt.Add(time.Second), []string{testHostFP}); err != nil {
		t.Fatalf("gate rejected an at-cap envelope: %v", err)
	}
	// Verify Exp-TS == maxSecs exactly.
	if got := expMinusTS(t, atCap[0].Sig); got != maxSecs {
		t.Fatalf("at-cap envelope Exp-TS = %d, want %d", got, maxSecs)
	}

	// Over the cap: rejected, no envelope minted.
	over, err := s.SignApproved([]signerkit.HostedSignCommand{{Cmd: "df -h", TTLSeconds: maxSecs + 1, HostKeyFP: testHostFP}}, approvedAt)
	if err == nil {
		t.Fatalf("SignApproved over-cap TTL (%d): expected error, got results %v", maxSecs+1, over)
	}
	if over != nil {
		t.Fatalf("SignApproved over-cap TTL returned non-nil results: %v", over)
	}

	// Non-positive TTL: rejected.
	for _, bad := range []int64{0, -1, -300} {
		if _, err := s.SignApproved([]signerkit.HostedSignCommand{{Cmd: "df -h", TTLSeconds: bad, HostKeyFP: testHostFP}}, approvedAt); err == nil {
			t.Fatalf("SignApproved TTL=%d: expected error, got nil", bad)
		}
	}

	// A batch where one command is over-cap must reject the WHOLE batch (no
	// partial results).
	mixed, err := s.SignApproved([]signerkit.HostedSignCommand{
		{Cmd: "ok", TTLSeconds: 60, HostKeyFP: testHostFP},
		{Cmd: "bad", TTLSeconds: maxSecs + 100, HostKeyFP: testHostFP},
	}, approvedAt)
	if err == nil {
		t.Fatalf("mixed batch with an over-cap command: expected error, got %v", mixed)
	}
	if mixed != nil {
		t.Fatalf("mixed batch returned partial results: %v", mixed)
	}
}

// TestSigner_TSIsApprovalTime proves the payload TS is the approval time we
// pass in (NOT wall-clock-now), so signatures are stamped at approval, never
// at submit/sign-invocation time.
func TestSigner_TSIsApprovalTime(t *testing.T) {
	t.Parallel()
	s, _ := testSigner(t)
	approvedAt := time.Unix(1_650_000_000, 0)
	results, err := s.SignApproved([]signerkit.HostedSignCommand{{Cmd: "id", TTLSeconds: 90, HostKeyFP: testHostFP}}, approvedAt)
	if err != nil {
		t.Fatalf("SignApproved: %v", err)
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

// TestSigner_WireShapeMatchesHosted is the wire-contract proof: the core's
// output, serialized into the server's poll-response shape, is consumed by the
// REAL HostedServerBackend (its private pollBody/signedSig decode path) — and
// surfaces to the daemon as backend.SignedCmd{Cmd, Sig} with the envelope
// intact and the per-command Cmd preserved (which is what daemon.respond()
// length+Cmd matches against). If the JSON tags ever drift, this test fails.
func TestSigner_WireShapeMatchesHosted(t *testing.T) {
	t.Parallel()
	s, pub := testSigner(t)
	approvedAt := time.Unix(1_700_000_000, 0)

	cmds := []signerkit.HostedSignCommand{
		{Cmd: "systemctl status nginx", TTLSeconds: 120, HostKeyFP: testHostFP},
		{Cmd: "journalctl -u nginx -n 50", TTLSeconds: 120, HostKeyFP: testHostFP},
	}
	results, err := s.SignApproved(cmds, approvedAt)
	if err != nil {
		t.Fatalf("SignApproved: %v", err)
	}

	// Marshal the core output exactly as the server's /v1/poll handler would: a
	// pollResponse-shaped body with {cmd, sig} signatures. We build the JSON
	// from the HostedSignResult (which carries the {cmd, sig} tags) to prove it
	// is itself poll-wire-shaped.
	sigsJSON, err := json.Marshal(results)
	if err != nil {
		t.Fatalf("marshal HostedSignResults: %v", err)
	}
	pollJSON := []byte(`{"request_id":"r_test","status":"approved","signatures":` + string(sigsJSON) + `}`)

	// Stand up a tiny server that returns 202 then the approved poll body, and
	// drive the REAL HostedServerBackend against it.
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

	h := &signerkit.HostedServerBackend{
		BaseURL:  ts.URL,
		APIKey:   apiKey,
		ClientID: "wire-test-client",
		PollWait: time.Second,
		Timeout:  5 * time.Second,
	}
	req := signerkit.ApprovalRequest{
		RequestID: "r_test",
		Submitted: approvedAt,
		Commands: []signerkit.CommandReq{
			{Cmd: cmds[0].Cmd, TTLSec: cmds[0].TTLSeconds, HostKeyFP: testHostFP},
			{Cmd: cmds[1].Cmd, TTLSec: cmds[1].TTLSeconds, HostKeyFP: testHostFP},
		},
	}

	ch, err := h.Request(context.Background(), req)
	if err != nil {
		t.Fatalf("HostedServerBackend.Request: %v", err)
	}
	res := <-ch

	if res.Status != signerkit.StatusApproved {
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
		// And the surfaced envelope still verifies under gate — proving the
		// wire round-trip did not corrupt the signature.
		if _, _, err := gate.VerifySigned(res.Signatures[i].Sig, pub, approvedAt.Add(time.Second), []string{testHostFP}); err != nil {
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
