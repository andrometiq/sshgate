package signer

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"path/filepath"
	"testing"
	"time"

	"github.com/karthikeyan5/sshgate/src/gate"
	"github.com/karthikeyan5/sshgate/src/signer/backend"
	"github.com/karthikeyan5/sshgate/src/sigwire"
	"github.com/karthikeyan5/sshgate/src/xfer"
)

// envelope_golden_test.go is a PHASE-0 FREEZE HARNESS (signerkit extraction,
// SPEC §Phase 0(a)). It pins the EXACT "SSHGATE_SIG:<sig>:<payload>" wire
// strings the signer's local-signing path emits, so the byte-for-byte envelope
// is provably identical before and after the core moves to pkg/signerkit. It is
// the cross-refactor proof: signAll (:1415) and signTransferLegs (:1094) are
// driven through a realistic Daemon + MockBackend flow, the emitted wire string
// is compared against a hand-frozen golden const, and EACH golden is then run
// through gate.VerifySigned — the REAL gate — so a frozen envelope provably
// passes TODAY's verifier (not merely a self-consistent encoder).
//
// The file lives in package signer (white-box) because signAll,
// signTransferLegs, and the randRead entropy seam are unexported; per critique
// note N2 it therefore TRAVELS with the core at phase 2. There is no
// gate->signer import cycle (gate/verify.go imports only sigwire), so importing
// gate here is safe.
//
// Determinism. Every input is pinned: a fixed-seed Ed25519 key (repo
// convention seed[i]=byte(i), as in hostkey/fingerprint_test.go), a fixed
// NowFunc, and a deterministic randRead stub swapped in for the nonce/xfer-id
// entropy source. Ed25519 signing is itself deterministic (RFC 8032), so with
// those three pinned the whole wire string is reproducible. The randRead swap
// mutates package state, so — exactly like TestSignAll_NonceFailure in
// daemon_internal_test.go — these tests do NOT call t.Parallel() and restore
// randRead via defer; Go runs the non-parallel bodies to completion before any
// t.Parallel() test resumes, so no parallel signer test races the swapped var.

// Shared golden fixtures. Also reused by socketrpc_golden_test.go (same
// package), which pins the full JSON response lines that carry these same
// wire strings.
const (
	goldenNowUnix int64 = 1000                      // fixed NowFunc epoch → payload.TS
	goldenTTL     int64 = 60                        // fixed ttl → Exp = TS + 60
	goldenCmd           = "systemctl restart nginx" // a representative write
	goldenHostFP        = "SHA256:Zm9vYmFyLWZpeGVkLWdvbGRlbi1ob3N0LWZwLTAwMDAwMDAx"

	// Transfer fixtures (SPEC §Phase 0(a): drive signTransferLegs).
	goldenSrcFP    = "SHA256:src-fp-golden-aaaaaaaaaaaaaaaaaaaaaaaa"
	goldenDestFP   = "SHA256:dst-fp-golden-bbbbbbbbbbbbbbbbbbbbbbbb"
	goldenSrcPath  = "/etc/src-secret.env"
	goldenDestPath = "/etc/dst-secret.env"
	goldenMode     = "0600"
)

// goldenSignerKey returns the fixed-seed Ed25519 signing key (and its public
// half) used by every golden in this package. The seed is the repo-conventional
// deterministic 32-byte ramp (seed[i]=byte(i)).
func goldenSignerKey() (ed25519.PrivateKey, ed25519.PublicKey) {
	seed := make([]byte, ed25519.SeedSize)
	for i := range seed {
		seed[i] = byte(i)
	}
	priv := ed25519.NewKeyFromSeed(seed)
	return priv, priv.Public().(ed25519.PublicKey)
}

// goldenNow is the fixed clock injected as Daemon.NowFunc for every golden.
func goldenNow() time.Time { return time.Unix(goldenNowUnix, 0) }

// fixedEntropy returns a deterministic replacement for the package randRead
// seam: call N fills the buffer with a fixed, N-dependent ramp so successive
// nonces / xfer-ids are DISTINCT yet fully reproducible. The golden consts
// below are frozen from this exact sequence. Callers swap it in and restore the
// original under defer (see the file-level determinism note).
func fixedEntropy() func([]byte) (int, error) {
	var call int
	return func(b []byte) (int, error) {
		for i := range b {
			b[i] = byte((call+1)*7 + i*3)
		}
		call++
		return len(b), nil
	}
}

// goldenSignDaemon builds a Daemon with the fixed key, the fixed clock, an
// in-memory audit sink, and the supplied backend — the minimal realistic core
// for driving the sign path.
func goldenSignDaemon(t *testing.T, bk backend.Backend) (*Daemon, ed25519.PublicKey) {
	t.Helper()
	priv, pub := goldenSignerKey()
	audit, err := NewMemAuditLog()
	if err != nil {
		t.Fatalf("mem audit: %v", err)
	}
	t.Cleanup(func() { audit.Close() })
	d := &Daemon{
		Key:     priv,
		Backend: bk,
		Audit:   audit,
		NowFunc: goldenNow,
	}
	return d, pub
}

// goldenXferDaemon builds a Daemon additionally wired with a transfer registry
// holding TWO endpoints (src + dest) whose box/id keys are FIXED, so the two
// signed legs — which embed the registry-sourced keys — are byte-reproducible.
func goldenXferDaemon(t *testing.T, bk backend.Backend) (*Daemon, ed25519.PublicKey) {
	t.Helper()
	d, pub := goldenSignDaemon(t, bk)
	reg, err := LoadXferRegistry(filepath.Join(t.TempDir(), "xfer-registry.json"))
	if err != nil {
		t.Fatalf("load registry: %v", err)
	}
	// Fixed box (X25519) + id (ed25519) public keys — any 32 bytes are a valid
	// public half for embedding into a leg. Both endpoints register the same
	// pair: the SEND leg carries dest's box key, the RECV leg carries src's id
	// key, and both are pinned here.
	var boxPub [32]byte
	idPub := make(ed25519.PublicKey, ed25519.PublicKeySize)
	for i := 0; i < 32; i++ {
		boxPub[i] = byte(0x40 + i)
		idPub[i] = byte(0x80 + i)
	}
	boxText := xfer.BoxPublicText(&boxPub)
	idText := xfer.IDPublicText(idPub)
	if err := reg.Register(goldenSrcFP, "src-golden", boxText, idText); err != nil {
		t.Fatalf("register src: %v", err)
	}
	if err := reg.Register(goldenDestFP, "dest-golden", boxText, idText); err != nil {
		t.Fatalf("register dest: %v", err)
	}
	d.XferRegistry = reg
	return d, pub
}

// driveGolden sends one JSON request line through HandleSignRequest and returns
// the response line with its trailing newline stripped (the byte-exact wire
// line). It is the shared driver for both golden files.
func driveGolden(t *testing.T, d *Daemon, body string) string {
	t.Helper()
	conn := &rwBuf{in: bytes.NewReader([]byte(body + "\n")), out: &bytes.Buffer{}}
	if err := d.HandleSignRequest(context.Background(), conn); err != nil {
		t.Fatalf("HandleSignRequest returned a hard error: %v", err)
	}
	return string(bytes.TrimRight(conn.out.Bytes(), "\n"))
}

// signRespGolden is the decoded shape used to extract the inner SSHGATE_SIG
// wire string from a sign response.
type signRespGolden struct {
	Status     string `json:"status"`
	Signatures []struct {
		Cmd string `json:"cmd"`
		Sig string `json:"sig"`
	} `json:"signatures"`
}

// transferRespGolden is the decoded shape used to extract the two leg wire
// strings from a transfer response.
type transferRespGolden struct {
	Status string `json:"status"`
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

// ---- Golden wire strings (frozen; see file header). ----
//
// Each is the EXACT "SSHGATE_SIG:<sigB64>:<payloadB64>" string signAll /
// signTransferLegs emit for the fixed inputs. A change to JSON field order in
// SigPayload, the base64 alphabet, the Host/Reveal stamping, the entropy
// sequence, or the fixed key flips these — and that is the tripwire.

// wantSignHostGolden: signAll with Host stamped (:1430), reveal=false.
const wantSignHostGolden = `SSHGATE_SIG:o7XPO8_vMG1BCD6MDyo-1F7baBpr6Pn8Q79fLvhrSGyRATHGJH3agHQLYROmr1go-X8flT-ttto2BIvXvSSgAg:eyJjbWQiOiJzeXN0ZW1jdGwgcmVzdGFydCBuZ2lueCIsInRzIjoxMDAwLCJleHAiOjEwNjAsIm5vbmNlIjoiQndvTkVCTVdHUndmSWlVb0t5NHhOQSIsImhvc3QiOiJTSEEyNTY6Wm05dlltRnlMV1pwZUdWa0xXZHZiR1JsYmkxb2IzTjBMV1p3TFRBd01EQXdNREF4In0`

// wantSignRevealGolden: signAll with Host stamped AND Reveal=true (:1436) — the
// signed payload carries the reveal capability.
const wantSignRevealGolden = `SSHGATE_SIG:zRQlkgBKsDW78fwy-nnlY_s2KvxcOEZADuLnRZ8JNyMIKuGCctvZLlG6_pgiV-8lcKo_ZgiSXYWn9r9hpAuQCQ:eyJjbWQiOiJzeXN0ZW1jdGwgcmVzdGFydCBuZ2lueCIsInRzIjoxMDAwLCJleHAiOjEwNjAsIm5vbmNlIjoiQndvTkVCTVdHUndmSWlVb0t5NHhOQSIsImhvc3QiOiJTSEEyNTY6Wm05dlltRnlMV1pwZUdWa0xXZHZiR1JsYmkxb2IzTjBMV1p3TFRBd01EQXdNREF4IiwicmV2ZWFsIjp0cnVlfQ`

// wantXferSendGolden / wantXferRecvGolden: the two signTransferLegs legs, each
// host-bound to its own gate (SEND=src_fp, RECV=dest_fp).
const wantXferSendGolden = `SSHGATE_SIG:BDyVWL2M2Bt2meUklzN5C-YWvXchZ7pvolHthi6SzV7sf8nY8EQghb-Ro4EXtlx2CMQhvvZKmGSHk61lRbMmAA:eyJjbWQiOiJTU0hHQVRFX1hGRVJfU0VORCBjM05vWjJGMFpTMTRabVZ5TFdKdmVDMTRNalUxTVRrZ1VVVkdRMUV3VWtaU2EyUkpVMVZ3VEZSRk1VOVVNVUpTVld4T1ZWWldXbGhYUm14aFZ6RjRaRmhzT0QwIFFuZHZUa1ZDVFZkSFVuZG1TV2xWYjB0NU5IaE9RUSBVMGhCTWpVMk9tUnpkQzFtY0MxbmIyeGtaVzR0WW1KaVltSmlZbUppWW1KaVltSmlZbUppWW1KaVltSmkgTDJWMFl5OXpjbU10YzJWamNtVjBMbVZ1ZGciLCJ0cyI6MTAwMCwiZXhwIjoxMDYwLCJub25jZSI6IkRoRVVGeG9kSUNNbUtTd3ZNalU0T3ciLCJob3N0IjoiU0hBMjU2OnNyYy1mcC1nb2xkZW4tYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhIn0`
const wantXferRecvGolden = `SSHGATE_SIG:FtvQ4JET-Q8UmWFdvCvdl91iTQLbHN47CUEccmshLA6R2VVHETCR9rhdOploM8pW7plpzilDdWohJxY20G0pDw:eyJjbWQiOiJTU0hHQVRFX1hGRVJfUkVDViBjM05vWjJGMFpTMTRabVZ5TFdsa0xXVmtNalUxTVRrZ1owbEhRMmMwVTBab2IyVkphVmx4VEdwSk1rOXFOVU5TYTNCUFZXeGFZVmh0U20xaGJUVjVaRzV3T0QwIFFuZHZUa1ZDVFZkSFVuZG1TV2xWYjB0NU5IaE9RUSBVMGhCTWpVMk9uTnlZeTFtY0MxbmIyeGtaVzR0WVdGaFlXRmhZV0ZoWVdGaFlXRmhZV0ZoWVdGaFlXRmggVTBoQk1qVTJPbVJ6ZEMxbWNDMW5iMnhrWlc0dFltSmlZbUppWW1KaVltSmlZbUppWW1KaVltSmlZbUppIE1EWXdNQSBMMlYwWXk5a2MzUXRjMlZqY21WMExtVnVkZyIsInRzIjoxMDAwLCJleHAiOjEwNjAsIm5vbmNlIjoiRlJnYkhpRWtKeW90TURNMk9Ud19RZyIsImhvc3QiOiJTSEEyNTY6ZHN0LWZwLWdvbGRlbi1iYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmIifQ`

// TestEnvelopeGolden_SignHost freezes the Host-bound (non-reveal) signAll
// envelope and proves it verifies on the gate bound to that host fingerprint.
func TestEnvelopeGolden_SignHost(t *testing.T) {
	// Not t.Parallel(): swaps the package-level randRead seam.
	orig := randRead
	defer func() { randRead = orig }()
	randRead = fixedEntropy()

	mock := backend.NewMockBackend()
	d, pub := goldenSignDaemon(t, mock)
	mock.Approve("r_host", "operator")

	body := `{"kind":"sign","request_id":"r_host","commands":[{"server":"prod","cmd":"` +
		goldenCmd + `","ttl_seconds":60,"host":"` + goldenHostFP + `"}]}`
	var resp signRespGolden
	if err := json.Unmarshal([]byte(driveGolden(t, d, body)), &resp); err != nil {
		t.Fatalf("decode sign response: %v", err)
	}
	if resp.Status != "approved" || len(resp.Signatures) != 1 {
		t.Fatalf("status=%q sigs=%d; want approved/1", resp.Status, len(resp.Signatures))
	}
	got := resp.Signatures[0].Sig
	if got != wantSignHostGolden {
		t.Errorf("Host-bound envelope drift:\n got  %q\n want %q", got, wantSignHostGolden)
	}
	// The frozen golden must pass TODAY's gate, bound to goldenHostFP.
	inner, reveal, err := gate.VerifySigned(wantSignHostGolden, pub, goldenNow(), []string{goldenHostFP})
	if err != nil {
		t.Fatalf("gate.VerifySigned(host golden): %v", err)
	}
	if inner != goldenCmd {
		t.Errorf("verified inner cmd = %q; want %q", inner, goldenCmd)
	}
	if reveal {
		t.Errorf("reveal = true; want false for the non-reveal golden")
	}
	// Cross-host un-replayability: it must NOT verify on a different host set.
	if _, _, err := gate.VerifySigned(wantSignHostGolden, pub, goldenNow(), []string{goldenDestFP}); err == nil {
		t.Error("host golden verified on a foreign host set — binding broken")
	}
}

// TestEnvelopeGolden_SignReveal freezes the Reveal-bearing signAll envelope and
// proves the gate surfaces reveal=true from the AUTHENTICATED payload.
func TestEnvelopeGolden_SignReveal(t *testing.T) {
	orig := randRead
	defer func() { randRead = orig }()
	randRead = fixedEntropy()

	mock := backend.NewMockBackend()
	d, pub := goldenSignDaemon(t, mock)
	mock.Approve("r_reveal", "operator")

	body := `{"kind":"sign","request_id":"r_reveal","commands":[{"server":"prod","cmd":"` +
		goldenCmd + `","ttl_seconds":60,"host":"` + goldenHostFP + `","reveal":true,"reason":"rotate creds"}]}`
	var resp signRespGolden
	if err := json.Unmarshal([]byte(driveGolden(t, d, body)), &resp); err != nil {
		t.Fatalf("decode sign response: %v", err)
	}
	if resp.Status != "approved" || len(resp.Signatures) != 1 {
		t.Fatalf("status=%q sigs=%d; want approved/1", resp.Status, len(resp.Signatures))
	}
	got := resp.Signatures[0].Sig
	if got != wantSignRevealGolden {
		t.Errorf("Reveal envelope drift:\n got  %q\n want %q", got, wantSignRevealGolden)
	}
	inner, reveal, err := gate.VerifySigned(wantSignRevealGolden, pub, goldenNow(), []string{goldenHostFP})
	if err != nil {
		t.Fatalf("gate.VerifySigned(reveal golden): %v", err)
	}
	if inner != goldenCmd {
		t.Errorf("verified inner cmd = %q; want %q", inner, goldenCmd)
	}
	if !reveal {
		t.Errorf("reveal = false; want true (the signed payload set it)")
	}
}

// TestEnvelopeGolden_TransferLegs freezes both signTransferLegs legs and proves
// each verifies ONLY on its own gate — SEND on src_fp, RECV on dest_fp — the
// per-leg host binding that makes a leg un-replayable on the wrong host.
func TestEnvelopeGolden_TransferLegs(t *testing.T) {
	orig := randRead
	defer func() { randRead = orig }()
	randRead = fixedEntropy()

	mock := backend.NewMockBackend()
	d, pub := goldenXferDaemon(t, mock)
	mock.Approve("t_golden", "operator")

	body := `{"kind":"transfer","request_id":"t_golden","src_alias":"src","src_fp":"` + goldenSrcFP +
		`","src_path":"` + goldenSrcPath + `","dest_alias":"dest","dest_fp":"` + goldenDestFP +
		`","dest_path":"` + goldenDestPath + `","mode":"` + goldenMode + `","ttl_seconds":60}`
	var resp transferRespGolden
	if err := json.Unmarshal([]byte(driveGolden(t, d, body)), &resp); err != nil {
		t.Fatalf("decode transfer response: %v", err)
	}
	if resp.Status != "approved" || resp.Send == nil || resp.Recv == nil {
		t.Fatalf("status=%q (err=%q) send=%v recv=%v; want approved/both-legs",
			resp.Status, resp.Error, resp.Send, resp.Recv)
	}
	if resp.Send.Sig != wantXferSendGolden {
		t.Errorf("SEND leg envelope drift:\n got  %q\n want %q", resp.Send.Sig, wantXferSendGolden)
	}
	if resp.Recv.Sig != wantXferRecvGolden {
		t.Errorf("RECV leg envelope drift:\n got  %q\n want %q", resp.Recv.Sig, wantXferRecvGolden)
	}
	// SEND verifies on the source gate only.
	if _, _, err := gate.VerifySigned(wantXferSendGolden, pub, goldenNow(), []string{goldenSrcFP}); err != nil {
		t.Fatalf("gate.VerifySigned(SEND golden, src host): %v", err)
	}
	if _, _, err := gate.VerifySigned(wantXferSendGolden, pub, goldenNow(), []string{goldenDestFP}); err == nil {
		t.Error("SEND golden verified on the DEST gate — host binding broken")
	}
	// RECV verifies on the destination gate only.
	if _, _, err := gate.VerifySigned(wantXferRecvGolden, pub, goldenNow(), []string{goldenDestFP}); err != nil {
		t.Fatalf("gate.VerifySigned(RECV golden, dest host): %v", err)
	}
	if _, _, err := gate.VerifySigned(wantXferRecvGolden, pub, goldenNow(), []string{goldenSrcFP}); err == nil {
		t.Error("RECV golden verified on the SRC gate — host binding broken")
	}
}

// sanity: sigwire round-trips the frozen goldens (guards the literals against a
// hand-transcription typo independent of the gate check above).
func TestEnvelopeGolden_RoundTrip(t *testing.T) {
	t.Parallel()
	for name, g := range map[string]string{
		"sign-host":   wantSignHostGolden,
		"sign-reveal": wantSignRevealGolden,
		"xfer-send":   wantXferSendGolden,
		"xfer-recv":   wantXferRecvGolden,
	} {
		if _, _, err := sigwire.DecodeSigned(g); err != nil {
			t.Errorf("%s golden does not decode: %v", name, err)
		}
	}
}
