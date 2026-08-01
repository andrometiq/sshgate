package signer_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"testing"

	"github.com/karthikeyan5/sshgate/pkg/signerkit"
	"github.com/karthikeyan5/sshgate/src/sigwire"
)

// TestDaemon_SignsRevealFlag pins that the daemon copies a command's reveal
// flag from the sign request into the SIGNED payload's Reveal field. Reveal is
// the capability that lets a single command's output bypass the gate redactor;
// it MUST be part of the signed bytes (so the agent cannot self-elevate) — a
// regression that dropped it would silently un-reveal every approval.
func TestDaemon_SignsRevealFlag(t *testing.T) {
	t.Parallel()
	mock := signerkit.NewMockBackend()
	d, pub, audit, _ := newDaemon(t, mock)
	defer audit.Close()

	const wantHost = "SHA256:prodServerHostKeyFingerprintAAAAAAAAAAAAAAAA"
	req := `{"kind":"sign","request_id":"r_rv1","commands":[{"server":"prod","cmd":"cat /etc/secret.env","ttl_seconds":60,"host":"` + wantHost + `","reveal":true,"reason":"need the DB password to debug auth"}]}`
	conn := &memConn{in: bytes.NewReader([]byte(req + "\n")), out: &bytes.Buffer{}}
	mock.Approve("r_rv1", "operator")

	if err := d.HandleSignRequest(context.Background(), conn); err != nil {
		t.Fatalf("HandleSignRequest: %v", err)
	}

	var resp struct {
		Status     string `json:"status"`
		Signatures []struct {
			Cmd string `json:"cmd"`
			Sig string `json:"sig"`
		} `json:"signatures"`
	}
	if err := json.Unmarshal(bytes.TrimRight(conn.out.Bytes(), "\n"), &resp); err != nil {
		t.Fatalf("unmarshal: %v\nraw=%q", err, conn.out.String())
	}
	if resp.Status != "approved" {
		t.Fatalf("Status = %q; want approved", resp.Status)
	}
	if len(resp.Signatures) != 1 {
		t.Fatalf("got %d sigs; want 1", len(resp.Signatures))
	}
	sig, payload, err := sigwire.DecodeSigned(resp.Signatures[0].Sig)
	if err != nil {
		t.Fatalf("decode sig: %v", err)
	}
	if !payload.Reveal {
		t.Errorf("payload.Reveal = false; want true (daemon must sign the reveal flag in)")
	}
	// The flag is part of the SIGNED bytes, not merely echoed.
	signedBytes, _ := json.Marshal(payload)
	if !ed25519.Verify(pub, signedBytes, sig) {
		t.Errorf("signature does not verify over the reveal-bearing payload")
	}
}

// TestDaemon_DefaultIsNotReveal pins that an ordinary write request (no reveal
// field) signs a reveal=false payload — the common case stays un-revealed.
func TestDaemon_DefaultIsNotReveal(t *testing.T) {
	t.Parallel()
	mock := signerkit.NewMockBackend()
	d, _, audit, _ := newDaemon(t, mock)
	defer audit.Close()

	const wantHost = "SHA256:prodServerHostKeyFingerprintAAAAAAAAAAAAAAAA"
	req := `{"kind":"sign","request_id":"r_rv2","commands":[{"server":"prod","cmd":"systemctl restart nginx","ttl_seconds":60,"host":"` + wantHost + `"}]}`
	conn := &memConn{in: bytes.NewReader([]byte(req + "\n")), out: &bytes.Buffer{}}
	mock.Approve("r_rv2", "operator")

	if err := d.HandleSignRequest(context.Background(), conn); err != nil {
		t.Fatalf("HandleSignRequest: %v", err)
	}
	var resp struct {
		Signatures []struct {
			Sig string `json:"sig"`
		} `json:"signatures"`
	}
	if err := json.Unmarshal(bytes.TrimRight(conn.out.Bytes(), "\n"), &resp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(resp.Signatures) != 1 {
		t.Fatalf("got %d sigs; want 1", len(resp.Signatures))
	}
	_, payload, err := sigwire.DecodeSigned(resp.Signatures[0].Sig)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if payload.Reveal {
		t.Errorf("payload.Reveal = true; want false for an ordinary write")
	}
}
