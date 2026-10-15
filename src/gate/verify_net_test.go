package gate_test

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/karthikeyan5/sshgate/src/gate"
	"github.com/karthikeyan5/sshgate/src/sigwire"
)

var netNow = time.Unix(1_700_000_000, 0)

func netPayload(isNet, isReveal bool) sigwire.SigPayload {
	return sigwire.SigPayload{
		Cmd: "curl -s https://example.com", TS: netNow.Unix(), Exp: netNow.Add(time.Minute).Unix(),
		Nonce: "nonce-net", Host: hostFP, Reveal: isReveal, Net: isNet,
	}
}

func TestVerifyReturnsNet(t *testing.T) {
	pub, priv := genKey(t)
	for _, isReveal := range []bool{false, true} {
		p := netPayload(true, isReveal)
		got, err := gate.Verify(signedLine(t, priv, p), pub, netNow, hostAny)
		if err != nil {
			t.Fatalf("reveal=%v: Verify: %v", isReveal, err)
		}
		want := gate.Verified{Cmd: p.Cmd, Reveal: isReveal, Net: true}
		if got != want {
			t.Errorf("reveal=%v: Verify = %+v; want %+v", isReveal, got, want)
		}
	}

	got, err := gate.Verify(signedLine(t, priv, netPayload(false, false)), pub, netNow, hostAny)
	if err != nil {
		t.Fatalf("net-less Verify: %v", err)
	}
	if got.Net {
		t.Errorf("net-less Verify returned Net=true")
	}

	// A net payload that fails verification surfaces no capability.
	got, err = gate.Verify(signedLine(t, priv, netPayload(true, true)), pub, netNow.Add(time.Hour), hostAny)
	if !errors.Is(err, gate.ErrExpired) {
		t.Fatalf("expired net Verify err = %v; want ErrExpired", err)
	}
	if got != (gate.Verified{}) {
		t.Errorf("failed Verify leaked %+v", got)
	}
}

// TestVerifySignedRefusesNet proves the legacy entry point never hands a
// network-granted command to a caller that would run it without the grant.
func TestVerifySignedRefusesNet(t *testing.T) {
	pub, priv := genKey(t)
	for _, isReveal := range []bool{false, true} {
		cmd, reveal, err := gate.VerifySigned(signedLine(t, priv, netPayload(true, isReveal)), pub, netNow, hostAny)
		if !errors.Is(err, gate.ErrNetUnsupported) {
			t.Fatalf("reveal=%v: VerifySigned err = %v; want ErrNetUnsupported", isReveal, err)
		}
		if cmd != "" || reveal {
			t.Errorf("reveal=%v: VerifySigned returned cmd=%q reveal=%v alongside the refusal", isReveal, cmd, reveal)
		}
	}
	if gate.ErrNetUnsupported.Error() != sigwire.GateNetUnsupported {
		t.Errorf("ErrNetUnsupported text = %q; want %q", gate.ErrNetUnsupported, sigwire.GateNetUnsupported)
	}

	p := netPayload(false, true)
	cmd, reveal, err := gate.VerifySigned(signedLine(t, priv, p), pub, netNow, hostAny)
	if err != nil || cmd != p.Cmd || !reveal {
		t.Errorf("net-less VerifySigned = (%q, %v, %v); want (%q, true, nil)", cmd, reveal, err, p.Cmd)
	}
}

// TestVerifyNetTamper proves net cannot be added to or stripped from a signed
// payload on the wire: the gate re-marshals what it decoded, so any change to
// the effective flag breaks the signature, and only spellings that decode to
// net=false verify against the net-less signature.
func TestVerifyNetTamper(t *testing.T) {
	pub, priv := genKey(t)
	netLess := netPayload(false, false)
	withNet := netPayload(true, false)
	netLessSig := signPayload(t, priv, netLess)
	withNetSig := signPayload(t, priv, withNet)
	netLessJSON := marshalPayload(t, netLess)

	appendField := func(field string) string {
		return strings.TrimSuffix(netLessJSON, "}") + "," + field + "}"
	}
	cases := []struct {
		name          string
		body          string
		sig           []byte
		isNetLessGood bool
	}{
		{"add net:true", appendField(`"net":true`), netLessSig, false},
		{"add NET:true", appendField(`"NET":true`), netLessSig, false},
		{"add Net:true", appendField(`"Net":true`), netLessSig, false},
		{"add nEt:true", appendField(`"nEt":true`), netLessSig, false},
		{"add duplicate ending true", appendField(`"net":false,"net":true`), netLessSig, false},
		{"strip net from a net signature", netLessJSON, withNetSig, false},
		{"net:null under net signature", appendField(`"net":null`), withNetSig, false},
		{"net:false under net signature", appendField(`"net":false`), withNetSig, false},
		{"net:null under net-less signature", appendField(`"net":null`), netLessSig, true},
		{"net:false under net-less signature", appendField(`"net":false`), netLessSig, true},
		{"duplicate ending false under net-less signature", appendField(`"net":true,"net":false`), netLessSig, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := gate.Verify(rawEnvelope(tc.sig, tc.body), pub, netNow, hostAny)
			if !tc.isNetLessGood {
				if !errors.Is(err, gate.ErrBadSig) {
					t.Fatalf("Verify err = %v; want ErrBadSig", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("Verify: %v", err)
			}
			if got.Net || got.Cmd != netLess.Cmd {
				t.Errorf("Verify = %+v; want the net-less command", got)
			}
		})
	}
}

func marshalPayload(t *testing.T, p sigwire.SigPayload) string {
	t.Helper()
	b, err := json.Marshal(p)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return string(b)
}

func signPayload(t *testing.T, priv ed25519.PrivateKey, p sigwire.SigPayload) []byte {
	t.Helper()
	return ed25519.Sign(priv, []byte(marshalPayload(t, p)))
}

// rawEnvelope builds a SSHGATE_SIG line from a signature and arbitrary JSON
// bytes, bypassing EncodeSigned so the payload can differ from what was signed.
func rawEnvelope(sig []byte, body string) string {
	encoding := base64.URLEncoding.WithPadding(base64.NoPadding)
	return "SSHGATE_SIG:" + encoding.EncodeToString(sig) + ":" + encoding.EncodeToString([]byte(body))
}
