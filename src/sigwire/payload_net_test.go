package sigwire

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

// v1SigPayload is a vendored copy of SigPayload as it was before the Net field
// (main at ad7407a). Every gate build shipped so far decodes into this shape
// with DisallowUnknownFields, so it stands in for an older gate's decoder.
type v1SigPayload struct {
	Cmd    string `json:"cmd"`
	TS     int64  `json:"ts"`
	Exp    int64  `json:"exp"`
	Nonce  string `json:"nonce"`
	Host   string `json:"host,omitempty"`
	Reveal bool   `json:"reveal,omitempty"`
}

// The Net goldens reuse fixedSig and fixedPayload's fields. Each payload half
// is the URL-safe, unpadded base64 of the JSON written beside it, derived
// independently of the encoder; "net" follows "reveal".
const (
	// {"cmd":"systemctl restart nginx","ts":1716100000,"exp":1716100060,"nonce":"n_a1b2c3d4","net":true}
	wantNetGolden = "SSHGATE_SIG:" +
		"AAcOFRwjKjE4P0ZNVFtiaXB3foWMk5qhqK-2vcTL0tng5-71_AMKERgfJi00O0JJUFdeZWxzeoGIj5adpKuyuQ" +
		":" +
		"eyJjbWQiOiJzeXN0ZW1jdGwgcmVzdGFydCBuZ2lueCIsInRzIjoxNzE2MTAwMDAwLCJleHAiOjE3MTYxMDAwNjAsIm5vbmNlIjoibl9hMWIyYzNkNCIsIm5ldCI6dHJ1ZX0"
	// {"cmd":"systemctl restart nginx","ts":1716100000,"exp":1716100060,"nonce":"n_a1b2c3d4","reveal":true,"net":true}
	wantRevealNetGolden = "SSHGATE_SIG:" +
		"AAcOFRwjKjE4P0ZNVFtiaXB3foWMk5qhqK-2vcTL0tng5-71_AMKERgfJi00O0JJUFdeZWxzeoGIj5adpKuyuQ" +
		":" +
		"eyJjbWQiOiJzeXN0ZW1jdGwgcmVzdGFydCBuZ2lueCIsInRzIjoxNzE2MTAwMDAwLCJleHAiOjE3MTYxMDAwNjAsIm5vbmNlIjoibl9hMWIyYzNkNCIsInJldmVhbCI6dHJ1ZSwibmV0Ijp0cnVlfQ"
)

func TestEncodeSigned_NetGolden(t *testing.T) {
	t.Parallel()
	p := fixedPayload
	p.Net = true
	assertEncodeGolden(t, p, wantNetGolden)
}

func TestEncodeSigned_RevealNetGolden(t *testing.T) {
	t.Parallel()
	p := fixedPayload
	p.Reveal = true
	p.Net = true
	assertEncodeGolden(t, p, wantRevealNetGolden)
}

// assertEncodeGolden checks that p encodes to want and that want decodes back
// to p.
func assertEncodeGolden(t *testing.T, p SigPayload, want string) {
	t.Helper()
	got, err := EncodeSigned(fixedSig, p)
	if err != nil {
		t.Fatalf("EncodeSigned: %v", err)
	}
	if got != want {
		t.Errorf("EncodeSigned golden drift:\n got  %q\n want %q", got, want)
	}
	_, decoded, err := DecodeSigned(want)
	if err != nil {
		t.Fatalf("DecodeSigned(golden): %v", err)
	}
	if decoded != p {
		t.Errorf("golden round-trip mismatch:\n got  %+v\n want %+v", decoded, p)
	}
}

// TestNetFalseByteIdentical proves a payload without network marshals to the
// same bytes as the pre-network struct, so its signature and wire string are
// unchanged.
func TestNetFalseByteIdentical(t *testing.T) {
	t.Parallel()
	const host = "SHA256:abcdefGHIJklmno1234567890PQRSTUVWXYZxyz"
	cases := []struct {
		name   string
		host   string
		reveal bool
	}{
		{"bare", "", false},
		{"host", host, false},
		{"reveal", "", true},
		{"host and reveal", host, true},
	}
	for _, tc := range cases {
		current, err := json.Marshal(SigPayload{Cmd: "ls", TS: 1, Exp: 2, Nonce: "n", Host: tc.host, Reveal: tc.reveal, Net: false})
		if err != nil {
			t.Fatalf("%s: marshal current: %v", tc.name, err)
		}
		old, err := json.Marshal(v1SigPayload{Cmd: "ls", TS: 1, Exp: 2, Nonce: "n", Host: tc.host, Reveal: tc.reveal})
		if err != nil {
			t.Fatalf("%s: marshal v1: %v", tc.name, err)
		}
		if !bytes.Equal(current, old) {
			t.Errorf("%s: net=false changed the signed bytes:\n got  %s\n want %s", tc.name, current, old)
		}
	}
}

// TestDecodeV1RejectsNet proves an older gate's strict decoder refuses every
// payload that names net, in any case and with any value, so it can never run
// a network-granted command while ignoring the grant.
func TestDecodeV1RejectsNet(t *testing.T) {
	t.Parallel()
	for _, field := range []string{`"net":true`, `"NET":true`, `"net":false`, `"net":null`} {
		body := `{"cmd":"ls","ts":1,"exp":2,"nonce":"n",` + field + `}`
		dec := json.NewDecoder(strings.NewReader(body))
		dec.DisallowUnknownFields()
		var p v1SigPayload
		err := dec.Decode(&p)
		if err == nil {
			t.Errorf("v1 decoder accepted %s", body)
			continue
		}
		if !strings.Contains(err.Error(), "unknown field") {
			t.Errorf("v1 decoder refused %s with %v; want an unknown-field error", body, err)
		}
		if strings.HasPrefix(field, `"net"`) && !strings.Contains(err.Error(), OldStrictDecodeNet) {
			t.Errorf("v1 decoder error %q does not contain %q", err, OldStrictDecodeNet)
		}
	}
}

// TestDecodeSignedNetVariants pins how the current decoder reads the net key:
// null leaves it false, the last duplicate wins, and keys match in any case.
func TestDecodeSignedNetVariants(t *testing.T) {
	t.Parallel()
	cases := []struct {
		field   string
		wantNet bool
	}{
		{`"net":true`, true},
		{`"net":false`, false},
		{`"net":null`, false},
		{`"net":true,"net":false`, false},
		{`"net":false,"net":true`, true},
		{`"NET":true`, true},
		{`"Net":true`, true},
	}
	for _, tc := range cases {
		body := `{"cmd":"ls","ts":1,"exp":2,"nonce":"n",` + tc.field + `}`
		envelope := "SSHGATE_SIG:" + sigEncoding.EncodeToString(fixedSig) + ":" + sigEncoding.EncodeToString([]byte(body))
		_, p, err := DecodeSigned(envelope)
		if err != nil {
			t.Errorf("DecodeSigned(%s): %v", body, err)
			continue
		}
		if p.Net != tc.wantNet {
			t.Errorf("DecodeSigned(%s).Net = %v; want %v", body, p.Net, tc.wantNet)
		}
	}
}

// TestNetWireConstants pins the exact bytes of every network wire constant:
// the gate, the signer and the MCP compare them, so any change is a wire break.
func TestNetWireConstants(t *testing.T) {
	t.Parallel()
	cases := []struct{ name, got, want string }{
		{"EnvelopePrefix", EnvelopePrefix, "SSHGATE_READ"},
		{"EnvelopeVerb", EnvelopeVerb, "SSHGATE_READ1"},
		{"EnvelopeFlagConfined", EnvelopeFlagConfined, "confined"},
		{"EnvelopeFlagNet", EnvelopeFlagNet, "net"},
		{"EnvelopeConfinedNet", EnvelopeConfinedNet, "SSHGATE_READ1 confined,net "},
		{"GateDenyBadEnvelope", GateDenyBadEnvelope, "bad envelope"},
		{"GateDenyNetNotPermitted", GateDenyNetNotPermitted, "network not permitted on this host"},
		{"GateDenyNetReadsOnly", GateDenyNetReadsOnly, "network grant covers reads only"},
		{"GateDenyNetDaemonRead", GateDenyNetDaemonRead, "network is not available for daemon-read verbs"},
		{"GateDenyEnvelopeNotRead", GateDenyEnvelopeNotRead, "the read envelope carries reads only"},
		{"GateDenySignedEnvelope", GateDenySignedEnvelope, "the read envelope is unsigned-only"},
		{"GateNetUnsupported", GateNetUnsupported, "signed network grants are not supported by this gate build"},
		{"SignerNetUnsupported", SignerNetUnsupported, "net_unsupported:"},
		{"OldStrictDecodeNet", OldStrictDecodeNet, `unknown field "net"`},
	}
	for _, tc := range cases {
		if tc.got != tc.want {
			t.Errorf("%s = %q; want %q", tc.name, tc.got, tc.want)
		}
	}
	// The envelope the MCP sends is built from the verb and both flags.
	if built := EnvelopeVerb + " " + EnvelopeFlagConfined + "," + EnvelopeFlagNet + " "; built != EnvelopeConfinedNet {
		t.Errorf("EnvelopeConfinedNet %q is not the verb and flags %q", EnvelopeConfinedNet, built)
	}
}
