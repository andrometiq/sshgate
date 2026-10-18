package sigwire

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

// sigPrefix is the literal ASCII prefix that marks a signed command on the
// wire. Keeping it unexported (and a constant) means it cannot drift between
// gate, signer, and the MCP.
const sigPrefix = "SSHGATE_SIG:"

// MaxSigValidity is the spec's "exp - ts < 300 seconds" upper bound on
// signature validity windows. gate enforces this on verification so that
// approved commands cannot be replayed long after the human tapped approve.
const MaxSigValidity time.Duration = 5 * time.Minute

// MaxClockSkew is how far a signature's timestamp may be ahead of the gate's
// clock. Admission is TS - MaxClockSkew <= now < Exp, so a signature is
// admissible for at most MaxSigValidity + MaxClockSkew (330 s) of gate time.
const MaxClockSkew time.Duration = 30 * time.Second

// SigPayload is the signed-command payload defined in the spec. It is the
// JSON object that signer signs and gate verifies, carried on the wire
// inside a SSHGATE_SIG envelope.
type SigPayload struct {
	Cmd   string `json:"cmd"`
	TS    int64  `json:"ts"`
	Exp   int64  `json:"exp"`
	Nonce string `json:"nonce"`
	// Host binds this signed payload to ONE target server's SSH host-key
	// fingerprint (OpenSSH "SHA256:..." form). The signer copies it in from
	// the MCP's sign request — which reads it from the TRUSTED registry, not
	// from any agent parameter — so an "approve on server X" signature is
	// cryptographically un-replayable on server Y: the gate self-derives its
	// own host-key fingerprints and rejects any signed write whose Host does
	// not match one of them (ErrHostMismatch).
	//
	// omitempty keeps a Host-less payload byte-identical to the pre-binding
	// wire format (so the golden test holds and an older verifier still
	// accepts legacy reads). On the SIGNED-WRITE path, however, an empty Host
	// is rejected fail-closed by the gate — binding is mandatory there.
	Host string `json:"host,omitempty"`
	// Reveal, when true, marks this signed command as a SECRET-REVEAL: the
	// gate runs its output WITHOUT the redactor, so raw secret values flow to
	// the agent. It is a capability encoded in the SIGNED payload precisely so
	// the (untrusted) agent cannot self-elevate — only a human approval that
	// the signer turns into a signature can set it, and the gate enforces it.
	//
	// omitempty keeps a reveal=false payload (the common case) byte-identical
	// to the pre-reveal wire format, so the golden test holds and the
	// canonical form never drifts. With DisallowUnknownFields a reveal-bearing
	// payload still decodes (the field is known); the security property is that
	// the bool is part of the signed bytes, so it cannot be flipped on the
	// wire without invalidating the signature.
	Reveal bool `json:"reveal,omitempty"`
	// Net, when true, marks this signed command as carrying a NETWORK grant:
	// the gate may run it with network access. Like Reveal it is a capability
	// in the SIGNED payload, so only a human approval the signer turns into a
	// signature can set it, and flipping it on the wire breaks the signature.
	//
	// omitempty keeps a net=false payload byte-identical to the pre-network
	// wire format. A gate built before this field decodes with
	// DisallowUnknownFields, so it rejects a net-bearing payload (exit 65)
	// rather than running it without the grant's meaning.
	Net bool `json:"net,omitempty"`
}

// sigEncoding is the base64 alphabet used for both halves of the wire
// envelope: URL-safe (no '+' or '/') and unpadded (no '='), so the encoded
// string is safe to drop directly onto an SSH command line without quoting.
var sigEncoding = base64.URLEncoding.WithPadding(base64.NoPadding)

// EncodeSigned produces the wire format "SSHGATE_SIG:<sigB64>:<payloadB64>"
// using URL-safe base64 without padding (SSH-command-line safe). sig is the
// 64-byte Ed25519 signature over the JSON-marshalled payload; EncodeSigned
// does not compute the signature — that is the caller's job (signer
// owns the key, this package owns the wire shape).
func EncodeSigned(sig []byte, payload SigPayload) (string, error) {
	pb, err := json.Marshal(payload)
	if err != nil {
		return "", fmt.Errorf("marshal payload: %w", err)
	}
	var b strings.Builder
	b.Grow(len(sigPrefix) + sigEncoding.EncodedLen(len(sig)) + 1 + sigEncoding.EncodedLen(len(pb)))
	b.WriteString(sigPrefix)
	b.WriteString(sigEncoding.EncodeToString(sig))
	b.WriteByte(':')
	b.WriteString(sigEncoding.EncodeToString(pb))
	return b.String(), nil
}

// DecodeSigned parses the wire format back into the raw sig bytes and the
// decoded payload. It returns an error if the prefix is missing, if the
// envelope's two-colon shape is broken, if either base64 block is
// malformed, or if the JSON payload is malformed or missing a required
// field.
//
// Per the spec the on-the-wire form is
// `SSHGATE_SIG:<sig>:<payload> <inner_cmd>` — i.e. a trailing space and
// the inner command line follow the envelope so SSH server logs render
// the operator's command in cleartext. The trailing content is
// unauthenticated (the inner_cmd that actually runs is the one inside
// the signed payload) and DecodeSigned ignores everything from the
// first ASCII space onwards in the payload base64 field. Leading
// whitespace is still rejected; trailing space-prefixed content is
// tolerated.
//
// DecodeSigned does not verify the signature — that is the caller's job,
// so this function can be reused by anything that needs to read the
// envelope (gate, audit tooling, tests).
func DecodeSigned(s string) (sig []byte, payload SigPayload, err error) {
	if !strings.HasPrefix(s, sigPrefix) {
		return nil, SigPayload{}, errors.New("missing SSHGATE_SIG: prefix")
	}
	rest := s[len(sigPrefix):]
	sep := strings.IndexByte(rest, ':')
	if sep < 0 {
		return nil, SigPayload{}, errors.New("missing payload separator")
	}
	sigB64 := rest[:sep]
	payloadB64 := rest[sep+1:]
	// Strip the optional " <inner_cmd>" trailer that the runner appends
	// for SSH-log readability. base64 (URL-safe) does not contain spaces
	// so a space cleanly delimits the envelope from the trailer.
	if i := strings.IndexByte(payloadB64, ' '); i >= 0 {
		payloadB64 = payloadB64[:i]
	}
	if sigB64 == "" {
		return nil, SigPayload{}, errors.New("empty signature field")
	}
	if payloadB64 == "" {
		return nil, SigPayload{}, errors.New("empty payload field")
	}
	sig, err = sigEncoding.DecodeString(sigB64)
	if err != nil {
		return nil, SigPayload{}, fmt.Errorf("decode signature: %w", err)
	}
	pb, err := sigEncoding.DecodeString(payloadB64)
	if err != nil {
		return nil, SigPayload{}, fmt.Errorf("decode payload: %w", err)
	}
	dec := json.NewDecoder(strings.NewReader(string(pb)))
	dec.DisallowUnknownFields()
	var p SigPayload
	if err := dec.Decode(&p); err != nil {
		return nil, SigPayload{}, fmt.Errorf("unmarshal payload: %w", err)
	}
	if p.Cmd == "" {
		return nil, SigPayload{}, errors.New("payload missing required field: cmd")
	}
	return sig, p, nil
}

// IsSigned reports whether s starts with the literal "SSHGATE_SIG:" prefix.
// It is a cheap pre-check intended for callers that route signed vs.
// unsigned commands down different paths before incurring the cost of a
// full DecodeSigned call.
func IsSigned(s string) bool {
	return strings.HasPrefix(s, sigPrefix)
}
