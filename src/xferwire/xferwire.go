// Package xferwire is the injection-safe codec for the two signed box→box
// transfer legs that ride INSIDE sigwire.SigPayload.Cmd, exactly like
// SSHGATE_UPDATE. It is the single source of truth for the SEND/RECV grammar:
// the signer uses it to BUILD the two leg Cmd strings (P2), and the gate uses
// it to PARSE them (P3). Keeping both directions in one package guarantees the
// producer and consumer can never drift.
//
// # Why this exists (the whole injection-safety story)
//
// A transfer leg names load-bearing fields — a recipient box public key, a
// sender identity public key, host fingerprints, absolute filesystem paths.
// Those fields travel space-separated on a single command line that a shell on
// the far side eventually sees. If any field could carry a space or a newline
// it could smuggle an extra token (forging a different recipient, a different
// path) or a banner line. So every non-verb field is wrapped with
// base64url-nopad (alphabet [A-Za-z0-9_-], no space, no newline, no ':'), the
// exact encoding sigwire uses for its own envelope. The parse is ANCHORED:
// strip the exact verb prefix, split into the EXACT expected token count, and
// reject anything that does not fully base64url-decode — the same discipline
// gate/…/update.go applies to SSHGATE_UPDATE. A field can therefore never
// carry a separator, and trailing/smuggled content is rejected, not tolerated.
//
// # Canonical key text
//
// The two key fields are the canonical xfer.PublicText form ("<tag> <stdb64>")
// b64url-wrapped, NOT the raw PublicText on the wire (its embedded space +
// StdEncoding '+//=' would break the anchored parse). One canonical key text
// spans the provisioning readback and the wire, so the gate re-uses
// xfer.ParseBoxPublicText / xfer.ParseIDPublicText verbatim after one decode.
package xferwire

import (
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"fmt"
	"path/filepath"
	"strings"

	"github.com/karthikeyan5/sshgate/src/xfer"
)

// Verb prefixes. Each is the literal verb token followed by a single ASCII
// space (mirroring update.go's updateVerbPrefix), so a leg is
// "<VERB> <field> <field> …". VerbPrefix is the shared ancestor prefix the
// signer's sign-path rejection and the gate's dispatch both key on.
const (
	// VerbPrefix is the common ancestor of every transfer verb. The signer's
	// generic sign path REJECTS any command with this prefix (transfers must go
	// through the dedicated "transfer" request kind), and the gate dispatches
	// on it before any classify/exec.
	VerbPrefix = "SSHGATE_XFER_"

	// VerbSend runs on the SOURCE gate; the payload's Host is the source fp.
	VerbSend = "SSHGATE_XFER_SEND"
	// VerbRecv runs on the DESTINATION gate; the payload's Host is the dest fp.
	VerbRecv = "SSHGATE_XFER_RECV"

	sendPrefix = VerbSend + " "
	recvPrefix = VerbRecv + " "
)

// Field-count contracts (verb excluded). Any other count is a rejection —
// this is the "exact length, reject trailing content" analogue of
// update.go's anchored parse.
const (
	sendFieldCount = 4 // w(box_pubtext) w(xferID) w(destID) w(src_path)
	recvFieldCount = 6 // w(id_pubtext) w(xferID) w(srcID) w(destID) w(mode) w(dest_path)
)

// Field bounds and the P2 mode allowlist. The mode grammar carries the octal
// file-mode so P3/P4 can widen the allowlist WITHOUT a wire change; P2 accepts
// only "0600".
const (
	maxXferIDLen      = 64
	maxFingerprintLen = 128
	maxPathLen        = 4096
	fingerprintPrefix = "SHA256:"
)

// allowedModes is the P2 mode allowlist (grammar-extensible later).
var allowedModes = map[string]struct{}{"0600": {}}

// sigEncoding is the SAME base64url-nopad codec sigwire uses for its envelope:
// URL-safe alphabet [A-Za-z0-9_-], no padding, so a wrapped token can never
// contain a space, newline, or ':' — the property the anchored parse relies on.
var sigEncoding = base64.URLEncoding.WithPadding(base64.NoPadding)

// SendLeg is the decoded SSHGATE_XFER_SEND leg. BoxPub is the recipient's
// X25519 box public half (what the SOURCE gate seals to) — parsed from the
// canonical key text, so a wrong-tag key (e.g. an id key in the box slot)
// fails closed.
type SendLeg struct {
	BoxPub  *[32]byte
	XferID  string
	DestID  string // destination host fingerprint ("SHA256:…")
	SrcPath string // absolute path on the source gate to read
}

// RecvLeg is the decoded SSHGATE_XFER_RECV leg. IDPub is the SENDER's ed25519
// identity public half (what the DESTINATION gate verifies the envelope
// attestation against — the reverse anti-MITM primitive), parsed from the
// canonical key text.
type RecvLeg struct {
	IDPub    ed25519.PublicKey
	XferID   string
	SrcID    string // source host fingerprint ("SHA256:…") — audit/binding metadata
	DestID   string // destination host fingerprint ("SHA256:…")
	Mode     string // octal file mode from the allowlist ("0600" in P2)
	DestPath string // absolute path on the destination gate to write
}

// EncodeSend builds the SSHGATE_XFER_SEND leg Cmd. The recipient box public key
// comes from the SIGNER'S registry (never a request), rendered to canonical
// text here so a single key form spans registry, wire, and gate. Every field is
// validated (fail closed) and b64url-wrapped; a malformed field returns an
// error rather than a malformed leg.
func EncodeSend(boxPub *[32]byte, xferID, destID, srcPath string) (string, error) {
	if boxPub == nil {
		return "", errors.New("xferwire: nil recipient box key")
	}
	if !ValidXferID(xferID) {
		return "", errors.New("xferwire: invalid xferID")
	}
	if !ValidFingerprint(destID) {
		return "", errors.New("xferwire: invalid destID")
	}
	if !ValidPath(srcPath) {
		return "", errors.New("xferwire: invalid src_path")
	}
	return sendPrefix + join(
		wrap(xfer.BoxPublicText(boxPub)),
		wrap(xferID),
		wrap(destID),
		wrap(srcPath),
	), nil
}

// EncodeRecv builds the SSHGATE_XFER_RECV leg Cmd. The sender identity public
// key comes from the SIGNER'S registry. Same validate-then-wrap discipline.
func EncodeRecv(idPub ed25519.PublicKey, xferID, srcID, destID, mode, destPath string) (string, error) {
	if len(idPub) != ed25519.PublicKeySize {
		return "", errors.New("xferwire: invalid sender identity key")
	}
	if !ValidXferID(xferID) {
		return "", errors.New("xferwire: invalid xferID")
	}
	if !ValidFingerprint(srcID) {
		return "", errors.New("xferwire: invalid srcID")
	}
	if !ValidFingerprint(destID) {
		return "", errors.New("xferwire: invalid destID")
	}
	if !ValidMode(mode) {
		return "", errors.New("xferwire: invalid mode")
	}
	if !ValidPath(destPath) {
		return "", errors.New("xferwire: invalid dest_path")
	}
	return recvPrefix + join(
		wrap(xfer.IDPublicText(idPub)),
		wrap(xferID),
		wrap(srcID),
		wrap(destID),
		wrap(mode),
		wrap(destPath),
	), nil
}

// ParseSend decodes a SSHGATE_XFER_SEND leg. Fail-closed, anchored, in order:
// strip the exact prefix, split into EXACTLY sendFieldCount tokens (any other
// count → reject), fully base64url-decode each token (a decode error rejects,
// and the alphabet guarantees no smuggled separator survived), then validate
// each decoded field. Never partially accepts.
func ParseSend(cmd string) (SendLeg, error) {
	tokens, err := splitLeg(cmd, sendPrefix, sendFieldCount)
	if err != nil {
		return SendLeg{}, err
	}
	boxText, err := unwrap(tokens[0])
	if err != nil {
		return SendLeg{}, fmt.Errorf("xferwire: decode box key: %w", err)
	}
	boxPub, err := xfer.ParseBoxPublicText(boxText)
	if err != nil {
		return SendLeg{}, fmt.Errorf("xferwire: box key: %w", err)
	}
	xferID, err := unwrapValidated(tokens[1], ValidXferID, "xferID")
	if err != nil {
		return SendLeg{}, err
	}
	destID, err := unwrapValidated(tokens[2], ValidFingerprint, "destID")
	if err != nil {
		return SendLeg{}, err
	}
	srcPath, err := unwrapValidated(tokens[3], ValidPath, "src_path")
	if err != nil {
		return SendLeg{}, err
	}
	return SendLeg{BoxPub: boxPub, XferID: xferID, DestID: destID, SrcPath: srcPath}, nil
}

// ParseRecv decodes a SSHGATE_XFER_RECV leg with the same anchored, fail-closed
// discipline as ParseSend.
func ParseRecv(cmd string) (RecvLeg, error) {
	tokens, err := splitLeg(cmd, recvPrefix, recvFieldCount)
	if err != nil {
		return RecvLeg{}, err
	}
	idText, err := unwrap(tokens[0])
	if err != nil {
		return RecvLeg{}, fmt.Errorf("xferwire: decode id key: %w", err)
	}
	idPub, err := xfer.ParseIDPublicText(idText)
	if err != nil {
		return RecvLeg{}, fmt.Errorf("xferwire: id key: %w", err)
	}
	xferID, err := unwrapValidated(tokens[1], ValidXferID, "xferID")
	if err != nil {
		return RecvLeg{}, err
	}
	srcID, err := unwrapValidated(tokens[2], ValidFingerprint, "srcID")
	if err != nil {
		return RecvLeg{}, err
	}
	destID, err := unwrapValidated(tokens[3], ValidFingerprint, "destID")
	if err != nil {
		return RecvLeg{}, err
	}
	mode, err := unwrapValidated(tokens[4], ValidMode, "mode")
	if err != nil {
		return RecvLeg{}, err
	}
	destPath, err := unwrapValidated(tokens[5], ValidPath, "dest_path")
	if err != nil {
		return RecvLeg{}, err
	}
	return RecvLeg{IDPub: idPub, XferID: xferID, SrcID: srcID, DestID: destID, Mode: mode, DestPath: destPath}, nil
}

// splitLeg strips prefix (rejecting a missing prefix) and splits the remainder
// on the single ASCII space into EXACTLY want tokens. Any other count is a
// rejection — the load-bearing "exact token count" anchor. A zero-length token
// (two adjacent spaces) is impossible to produce with a non-empty wrapped
// field and is rejected here too.
func splitLeg(cmd, prefix string, want int) ([]string, error) {
	if !strings.HasPrefix(cmd, prefix) {
		return nil, fmt.Errorf("xferwire: missing %q prefix", strings.TrimSpace(prefix))
	}
	rest := cmd[len(prefix):]
	tokens := strings.Split(rest, " ")
	if len(tokens) != want {
		return nil, fmt.Errorf("xferwire: got %d fields, want %d (trailing/missing/smuggled content)", len(tokens), want)
	}
	for _, tok := range tokens {
		if tok == "" {
			return nil, errors.New("xferwire: empty field token")
		}
	}
	return tokens, nil
}

// wrap b64url-nopad encodes a raw field value into a wire token.
func wrap(s string) string { return sigEncoding.EncodeToString([]byte(s)) }

// unwrap b64url-nopad decodes a wire token back to its raw field value. It
// FIRST rejects any byte outside the strict URL-safe alphabet [A-Za-z0-9_-]:
// Go's base64 decoder silently STRIPS embedded '\r'/'\n' rather than erroring,
// so without this pre-scan a token could syntactically carry a newline (it
// would be dropped, not rejected). Rejecting up front makes the spec's property
// literal — "a token can never carry an injected space/newline/separator" — and
// fail-closed rather than relying on a stdlib quirk. It also rejects the padded/
// standard-base64 chars '+', '/', '=' that are not part of this encoding.
func unwrap(tok string) (string, error) {
	for i := 0; i < len(tok); i++ {
		c := tok[i]
		if !(c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '_' || c == '-') {
			return "", errors.New("token carries a non-alphabet byte")
		}
	}
	raw, err := sigEncoding.DecodeString(tok)
	if err != nil {
		return "", err
	}
	return string(raw), nil
}

// unwrapValidated decodes a token then runs field-specific validation,
// returning a named error on either failure.
func unwrapValidated(tok string, ok func(string) bool, field string) (string, error) {
	v, err := unwrap(tok)
	if err != nil {
		return "", fmt.Errorf("xferwire: decode %s: %w", field, err)
	}
	if !ok(v) {
		return "", fmt.Errorf("xferwire: invalid %s", field)
	}
	return v, nil
}

// join concatenates tokens with a single ASCII space.
func join(tokens ...string) string { return strings.Join(tokens, " ") }

// ValidXferID reports whether s is a valid transfer id: non-empty, <= 64 bytes,
// charset [A-Za-z0-9_-] (it is minted by base64.RawURLEncoding).
func ValidXferID(s string) bool {
	if s == "" || len(s) > maxXferIDLen {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !(c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '_' || c == '-') {
			return false
		}
	}
	return true
}

// ValidFingerprint reports whether s is a valid host-key fingerprint: non-empty,
// starts "SHA256:", <= 128 bytes, printable ASCII, no space/newline.
func ValidFingerprint(s string) bool {
	if s == "" || len(s) > maxFingerprintLen {
		return false
	}
	if !strings.HasPrefix(s, fingerprintPrefix) {
		return false
	}
	return isPrintableASCIINoSpace(s)
}

// ValidPath reports whether s is an acceptable transfer path: non-empty,
// absolute, <= 4096 bytes, no NUL, no newline. (It may contain spaces — the
// b64url wrapping keeps a spaced path a single opaque token.)
func ValidPath(s string) bool {
	if s == "" || len(s) > maxPathLen {
		return false
	}
	if !filepath.IsAbs(s) {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] == 0x00 || s[i] == '\n' || s[i] == '\r' {
			return false
		}
	}
	return true
}

// ValidMode reports whether s is in the P2 mode allowlist.
func ValidMode(s string) bool {
	_, ok := allowedModes[s]
	return ok
}

// isPrintableASCIINoSpace reports whether every byte of s is a printable ASCII
// char in (0x20, 0x7f) — i.e. no control chars, no space, no newline, no
// high-bit bytes.
func isPrintableASCIINoSpace(s string) bool {
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c <= 0x20 || c >= 0x7f {
			return false
		}
	}
	return true
}
