package xferwire_test

import (
	"bytes"
	"strings"
	"testing"

	"github.com/karthikeyan5/sshgate/src/xfer"
	"github.com/karthikeyan5/sshgate/src/xferwire"
)

// The two canonical example keys from the P2 spec §1d (real 32-byte PublicText
// forms). Parsed once so the golden-line assertions below exercise the whole
// bytes→canonical-text→b64url-wrap chain.
const (
	exBoxPubText = "sshgate-xfer-box-x25519 AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8="
	exIDPubText  = "sshgate-xfer-id-ed25519 AwoRGB8mLTQ7QklQV15lbHN6gYiPlp2kq7K5wMfO1dw="

	exXferID   = "AQ4bKDVCT1xpdoOQnaq3xA"
	exSrcFP    = "SHA256:kQ4jRram-example-source-fp-000000000000ab"
	exDestFP   = "SHA256:9Zt7Xhost-example-dest-fp-1111111111111cd"
	exSrcPath  = "/run/sshgate-xfer/9c1f.tmp"
	exDestPath = "/etc/default/ops-alerts"
	exMode     = "0600"

	// Golden leg lines from the P2 spec §1d worked example.
	goldenSend = "SSHGATE_XFER_SEND c3NoZ2F0ZS14ZmVyLWJveC14MjU1MTkgQUFFQ0F3UUZCZ2NJQ1FvTERBME9EeEFSRWhNVUZSWVhHQmthR3h3ZEhoOD0 QVE0YktEVkNUMXhwZG9PUW5hcTN4QQ U0hBMjU2OjladDdYaG9zdC1leGFtcGxlLWRlc3QtZnAtMTExMTExMTExMTExMWNk L3J1bi9zc2hnYXRlLXhmZXIvOWMxZi50bXA"
	goldenRecv = "SSHGATE_XFER_RECV c3NoZ2F0ZS14ZmVyLWlkLWVkMjU1MTkgQXdvUkdCOG1MVFE3UWtsUVYxNWxiSE42Z1lpUGxwMmtxN0s1d01mTzFkdz0 QVE0YktEVkNUMXhwZG9PUW5hcTN4QQ U0hBMjU2OmtRNGpScmFtLWV4YW1wbGUtc291cmNlLWZwLTAwMDAwMDAwMDAwMGFi U0hBMjU2OjladDdYaG9zdC1leGFtcGxlLWRlc3QtZnAtMTExMTExMTExMTExMWNk MDYwMA L2V0Yy9kZWZhdWx0L29wcy1hbGVydHM"
)

func mustBoxPub(t *testing.T) *[32]byte {
	t.Helper()
	k, err := xfer.ParseBoxPublicText(exBoxPubText)
	if err != nil {
		t.Fatalf("parse box pub: %v", err)
	}
	return k
}

func mustIDPub(t *testing.T) []byte {
	t.Helper()
	k, err := xfer.ParseIDPublicText(exIDPubText)
	if err != nil {
		t.Fatalf("parse id pub: %v", err)
	}
	return k
}

// TestEncodeSend_Golden pins the SEND leg byte-for-byte against the spec's
// worked example — proving the codec (canonical key text + b64url-nopad wrap +
// exact token layout) matches the pinned wire protocol.
func TestEncodeSend_Golden(t *testing.T) {
	got, err := xferwire.EncodeSend(mustBoxPub(t), exXferID, exDestFP, exSrcPath)
	if err != nil {
		t.Fatalf("EncodeSend: %v", err)
	}
	if got != goldenSend {
		t.Errorf("SEND leg mismatch\n got: %s\nwant: %s", got, goldenSend)
	}
}

func TestEncodeRecv_Golden(t *testing.T) {
	got, err := xferwire.EncodeRecv(mustIDPub(t), exXferID, exSrcFP, exDestFP, exMode, exDestPath)
	if err != nil {
		t.Fatalf("EncodeRecv: %v", err)
	}
	if got != goldenRecv {
		t.Errorf("RECV leg mismatch\n got: %s\nwant: %s", got, goldenRecv)
	}
}

// TestRoundTripSend proves Encode→Parse recovers every field, and that a path
// carrying a SPACE survives as one opaque token (the b64url wrapping is what
// makes a spaced value safe on a space-delimited line).
func TestRoundTripSend(t *testing.T) {
	box := mustBoxPub(t)
	spacedPath := "/var/lib/my app/secret .env"
	line, err := xferwire.EncodeSend(box, exXferID, exDestFP, spacedPath)
	if err != nil {
		t.Fatalf("EncodeSend: %v", err)
	}
	leg, err := xferwire.ParseSend(line)
	if err != nil {
		t.Fatalf("ParseSend: %v", err)
	}
	if *leg.BoxPub != *box {
		t.Errorf("box pub round-trip mismatch")
	}
	if leg.XferID != exXferID || leg.DestID != exDestFP || leg.SrcPath != spacedPath {
		t.Errorf("field round-trip mismatch: %+v", leg)
	}
}

func TestRoundTripRecv(t *testing.T) {
	id := mustIDPub(t)
	line, err := xferwire.EncodeRecv(id, exXferID, exSrcFP, exDestFP, exMode, exDestPath)
	if err != nil {
		t.Fatalf("EncodeRecv: %v", err)
	}
	leg, err := xferwire.ParseRecv(line)
	if err != nil {
		t.Fatalf("ParseRecv: %v", err)
	}
	if !bytes.Equal(leg.IDPub, id) {
		t.Errorf("id pub round-trip mismatch")
	}
	if leg.XferID != exXferID || leg.SrcID != exSrcFP || leg.DestID != exDestFP || leg.Mode != exMode || leg.DestPath != exDestPath {
		t.Errorf("field round-trip mismatch: %+v", leg)
	}
}

// TestParseSend_RejectTrailingContent: appending an extra token (or trailing
// junk after a space) breaks the exact-token-count anchor.
func TestParseSend_RejectTrailingContent(t *testing.T) {
	line, _ := xferwire.EncodeSend(mustBoxPub(t), exXferID, exDestFP, exSrcPath)
	if _, err := xferwire.ParseSend(line + " ZXh0cmE"); err == nil {
		t.Error("ParseSend accepted trailing content")
	}
}

// TestParseSend_RejectMissingField: dropping a field breaks the count.
func TestParseSend_RejectMissingField(t *testing.T) {
	line, _ := xferwire.EncodeSend(mustBoxPub(t), exXferID, exDestFP, exSrcPath)
	toks := strings.Split(line, " ")
	short := strings.Join(toks[:len(toks)-1], " ")
	if _, err := xferwire.ParseSend(short); err == nil {
		t.Error("ParseSend accepted a leg with a missing field")
	}
}

// TestParseSend_RejectNonB64URL: a token carrying a non-alphabet byte (an
// attempt to smuggle a separator) fails the decode.
func TestParseSend_RejectNonB64URL(t *testing.T) {
	line, _ := xferwire.EncodeSend(mustBoxPub(t), exXferID, exDestFP, exSrcPath)
	toks := strings.Split(line, " ")
	toks[3] = "not+valid/b64=" // '+' '/' '=' are not in the URL-safe nopad alphabet
	if _, err := xferwire.ParseSend(strings.Join(toks, " ")); err == nil {
		t.Error("ParseSend accepted a non-b64url token")
	}
}

// TestParseSend_RejectEmbeddedNewline: a wrapped value containing a newline
// must NOT decode (the alphabet excludes newline), so a phishing line cannot be
// smuggled inside a field.
func TestParseSend_RejectEmbeddedNewline(t *testing.T) {
	line, _ := xferwire.EncodeSend(mustBoxPub(t), exXferID, exDestFP, exSrcPath)
	toks := strings.Split(line, " ")
	// Splice a newline into the middle of a token; b64url-nopad has no newline.
	toks[1] = toks[1][:2] + "\n" + toks[1][2:]
	if _, err := xferwire.ParseSend(strings.Join(toks, " ")); err == nil {
		t.Error("ParseSend accepted a token with an embedded newline")
	}
}

// TestParseRecv_RejectBoxKeyInIDSlot: the tag check (xfer.ParseIDPublicText)
// makes a BOX key text in the ID slot fail closed.
func TestParseRecv_RejectBoxKeyInIDSlot(t *testing.T) {
	line, _ := xferwire.EncodeRecv(mustIDPub(t), exXferID, exSrcFP, exDestFP, exMode, exDestPath)
	toks := strings.Split(line, " ")
	// Overwrite the id-key token (index 1, after the verb) with a wrapped BOX
	// key text. wrap == b64url-nopad(exBoxPubText).
	boxLine, _ := xferwire.EncodeSend(mustBoxPub(t), exXferID, exDestFP, exSrcPath)
	toks[1] = strings.Split(boxLine, " ")[1] // wrapped box pub text
	if _, err := xferwire.ParseRecv(strings.Join(toks, " ")); err == nil {
		t.Error("ParseRecv accepted a box key in the id slot")
	}
}

// TestEncode_RejectNonAbsPath: a relative path is refused at encode time.
func TestEncode_RejectNonAbsPath(t *testing.T) {
	if _, err := xferwire.EncodeSend(mustBoxPub(t), exXferID, exDestFP, "relative/path"); err == nil {
		t.Error("EncodeSend accepted a non-absolute path")
	}
}

// TestEncode_RejectBadMode: only the P2 allowlist ("0600") is accepted.
func TestEncode_RejectBadMode(t *testing.T) {
	if _, err := xferwire.EncodeRecv(mustIDPub(t), exXferID, exSrcFP, exDestFP, "0777", exDestPath); err == nil {
		t.Error("EncodeRecv accepted a mode outside the allowlist")
	}
}

// TestEncode_RejectOversizedXferID: a > 64-byte xferID is refused.
func TestEncode_RejectOversizedXferID(t *testing.T) {
	big := strings.Repeat("A", 65)
	if _, err := xferwire.EncodeSend(mustBoxPub(t), big, exDestFP, exSrcPath); err == nil {
		t.Error("EncodeSend accepted an oversized xferID")
	}
}

// TestEncode_RejectBadFingerprint: a fingerprint without the SHA256: prefix, or
// carrying a space, is refused.
func TestEncode_RejectBadFingerprint(t *testing.T) {
	if _, err := xferwire.EncodeSend(mustBoxPub(t), exXferID, "MD5:nope", exSrcPath); err == nil {
		t.Error("EncodeSend accepted a non-SHA256 fingerprint")
	}
	if _, err := xferwire.EncodeSend(mustBoxPub(t), exXferID, "SHA256:has space", exSrcPath); err == nil {
		t.Error("EncodeSend accepted a fingerprint with a space")
	}
}

// TestParseSend_RejectWrongVerb: the RECV parser refuses a SEND line (and vice
// versa) at the prefix anchor.
func TestParse_RejectWrongVerb(t *testing.T) {
	send, _ := xferwire.EncodeSend(mustBoxPub(t), exXferID, exDestFP, exSrcPath)
	if _, err := xferwire.ParseRecv(send); err == nil {
		t.Error("ParseRecv accepted a SEND leg")
	}
	recv, _ := xferwire.EncodeRecv(mustIDPub(t), exXferID, exSrcFP, exDestFP, exMode, exDestPath)
	if _, err := xferwire.ParseSend(recv); err == nil {
		t.Error("ParseSend accepted a RECV leg")
	}
}
