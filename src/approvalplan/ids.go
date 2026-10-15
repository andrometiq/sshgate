package approvalplan

import (
	"crypto/sha256"
	"encoding/base32"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"strings"
)

const (
	requestIDPrefix = "a2_"
	requestIDLen    = len(requestIDPrefix) + 22 // base64url of 16 bytes, unpadded (E31)

	// CardHandleLen is the length of a Telegram card handle and of a deny-all
	// or cancel snapshot ID (E47): 60 bits of lowercase base32.
	CardHandleLen = 12
	// RecordHandleLen is the length of a derived record handle (SA-2): 80 bits.
	RecordHandleLen = 16
	// ChallengeLen is the hex length of a 64-bit card challenge (E47).
	ChallengeLen = 16
	// EpochLen is the hex length of a 128-bit store epoch.
	EpochLen = 32
	// MaxOperatorIDBytes bounds an operator ID (signer-server main.go:630).
	MaxOperatorIDBytes = 128
)

// lowerBase32 is RFC 4648 base32 in lowercase, unpadded: the alphabet of every
// derived key and handle.
var lowerBase32 = base32.NewEncoding("abcdefghijklmnopqrstuvwxyz234567").WithPadding(base32.NoPadding)

// NewRequestID mints a v2 request ID, "a2_" + base64url(16 random bytes) (E31).
// Only the MCP mints one, once per tool call.
func NewRequestID(r io.Reader) (string, error) {
	var buf [16]byte
	if _, err := io.ReadFull(r, buf[:]); err != nil {
		return "", fmt.Errorf("approvalplan: request id: %w", err)
	}
	return requestIDPrefix + base64.RawURLEncoding.EncodeToString(buf[:]), nil
}

// ValidRequestID reports whether s matches ^a2_[A-Za-z0-9_-]{22}$ (E31).
func ValidRequestID(s string) bool {
	if len(s) != requestIDLen || !strings.HasPrefix(s, requestIDPrefix) {
		return false
	}
	for i := len(requestIDPrefix); i < len(s); i++ {
		if !isBase64URLByte(s[i]) {
			return false
		}
	}
	return true
}

// ValidRequesterSub reports whether s matches ^local-uid:[0-9]{1,10}$, the
// hosted sub_principal grammar (E19), which is also the local principal form.
func ValidRequesterSub(s string) bool {
	digits, ok := strings.CutPrefix(s, "local-uid:")
	if !ok || len(digits) < 1 || len(digits) > 10 {
		return false
	}
	return allBytes(digits, isDigit)
}

// NewCardHandle mints a card handle or snapshot ID: 12 lowercase base32
// characters (E47).
func NewCardHandle(r io.Reader) (string, error) {
	var buf [8]byte
	if _, err := io.ReadFull(r, buf[:]); err != nil {
		return "", fmt.Errorf("approvalplan: card handle: %w", err)
	}
	return lowerBase32.EncodeToString(buf[:])[:CardHandleLen], nil
}

// ValidCardHandle reports whether s is a card handle or snapshot ID.
func ValidCardHandle(s string) bool {
	return len(s) == CardHandleLen && allBytes(s, isLowerBase32Byte)
}

// NewChallenge mints a 64-bit card challenge as 16 lowercase hex characters,
// the form the callback data carries (E47). Only its ChallengeHash is stored.
func NewChallenge(r io.Reader) (string, error) {
	var buf [8]byte
	if _, err := io.ReadFull(r, buf[:]); err != nil {
		return "", fmt.Errorf("approvalplan: challenge: %w", err)
	}
	return hex.EncodeToString(buf[:]), nil
}

// ValidChallenge reports whether s is 16 lowercase hex characters.
func ValidChallenge(s string) bool { return isLowerHex(s, ChallengeLen) }

// NewEpoch mints a store epoch: 128 random bits as lowercase hex.
func NewEpoch(r io.Reader) (string, error) {
	var buf [16]byte
	if _, err := io.ReadFull(r, buf[:]); err != nil {
		return "", fmt.Errorf("approvalplan: epoch: %w", err)
	}
	return hex.EncodeToString(buf[:]), nil
}

// ValidEpoch reports whether s is an epoch.
func ValidEpoch(s string) bool { return isLowerHex(s, EpochLen) }

// ValidRecordHandle reports whether s has the form RecordHandle returns.
func ValidRecordHandle(s string) bool {
	return len(s) == RecordHandleLen && allBytes(s, isLowerBase32Byte)
}

// ValidOperatorID reports whether s is an operator ID: the hosted bootstrap
// grammar ^[A-Za-z0-9][A-Za-z0-9._@-]{0,127}$ (signer-server main.go:630),
// widened by ':' so a local operator can carry a namespace such as
// "telegram:<user id>". No character in it is escaped by json.Marshal.
func ValidOperatorID(s string) bool {
	if len(s) < 1 || len(s) > MaxOperatorIDBytes || !isAlnum(s[0]) {
		return false
	}
	return allBytes(s, func(c byte) bool {
		return isAlnum(c) || c == '.' || c == '_' || c == '@' || c == '-' || c == ':'
	})
}

// RecordKey is the local signer's storage key for one R1 record (SA-3): the
// file name "r-" + base32(SHA-256("sshgate-approval-rec-v1\0" ‖ principal ‖
// 0x00 ‖ request_id)). principal is "local-uid:<uid>".
func RecordKey(principal, requestID string) string {
	return "r-" + digestBase32("sshgate-approval-rec-v1\x00", principal, "\x00", requestID)
}

// HostedRecordKey is the hosted record key for the row keyed (client_id,
// sub_principal, request_id) (SA-2). It is used where a record key must be one
// string: the record handle and an event's event_key. Neither sub_principal
// nor a request ID can contain 0x00, so the encoding is injective.
func HostedRecordKey(clientID, subPrincipal, requestID string) string {
	return "h-" + digestBase32("sshgate-approval-rec-hosted-v1\x00", clientID, "\x00", subPrincipal, "\x00", requestID)
}

// JobKey is the executor's storage key for one R2 job record (SA-3).
func JobKey(requestID string) string {
	return "j-" + digestBase32("sshgate-exec-job-v1\x00", requestID)
}

// RecordHandle derives the operator-facing handle of a record from its record
// key (SA-2): the first 16 characters of base32(SHA-256(
// "sshgate-v2-record-handle-v1\0" ‖ record key)).
func RecordHandle(recordKey string) string {
	return digestBase32("sshgate-v2-record-handle-v1\x00", recordKey)[:RecordHandleLen]
}

func digestBase32(parts ...string) string {
	h := sha256.New()
	for _, p := range parts {
		h.Write([]byte(p))
	}
	return lowerBase32.EncodeToString(h.Sum(nil))
}

func allBytes(s string, ok func(byte) bool) bool {
	for i := 0; i < len(s); i++ {
		if !ok(s[i]) {
			return false
		}
	}
	return true
}

func isDigit(c byte) bool           { return c >= '0' && c <= '9' }
func isAlnum(c byte) bool           { return isDigit(c) || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') }
func isLowerHexByte(c byte) bool    { return isDigit(c) || (c >= 'a' && c <= 'f') }
func isLowerBase32Byte(c byte) bool { return (c >= 'a' && c <= 'z') || (c >= '2' && c <= '7') }
func isBase64URLByte(c byte) bool   { return isAlnum(c) || c == '-' || c == '_' }

func isLowerHex(s string, n int) bool { return len(s) == n && allBytes(s, isLowerHexByte) }

// ValidSHA256Hex reports whether s is a SHA-256 digest in 64 lowercase hex.
func ValidSHA256Hex(s string) bool { return isLowerHex(s, 64) }
