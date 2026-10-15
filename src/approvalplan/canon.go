package approvalplan

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"
)

// Canonical returns v's canonical encoding: exactly the json.Marshal bytes,
// which is what securestate stores and requires on read
// (internal/securestate/store_linux.go:305-334). Struct field order is the
// encoding order; '<', '>', '&', U+2028 and U+2029 are escaped.
func Canonical(v any) ([]byte, error) {
	b, err := json.Marshal(v)
	if err != nil {
		return nil, fmt.Errorf("approvalplan: canonical encoding: %w", err)
	}
	return b, nil
}

// decodeCanonical decodes exactly one JSON value into dst, refusing unknown
// fields and trailing data, and requires the bytes to equal dst's canonical
// re-encoding. That last check refuses duplicate keys, case-folded keys,
// whitespace, alternate escapes and number forms, invalid UTF-8 and every
// non-canonical time.
func decodeCanonical(b []byte, dst any) error {
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		return err
	}
	var trailing json.RawMessage
	if err := dec.Decode(&trailing); !errors.Is(err, io.EOF) {
		return errors.New("trailing data after the JSON value")
	}
	again, err := json.Marshal(dst)
	if err != nil {
		return err
	}
	if !bytes.Equal(again, b) {
		return errors.New("not in canonical form")
	}
	return nil
}

func hashHex(domain string, body []byte) string {
	h := sha256.New()
	h.Write([]byte(domain))
	h.Write(body)
	return hex.EncodeToString(h.Sum(nil))
}

func canonicalHash(domain string, v any) (string, error) {
	b, err := Canonical(v)
	if err != nil {
		return "", err
	}
	return hashHex(domain, b), nil
}

// DraftHash is SHA-256("sshgate-approval-draft-v1\0" ‖ canonical(draft)): the
// Submit idempotency key together with the principal and request ID (E27).
func DraftHash(d ApprovalDraft) (string, error) {
	return canonicalHash("sshgate-approval-draft-v1\x00", d)
}

// PlanHash is SHA-256("sshgate-approval-plan-v1\0" ‖ canonical(plan)),
// computed once at freeze (E27).
func PlanHash(p ApprovalPlanV1) (string, error) {
	return canonicalHash("sshgate-approval-plan-v1\x00", p)
}

// ClaimTokenHash is SHA-256("sshgate-executor-claim-v1" ‖ token), the
// executor_claim_token_hash a draft carries (E25). Compare it in constant time.
func ClaimTokenHash(token [32]byte) string {
	return hashHex("sshgate-executor-claim-v1", token[:])
}

// InputHash is SHA-256("sshgate-exec-input-v1\0" ‖ canonical(input)) over an
// exec_submit input, which includes the caller-fixed submit_not_after (SA-2).
func InputHash(input any) (string, error) {
	return canonicalHash("sshgate-exec-input-v1\x00", input)
}

// ChallengeHash is the stored form of a card challenge (E47):
// SHA-256("sshgate-card-challenge-v1\0" ‖ challenge), challenge being the 16
// lowercase hex characters the callback carries.
func ChallengeHash(challenge string) string {
	return hashHex("sshgate-card-challenge-v1\x00", []byte(challenge))
}

// SessionBinding is SHA-256("sshgate-vote-session-v1" ‖ session_id) (E7). The
// raw session ID is never stored or put in a challenge.
func SessionBinding(sessionID string) string {
	return hashHex("sshgate-vote-session-v1", []byte(sessionID))
}

// legacyHostedPlan is the canonical encoding LegacyHostedPlanHash hashes.
type legacyHostedPlan struct {
	RequestID         string `json:"request_id"`
	ClientID          string `json:"client_id"`
	Commands          []byte `json:"commands"`
	CreatedAtUnixNano int64  `json:"created_at_unix_nano"`
	RequiredApprovals int    `json:"required_approvals"`
}

// LegacyHostedPlanHash binds a hosted v1 row into a vote challenge in place of
// a plan_hash (E7). commands is the row's stored commands blob.
func LegacyHostedPlanHash(requestID, clientID string, commands []byte, createdAt time.Time, requiredApprovals int) string {
	b := mustCanonical(legacyHostedPlan{
		RequestID: requestID, ClientID: clientID, Commands: commands,
		CreatedAtUnixNano: createdAt.UnixNano(), RequiredApprovals: requiredApprovals,
	})
	return hashHex("sshgate-legacy-hosted-plan-v1\x00", b)
}

// Vote-challenge planes (E7).
const (
	PlaneV1 = "v1"
	PlaneV2 = "v2"
)

// ChallengeBinding is everything a hosted MAC challenge binds (E7).
// PlanHash is the record's plan_hash on v2 and LegacyHostedPlanHash on v1.
type ChallengeBinding struct {
	Plane          string   `json:"plane"`
	RecordKey      string   `json:"record_key"`
	PlanHash       string   `json:"plan_hash"`
	Operator       string   `json:"operator"`
	SessionBinding string   `json:"session_binding"`
	AssistRevision int      `json:"assist_revision"`
	AssistDigest   string   `json:"assist_digest"`
	AllowedActions []string `json:"allowed_actions"`
	ExpiresAt      int64    `json:"expires_at"`
	Nonce          []byte   `json:"nonce"`
}

// ChallengeMACInput is the byte string a hosted vote challenge MACs:
// "sshgate-vote-challenge-v1\0" ‖ canonical(binding).
func ChallengeMACInput(b ChallengeBinding) []byte {
	return append([]byte("sshgate-vote-challenge-v1\x00"), mustCanonical(b)...)
}

// Digest is the route snapshot's registry_entry_digest (E35):
// SHA-256("sshgate-route-snapshot-v1\0" ‖ canonical(snapshot)), with added_at
// normalized to UTC so one registry entry digests the same in every zone. A
// snapshot whose time cannot be encoded (a year outside 1..9999) digests to "",
// which equals no valid digest.
func (r RouteSnapshot) Digest() string {
	r.AddedAt = r.AddedAt.UTC()
	b, err := json.Marshal(r)
	if err != nil {
		return ""
	}
	return hashHex("sshgate-route-snapshot-v1\x00", b)
}

// mustCanonical encodes a value whose encoding cannot fail: strings, integers,
// booleans, nil and byte slices only.
func mustCanonical(v any) []byte {
	b, err := json.Marshal(v)
	if err != nil {
		panic("approvalplan: canonical encoding of a fixed shape failed: " + err.Error())
	}
	return b
}

// checkCanonicalJSON requires b to be one JSON value in the exact form
// json.Marshal gives a Go struct holding it: no whitespace, no duplicate key in
// any object, every string valid UTF-8 with Go's escapes, and every number a
// canonical integer. It keeps the member order, which a struct fixes, so a
// value whose schema another package owns can still be held to the canonical
// contract at every depth.
func checkCanonicalJSON(b []byte) error {
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.UseNumber()
	var out bytes.Buffer
	if err := canonicalValue(dec, &out); err != nil {
		return err
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return errors.New("trailing data after the JSON value")
	}
	if !bytes.Equal(out.Bytes(), b) {
		return errors.New("not in canonical form")
	}
	return nil
}

// canonicalValue reads one value from dec and writes its canonical form.
func canonicalValue(dec *json.Decoder, out *bytes.Buffer) error {
	tok, err := dec.Token()
	if err != nil {
		return err
	}
	switch v := tok.(type) {
	case json.Delim:
		return canonicalContainer(dec, out, v)
	case string:
		out.Write(mustCanonical(v))
	case json.Number:
		if !isCanonicalInteger(string(v)) {
			return fmt.Errorf("number %s is not a canonical integer", v)
		}
		out.WriteString(string(v))
	case bool, nil:
		out.Write(mustCanonical(v))
	default:
		return fmt.Errorf("unexpected token %v", tok)
	}
	return nil
}

func canonicalContainer(dec *json.Decoder, out *bytes.Buffer, open json.Delim) error {
	isObject := open == '{'
	out.WriteByte(byte(open))
	seen := map[string]bool{}
	for first := true; dec.More(); first = false {
		if !first {
			out.WriteByte(',')
		}
		if isObject {
			tok, err := dec.Token()
			if err != nil {
				return err
			}
			key := tok.(string)
			if seen[key] {
				return fmt.Errorf("duplicate key %q", key)
			}
			seen[key] = true
			out.Write(mustCanonical(key))
			out.WriteByte(':')
		}
		if err := canonicalValue(dec, out); err != nil {
			return err
		}
	}
	end, err := dec.Token()
	if err != nil {
		return err
	}
	out.WriteByte(byte(end.(json.Delim)))
	return nil
}

func isCanonicalInteger(s string) bool {
	digits := strings.TrimPrefix(s, "-")
	if digits == "0" {
		return s == "0"
	}
	return digits != "" && digits[0] != '0' && allBytes(digits, isDigit)
}
