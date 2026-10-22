package hosted

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"time"

	ap "github.com/karthikeyan5/sshgate/src/approvalplan"
)

type voteSessionContextKey struct{}

type voteSession struct {
	ID        string
	ExpiresAt time.Time
}

type voteChallenge struct {
	Challenge      string   `json:"challenge"`
	PlanHash       string   `json:"plan_hash"`
	AssistRevision int      `json:"assist_revision"`
	AssistDigest   string   `json:"assist_digest"`
	AllowedActions []string `json:"allowed_actions"`
	ExpiresAt      int64    `json:"expires_at"`
}

// issueVoteChallenge binds a trusted view to the authenticated session. The token
// carries only a nonce, a big-endian Unix expiry and a MAC, encoded as base64url.
func (h *HumanAPI) issueVoteChallenge(ctx context.Context, binding ap.ChallengeBinding, expiresAt time.Time) (voteChallenge, error) {
	session, ok := ctx.Value(voteSessionContextKey{}).(voteSession)
	if !ok || session.ID == "" || session.ExpiresAt.IsZero() || h.voteMACKey == nil {
		return voteChallenge{}, errors.New("hosted: vote challenge requires an attached human plane and session")
	}
	if expiresAt.After(session.ExpiresAt) {
		expiresAt = session.ExpiresAt
	}
	var token [16 + 8 + sha256.Size]byte
	rand.Read(token[:16])
	binding.SessionBinding = ap.SessionBinding(session.ID)
	binding.ExpiresAt = expiresAt.Unix()
	binding.Nonce = token[:16]
	binary.BigEndian.PutUint64(token[16:24], uint64(binding.ExpiresAt))
	copy(token[24:], h.voteChallengeMAC(binding))
	return voteChallenge{
		Challenge: base64.RawURLEncoding.EncodeToString(token[:]),
		PlanHash:  binding.PlanHash, AssistRevision: binding.AssistRevision,
		AssistDigest: binding.AssistDigest, AllowedActions: append([]string(nil), binding.AllowedActions...),
		ExpiresAt: binding.ExpiresAt,
	}, nil
}

// verifyVoteChallenge returns an audit refusal reason, or empty on success.
// binding must come from the authoritative view, never from POST metadata.
func (h *HumanAPI) verifyVoteChallenge(ctx context.Context, binding ap.ChallengeBinding, challenge string, now time.Time) string {
	session, ok := ctx.Value(voteSessionContextKey{}).(voteSession)
	if !ok || session.ID == "" || session.ExpiresAt.IsZero() || h.voteMACKey == nil {
		return "stale_challenge"
	}
	// Reject oversized input before decoding; the wire has exactly 56 bytes.
	if len(challenge) != base64.RawURLEncoding.EncodedLen(56) {
		return "stale_challenge"
	}
	token, err := base64.RawURLEncoding.Strict().DecodeString(challenge)
	if err != nil || len(token) != 56 {
		return "stale_challenge"
	}
	binding.SessionBinding = ap.SessionBinding(session.ID)
	binding.ExpiresAt = int64(binary.BigEndian.Uint64(token[16:24]))
	binding.Nonce = token[:16]
	if !hmac.Equal(token[24:], h.voteChallengeMAC(binding)) {
		return "stale_challenge"
	}
	if binding.ExpiresAt > session.ExpiresAt.Unix() {
		return "stale_challenge"
	}
	if now.Unix() >= binding.ExpiresAt {
		return "expired_challenge"
	}
	return ""
}

func (h *HumanAPI) voteChallengeMAC(binding ap.ChallengeBinding) []byte {
	mac := hmac.New(sha256.New, h.voteMACKey[:])
	mac.Write(ap.ChallengeMACInput(binding))
	return mac.Sum(nil)
}
