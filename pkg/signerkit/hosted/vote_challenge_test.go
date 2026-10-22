package hosted

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/karthikeyan5/sshgate/pkg/signerkit"
	"github.com/karthikeyan5/sshgate/pkg/signerkit/store"
	ap "github.com/karthikeyan5/sshgate/src/approvalplan"
)

type voteSessionStore struct {
	store.Store
	session store.Session
}

func (s *voteSessionStore) GetSession(_ context.Context, id string) (*store.Session, error) {
	if id != s.session.ID {
		return nil, store.ErrNotFound
	}
	copy := s.session
	return &copy, nil
}

func voteChallengeFixture(t *testing.T, highLevel bool) (*Server, context.Context, ap.ChallengeBinding, time.Time) {
	t.Helper()
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	st := &voteSessionStore{session: store.Session{ID: "secret-session-id", UserID: "operator", ExpiresAt: now.Add(time.Hour)}}
	auth := AuthConfig{RPID: "localhost", RPOrigins: []string{"https://localhost"}, SessionTTL: time.Hour}
	var s *Server
	if highLevel {
		_, key, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		core, err := signerkit.New(signerkit.Config{Signer: key, Audit: signerkit.NewAppendOnlySink(io.Discard)})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { core.Close() })
		s, err = New(Config{Core: core, Store: st, APIKey: "test-key", MachineClientID: "client", RequiredApprovals: 1, Auth: auth})
		if err != nil {
			t.Fatal(err)
		}
	} else {
		s = NewServer("test-key", st, nil)
		s.MachineClientID = "client"
		am, err := NewAuthManager(st, auth)
		if err != nil {
			t.Fatal(err)
		}
		s.AttachHuman(&HumanAPI{Auth: am, Store: st})
	}
	t.Cleanup(func() { s.Close() })
	var ctx context.Context
	handler := s.Human.withSession(func(w http.ResponseWriter, r *http.Request, user string) {
		if user != st.session.UserID {
			t.Fatalf("operator = %q", user)
		}
		ctx = r.Context()
		w.WriteHeader(http.StatusNoContent)
	})
	req := httptest.NewRequest("GET", "https://localhost/ui/pending", nil)
	req.AddCookie(&http.Cookie{Name: SessionCookieName, Value: st.session.ID})
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, req)
	if response.Code != http.StatusNoContent || ctx == nil {
		t.Fatal("session middleware did not dispatch")
	}
	session, ok := ctx.Value(voteSessionContextKey{}).(voteSession)
	if !ok || session.ID != st.session.ID || !session.ExpiresAt.Equal(st.session.ExpiresAt) {
		t.Fatalf("session context = %+v", session)
	}
	for _, cookie := range []string{"", "wrong-session"} {
		req := httptest.NewRequest("GET", "https://localhost/ui/pending", nil)
		if cookie != "" {
			req.AddCookie(&http.Cookie{Name: SessionCookieName, Value: cookie})
		}
		rec := httptest.NewRecorder()
		s.Human.withSession(func(http.ResponseWriter, *http.Request, string) { t.Fatal("unauthenticated dispatch") }).ServeHTTP(rec, req)
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("unauthenticated status = %d", rec.Code)
		}
	}
	return s, ctx, ap.ChallengeBinding{Plane: ap.PlaneV2, RecordKey: "record", PlanHash: "plan", Operator: "operator", AssistRevision: 1, AssistDigest: "digest", AllowedActions: []string{ap.ActionApprove, ap.ActionDeny}}, now
}

func TestVoteChallengeConstructionAndSession(t *testing.T) {
	for _, highLevel := range []bool{false, true} {
		s, ctx, binding, now := voteChallengeFixture(t, highLevel)
		other := NewServer("test-key", nil, nil)
		if s.voteMACKey == ([32]byte{}) || other.voteMACKey == ([32]byte{}) || s.voteMACKey == other.voteMACKey {
			t.Fatal("keys must be fresh and nonzero")
		}
		if s.Human.voteMACKey != &s.voteMACKey {
			t.Fatal("human plane does not use server key")
		}
		challenge, err := s.Human.issueVoteChallenge(ctx, binding, now.Add(2*time.Hour))
		if err != nil {
			t.Fatal(err)
		}
		if challenge.ExpiresAt != now.Add(time.Hour).Unix() {
			t.Fatal("expiry exceeds session")
		}
		if reason := s.Human.verifyVoteChallenge(ctx, binding, challenge.Challenge, now); reason != "" {
			t.Fatal(reason)
		}
		data, _ := json.Marshal(challenge)
		if bytes.Contains(data, []byte("secret-session-id")) || bytes.Contains(data, []byte("session_binding")) || bytes.Contains(data, s.voteMACKey[:]) {
			t.Fatal("challenge exposed session or key")
		}
		other.MachineClientID = "client"
		other.AttachHuman(&HumanAPI{})
		if got := other.Human.verifyVoteChallenge(ctx, binding, challenge.Challenge, now); got != "stale_challenge" {
			t.Fatalf("restart: %q", got)
		}
	}
}

func TestVoteChallengeBindings(t *testing.T) {
	s, ctx, binding, now := voteChallengeFixture(t, false)
	for _, plane := range []string{ap.PlaneV1, ap.PlaneV2} {
		t.Run(plane, func(t *testing.T) {
			binding.Plane = plane
			challenge, err := s.Human.issueVoteChallenge(ctx, binding, now.Add(time.Minute))
			if err != nil {
				t.Fatal(err)
			}
			changes := map[string]func(*ap.ChallengeBinding){
				"plane":    func(b *ap.ChallengeBinding) { b.Plane += "other" },
				"record":   func(b *ap.ChallengeBinding) { b.RecordKey += "other" },
				"plan":     func(b *ap.ChallengeBinding) { b.PlanHash += "other" },
				"operator": func(b *ap.ChallengeBinding) { b.Operator += "other" },
				"revision": func(b *ap.ChallengeBinding) { b.AssistRevision++ },
				"digest":   func(b *ap.ChallengeBinding) { b.AssistDigest += "other" },
				"actions":  func(b *ap.ChallengeBinding) { b.AllowedActions = []string{ap.ActionDeny} },
			}
			for name, change := range changes {
				t.Run(name, func(t *testing.T) {
					altered := binding
					change(&altered)
					if got := s.Human.verifyVoteChallenge(ctx, altered, challenge.Challenge, now); got != "stale_challenge" {
						t.Fatalf("changed binding: %q", got)
					}
				})
			}
			other := context.WithValue(ctx, voteSessionContextKey{}, voteSession{ID: "new-login-same-operator", ExpiresAt: now.Add(time.Hour)})
			if got := s.Human.verifyVoteChallenge(other, binding, challenge.Challenge, now); got != "stale_challenge" {
				t.Fatalf("other session: %q", got)
			}
			raw, _ := base64.RawURLEncoding.DecodeString(challenge.Challenge)
			for i := range raw {
				altered := bytes.Clone(raw)
				altered[i] ^= 1
				if got := s.Human.verifyVoteChallenge(ctx, binding, base64.RawURLEncoding.EncodeToString(altered), now); got != "stale_challenge" {
					t.Fatalf("byte %d: %q", i, got)
				}
			}
			for _, delta := range []time.Duration{-time.Hour, 59 * time.Second, time.Minute, 2 * time.Minute} {
				want := ""
				if delta >= time.Minute {
					want = "expired_challenge"
				}
				if got := s.Human.verifyVoteChallenge(ctx, binding, challenge.Challenge, now.Add(delta)); got != want {
					t.Fatalf("time %s: %q want %q", delta, got, want)
				}
			}
			shorter := context.WithValue(ctx, voteSessionContextKey{}, voteSession{ID: "secret-session-id", ExpiresAt: now.Add(30 * time.Second)})
			if got := s.Human.verifyVoteChallenge(shorter, binding, challenge.Challenge, now); got != "stale_challenge" {
				t.Fatalf("session cap: %q", got)
			}
		})
	}
}

func TestVoteChallengeMalformedAndMissingContext(t *testing.T) {
	s, ctx, binding, now := voteChallengeFixture(t, false)
	challenge, err := s.Human.issueVoteChallenge(ctx, binding, now.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := base64.RawURLEncoding.DecodeString(challenge.Challenge)
	if len(raw) != 56 || int64(binary.BigEndian.Uint64(raw[16:24])) != challenge.ExpiresAt {
		t.Fatal("token layout")
	}
	alphabet := "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
	noncanonical := challenge.Challenge[:74] + string(alphabet[strings.IndexByte(alphabet, challenge.Challenge[74])|1])
	for _, token := range []string{"", "x", strings.Repeat("!", 75), noncanonical, challenge.Challenge + "=", challenge.Challenge + "\n", base64.RawURLEncoding.EncodeToString(raw[:55])} {
		if got := s.Human.verifyVoteChallenge(ctx, binding, token, now); got != "stale_challenge" {
			t.Fatalf("malformed: %q", got)
		}
	}
	for _, session := range []any{nil, voteSession{}, voteSession{ID: "id"}, voteSession{ExpiresAt: now}} {
		empty := context.Background()
		if session != nil {
			empty = context.WithValue(empty, voteSessionContextKey{}, session)
		}
		if _, err := s.Human.issueVoteChallenge(empty, binding, now); err == nil {
			t.Fatal("issued without session")
		}
		if got := s.Human.verifyVoteChallenge(empty, binding, challenge.Challenge, now); got != "stale_challenge" {
			t.Fatal("verified without session")
		}
	}
	unattached := &HumanAPI{}
	if _, err := unattached.issueVoteChallenge(ctx, binding, now); err == nil {
		t.Fatal("issued without key")
	}
	if got := unattached.verifyVoteChallenge(ctx, binding, challenge.Challenge, now); got != "stale_challenge" {
		t.Fatal("verified without key")
	}
}

func TestVoteChallengeConcurrentNonces(t *testing.T) {
	s, ctx, binding, now := voteChallengeFixture(t, false)
	results := make(chan string, 32)
	var wg sync.WaitGroup
	for range 32 {
		wg.Go(func() {
			c, err := s.Human.issueVoteChallenge(ctx, binding, now.Add(time.Minute))
			if err != nil {
				t.Error(err)
				return
			}
			if got := s.Human.verifyVoteChallenge(ctx, binding, c.Challenge, now); got != "" {
				t.Error(got)
			}
			results <- c.Challenge
		})
	}
	wg.Wait()
	close(results)
	seen := map[string]bool{}
	for token := range results {
		if seen[token] {
			t.Fatal("nonce reused")
		}
		seen[token] = true
	}
	if len(seen) != 32 {
		t.Fatal("missing challenge")
	}
}
