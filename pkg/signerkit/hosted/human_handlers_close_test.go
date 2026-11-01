package hosted

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"testing"
	"time"

	"github.com/karthikeyan5/sshgate/pkg/signerkit/sqlitestore"
	"github.com/karthikeyan5/sshgate/pkg/signerkit/store"
	ap "github.com/karthikeyan5/sshgate/src/approvalplan"
	"github.com/karthikeyan5/sshgate/src/approvalreview"
	redactrules "github.com/karthikeyan5/sshgate/src/redact/rules"
	"github.com/pquerna/otp/totp"
)

type voteRevisionStore struct {
	*sqlitestore.DB
	beforeRole func()
}

func (s *voteRevisionStore) GetUser(ctx context.Context, id string) (*store.User, error) {
	if s.beforeRole != nil {
		hook := s.beforeRole
		s.beforeRole = nil
		hook()
	}
	return s.DB.GetUser(ctx, id)
}

func TestHumanVoteV2StaleRevisionSpendsNoTOTP(t *testing.T) {
	for _, race := range []bool{false, true} {
		t.Run(map[bool]string{false: "before-post", true: "mac-valid-race"}[race], func(t *testing.T) {
			e, db, clock := approvalEngineFixture(t, false)
			s, ctx, _, _ := voteChallengeFixture(t, false)
			h := s.Human
			h.Store = db
			h.ordinaryEngine = func() *ApprovalV2Engine { return e }
			ctx = alignVoteSession(s, ctx, clock.Wall())
			h.Cfg.RequireStepUp = true
			h.Auth.now = clock.Wall
			st := &voteTOTPStore{Store: db}
			h.Auth.store.(*voteSessionStore).Store = st
			enrolled, err := h.Auth.EnrollTOTP(ctx, "operator", "operator")
			if err != nil {
				t.Fatal(err)
			}
			submitApproval(t, e, 1)
			row := readApproval(t, db, 1)
			path := "/ui/v2/request/" + row.RecordHandle
			var old voteChallenge
			if err := json.Unmarshal(listJSON(t, s, path)["vote_challenge"], &old); err != nil {
				t.Fatal(err)
			}
			if got := h.verifyVoteChallenge(ctx, v2VoteBinding(row, "operator"), old.Challenge, clock.Wall()); got != "" {
				t.Fatal(got)
			}
			// Advance after step 3 captured the binding, before step 5's writer check.
			// A revision changed before the POST's read instead fails MAC verification.
			bump := func() {
				if _, _, err := e.mutate(ctx, row.Key, ap.AssistDone{Unavailable: "test"}, ap.Inputs{}); err != nil {
					t.Fatal(err)
				}
				if got := h.verifyVoteChallenge(ctx, v2VoteBinding(row, "operator"), old.Challenge, clock.Wall()); got != "" {
					t.Fatalf("old view MAC did not verify: %s", got)
				}
			}
			if race {
				h.Store = &voteRevisionStore{DB: db, beforeRole: bump}
			} else {
				bump()
			}
			code, err := totp.GenerateCode(enrolled.Secret, clock.Wall())
			if err != nil {
				t.Fatal(err)
			}
			w := voteHTTP(t, s, path+"/deny", old.Challenge, code)
			if w.Code != 409 || !bytes.Contains(w.Body.Bytes(), []byte("view changed")) || st.calls != 0 {
				t.Fatalf("stale: %d %s, TOTP calls=%d", w.Code, w.Body, st.calls)
			}
			var fresh voteChallenge
			if err := json.Unmarshal(listJSON(t, s, path)["vote_challenge"], &fresh); err != nil {
				t.Fatal(err)
			}
			w = voteHTTP(t, s, path+"/approve", fresh.Challenge, code)
			if w.Code != 200 || st.calls != 1 || len(readApproval(t, db, 1).Record.Header.Votes) != 1 {
				t.Fatalf("fresh: %d %s, calls=%d", w.Code, w.Body, st.calls)
			}
		})
	}
}

func TestUIPendingCursorUsesSeparateKey(t *testing.T) {
	_, db, _ := approvalEngineFixture(t, false)
	s, ctx, _, _ := voteChallengeFixture(t, false)
	s.Human.Store = db
	aead, binding, err := s.Human.pendingCursorCipher(ctx)
	if err != nil {
		t.Fatal(err)
	}
	nonce := make([]byte, aead.NonceSize())
	sealed := aead.Seal(nil, nonce, []byte("cursor"), binding)
	block, err := aes.NewCipher(s.Human.voteMACKey[:])
	if err != nil {
		t.Fatal(err)
	}
	raw, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := raw.Open(nil, nonce, sealed, binding); err == nil {
		t.Fatal("vote MAC key decrypts cursor")
	}
	key, err := hkdf.Key(sha256.New, s.Human.voteMACKey[:], nil, "sshgate-ui-pending-cursor-v2", 32)
	if err != nil {
		t.Fatal(err)
	}
	block, err = aes.NewCipher(key)
	if err != nil {
		t.Fatal(err)
	}
	derived, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatal(err)
	}
	plaintext, err := derived.Open(nil, nonce, sealed, binding)
	if err != nil || string(plaintext) != "cursor" {
		t.Fatalf("labelled HKDF does not decrypt cursor: %q %v", plaintext, err)
	}
}

func TestWireFrozen_UIV1SecretRowGolden(t *testing.T) {
	row := &store.Request{RequestID: "r_secret", ClientID: "client", Status: store.StatusDenied, TerminalReason: "canceled", CreatedAt: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC), RequiredApprovals: 1,
		Commands: []byte(`[{"server":"web","cmd":"PASSWORD=planted-secret-value true","ttl_seconds":60}]`)}
	got, err := json.Marshal(summarizeWithSalt(row, [32]byte{}))
	if err != nil {
		t.Fatal(err)
	}
	const want = `{"redacted":true,"display_failed":false,"legacy_label":"Protocol-generated legacy intent (unverified; client supplied no reason)","terminal_reason":"canceled","request_id":"r_secret","status":"denied","client_id":"client","commands":["PASSWORD=[SSHGATE_REDACTED key=6a428a71] true"],"command_details":[{"redacted":true,"redacted_label":"Display-redacted command — signature covers undisplayed original bytes","server":"web","cmd":"PASSWORD=[SSHGATE_REDACTED key=6a428a71] true","ttl_seconds":60,"sha256":"2403e76cc001d395b149c80985e95a6ad2a130bf7e8f58c817a8273d5b188584"}],"created_at":"2026-01-01T00:00:00Z","required_approvals":1}`
	if string(got) != want {
		t.Fatalf("secret-bearing v1 row golden:\n%s", got)
	}
}

func TestUIV1SecretJSONAndV2ID(t *testing.T) {
	e, db, _ := approvalEngineFixture(t, false)
	s, _, _, now := voteChallengeFixture(t, false)
	s.Human.Store = db
	s.Human.Auth.now = func() time.Time { return now }
	expiry := now.Add(time.Hour)
	row := &store.Request{RequestID: "r_secret", ClientID: "client", Status: store.StatusPending, CreatedAt: now, ExpiresAt: &expiry, RequiredApprovals: 1,
		Commands: []byte(`[{"server":"web","cmd":"PASSWORD=planted-secret-value true","ttl_seconds":60}]`)}
	if err := db.Insert(context.Background(), row); err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256([]byte("PASSWORD=planted-secret-value true"))
	for _, canceled := range []bool{false, true} {
		if canceled {
			if changed, _, err := db.CancelLegacy(context.Background(), row.RequestID, now); err != nil || !changed {
				t.Fatalf("cancel: %v %v", changed, err)
			}
		}
		for _, path := range []string{"/ui/pending", "/ui/request/r_secret", "/ui/audit"} {
			w := listHTTP(s, path)
			if w.Code != 200 {
				t.Fatalf("%s: %d %s", path, w.Code, w.Body)
			}
			for _, secret := range []string{"planted-secret-value", hex.EncodeToString(s.Human.voteMACKey[:]), base64.RawURLEncoding.EncodeToString(s.Human.voteMACKey[:])} {
				if bytes.Contains(w.Body.Bytes(), []byte(secret)) {
					t.Fatalf("%s leaked secret", path)
				}
			}
			if ((!canceled && path != "/ui/audit") || (canceled && path != "/ui/pending")) && !bytes.Contains(w.Body.Bytes(), []byte(hex.EncodeToString(digest[:]))) {
				t.Fatal("raw digest lost")
			}
		}
		if canceled {
			data := listJSON(t, s, "/ui/request/r_secret")
			if string(data["terminal_reason"]) != `"canceled"` || string(data["status"]) != `"denied"` {
				t.Fatalf("terminal detail: %s", data)
			}
		}

	}
	submitApproval(t, e, 1)
	v2 := readApproval(t, db, 1)
	if w := listHTTP(s, "/ui/request/"+v2.Key.RequestID); w.Code != 404 {
		t.Fatalf("v2 ID on v1 route: %d", w.Code)
	}
}

type uiSecretSnapshot struct{ salt [32]byte }

func (b uiSecretSnapshot) BuildSnapshot(_ context.Context, p ap.ApprovalPlanV1) ([]byte, string, error) {
	snapshot, err := approvalreview.BuildSnapshot(p, &b.salt, redactrules.Combined())
	if err != nil {
		return nil, "", err
	}
	view, err := approvalreview.BuildView(snapshot, approvalreview.Assist{State: ap.AssistPreparing})
	if err != nil {
		return nil, "", err
	}
	data, err := snapshot.Encode()
	return data, view.Reason, err
}

func TestUIV2AllJSONOmitsSecrets(t *testing.T) {
	e, db, _ := approvalEngineFixture(t, false)
	var salt [32]byte
	copy(salt[:], "planted-render-salt-0123456789abcd")
	e.config.SnapshotBuilder = uiSecretSnapshot{salt: salt}
	s := lifecycleUI(t, e, db)
	draft := approvalDraft(1)
	draft.Rationale = "Run PASSWORD=planted-secret-value maintenance"
	draft.CommandJob.Steps[0].ExactCommand = "PASSWORD=planted-secret-value true"
	sum := sha256.Sum256([]byte(draft.CommandJob.Steps[0].ExactCommand))
	draft.CommandJob.Steps[0].CommandSHA256 = hex.EncodeToString(sum[:])
	if _, err := e.Submit(context.Background(), "client", "", draft); err != nil {
		t.Fatal(err)
	}
	row := readApproval(t, db, 1)
	encodedSalt, _ := json.Marshal(salt)
	encodedKey, _ := json.Marshal(*s.Human.voteMACKey)
	forbidden := []string{string(encodedSalt), string(encodedKey), "planted-secret-value", string(salt[:]), hex.EncodeToString(salt[:]), base64.StdEncoding.EncodeToString(salt[:]), base64.RawURLEncoding.EncodeToString(salt[:]), hex.EncodeToString(s.Human.voteMACKey[:]), base64.StdEncoding.EncodeToString(s.Human.voteMACKey[:]), base64.RawURLEncoding.EncodeToString(s.Human.voteMACKey[:])}
	check := func(body []byte) {
		t.Helper()
		for _, secret := range forbidden {
			if bytes.Contains(body, []byte(secret)) {
				t.Fatal("UI leaked secret, salt or MAC key")
			}
		}
	}
	paths := []string{"/ui/pending", "/ui/v2/request/" + row.RecordHandle, "/ui/audit"}
	for _, path := range paths {
		w := listHTTP(s, path)
		if w.Code != 200 {
			t.Fatalf("%s: %d %s", path, w.Code, w.Body)
		}
		check(w.Body.Bytes())
	}
	var token voteChallenge
	json.Unmarshal(listJSON(t, s, paths[1])["vote_challenge"], &token)
	s.Human.Cfg.ApprovalPolicy.DenyVeto = true
	w := voteHTTP(t, s, paths[1]+"/deny", token.Challenge)
	if w.Code != 200 {
		t.Fatalf("deny: %d %s", w.Code, w.Body)
	}
	check(w.Body.Bytes())
	for _, path := range paths {
		w := listHTTP(s, path)
		if w.Code != 200 {
			t.Fatalf("%s: %d %s", path, w.Code, w.Body)
		}
		check(w.Body.Bytes())
	}
}

func TestUIV1UnredactedCommandBytesUnchanged(t *testing.T) {
	const command = "printf 'hello\\n'\n# \u202e"
	commands, err := json.Marshal([]signRequestCmd{{Cmd: command}})
	if err != nil {
		t.Fatal(err)
	}
	row := summarizeWithSalt(&store.Request{Commands: commands}, [32]byte{})
	if len(row.Commands) != 1 || len(row.CommandDetails) != 1 || row.Commands[0] != command || row.CommandDetails[0].Cmd != command {
		t.Fatalf("unredacted bytes changed: %+v", row)
	}
}
