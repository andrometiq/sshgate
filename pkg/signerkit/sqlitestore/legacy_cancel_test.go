package sqlitestore

import (
	"context"
	"crypto/sha256"
	"fmt"
	"testing"
	"time"

	"github.com/karthikeyan5/sshgate/pkg/signerkit/store"
)

// Ruling 31: a hosted v1 cancel writes durable, admin-attributed evidence in
// the same transaction as the terminal transition.
func TestLegacyCancelWritesVersionedEvidence(t *testing.T) {
	db := legacyDB(t)
	ctx := context.Background()
	for _, id := range []string{"with-vote", "no-vote"} {
		if err := db.Insert(ctx, legacyRequest(id)); err != nil {
			t.Fatal(err)
		}
	}
	vote := &store.Vote{RequestID: "with-vote", Operator: "operator", Decision: store.DecisionApprove, AuthnMethod: "totp", TS: time.Unix(1001, 0).UTC()}
	if _, _, err := db.PrepareVote(ctx, vote); err != nil {
		t.Fatal(err)
	}
	at := time.Unix(1500, 0).UTC()
	for _, tc := range []struct{ id, evidence string }{
		{"with-vote", `{"v":1,"reason":"canceled","admin":"root","votes":[{"RequestID":"with-vote","Operator":"operator","Decision":"approve","AuthnMethod":"totp","TS":"1970-01-01T00:16:41Z","Audited":false}]}`},
		{"no-vote", `{"v":1,"reason":"canceled","admin":"root","votes":[]}`},
	} {
		changed, _, err := db.CancelLegacy(ctx, tc.id, at, "root")
		if err != nil || !changed {
			t.Fatalf("%s: cancel %v %v", tc.id, changed, err)
		}
		var key, evidence string
		var resolved int64
		if err := db.db.QueryRow(`SELECT event_key,resolved_at,evidence FROM legacy_expiry_outbox WHERE request_id=?`, tc.id).Scan(&key, &resolved, &evidence); err != nil {
			t.Fatal(err)
		}
		if want := fmt.Sprintf("legacy-cancel:%x:1500", sha256.Sum256([]byte(tc.id))); key != want || resolved != 1500 {
			t.Fatalf("%s: key %q at %d, want %q", tc.id, key, resolved, want)
		}
		if evidence != tc.evidence {
			t.Fatalf("%s: evidence %s", tc.id, evidence)
		}
	}
	// A repeat is a CAS no-op and writes no second line.
	if changed, _, err := db.CancelLegacy(ctx, "no-vote", at.Add(time.Second), "root"); err != nil || changed {
		t.Fatalf("repeat: %v %v", changed, err)
	}
	var count int
	if err := db.db.QueryRow(`SELECT count(*) FROM legacy_expiry_outbox`).Scan(&count); err != nil || count != 2 {
		t.Fatalf("outbox rows %d %v", count, err)
	}
	// Expiry evidence keeps the v0 bytes: a nil vote list is null.
	expiring := legacyRequest("expiring")
	expiry := time.Unix(1200, 0).UTC()
	expiring.ExpiresAt = &expiry
	if err := db.Insert(ctx, expiring); err != nil {
		t.Fatal(err)
	}
	if changed, _, err := db.ExpireLegacy(ctx, "expiring", at); err != nil || !changed {
		t.Fatalf("expire: %v %v", changed, err)
	}
	var key, evidence string
	if err := db.db.QueryRow(`SELECT event_key,evidence FROM legacy_expiry_outbox WHERE request_id='expiring'`).Scan(&key, &evidence); err != nil {
		t.Fatal(err)
	}
	if want := fmt.Sprintf("legacy-expiry:%x:1500", sha256.Sum256([]byte("expiring"))); key != want || evidence != "null" {
		t.Fatalf("expiry evidence moved: %q %s", key, evidence)
	}
}

func TestLegacyCancelRequiresAdminAndRollsBackWithoutOutbox(t *testing.T) {
	db := legacyDB(t)
	ctx := context.Background()
	if err := db.Insert(ctx, legacyRequest("pending")); err != nil {
		t.Fatal(err)
	}
	if changed, _, err := db.CancelLegacy(ctx, "pending", time.Unix(1500, 0), ""); err == nil || changed {
		t.Fatalf("anonymous cancel accepted: %v %v", changed, err)
	}
	migration7Exec(t, db.db, `DROP TABLE legacy_expiry_outbox`)
	if _, _, err := db.CancelLegacy(ctx, "pending", time.Unix(1500, 0), "root"); err == nil {
		t.Fatal("cancel without its evidence accepted")
	}
	row, err := db.GetByID(ctx, "pending")
	if err != nil || row.Status != store.StatusPending || row.TerminalReason != "" {
		t.Fatalf("terminal without evidence: %+v %v", row, err)
	}
}
