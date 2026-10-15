package sqlitestore

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"reflect"
	"sync"
	"testing"
	"time"

	"github.com/karthikeyan5/sshgate/pkg/signerkit/store"
)

func legacyDB(t *testing.T) *DB {
	t.Helper()
	db, err := Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	return db
}

func legacyRequest(id string) *store.Request {
	return &store.Request{RequestID: id, ClientID: "client", Status: store.StatusPending, Commands: []byte(`[]`), CreatedAt: time.Unix(1000, 0).UTC()}
}

func TestLegacyInsertExpiry(t *testing.T) {
	db := legacyDB(t)
	ctx := context.Background()
	custom := time.Unix(2000, 0).UTC()
	for _, tc := range []struct {
		name   string
		expiry *time.Time
		want   time.Time
	}{
		{"default", nil, time.Unix(1000, 0).Add(24 * time.Hour)},
		{"custom", &custom, custom},
	} {
		r := legacyRequest(tc.name)
		r.ExpiresAt = tc.expiry
		if err := db.Insert(ctx, r); err != nil {
			t.Fatal(err)
		}
		got, err := db.GetByID(ctx, r.RequestID)
		if err != nil || got.ExpiresAt == nil || !got.ExpiresAt.Equal(tc.want) {
			t.Fatalf("%s: got %+v err=%v", tc.name, got, err)
		}
	}
	for _, read := range []func() ([]*store.Request, error){
		func() ([]*store.Request, error) { return db.ListPending(ctx) },
		func() ([]*store.Request, error) { return db.ListPendingPage(ctx, 100, 0) },
		func() ([]*store.Request, error) { return db.RecentAudit(ctx, 100) },
	} {
		rows, err := read()
		if err != nil || len(rows) != 2 {
			t.Fatalf("rows=%v err=%v", rows, err)
		}
		for _, row := range rows {
			if row.ExpiresAt == nil {
				t.Fatal("reader lost expiry")
			}
		}
	}
}

func TestLegacyResolutionPreservesVotes(t *testing.T) {
	for _, reason := range []string{"expired", "canceled"} {
		t.Run(reason, func(t *testing.T) {
			db := legacyDB(t)
			ctx := context.Background()
			r := legacyRequest("request")
			deadline := r.CreatedAt.Add(time.Hour)
			r.ExpiresAt = &deadline
			if err := db.Insert(ctx, r); err != nil {
				t.Fatal(err)
			}
			for i, decision := range []store.Decision{store.DecisionApprove, store.DecisionDeny} {
				v := &store.Vote{RequestID: r.RequestID, Operator: fmt.Sprint(i), Decision: decision, TS: r.CreatedAt, AuthnMethod: "totp"}
				if _, _, err := db.PrepareVote(ctx, v); err != nil {
					t.Fatal(err)
				}
				if i == 0 {
					if err := db.MarkVoteAudited(ctx, r.RequestID, v.Operator); err != nil {
						t.Fatal(err)
					}
				}
			}
			resolve := db.ExpireLegacy
			wantStatus := store.StatusError
			if reason == "canceled" {
				resolve = db.CancelLegacy
				wantStatus = store.StatusDenied
			} else {
				changed, votes, err := resolve(ctx, r.RequestID, deadline.Add(-time.Second))
				if err != nil || changed || len(votes) != 0 {
					t.Fatalf("early expiry: %v %v %v", changed, votes, err)
				}
			}
			changed, votes, err := resolve(ctx, r.RequestID, deadline)
			if err != nil || !changed || len(votes) != 2 {
				t.Fatalf("resolution: %v %v %v", changed, votes, err)
			}
			if votes[0].Operator != "0" || votes[0].Decision != store.DecisionApprove || !votes[0].Audited || votes[1].Operator != "1" || votes[1].Decision != store.DecisionDeny || votes[1].Audited {
				t.Fatalf("evidence: %+v %+v", votes[0], votes[1])
			}
			for _, v := range votes {
				got, err := db.getVote(ctx, r.RequestID, v.Operator)
				if err != nil || !reflect.DeepEqual(got, v) {
					t.Fatalf("vote changed: %+v %v", got, err)
				}
			}
			// Complete the interrupted audit before trying the racing final approve:
			// only the pending CAS, not the audit barrier, can now stop the flip.
			if err := db.MarkVoteAudited(ctx, r.RequestID, "1"); err != nil {
				t.Fatal(err)
			}
			if err := db.UpdateStatus(ctx, r.RequestID, store.StatusApproved, []byte(`["signature"]`), "0"); err != nil {
				t.Fatal(err)
			}
			got, err := db.GetByID(ctx, r.RequestID)
			if err != nil || got.Status != wantStatus || got.TerminalReason != reason || got.ResolvedAt == nil || !got.ResolvedAt.Equal(deadline) || len(got.Signatures) != 0 || got.ApprovedBy != "" {
				t.Fatalf("terminal row: %+v err=%v", got, err)
			}
			for _, id := range []string{r.RequestID, "missing"} {
				for _, fn := range []func(context.Context, string, time.Time) (bool, []*store.Vote, error){db.ExpireLegacy, db.CancelLegacy} {
					changed, votes, err := fn(ctx, id, deadline.Add(time.Hour))
					if err != nil || changed || len(votes) != 0 {
						t.Fatalf("repeat/missing: %v %v %v", changed, votes, err)
					}
				}
			}
		})
	}
}

func seedV2Quota(t *testing.T, db *DB, count int, client string) {
	t.Helper()
	_, err := db.db.Exec(`WITH RECURSIVE n(x) AS (SELECT 1 UNION ALL SELECT x+1 FROM n WHERE x < ?)
 INSERT INTO approvals_v2(client_id,sub_principal,request_id,record_json,mint_state,claim_count,audited_complete,shed,payload_bytes,submit_not_after,created_at,request_expires_at,view_status,class,record_handle)
 SELECT ?, 'sub', CAST(x AS TEXT), '{}', 'none', 0, 1, 0, 0, 1, 1, 2, 'pending', 'settled', 'handle' FROM n`, count, client)
	if err != nil {
		t.Fatal(err)
	}
}

func TestLegacyMixedQuota(t *testing.T) {
	for _, global := range []bool{false, true} {
		t.Run(fmt.Sprint(global), func(t *testing.T) {
			db := legacyDB(t)
			ctx := context.Background()
			count := maxPendingPerClient - 1
			client := "client"
			if global {
				count = maxPendingGlobal - 1
				client = "other"
			}
			seedV2Quota(t, db, count, client)
			if err := db.Insert(ctx, legacyRequest("last")); err != nil {
				t.Fatal(err)
			}
			if err := db.Insert(ctx, legacyRequest("over")); !errors.Is(err, store.ErrQueueFull) {
				t.Fatalf("over quota: %v", err)
			}
			if err := db.Insert(ctx, legacyRequest("last")); !errors.Is(err, store.ErrDuplicateID) {
				t.Fatalf("duplicate: %v", err)
			}
			// Cached live rows with terminal slots must release capacity immediately.
			if _, err := db.db.Exec(`UPDATE approvals_v2 SET decision_status='denied', class='live' WHERE request_id='1'`); err != nil {
				t.Fatal(err)
			}
			if err := db.Insert(ctx, legacyRequest("released")); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestLegacyConcurrentMixedQuota(t *testing.T) {
	path := filepath.Join(t.TempDir(), "store.db")
	first, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()
	second, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()
	seedV2Quota(t, first, maxPendingPerClient-1, "client")
	var wg sync.WaitGroup
	results := make(chan error, 12)
	start := make(chan struct{})
	for i := range 12 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			db := first
			if i%2 == 1 {
				db = second
			}
			results <- db.Insert(context.Background(), legacyRequest(fmt.Sprint(i)))
		}()
	}
	close(start)
	wg.Wait()
	close(results)
	admitted := 0
	for err := range results {
		if err == nil {
			admitted++
		} else if !errors.Is(err, store.ErrQueueFull) {
			t.Fatal(err)
		}
	}
	if admitted != 1 {
		t.Fatalf("admitted %d; want 1", admitted)
	}
}

func TestLegacyResolutionRace(t *testing.T) {
	db := legacyDB(t)
	ctx := context.Background()
	r := legacyRequest("race")
	deadline := r.CreatedAt.Add(24 * time.Hour)
	if err := db.Insert(ctx, r); err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	results := make(chan bool, 12)
	failures := make(chan error, 12)
	start := make(chan struct{})
	for i := range 12 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			resolve := db.ExpireLegacy
			if i%2 == 1 {
				resolve = db.CancelLegacy
			}
			changed, _, err := resolve(ctx, r.RequestID, deadline)
			results <- changed
			if err != nil {
				failures <- err
			}
		}()
	}
	close(start)
	wg.Wait()
	close(results)
	close(failures)
	for err := range failures {
		t.Fatal(err)
	}
	winners := 0
	for changed := range results {
		if changed {
			winners++
		}
	}
	if winners != 1 {
		t.Fatalf("terminal CAS winners=%d; want 1", winners)
	}
}
