package sqlitestore

import (
	"bytes"
	"context"
	"reflect"
	"testing"
	"time"

	ap "github.com/karthikeyan5/sshgate/src/approvalplan"
	"github.com/karthikeyan5/sshgate/src/approvalplan/statetest"
)

func checkV2Projection(t *testing.T, db *DB, rec ap.R1, now ap.Now, settings ap.Settings) {
	t.Helper()
	// Hosted does not support standing grants. Keep the generator's execution
	// records, whose slots exercise the same pure core on both surfaces.
	if !rec.Header.Kind.ExecutionApplicable() {
		return
	}
	ctx := context.Background()
	projection := V2Projection{Now: now, Epoch: statetest.Epoch(1), Settings: settings}
	tx, err := db.BeginV2(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	if err := db.PutV2(ctx, tx, keyV2(rec), rec, projection); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	row, err := db.ReadV2(ctx, keyV2(rec))
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := ap.EncodeR1(rec)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(row.RecordJSON, encoded) {
		t.Fatal("record bytes did not round-trip")
	}
	back, err := ap.EncodeR1(row.Record)
	if err != nil || !bytes.Equal(back, encoded) {
		t.Fatal("decoded record changed", err)
	}
	settings.Hosted = true
	view := ap.View(rec, now, projection.Epoch, settings, false)
	work := ap.Next(rec, now, projection.Epoch, settings, false)
	status := string(view.ApprovalStatus)
	if view.ExecutionStatus != ap.ExecutionNone && view.ExecutionStatus != ap.ExecutionNotApplicable {
		status = string(view.ExecutionStatus)
	}
	var decision, decided, mintReason, last, final, due any
	if rec.Header.Decision != nil {
		decision = string(rec.Header.Decision.Status)
		decided = rec.Header.Decision.DecidedAt.Unix()
	}
	mint := "none"
	if m := rec.Header.Mint; m != nil {
		mint = "error"
		mintReason = m.Reason
		if m.State == ap.MintSignatures {
			mint = "erased"
			mintReason = nil
			if rec.Payload != nil && len(rec.Payload.Signatures) > 0 {
				mint = "bytes"
			}
		}
	}
	if end, ok := ap.LastEnd(rec); ok {
		last = end.Unix()
	}
	if rec.Header.FinalReport != nil {
		final = string(rec.Header.FinalReport.Class)
	}
	if !work.DueAt.IsZero() {
		due = work.DueAt.Unix()
	}
	var payloadBytes int64
	if rec.Payload != nil {
		b, err := ap.Canonical(rec.Payload)
		if err != nil {
			t.Fatal(err)
		}
		payloadBytes = int64(len(b))
	}
	audited, shed, live := int64(1), int64(0), int64(0)
	if ap.Unflushed(rec) {
		audited = 0
	}
	if rec.Header.Shed {
		shed = 1
	}
	if view.Class == ap.ClassLive {
		live = 1
	}
	want := []any{decision, decided, mint, mintReason, last, rec.Header.ClaimCount, final, audited, shed, payloadBytes,
		rec.Header.SubmitNotAfter.Unix(), rec.Header.CreatedAt.Unix(), rec.Header.RequestExpiresAt.Unix(), status, string(view.Class), due,
		ap.RecordHandle(ap.HostedRecordKey(rec.Header.Principal, rec.Header.SubPrincipal, rec.Header.RequestID)), live}
	got := make([]any, len(want))
	dest := make([]any, len(want))
	for i := range got {
		dest[i] = &got[i]
	}
	err = db.db.QueryRow(`SELECT decision_status,decided_at,mint_state,mint_error_reason,last_window_end,claim_count,
 final_class,audited_complete,shed,payload_bytes,submit_not_after,created_at,request_expires_at,view_status,class,
 next_due_at,record_handle,`+liveV2Predicate+` FROM approvals_v2`+keyWhereV2, keyV2(rec).ClientID, keyV2(rec).SubPrincipal, keyV2(rec).RequestID).Scan(dest...)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("columns differ:\ngot  %#v\nwant %#v", got, want)
	}
}

func TestV2StatetestProjectionProperties(t *testing.T) {
	db := legacyDB(t)
	for seed := uint64(1); seed <= 12; seed++ {
		model := statetest.NewModel(seed)
		if err := model.Run(80); err != nil {
			t.Fatal(err)
		}
		for _, rec := range model.Signer.Store {
			checkV2Projection(t, db, rec, model.Clock.Now(), model.Signer.Settings)
		}
	}
	// Model.Run quiesces before returning. Sample the intermediate live, minted,
	// erased and awaiting-report states through the same A1b harness as well.
	clock := &statetest.Clock{Wall: statetest.T0, Elapsed: time.Hour}
	signer := statetest.NewSigner(clock, 17)
	id := statetest.ID(999)
	key := ap.RecordKey(statetest.PrincipalA, id)
	signer.Submit(statetest.PrincipalA, statetest.JobDraft(id, ap.CoordinatorExecutor, clock.Wall, statetest.Write("true", 60)))
	check := func() {
		t.Helper()
		if signer.Err != nil {
			t.Fatal(signer.Err)
		}
		checkV2Projection(t, db, signer.Store[key], clock.Now(), signer.Settings)
	}
	check()
	clock.Advance(6 * time.Second)
	signer.Tick()
	check()
	signer.Tap(key, ap.VoteApprove, statetest.Operator, true)
	check()
	signer.FlushPass()
	check()
	signer.Claim(key, statetest.Token(id))
	check()
	clock.Advance(time.Minute)
	signer.Tick()
	check()
	clock.Advance(25 * time.Hour)
	signer.Tick()
	check()
	// Compare membership against every actual record, not just the SQL flag.
	rows, err := db.UnflushedV2(context.Background(), 256)
	if err != nil {
		t.Fatal(err)
	}
	seen := map[V2Key]bool{}
	for _, row := range rows {
		if !ap.Unflushed(row.Record) {
			t.Fatal("flushed row selected")
		}
		seen[row.Key] = true
	}
	all, err := db.queryV2(context.Background(), selectV2)
	if err != nil {
		t.Fatal(err)
	}
	var full int64
	for _, row := range all {
		if seen[row.Key] != ap.Unflushed(row.Record) {
			t.Fatal("unflushed membership differs")
		}
		if !row.Record.Header.Shed {
			full++
		}
	}
	tx, err := db.BeginV2(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	counts, err := db.CountV2(context.Background(), tx)
	if err != nil || counts != (V2Counts{full, int64(len(all))}) {
		t.Fatalf("counts: %+v %v", counts, err)
	}
}
