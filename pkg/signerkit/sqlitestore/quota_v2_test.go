package sqlitestore

import (
	"testing"
	"time"

	ap "github.com/karthikeyan5/sshgate/src/approvalplan"
	"github.com/karthikeyan5/sshgate/src/approvalplan/statetest"
)

func checkLivePredicate(t *testing.T, db *DB, rec ap.R1, now ap.Now) {
	t.Helper()
	// Hosted has no standing grants or transfer-key registration requests.
	if !rec.Header.Kind.ExecutionApplicable() {
		return
	}
	var decision, final any
	if rec.Header.Decision != nil {
		decision = string(rec.Header.Decision.Status)
	}
	if rec.Header.FinalReport != nil {
		final = string(rec.Header.FinalReport.Class)
	}
	mint := "none"
	if rec.Header.Mint != nil {
		mint = "error"
		if rec.Header.Mint.State == ap.MintSignatures {
			mint = "erased"
			if rec.Payload != nil && len(rec.Payload.Signatures) > 0 {
				mint = "bytes"
			}
		}
	}
	var live bool
	err := db.db.QueryRow(`SELECT `+liveV2Predicate+` FROM (SELECT ? AS decision_status, ? AS mint_state, ? AS final_class)`, decision, mint, final).Scan(&live)
	if err != nil {
		t.Fatal(err)
	}
	want := ap.Class(rec, now, statetest.ModelSettings, false) == ap.ClassLive
	if live != want {
		t.Fatalf("decision=%v mint=%s final=%v: SQL live=%v Class live=%v", decision, mint, final, live, want)
	}
}

func TestLiveV2PredicateMatchesClass(t *testing.T) {
	db := legacyDB(t)
	// Exercise every predicate branch, including open bytes after a final report.
	for _, decision := range []ap.ApprovalStatus{"", ap.ApprovalApproved, ap.ApprovalDenied, ap.ApprovalExpired, ap.ApprovalCanceled, ap.ApprovalError} {
		for _, mint := range []string{"none", "bytes", "erased", "error"} {
			for _, final := range []bool{false, true} {
				rec := ap.R1{}
				rec.Header.Kind = ap.KindCommandJob
				if decision != "" {
					rec.Header.Decision = &ap.Decision{Status: decision}
				}
				if mint != "none" {
					rec.Header.Mint = &ap.MintSlot{State: ap.MintError, Reason: ap.MintReasonWindowClosed}
				}
				if mint == "bytes" || mint == "erased" {
					rec.Header.Mint.State = ap.MintSignatures
				}
				if mint == "bytes" {
					rec.Payload = &ap.R1Payload{Signatures: []string{"signature"}}
				}
				if final {
					rec.Header.FinalReport = &ap.FinalReport{Class: ap.JobClass("succeeded")}
				}
				checkLivePredicate(t, db, rec, ap.Now{Wall: statetest.T0})
			}
		}
	}
	// Sample reachable records from A1b's generated schedules.
	for seed := uint64(1); seed <= 12; seed++ {
		model := statetest.NewModel(seed)
		if err := model.Run(80); err != nil {
			t.Fatal(err)
		}
		for _, rec := range model.Signer.Store {
			checkLivePredicate(t, db, rec, model.Clock.Now())
		}
	}
	// Also sample the live intermediate records before the generator quiesces.
	clock := &statetest.Clock{Wall: statetest.T0, Elapsed: time.Hour}
	signer := statetest.NewSigner(clock, 17)
	id := statetest.ID(1)
	key := ap.RecordKey(statetest.PrincipalA, id)
	signer.Submit(statetest.PrincipalA, statetest.JobDraft(id, ap.CoordinatorExecutor, clock.Wall, statetest.Write("true", 60)))
	checkLivePredicate(t, db, signer.Store[key], clock.Now())
	clock.Advance(6 * time.Second)
	signer.Tick()
	signer.Tap(key, ap.VoteApprove, statetest.Operator, true)
	signer.FlushPass()
	checkLivePredicate(t, db, signer.Store[key], clock.Now())
	signer.Claim(key, statetest.Token(id))
	checkLivePredicate(t, db, signer.Store[key], clock.Now())
	clock.Advance(time.Hour)
	signer.Tick()
	checkLivePredicate(t, db, signer.Store[key], clock.Now())
	if signer.Err != nil {
		t.Fatal(signer.Err)
	}
}
