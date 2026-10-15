package sqlitestore

import (
	"testing"

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
	for _, snapshot := range generatedV2Snapshots(t) {
		checkV2Projection(t, db, snapshot.record, snapshot.now, snapshot.settings)
		checkV2Unflushed(t, db)
	}
}
