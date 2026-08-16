package sqlitestore

import (
	"database/sql"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

const policyTestCompactSQL = `
	UPDATE policy_requests SET storage_kind='tombstone',compaction_delete_guard=1,
	 canonical_request=NULL,payload=NULL,trusted_head_envelope=NULL,trusted_head_digest=NULL,
	 trusted_head_key_id=NULL,trusted_head_public_key=NULL,trusted_head_epoch_be=NULL,
	 trusted_head_revision_be=NULL,trusted_head_row_version=NULL,claimed_head_envelope=NULL,
	 claimed_head_digest=NULL,claimed_head_key_id=NULL,claimed_head_public_key=NULL,
	 claimed_head_epoch_be=NULL,claimed_head_revision_be=NULL,claimed_head_row_version=NULL,
	 frozen_signer_key_id=NULL,frozen_signer_public_key=NULL,review_json=NULL,review_sha256=NULL,
	 review_rendered_bytes=NULL,review_item_count=NULL,review_renderer_version=NULL,review_rules_digest=NULL,
	 eligible_voters_json=NULL,eligible_voters_sha256=NULL,eligible_voter_count=NULL,
	 result_envelope=NULL,pending_response=NULL,terminal_response=NULL,
	 archive_id=?,archive_object_sha256=?,archive_record_bytes=4096,
	 terminal_response_sha256=?,terminal_response_bytes=2,logical_bytes=512
	WHERE principal=? AND request_id=?`

func TestOpenExistingDoesNotCreateOrMigrate(t *testing.T) {
	directory := t.TempDir()
	absent := filepath.Join(directory, "absent.db")
	if _, err := OpenExisting(absent); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("OpenExisting(absent) error = %v; want os.ErrNotExist", err)
	}
	if _, err := os.Stat(absent); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("OpenExisting created absent database: %v", err)
	}

	unmigrated := filepath.Join(directory, "unmigrated.db")
	raw, err := sql.Open("sqlite", fmt.Sprintf("file:%s?mode=rwc", unmigrated))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := raw.Exec(`CREATE TABLE owner_marker (value TEXT)`); err != nil {
		t.Fatal(err)
	}
	if err := raw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(unmigrated, 0o600); err != nil {
		t.Fatal(err)
	}
	existing, err := OpenExisting(unmigrated)
	if err != nil {
		t.Fatalf("OpenExisting(unmigrated): %v", err)
	}
	defer existing.Close()
	var migrationsTable int
	if err := existing.db.QueryRow(`SELECT count(*) FROM sqlite_master WHERE type='table' AND name='schema_migrations'`).Scan(&migrationsTable); err != nil {
		t.Fatal(err)
	}
	if migrationsTable != 0 {
		t.Fatal("OpenExisting migrated an unverified database")
	}
	var journalMode string
	if err := existing.db.QueryRow(`PRAGMA journal_mode`).Scan(&journalMode); err != nil {
		t.Fatal(err)
	}
	if journalMode != "delete" {
		t.Fatalf("OpenExisting changed journal mode to %q; want delete", journalMode)
	}
}

func TestOpenExistingLeavesMigratedSchemaUnchanged(t *testing.T) {
	path := filepath.Join(t.TempDir(), "existing.db")
	database, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	var beforeVersion, beforeMigrations int
	if err := database.db.QueryRow(`PRAGMA schema_version`).Scan(&beforeVersion); err != nil {
		t.Fatal(err)
	}
	if err := database.db.QueryRow(`SELECT count(*) FROM schema_migrations`).Scan(&beforeMigrations); err != nil {
		t.Fatal(err)
	}
	if err := database.Close(); err != nil {
		t.Fatal(err)
	}

	existing, err := OpenExisting(path)
	if err != nil {
		t.Fatal(err)
	}
	defer existing.Close()
	var afterVersion, afterMigrations int
	if err := existing.db.QueryRow(`PRAGMA schema_version`).Scan(&afterVersion); err != nil {
		t.Fatal(err)
	}
	if err := existing.db.QueryRow(`SELECT count(*) FROM schema_migrations`).Scan(&afterMigrations); err != nil {
		t.Fatal(err)
	}
	if afterVersion != beforeVersion || afterMigrations != beforeMigrations {
		t.Fatalf("OpenExisting changed schema: version %d/%d migrations %d/%d", beforeVersion, afterVersion, beforeMigrations, afterMigrations)
	}
}

func TestConcurrentFirstOpenSerializesMigrationLedger(t *testing.T) {
	path := filepath.Join(t.TempDir(), "concurrent.db")
	const openers = 16
	start := make(chan struct{})
	results := make(chan error, openers)
	var wait sync.WaitGroup
	for range openers {
		wait.Add(1)
		go func() {
			defer wait.Done()
			<-start
			database, err := Open(path)
			if err == nil {
				err = database.Close()
			}
			results <- err
		}()
	}
	close(start)
	wait.Wait()
	close(results)
	for err := range results {
		if err != nil {
			t.Fatalf("concurrent Open: %v", err)
		}
	}

	database, err := OpenExisting(path)
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	rows, err := database.db.Query(`SELECT version, name FROM schema_migrations ORDER BY version`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	version := 0
	for rows.Next() {
		version++
		var gotVersion int
		var name string
		if err := rows.Scan(&gotVersion, &name); err != nil {
			t.Fatal(err)
		}
		if gotVersion != version || name != migrations[version-1].Name {
			t.Fatalf("ledger row = (%d,%q); want (%d,%q)", gotVersion, name, version, migrations[version-1].Name)
		}
	}
	if version != len(migrations) {
		t.Fatalf("ledger contains %d migrations; want %d", version, len(migrations))
	}
}

func TestMigrationLedgerRejectsNameAndFutureVersionDrift(t *testing.T) {
	for _, test := range []struct {
		name   string
		mutate string
	}{
		{name: "name", mutate: `UPDATE schema_migrations SET name='substituted' WHERE version=6`},
		{name: "future", mutate: `INSERT INTO schema_migrations(version,name,applied_at) VALUES(7,'future',1)`},
	} {
		t.Run(test.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "drift.db")
			database, err := Open(path)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := database.db.Exec(test.mutate); err != nil {
				t.Fatal(err)
			}
			if err := database.Close(); err != nil {
				t.Fatal(err)
			}
			if reopened, err := Open(path); err == nil {
				_ = reopened.Close()
				t.Fatal("Open accepted migration ledger drift")
			}
		})
	}
}

func TestMigrationLedgerRejectsMissingPolicySchemaObject(t *testing.T) {
	path := filepath.Join(t.TempDir(), "missing-trigger.db")
	database, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := database.db.Exec(`DROP TRIGGER policy_vote_immutable`); err != nil {
		t.Fatal(err)
	}
	if err := database.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := Open(path)
	if err == nil {
		_ = reopened.Close()
		t.Fatal("Open accepted a recorded migration with a missing policy trigger")
	}
	if !strings.Contains(err.Error(), "missing policy schema object policy_vote_immutable") {
		t.Fatalf("Open error = %v; want missing policy trigger", err)
	}
}

func TestMigrationLedgerRejectsRecreatedPolicyTrigger(t *testing.T) {
	path := filepath.Join(t.TempDir(), "permissive-trigger.db")
	database, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := database.db.Exec(`DROP TRIGGER policy_vote_immutable`); err != nil {
		t.Fatal(err)
	}
	if _, err := database.db.Exec(`CREATE TRIGGER policy_vote_immutable BEFORE UPDATE ON policy_votes
		BEGIN SELECT 1; END`); err != nil {
		t.Fatal(err)
	}
	if err := database.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := Open(path)
	if err == nil {
		_ = reopened.Close()
		t.Fatal("Open accepted a permissively recreated policy trigger")
	}
	if !strings.Contains(err.Error(), "policy schema object policy_vote_immutable SQL differs") {
		t.Fatalf("Open error = %v; want exact trigger-SQL disagreement", err)
	}
}

func TestMigration6ExactColumnCensus(t *testing.T) {
	database := openPolicyTestDB(t)
	for table, want := range policySchemaColumns {
		rows, err := database.db.Query(fmt.Sprintf("PRAGMA table_info(%q)", table))
		if err != nil {
			t.Fatal(err)
		}
		var got []string
		for rows.Next() {
			var (
				columnID       int
				name, typeName string
				notNull        int
				defaultValue   sql.NullString
				primaryKey     int
			)
			if err := rows.Scan(&columnID, &name, &typeName, &notNull, &defaultValue, &primaryKey); err != nil {
				_ = rows.Close()
				t.Fatal(err)
			}
			got = append(got, name)
		}
		if err := rows.Close(); err != nil {
			t.Fatal(err)
		}
		if strings.Join(got, ",") != strings.Join(want, ",") {
			t.Fatalf("%s columns = %v; want %v", table, got, want)
		}
	}
}

func TestMigration6PolicyIdentityChecksAtSchema(t *testing.T) {
	tests := []struct {
		name     string
		identity string
	}{
		{name: "empty", identity: ""},
		{name: "over bound", identity: strings.Repeat("x", 129)},
		{name: "nul", identity: "operator\x00suffix"},
		{name: "invalid utf8", identity: string([]byte{0xff})},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			database := openPolicyTestDB(t)
			if err := insertPolicyMeta(database.db, test.identity); err == nil {
				t.Fatalf("schema accepted policy identity %q", test.identity)
			}

			rowDatabase := openPolicyTestDB(t)
			if err := insertPolicyMeta(rowDatabase.db, "requester"); err != nil {
				t.Fatal(err)
			}
			if err := insertAcceptedPending(rowDatabase.db, test.identity, requestID("9"), reviewID("9"), "host-nine"); err == nil {
				t.Fatalf("request schema accepted principal %q", test.identity)
			}
			if err := insertAcceptedPending(rowDatabase.db, "alice", requestID("9"), reviewID("9"), "host-nine"); err != nil {
				t.Fatal(err)
			}
			if _, err := rowDatabase.db.Exec(`UPDATE policy_requests SET state_version=2
				WHERE principal='alice' AND request_id=?`, requestID("9")); err != nil {
				t.Fatal(err)
			}
			if _, err := rowDatabase.db.Exec(`INSERT INTO policy_votes(
				principal,request_id,operator,decision,authn_method,ts,audited,audit_state_version,
				tuple_digest,purpose,payload_sha256,candidate_digest,head_digest,signer_key_id,logical_bytes)
				VALUES('alice',?,?,'approve','session',1,0,2,?,'base_manifest_sign_v1',?,?,?,?,256)`,
				requestID("9"), test.identity, hex64("1"), hex64("2"), hex64("3"), "", hex64("a")); err == nil {
				t.Fatalf("vote schema accepted operator %q", test.identity)
			}
		})
	}
	database := openPolicyTestDB(t)
	if err := insertPolicyMeta(database.db, strings.Repeat("界", 42)+"ab"); err != nil {
		t.Fatalf("schema rejected exact 128-byte UTF-8 identity: %v", err)
	}
}

func TestMigration6BootstrapAllowsMoreThan32LogicalChanges(t *testing.T) {
	database := openPolicyTestDB(t)
	if err := insertPolicyMeta(database.db, "requester"); err != nil {
		t.Fatal(err)
	}
	if err := insertAcceptedShapeWithChanges(database.db, "alice", requestID("8"), reviewID("8"),
		"host-eight", true, "pending", 1, 33); err != nil {
		t.Fatalf("schema rejected legal 33-part bootstrap review: %v", err)
	}
}

func TestMigration6DirectSQLGuards(t *testing.T) {
	database := openPolicyTestDB(t)
	if err := insertPolicyMeta(database.db, "requester"); err != nil {
		t.Fatal(err)
	}
	if _, err := database.db.Exec(`UPDATE policy_authority_meta SET archive_id=? WHERE singleton=1`, archiveID("b")); err == nil {
		t.Fatal("authority metadata mutation succeeded")
	}
	if _, err := database.db.Exec(`INSERT INTO policy_authority_key_bindings VALUES(?,?,?,1)`, hex64("a"), make([]byte, 32), authorityID("a")); err != nil {
		t.Fatal(err)
	}
	if _, err := database.db.Exec(`UPDATE policy_authority_key_bindings SET authority_id=?`, authorityID("b")); err == nil {
		t.Fatal("key binding update succeeded")
	}
	if _, err := database.db.Exec(`DELETE FROM policy_authority_key_bindings`); err == nil {
		t.Fatal("key binding delete succeeded")
	}

	if err := insertAcceptedPending(database.db, "alice", requestID("1"), reviewID("1"), "host-one"); err != nil {
		t.Fatalf("insert accepted pending: %v", err)
	}
	if _, err := database.db.Exec(`UPDATE policy_requests SET host_key_fp='substituted' WHERE principal='alice'`); err == nil {
		t.Fatal("immutable request mutation succeeded")
	}
	if _, err := database.db.Exec(`UPDATE policy_requests SET reserved_bytes=reserved_bytes+1 WHERE principal='alice'`); err == nil {
		t.Fatal("reservation increase succeeded")
	}
	if _, err := database.db.Exec(`UPDATE policy_requests SET state='approved', state_version=state_version+1 WHERE principal='alice'`); err == nil {
		t.Fatal("illegal state/version transition succeeded")
	}
	if _, err := database.db.Exec(`
		UPDATE policy_requests SET state='error_received', state_version=state_version+1,
		  error_family='publication-error', failure_code='stale_policy_head', reserved_bytes=reserved_bytes-1
		WHERE principal='alice'`); err == nil {
		t.Fatal("wrong pending error family/source transition succeeded")
	}
	if _, err := database.db.Exec(`
		UPDATE policy_requests SET state='error_received', state_version=state_version+1,
		  error_family='semantic-rejection', failure_code='quorum_unattainable', payload=x'00',
		  reserved_bytes=reserved_bytes-1
		WHERE principal='alice'`); err == nil {
		t.Fatal("Matrix-2b blob mutation succeeded")
	}
}

func TestMigration6VoteAndCompactionTriggersAreAtomic(t *testing.T) {
	database := openPolicyTestDB(t)
	if err := insertPolicyMeta(database.db, "requester"); err != nil {
		t.Fatal(err)
	}
	request := requestID("2")
	if err := insertAcceptedPending(database.db, "alice", request, reviewID("2"), "host-two"); err != nil {
		t.Fatal(err)
	}
	if _, err := database.db.Exec(`UPDATE policy_requests SET state_version=2, reserved_bytes=90000 WHERE principal='alice' AND request_id=?`, request); err != nil {
		t.Fatalf("reserve vote version: %v", err)
	}
	if _, err := database.db.Exec(`
		INSERT INTO policy_votes(principal,request_id,operator,decision,authn_method,ts,audited,
		 audit_state_version,tuple_digest,purpose,payload_sha256,candidate_digest,head_digest,signer_key_id,logical_bytes)
		VALUES('alice',?,'operator','approve','session',1,0,2,?,'base_manifest_sign_v1',?,?,?,?,256)`,
		request, hex64("1"), hex64("2"), hex64("3"), "", hex64("a")); err != nil {
		t.Fatalf("insert bootstrap vote with empty head digest: %v", err)
	}
	if _, err := database.db.Exec(`DELETE FROM policy_votes WHERE principal='alice' AND request_id=?`, request); err == nil {
		t.Fatal("direct vote delete succeeded")
	}
	if _, err := database.db.Exec(`UPDATE policy_votes SET decision='deny' WHERE principal='alice' AND request_id=?`, request); err == nil {
		t.Fatal("vote mutation succeeded")
	}
	if _, err := database.db.Exec(`UPDATE policy_votes SET audited=1 WHERE principal='alice' AND request_id=?`, request); err != nil {
		t.Fatalf("audit vote: %v", err)
	}
	if _, err := database.db.Exec(`
		UPDATE policy_requests SET state='denial_received',state_version=3,reserved_bytes=1000
		WHERE principal='alice' AND request_id=?`, request); err != nil {
		t.Fatalf("claim denial: %v", err)
	}
	if _, err := database.db.Exec(`
		UPDATE policy_requests SET terminal_audited=1,reserved_bytes=999
		WHERE principal='alice' AND request_id=?`, request); err == nil {
		t.Fatal("terminal audit acknowledgement consumed reservation")
	}
	if _, err := database.db.Exec(`
		UPDATE policy_requests SET terminal_audited=1
		WHERE principal='alice' AND request_id=?`, request); err != nil {
		t.Fatalf("terminal audit ack: %v", err)
	}
	if _, err := database.db.Exec(`
		UPDATE policy_requests SET state='denied',terminal_response=x'7b7d',terminal_http_status=200,
		 resolved_at=10,reserved_bytes=1
		WHERE principal='alice' AND request_id=?`, request); err == nil {
		t.Fatal("accepted terminal retained reservation above zero floor")
	}
	if _, err := database.db.Exec(`
		UPDATE policy_requests SET state='denied',terminal_response=x'7b7d',terminal_http_status=200,
		 resolved_at=10,reserved_bytes=0
		WHERE principal='alice' AND request_id=?`, request); err != nil {
		t.Fatalf("publish denied: %v", err)
	}
	changedTimestampSQL := strings.Replace(policyTestCompactSQL, "logical_bytes=512", "logical_bytes=512,updated_at=updated_at+1", 1)
	if _, err := database.db.Exec(changedTimestampSQL,
		archiveID("a"), hex64("b"), hex64("c"), "alice", request); err == nil {
		t.Fatal("compaction changed retained updated_at")
	}
	if _, err := database.db.Exec(`
		CREATE TRIGGER test_fail_compaction_clear
		BEFORE UPDATE ON policy_requests
		WHEN OLD.storage_kind='tombstone' AND OLD.compaction_delete_guard=1 AND
		     NEW.storage_kind='tombstone' AND NEW.compaction_delete_guard=0
		BEGIN SELECT RAISE(ABORT, 'forced nested-clear failure'); END`); err != nil {
		t.Fatal(err)
	}
	if _, err := database.db.Exec(policyTestCompactSQL, archiveID("a"), hex64("b"), hex64("c"), "alice", request); err == nil {
		t.Fatal("compaction committed despite nested-clear failure")
	}
	var storage string
	var failedGuard, retainedVotes int
	if err := database.db.QueryRow(`SELECT storage_kind,compaction_delete_guard FROM policy_requests
		WHERE principal='alice' AND request_id=?`, request).Scan(&storage, &failedGuard); err != nil {
		t.Fatal(err)
	}
	if err := database.db.QueryRow(`SELECT count(*) FROM policy_votes WHERE principal='alice' AND request_id=?`, request).Scan(&retainedVotes); err != nil {
		t.Fatal(err)
	}
	if storage != "full" || failedGuard != 0 || retainedVotes != 1 {
		t.Fatalf("failed compaction left storage=%s guard=%d votes=%d; want full/0/1", storage, failedGuard, retainedVotes)
	}
	if _, err := database.db.Exec(`DROP TRIGGER test_fail_compaction_clear`); err != nil {
		t.Fatal(err)
	}
	if _, err := database.db.Exec(policyTestCompactSQL, archiveID("a"), hex64("b"), hex64("c"), "alice", request); err != nil {
		t.Fatalf("compact terminal: %v", err)
	}
	var guard, votes int
	if err := database.db.QueryRow(`SELECT compaction_delete_guard FROM policy_requests WHERE principal='alice' AND request_id=?`, request).Scan(&guard); err != nil {
		t.Fatal(err)
	}
	if err := database.db.QueryRow(`SELECT count(*) FROM policy_votes WHERE principal='alice' AND request_id=?`, request).Scan(&votes); err != nil {
		t.Fatal(err)
	}
	if guard != 0 || votes != 0 {
		t.Fatalf("compaction committed guard=%d votes=%d; want 0/0", guard, votes)
	}
	columns := policySchemaColumns["policy_requests"]
	selectColumns := append([]string(nil), columns...)
	for index, column := range selectColumns {
		if column == "compaction_delete_guard" {
			selectColumns[index] = "1"
		}
	}
	_, err := database.db.Exec(`INSERT INTO policy_requests (`+strings.Join(columns, ",")+`)
		SELECT `+strings.Join(selectColumns, ",")+` FROM policy_requests
		WHERE principal='alice' AND request_id=?`, request)
	if err == nil {
		t.Fatal("tombstone insertion with compaction guard succeeded")
	}
	if !strings.Contains(err.Error(), "cannot be inserted with compaction guard") {
		t.Fatalf("guarded tombstone insert error = %v; want compaction insert guard", err)
	}
}

func TestMigration6VoteHeadDigestBootstrapGrammar(t *testing.T) {
	for _, test := range []struct {
		name       string
		headDigest string
		wantOK     bool
	}{
		{name: "bootstrap empty", headDigest: "", wantOK: true},
		{name: "successor digest", headDigest: hex64("4"), wantOK: true},
		{name: "malformed", headDigest: "not-a-digest", wantOK: false},
	} {
		t.Run(test.name, func(t *testing.T) {
			database := openPolicyTestDB(t)
			if err := insertPolicyMeta(database.db, "requester"); err != nil {
				t.Fatal(err)
			}
			request := requestID("6")
			if err := insertAcceptedPending(database.db, "alice", request, reviewID("6"), "host-six"); err != nil {
				t.Fatal(err)
			}
			if _, err := database.db.Exec(`UPDATE policy_requests SET state_version=2
				WHERE principal='alice' AND request_id=?`, request); err != nil {
				t.Fatal(err)
			}
			_, err := database.db.Exec(`
				INSERT INTO policy_votes(principal,request_id,operator,decision,authn_method,ts,audited,
				 audit_state_version,tuple_digest,purpose,payload_sha256,candidate_digest,head_digest,
				 signer_key_id,logical_bytes)
				VALUES('alice',?,'operator','approve','session',1,0,2,?,'base_manifest_sign_v1',?,?,?,?,256)`,
				request, hex64("1"), hex64("2"), hex64("3"), test.headDigest, hex64("a"))
			if (err == nil) != test.wantOK {
				t.Fatalf("vote insert error = %v; wantOK=%v", err, test.wantOK)
			}
		})
	}
}

func TestMigration6ApprovedTombstoneRetainsResultDigest(t *testing.T) {
	database := openPolicyTestDB(t)
	if err := insertPolicyMeta(database.db, "requester"); err != nil {
		t.Fatal(err)
	}
	request := requestID("7")
	if err := insertAcceptedPending(database.db, "alice", request, reviewID("7"), "host-seven"); err != nil {
		t.Fatal(err)
	}
	if _, err := database.db.Exec(`UPDATE policy_requests SET state='approved_materializing',state_version=2,
		 recovery_lease_owner='worker',recovery_lease_until=100,recovery_lease_generation=1,reserved_bytes=2000
		WHERE principal='alice' AND request_id=?`, request); err != nil {
		t.Fatalf("claim bootstrap approval: %v", err)
	}
	if _, err := database.db.Exec(`UPDATE policy_requests SET pre_mint_audited=1
		WHERE principal='alice' AND request_id=?`, request); err != nil {
		t.Fatalf("audit pre-mint: %v", err)
	}
	resultDigest := hex64("8")
	if _, err := database.db.Exec(`UPDATE policy_requests SET state='approved_unexposed',state_version=3,
		 result_envelope=x'7b7d',result_sha256=?,reserved_bytes=1000
		WHERE principal='alice' AND request_id=?`, resultDigest, request); err != nil {
		t.Fatalf("persist materialized result: %v", err)
	}
	if _, err := database.db.Exec(`UPDATE policy_requests SET result_audited=1
		WHERE principal='alice' AND request_id=?`, request); err != nil {
		t.Fatalf("audit materialized result: %v", err)
	}
	if _, err := database.db.Exec(`UPDATE policy_requests SET state='approved',terminal_response=x'7b7d',
		 terminal_http_status=200,resolved_at=10,reserved_bytes=0,
		 recovery_lease_owner='',recovery_lease_until=0
		 WHERE principal='alice' AND request_id=?`, request); err != nil {
		t.Fatalf("publish approval: %v", err)
	}
	if _, err := database.db.Exec(policyTestCompactSQL,
		archiveID("a"), hex64("b"), hex64("c"), "alice", request); err != nil {
		t.Fatalf("compact approved terminal with retained result digest: %v", err)
	}
	var storage, storedDigest, leaseOwner string
	var leaseUntil, leaseGeneration int64
	var envelope []byte
	if err := database.db.QueryRow(`SELECT storage_kind,result_envelope,result_sha256,
		recovery_lease_owner,recovery_lease_until,recovery_lease_generation FROM policy_requests
		WHERE principal='alice' AND request_id=?`, request).
		Scan(&storage, &envelope, &storedDigest, &leaseOwner, &leaseUntil, &leaseGeneration); err != nil {
		t.Fatal(err)
	}
	if storage != "tombstone" || envelope != nil || storedDigest != resultDigest || leaseOwner != "" || leaseUntil != 0 || leaseGeneration != 1 {
		t.Fatalf("approved tombstone storage/envelope/digest/lease = %s/%x/%s %q/%d/%d",
			storage, envelope, storedDigest, leaseOwner, leaseUntil, leaseGeneration)
	}
}

func TestMigration6SuccessorNoOpKeepsClaimedPredecessorAbsent(t *testing.T) {
	database := openPolicyTestDB(t)
	if err := insertPolicyMeta(database.db, "requester"); err != nil {
		t.Fatal(err)
	}
	request := requestID("3")
	if err := insertAcceptedSuccessorReceived(database.db, "alice", request, reviewID("3"), "host-three"); err != nil {
		t.Fatalf("insert accepted successor: %v", err)
	}
	if _, err := database.db.Exec(`
		UPDATE policy_requests SET state='no_op_unexposed',state_version=2,no_op=1,
		 result_envelope=x'7b7d',result_sha256=?,reserved_bytes=1000
		WHERE principal='alice' AND request_id=?`, hex64("8"), request); err != nil {
		t.Fatalf("stage successor no-op without claimed predecessor: %v", err)
	}
	if _, err := database.db.Exec(`UPDATE policy_requests SET terminal_audited=1
		WHERE principal='alice' AND request_id=?`, request); err != nil {
		t.Fatalf("audit successor no-op terminal: %v", err)
	}
	if _, err := database.db.Exec(`
		UPDATE policy_requests SET state='approved',terminal_response=x'7b7d',terminal_http_status=200,
		 resolved_at=10,reserved_bytes=0 WHERE principal='alice' AND request_id=?`, request); err != nil {
		t.Fatalf("publish successor no-op without claimed predecessor: %v", err)
	}
	var claimedCount int
	if err := database.db.QueryRow(`SELECT count(claimed_head_envelope) FROM policy_requests
		WHERE principal='alice' AND request_id=?`, request).Scan(&claimedCount); err != nil {
		t.Fatal(err)
	}
	if claimedCount != 0 {
		t.Fatalf("successor no-op fabricated %d claimed predecessors", claimedCount)
	}

	errorRequest := requestID("5")
	if err := insertAcceptedSuccessorReceived(database.db, "bob", errorRequest, reviewID("5"), "host-five"); err != nil {
		t.Fatalf("insert second accepted successor: %v", err)
	}
	if _, err := database.db.Exec(`
		UPDATE policy_requests SET state='no_op_unexposed',state_version=2,no_op=1,
		 result_envelope=x'7b7d',result_sha256=?,reserved_bytes=1000
		WHERE principal='bob' AND request_id=?`, hex64("8"), errorRequest); err != nil {
		t.Fatalf("stage successor no-op for error path: %v", err)
	}
	if _, err := database.db.Exec(`UPDATE policy_requests SET
		 recovery_lease_owner='worker',recovery_lease_until=100,recovery_lease_generation=1
		WHERE principal='bob' AND request_id=?`, errorRequest); err != nil {
		t.Fatalf("lease successor no-op: %v", err)
	}
	if _, err := database.db.Exec(`UPDATE policy_requests SET state='error_received',state_version=3,
		 error_family='publication-error',failure_code='stale_policy_head',reserved_bytes=500
		WHERE principal='bob' AND request_id=?`, errorRequest); err == nil {
		t.Fatal("staged no-op publication error before terminal audit")
	}
	if _, err := database.db.Exec(`UPDATE policy_requests SET terminal_audited=1
		WHERE principal='bob' AND request_id=?`, errorRequest); err != nil {
		t.Fatalf("audit successor no-op before publication-error race: %v", err)
	}
	if _, err := database.db.Exec(`UPDATE policy_requests SET state='error_received',state_version=3,
		 error_family='publication-error',failure_code='stale_policy_head',reserved_bytes=500
		WHERE principal='bob' AND request_id=?`, errorRequest); err != nil {
		t.Fatalf("stage leased successor no-op error without claimed predecessor: %v", err)
	}
	if _, err := database.db.Exec(`UPDATE policy_requests SET state='error',terminal_response=x'7b7d',
		 terminal_http_status=409,resolved_at=10,reserved_bytes=0,
		 recovery_lease_owner='',recovery_lease_until=0
		 WHERE principal='bob' AND request_id=?`, errorRequest); err != nil {
		t.Fatalf("publish successor no-op error: %v", err)
	}
	if _, err := database.db.Exec(policyTestCompactSQL,
		archiveID("a"), hex64("b"), hex64("c"), "bob", errorRequest); err != nil {
		t.Fatalf("compact successor no-op publication error: %v", err)
	}
	var errorStorage, errorResultDigest, errorLeaseOwner string
	var errorLeaseUntil, errorLeaseGeneration int64
	if err := database.db.QueryRow(`SELECT storage_kind,result_sha256,recovery_lease_owner,
		recovery_lease_until,recovery_lease_generation FROM policy_requests
		WHERE principal='bob' AND request_id=?`, errorRequest).
		Scan(&errorStorage, &errorResultDigest, &errorLeaseOwner, &errorLeaseUntil, &errorLeaseGeneration); err != nil {
		t.Fatal(err)
	}
	if errorStorage != "tombstone" || errorResultDigest != hex64("8") || errorLeaseOwner != "" ||
		errorLeaseUntil != 0 || errorLeaseGeneration != 1 {
		t.Fatalf("publication-error tombstone storage/digest/lease = %s/%s %q/%d/%d",
			errorStorage, errorResultDigest, errorLeaseOwner, errorLeaseUntil, errorLeaseGeneration)
	}
}

func TestMigration6ErrorPublicationPreservesStagedResult(t *testing.T) {
	database := openPolicyTestDB(t)
	if err := insertPolicyMeta(database.db, "requester"); err != nil {
		t.Fatal(err)
	}
	request := requestID("4")
	if err := insertAcceptedShape(database.db, "alice", request, reviewID("4"), "host-four", true, "received_unaudited", 1); err != nil {
		t.Fatalf("insert accepted intake row: %v", err)
	}
	if _, err := database.db.Exec(`
		UPDATE policy_requests SET state='error_received',state_version=2,
		 error_family='processing-error',failure_code='signer_key_changed',reserved_bytes=1000
		WHERE principal='alice' AND request_id=?`, request); err != nil {
		t.Fatalf("stage intake error: %v", err)
	}
	if _, err := database.db.Exec(`UPDATE policy_requests SET terminal_audited=1
		WHERE principal='alice' AND request_id=?`, request); err != nil {
		t.Fatalf("audit intake error terminal: %v", err)
	}
	_, err := database.db.Exec(`
		UPDATE policy_requests SET state='error',result_envelope=x'7b7d',result_sha256=?,
		 terminal_response=x'7b7d',terminal_http_status=409,resolved_at=10,reserved_bytes=0
		WHERE principal='alice' AND request_id=?`, hex64("8"), request)
	if err == nil {
		t.Fatal("error publication introduced a result envelope")
	}
	if !strings.Contains(err.Error(), "terminal publication changed staged result") {
		t.Fatalf("error publication mutation error = %v; want staged-result fence", err)
	}
	if _, err := database.db.Exec(`
		UPDATE policy_requests SET state='error',terminal_response=x'7b7d',terminal_http_status=409,
		 resolved_at=10,reserved_bytes=0 WHERE principal='alice' AND request_id=?`, request); err != nil {
		t.Fatalf("publish intake error without result mutation: %v", err)
	}
}

func openPolicyTestDB(t *testing.T) *DB {
	t.Helper()
	database, err := Open(filepath.Join(t.TempDir(), "policy.db"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = database.Close() })
	return database
}

func insertPolicyMeta(database *sql.DB, requester string) error {
	_, err := database.Exec(`
		INSERT INTO policy_authority_meta(
		 singleton,authority_id,accounting_version,archive_id,max_heads,max_requests,max_logical_bytes,
		 max_active_global,max_active_per_principal,max_votes_per_request,
		 max_rejection_reserved_bytes_per_principal,config_digest,requester_operator_id,
		 required_approvals,deny_veto,allow_self_approve,policy_voter_role,voter_eligibility_version,
		 vote_step_up_required,vote_auth_methods_json,review_renderer_version,review_rules_digest,
		 logical_used_bytes,logical_reserved_bytes,full_request_count,head_count,active_count,created_at)
		VALUES(1,?,'sshgate-policy-logical-bytes-v3',?,256,1024,268435456,256,64,256,
		 8388608,?,?,1,1,0,'operator','v1',0,'["session"]','sshgate-policy-review-v2',?,0,0,0,0,0,1)`,
		authorityID("a"), archiveID("a"), hex64("d"), requester, hex64("e"))
	return err
}

func insertAcceptedPending(database *sql.DB, principal, request, review, host string) error {
	return insertAcceptedShape(database, principal, request, review, host, true, "pending", 1)
}

func insertAcceptedSuccessorReceived(database *sql.DB, principal, request, review, host string) error {
	return insertAcceptedShape(database, principal, request, review, host, false, "received_unaudited", 1)
}

func insertAcceptedShape(database *sql.DB, principal, request, review, host string, bootstrap bool, state string, submissionAudited int) error {
	return insertAcceptedShapeWithChanges(database, principal, request, review, host, bootstrap, state, submissionAudited, 1)
}

func insertAcceptedShapeWithChanges(database *sql.DB, principal, request, review, host string, bootstrap bool, state string, submissionAudited, logicalChangeCount int) error {
	expectedHead := ""
	bootstrapValue := 1
	var trustedEnvelope, trustedDigest, trustedKeyID, trustedPublicKey, trustedEpoch, trustedRevision, trustedRowVersion any
	if !bootstrap {
		expectedHead = hex64("9")
		bootstrapValue = 0
		trustedEnvelope = []byte("trusted-envelope")
		trustedDigest = expectedHead
		trustedKeyID = hex64("a")
		trustedPublicKey = make([]byte, 32)
		trustedEpoch = []byte{0, 0, 0, 0, 0, 0, 0, 1}
		trustedRevision = []byte{0, 0, 0, 0, 0, 0, 0, 1}
		trustedRowVersion = int64(1)
	}
	_, err := database.Exec(`
		INSERT INTO policy_requests(
		 principal,request_id,review_id,authority_singleton,authority_id,storage_kind,purpose,
		 canonical_request,payload,tuple_digest,payload_sha256,base_digest,host_key_fp,
		 expected_head_digest,expected_signer_key_id,bootstrap,trusted_head_envelope,trusted_head_digest,
		 trusted_head_key_id,trusted_head_public_key,trusted_head_epoch_be,trusted_head_revision_be,
		 trusted_head_row_version,frozen_signer_key_id,frozen_signer_public_key,epoch_be,revision_be,
		 miss_action,growth,entry_count,revocation_count,logical_change_count,review_json,review_sha256,
		 review_rendered_bytes,review_item_count,review_renderer_version,review_rules_digest,
		 eligible_voters_json,eligible_voters_sha256,eligible_voter_count,vote_step_up_required,
		 vote_auth_methods_json,vote_auth_methods_sha256,required_approvals,deny_veto,allow_self_approve,
		 requester_principal,state,state_version,submission_audited,pending_response,reserved_bytes,
		 logical_bytes,created_at,updated_at)
		VALUES(?,?,?,1,?,'full','base_manifest_sign_v1',x'7b7d',x'7b7d',?,?,?,?,
		 ?,?,?,?,?,?,?,?,?,?,?,zeroblob(32),x'0000000000000001',x'0000000000000001',
		 'ask','sign-to-add',0,0,?,x'7b7d',?,2,?,'sshgate-policy-review-v2',?,
		 x'5b226f70657261746f72225d',?,1,0,x'5b2273657373696f6e225d',?,1,1,0,?,
		 ?,1,?,x'7b7d',100000,1024,1,1)`,
		principal, request, review, authorityID("a"), hex64("1"), hex64("2"), hex64("3"), host,
		expectedHead, hex64("a"), bootstrapValue, trustedEnvelope, trustedDigest, trustedKeyID,
		trustedPublicKey, trustedEpoch, trustedRevision, trustedRowVersion, hex64("a"), logicalChangeCount, hex64("4"),
		logicalChangeCount, hex64("5"), hex64("6"), hex64("7"), principal, state, submissionAudited)
	return err
}

func authorityID(character string) string { return "pauth_" + strings.Repeat(character, 32) }
func archiveID(character string) string   { return "parch_" + strings.Repeat(character, 32) }
func requestID(character string) string   { return "pm_" + strings.Repeat(character, 32) }
func reviewID(character string) string    { return "pr_" + strings.Repeat(character, 32) }
func hex64(character string) string       { return strings.Repeat(character, 64) }
