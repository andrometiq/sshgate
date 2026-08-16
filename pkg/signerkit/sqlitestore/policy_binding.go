package sqlitestore

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"reflect"
	"slices"
	"sort"
	"time"

	"github.com/karthikeyan5/sshgate/pkg/signerkit/policystore"
	"github.com/karthikeyan5/sshgate/src/policy"
	"github.com/karthikeyan5/sshgate/src/policyauthority"
	"github.com/karthikeyan5/sshgate/src/policyreview"
	"github.com/karthikeyan5/sshgate/src/policywire"
)

type policyDB struct {
	database *sql.DB
	fence    *policystore.Lease
}

// PolicyStore returns the policy-only adapter. It is intentionally a distinct
// value because *DB already implements the ordinary store with colliding
// method names and must never satisfy the policy interface.
func (database *DB) PolicyStore() policystore.Store {
	return &policyDB{database: database.db}
}

var _ policystore.Store = (*policyDB)(nil)

type policyMeta struct {
	AuthorityID                           string
	AccountingVersion                     string
	ArchiveID                             string
	MaxHeads                              uint64
	MaxRequests                           uint64
	MaxLogicalBytes                       uint64
	MaxActiveGlobal                       uint64
	MaxActivePerPrincipal                 uint64
	MaxVotesPerRequest                    uint64
	MaxRejectionReservedBytesPerPrincipal uint64
	ConfigDigest                          string
	RequesterOperatorID                   string
	RequiredApprovals                     uint64
	DenyVeto                              bool
	AllowSelfApprove                      bool
	PolicyVoterRole                       string
	VoterEligibilityVersion               string
	VoteStepUpRequired                    bool
	VoteAuthMethodsJSON                   []byte
	ReviewRendererVersion                 string
	ReviewRulesDigest                     string
	LogicalUsedBytes                      uint64
	LogicalReservedBytes                  uint64
	FullRequestCount                      uint64
	HeadCount                             uint64
	ActiveCount                           uint64
	CreatedAt                             int64
}

func (meta policyMeta) config() policystore.ConfigDigestInput {
	return policystore.ConfigDigestInput{
		RequesterOperatorID:                   meta.RequesterOperatorID,
		RequiredApprovals:                     meta.RequiredApprovals,
		DenyVeto:                              meta.DenyVeto,
		AllowSelfApprove:                      meta.AllowSelfApprove,
		PolicyVoterRole:                       meta.PolicyVoterRole,
		VoterEligibilityVersion:               meta.VoterEligibilityVersion,
		VoteStepUpRequired:                    meta.VoteStepUpRequired,
		VoteAuthMethodsJSON:                   slices.Clone(meta.VoteAuthMethodsJSON),
		MaxHeads:                              meta.MaxHeads,
		MaxRequests:                           meta.MaxRequests,
		MaxLogicalBytes:                       meta.MaxLogicalBytes,
		MaxActiveGlobal:                       meta.MaxActiveGlobal,
		MaxActivePerPrincipal:                 meta.MaxActivePerPrincipal,
		MaxVotesPerRequest:                    meta.MaxVotesPerRequest,
		MaxRejectionReservedBytesPerPrincipal: meta.MaxRejectionReservedBytesPerPrincipal,
		ArchiveID:                             meta.ArchiveID,
		ReviewRendererVersion:                 meta.ReviewRendererVersion,
		ReviewRulesDigest:                     meta.ReviewRulesDigest,
	}
}

func validateAuthorityBinding(binding policystore.AuthorityBinding) (policystore.AuthorityBinding, error) {
	if !policyauthority.ValidAuthorityID(binding.AuthorityID) {
		return binding, fmt.Errorf("%w: invalid authority ID", policystore.ErrAuthorityMismatch)
	}
	if binding.ArchiveID != binding.Config.ArchiveID || !policystore.ValidArchiveID(binding.ArchiveID) {
		return binding, fmt.Errorf("%w: invalid archive binding", policystore.ErrAuthorityMismatch)
	}
	if binding.AccountingVersion != policystore.AccountingVersion {
		return binding, fmt.Errorf("%w: accounting version %q", policystore.ErrAuthorityMismatch, binding.AccountingVersion)
	}
	if binding.MaxRejectionReservedBytesPerPrincipal != binding.Config.MaxRejectionReservedBytesPerPrincipal {
		return binding, fmt.Errorf("%w: rejection byte cap mismatch", policystore.ErrAuthorityMismatch)
	}
	if err := binding.Config.Validate(); err != nil {
		return binding, err
	}
	digest, err := policystore.ConfigDigest(binding.Config)
	if err != nil {
		return binding, err
	}
	if binding.ConfigDigest != digest {
		return binding, fmt.Errorf("%w: config digest mismatch", policystore.ErrAuthorityMismatch)
	}
	keyID, err := policy.SignerKeyID(binding.SignerPublicKey)
	if err != nil || keyID != binding.SignerKeyID {
		return binding, fmt.Errorf("%w: signer key ID mismatch", policystore.ErrAuthorityMismatch)
	}
	binding.SignerPublicKey = slices.Clone(binding.SignerPublicKey)
	return binding, nil
}

func (store *policyDB) BindAuthority(ctx context.Context, binding policystore.AuthorityBinding) error {
	binding, err := validateAuthorityBinding(binding)
	if err != nil {
		return err
	}
	_, err = withPolicyImmediate(ctx, store.database, func(transaction *sql.Tx) (struct{}, error) {
		if err := requirePolicyMigration(ctx, transaction); err != nil {
			return struct{}{}, err
		}
		if err := verifyPolicySchema(ctx, transaction); err != nil {
			return struct{}{}, err
		}
		if err := verifyPolicyRosterIdentities(ctx, transaction, binding.Config.PolicyVoterRole, binding.Config.VoteStepUpRequired); err != nil {
			return struct{}{}, err
		}
		meta, err := readPolicyMeta(ctx, transaction)
		switch {
		case errors.Is(err, policystore.ErrNotFound):
			config := binding.Config
			_, err = transaction.ExecContext(ctx, `INSERT INTO policy_authority_meta (`+policyColumnNames(policystore.MetaColumns[:])+`)
				VALUES (`+policyPlaceholders(policystore.MetaColumnCount)+`)`,
				int64(1), binding.AuthorityID, binding.AccountingVersion, binding.ArchiveID,
				int64(config.MaxHeads), int64(config.MaxRequests), int64(config.MaxLogicalBytes),
				int64(config.MaxActiveGlobal), int64(config.MaxActivePerPrincipal), int64(config.MaxVotesPerRequest),
				int64(config.MaxRejectionReservedBytesPerPrincipal), binding.ConfigDigest,
				config.RequesterOperatorID, int64(config.RequiredApprovals), boolInteger(config.DenyVeto),
				boolInteger(config.AllowSelfApprove), config.PolicyVoterRole, config.VoterEligibilityVersion,
				boolInteger(config.VoteStepUpRequired), string(config.VoteAuthMethodsJSON), config.ReviewRendererVersion,
				config.ReviewRulesDigest, int64(0), int64(0), int64(0), int64(0), int64(0), time.Now().UTC().Unix())
			if err != nil {
				return struct{}{}, fmt.Errorf("bind policy authority meta: %w", err)
			}
		case err != nil:
			return struct{}{}, err
		default:
			if err := meta.matchesBinding(binding); err != nil {
				return struct{}{}, err
			}
			if _, err := scanPolicyLedger(ctx, transaction, meta); err != nil {
				return struct{}{}, err
			}
		}
		if err := bindPolicyKey(ctx, transaction, binding); err != nil {
			return struct{}{}, err
		}
		return struct{}{}, nil
	})
	return err
}

func (store *policyDB) VerifyAuthorityBinding(ctx context.Context) (policystore.AuthorityBinding, error) {
	if err := requirePolicyMigration(ctx, store.database); err != nil {
		return policystore.AuthorityBinding{}, err
	}
	if err := verifyPolicySchema(ctx, store.database); err != nil {
		return policystore.AuthorityBinding{}, err
	}
	meta, err := readPolicyMeta(ctx, store.database)
	if err != nil {
		return policystore.AuthorityBinding{}, err
	}
	if err := validatePolicyMeta(meta); err != nil {
		return policystore.AuthorityBinding{}, err
	}
	if err := verifyPolicyKeyBindings(ctx, store.database, meta.AuthorityID, false); err != nil {
		return policystore.AuthorityBinding{}, err
	}
	if _, err := scanPolicyLedger(ctx, store.database, meta); err != nil {
		return policystore.AuthorityBinding{}, err
	}
	return policystore.AuthorityBinding{
		AuthorityID:                           meta.AuthorityID,
		ArchiveID:                             meta.ArchiveID,
		AccountingVersion:                     meta.AccountingVersion,
		ConfigDigest:                          meta.ConfigDigest,
		MaxRejectionReservedBytesPerPrincipal: meta.MaxRejectionReservedBytesPerPrincipal,
		Config:                                meta.config(),
	}, nil
}

// SafetyScan verifies the complete bounded policy ledger in one
// BEGIN IMMEDIATE snapshot and performs no mutation. Archive inspection stays
// inside that snapshot so readiness never relies on a resumable cursor or a
// synthesized snapshot-equivalence protocol.
func (store *policyDB) SafetyScan(ctx context.Context, inspectArchive func(*policystore.Request) error) error {
	_, err := withPolicyImmediate(ctx, store.database, func(transaction *sql.Tx) (struct{}, error) {
		if err := requirePolicyMigration(ctx, transaction); err != nil {
			return struct{}{}, err
		}
		if err := verifyPolicySchema(ctx, transaction); err != nil {
			return struct{}{}, err
		}
		meta, err := readPolicyMeta(ctx, transaction)
		if err != nil {
			return struct{}{}, err
		}
		if err := verifyPolicyRosterIdentities(ctx, transaction, meta.PolicyVoterRole, meta.VoteStepUpRequired); err != nil {
			return struct{}{}, err
		}
		if err := verifyPolicyKeyBindings(ctx, transaction, meta.AuthorityID, false); err != nil {
			return struct{}{}, err
		}
		if _, err := scanPolicyLedger(ctx, transaction, meta); err != nil {
			return struct{}{}, err
		}
		if inspectArchive == nil {
			var tombstones int
			if err := transaction.QueryRowContext(ctx, "SELECT count(*) FROM policy_requests WHERE storage_kind='tombstone'").Scan(&tombstones); err != nil {
				return struct{}{}, err
			}
			if tombstones != 0 {
				return struct{}{}, errors.New("policy safety scan: archive inspector is required for tombstones")
			}
			return struct{}{}, nil
		}
		// A nil request is the once-per-snapshot root/binding/shard hook.
		if err := inspectArchive(nil); err != nil {
			return struct{}{}, fmt.Errorf("policy safety scan: inspect archive root: %w", err)
		}
		rows, err := transaction.QueryContext(ctx, `SELECT `+policyColumnNames(policystore.RequestColumns[:])+` FROM policy_requests WHERE storage_kind='tombstone' ORDER BY principal,request_id`)
		if err != nil {
			return struct{}{}, err
		}
		defer rows.Close()
		for rows.Next() {
			fields, err := scanPolicyFields(rows, policystore.RequestColumns[:])
			if err != nil {
				return struct{}{}, err
			}
			request, err := policystore.RequestFromFields(fields)
			if err != nil {
				return struct{}{}, err
			}
			if err := inspectArchive(&request); err != nil {
				return struct{}{}, fmt.Errorf("policy safety scan: inspect archive %s/%s: %w", request.Principal, request.RequestID, err)
			}
		}
		return struct{}{}, rows.Err()
	})
	return err
}

var _ policystore.SafetyScanner = (*policyDB)(nil)

func verifyPolicyRosterIdentities(ctx context.Context, queryer policyQueryer, role string, stepUp bool) error {
	query := `SELECT u.id FROM users u WHERE u.role=? AND EXISTS
		(SELECT 1 FROM totp_secrets t WHERE t.user_id=u.id) ORDER BY u.id`
	if !stepUp {
		query = `SELECT u.id FROM users u WHERE u.role=? AND
		(EXISTS (SELECT 1 FROM totp_secrets t WHERE t.user_id=u.id) OR
		 EXISTS (SELECT 1 FROM webauthn_credentials w WHERE w.user_id=u.id))
		ORDER BY u.id`
	}
	rows, err := queryer.QueryContext(ctx, query, role)
	if err != nil {
		return fmt.Errorf("read policy voter roster: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var identity string
		if err := rows.Scan(&identity); err != nil {
			return fmt.Errorf("scan policy voter roster: %w", err)
		}
		if err := policystore.ValidateIdentity(identity); err != nil {
			return fmt.Errorf("%w: policy voter roster identity: %v", policystore.ErrCorrupt, err)
		}
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("iterate policy voter roster: %w", err)
	}
	return nil
}

func requirePolicyMigration(ctx context.Context, queryer policyQueryer) error {
	var name string
	err := queryer.QueryRowContext(ctx, `SELECT name FROM schema_migrations WHERE version=6`).Scan(&name)
	if errors.Is(err, sql.ErrNoRows) || stringsContainsMissingTable(err) {
		return errors.New("policy store: migration 6 is not installed")
	}
	if err != nil {
		return fmt.Errorf("verify policy migration: %w", err)
	}
	for _, migration := range migrations {
		if migration.Version == 6 {
			if name != migration.Name {
				return fmt.Errorf("policy store: migration 6 name %q; want %q", name, migration.Name)
			}
			return nil
		}
	}
	return errors.New("policy store: implementation has no migration 6")
}

func stringsContainsMissingTable(err error) bool {
	return err != nil && (bytes.Contains([]byte(err.Error()), []byte("no such table")) || bytes.Contains([]byte(err.Error()), []byte("does not exist")))
}

func readPolicyMeta(ctx context.Context, queryer policyQueryer) (policyMeta, error) {
	var meta policyMeta
	var singleton int64
	var maxHeads, maxRequests, maxLogical, maxActiveGlobal, maxActivePrincipal, maxVotes, maxRejection int64
	var required, deny, self, stepUp int64
	var used, reserved, full, heads, active int64
	var methods string
	err := queryer.QueryRowContext(ctx, `SELECT `+policyColumnNames(policystore.MetaColumns[:])+` FROM policy_authority_meta WHERE singleton=1`).Scan(
		&singleton, &meta.AuthorityID, &meta.AccountingVersion, &meta.ArchiveID,
		&maxHeads, &maxRequests, &maxLogical, &maxActiveGlobal, &maxActivePrincipal, &maxVotes, &maxRejection,
		&meta.ConfigDigest, &meta.RequesterOperatorID, &required, &deny, &self,
		&meta.PolicyVoterRole, &meta.VoterEligibilityVersion, &stepUp, &methods,
		&meta.ReviewRendererVersion, &meta.ReviewRulesDigest, &used, &reserved, &full, &heads, &active, &meta.CreatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return meta, policystore.ErrNotFound
	}
	if err != nil {
		return meta, fmt.Errorf("read policy authority meta: %w", err)
	}
	if singleton != 1 {
		return meta, fmt.Errorf("%w: authority singleton=%d", policystore.ErrCorrupt, singleton)
	}
	numbers := []struct {
		name   string
		input  int64
		output *uint64
	}{
		{"max_heads", maxHeads, &meta.MaxHeads}, {"max_requests", maxRequests, &meta.MaxRequests},
		{"max_logical_bytes", maxLogical, &meta.MaxLogicalBytes}, {"max_active_global", maxActiveGlobal, &meta.MaxActiveGlobal},
		{"max_active_per_principal", maxActivePrincipal, &meta.MaxActivePerPrincipal}, {"max_votes_per_request", maxVotes, &meta.MaxVotesPerRequest},
		{"max_rejection_reserved_bytes_per_principal", maxRejection, &meta.MaxRejectionReservedBytesPerPrincipal},
		{"required_approvals", required, &meta.RequiredApprovals}, {"logical_used_bytes", used, &meta.LogicalUsedBytes},
		{"logical_reserved_bytes", reserved, &meta.LogicalReservedBytes}, {"full_request_count", full, &meta.FullRequestCount},
		{"head_count", heads, &meta.HeadCount}, {"active_count", active, &meta.ActiveCount},
	}
	for _, number := range numbers {
		if number.input < 0 {
			return meta, fmt.Errorf("%w: negative meta %s", policystore.ErrCorrupt, number.name)
		}
		*number.output = uint64(number.input)
	}
	if (deny != 0 && deny != 1) || (self != 0 && self != 1) || (stepUp != 0 && stepUp != 1) {
		return meta, fmt.Errorf("%w: non-boolean policy meta", policystore.ErrCorrupt)
	}
	meta.DenyVeto, meta.AllowSelfApprove, meta.VoteStepUpRequired = deny == 1, self == 1, stepUp == 1
	meta.VoteAuthMethodsJSON = []byte(methods)
	return meta, nil
}

func validatePolicyMeta(meta policyMeta) error {
	if !policyauthority.ValidAuthorityID(meta.AuthorityID) || meta.AccountingVersion != policystore.AccountingVersion {
		return fmt.Errorf("%w: authority/accounting binding", policystore.ErrAuthorityMismatch)
	}
	config := meta.config()
	if err := config.Validate(); err != nil {
		return err
	}
	digest, err := policystore.ConfigDigest(config)
	if err != nil {
		return err
	}
	if digest != meta.ConfigDigest {
		return fmt.Errorf("%w: persisted config digest", policystore.ErrAuthorityMismatch)
	}
	return nil
}

func (meta policyMeta) matchesBinding(binding policystore.AuthorityBinding) error {
	if err := validatePolicyMeta(meta); err != nil {
		return err
	}
	want := binding.Config
	if meta.AuthorityID != binding.AuthorityID || meta.ArchiveID != binding.ArchiveID ||
		meta.AccountingVersion != binding.AccountingVersion || meta.ConfigDigest != binding.ConfigDigest ||
		!reflect.DeepEqual(meta.config(), want) {
		return fmt.Errorf("%w: persisted authority/config differs", policystore.ErrAuthorityMismatch)
	}
	return nil
}

func bindPolicyKey(ctx context.Context, transaction *sql.Tx, binding policystore.AuthorityBinding) error {
	if err := verifyPolicyKeyBindings(ctx, transaction, binding.AuthorityID, true); err != nil {
		return err
	}
	var existingID, existingAuthority string
	var existingPublic []byte
	err := transaction.QueryRowContext(ctx, `SELECT signer_key_id,signer_public_key,authority_id
		FROM policy_authority_key_bindings WHERE signer_key_id=? OR signer_public_key=?`,
		binding.SignerKeyID, []byte(binding.SignerPublicKey)).Scan(&existingID, &existingPublic, &existingAuthority)
	switch {
	case err == nil:
		if existingID != binding.SignerKeyID || !bytes.Equal(existingPublic, binding.SignerPublicKey) || existingAuthority != binding.AuthorityID {
			return fmt.Errorf("%w: signer key is already bound to another authority", policystore.ErrAuthorityMismatch)
		}
		return nil
	case !errors.Is(err, sql.ErrNoRows):
		return fmt.Errorf("query policy key binding: %w", err)
	}
	var count int64
	if err := transaction.QueryRowContext(ctx, `SELECT COUNT(*) FROM policy_authority_key_bindings`).Scan(&count); err != nil {
		return fmt.Errorf("count policy key bindings: %w", err)
	}
	if count >= policystore.MaxVotesPerRequest {
		return fmt.Errorf("%w: policy key-binding ledger full", policystore.ErrCapacity)
	}
	if _, err := transaction.ExecContext(ctx, `INSERT INTO policy_authority_key_bindings
		(signer_key_id,signer_public_key,authority_id,created_at) VALUES (?,?,?,?)`,
		binding.SignerKeyID, []byte(binding.SignerPublicKey), binding.AuthorityID, time.Now().UTC().Unix()); err != nil {
		return fmt.Errorf("insert policy key binding: %w", err)
	}
	return nil
}

func verifyPolicyKeyBindings(ctx context.Context, queryer policyQueryer, authorityID string, allowEmpty bool) error {
	rows, err := queryer.QueryContext(ctx, `SELECT signer_key_id,signer_public_key,authority_id FROM policy_authority_key_bindings ORDER BY signer_key_id`)
	if err != nil {
		return fmt.Errorf("read policy key bindings: %w", err)
	}
	defer rows.Close()
	count := 0
	for rows.Next() {
		var keyID, boundAuthority string
		var publicKey []byte
		if err := rows.Scan(&keyID, &publicKey, &boundAuthority); err != nil {
			return fmt.Errorf("scan policy key binding: %w", err)
		}
		derived, deriveErr := policy.SignerKeyID(ed25519.PublicKey(publicKey))
		if deriveErr != nil || derived != keyID || boundAuthority != authorityID {
			return fmt.Errorf("%w: invalid policy key binding", policystore.ErrCorrupt)
		}
		count++
		if count > policystore.MaxVotesPerRequest {
			return fmt.Errorf("%w: policy key-binding ledger exceeds 256", policystore.ErrCorrupt)
		}
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("iterate policy key bindings: %w", err)
	}
	if count == 0 && !allowEmpty {
		return fmt.Errorf("%w: no policy key binding", policystore.ErrAuthorityMismatch)
	}
	return nil
}

type policyCounters struct {
	Used, Reserved, Full, Heads, Active uint64
}

func (counters policyCounters) check(meta policyMeta) error {
	checks := []struct {
		name               string
		stored, recomputed uint64
	}{
		{"logical_used_bytes", meta.LogicalUsedBytes, counters.Used},
		{"logical_reserved_bytes", meta.LogicalReservedBytes, counters.Reserved},
		{"full_request_count", meta.FullRequestCount, counters.Full},
		{"head_count", meta.HeadCount, counters.Heads},
		{"active_count", meta.ActiveCount, counters.Active},
	}
	for _, check := range checks {
		if check.stored != check.recomputed {
			return &policystore.CounterDriftError{Counter: check.name, Stored: check.stored, Recomputed: check.recomputed}
		}
	}
	return nil
}

func scanPolicyLedger(ctx context.Context, queryer policyQueryer, meta policyMeta) (policyCounters, error) {
	return scanPolicyLedgerMode(ctx, queryer, meta, true)
}

func recomputePolicyLedger(ctx context.Context, queryer policyQueryer, meta policyMeta) (policyCounters, error) {
	return scanPolicyLedgerMode(ctx, queryer, meta, false)
}

func scanPolicyLedgerMode(ctx context.Context, queryer policyQueryer, meta policyMeta, enforceStoredCounters bool) (policyCounters, error) {
	if err := validatePolicyMeta(meta); err != nil {
		return policyCounters{}, err
	}
	var counters policyCounters
	activeByPrincipal := make(map[string]uint64)
	rejectionRows := make(map[string]uint64)
	rejectionBytes := make(map[string]uint64)
	recentRejections := make(map[string][]int64)
	requests := make(map[policystore.Key]*policystore.Request)

	rows, err := queryer.QueryContext(ctx, `SELECT `+policyColumnNames(policystore.RequestColumns[:])+` FROM policy_requests ORDER BY principal,request_id`)
	if err != nil {
		return counters, fmt.Errorf("scan policy requests: %w", err)
	}
	for rows.Next() {
		fields, err := scanPolicyFields(rows, policystore.RequestColumns[:])
		if err != nil {
			rows.Close()
			return counters, err
		}
		request, err := policystore.RequestFromFields(fields)
		if err != nil {
			rows.Close()
			return counters, err
		}
		if err := validatePolicyRequestRecord(&request, meta); err != nil {
			rows.Close()
			return counters, err
		}
		if err := verifyRequestPolicyKeys(ctx, queryer, &request, meta.AuthorityID); err != nil {
			rows.Close()
			return counters, err
		}
		charge, err := policystore.RequestLogicalCharge(fields)
		if err != nil {
			rows.Close()
			return counters, err
		}
		if request.LogicalBytes != charge {
			rows.Close()
			return counters, fmt.Errorf("%w: request logical_bytes=%d recomputed=%d", policystore.ErrCorrupt, request.LogicalBytes, charge)
		}
		if err := addCounter(&counters.Used, charge); err != nil {
			rows.Close()
			return counters, err
		}
		if err := addCounter(&counters.Reserved, request.ReservedBytes); err != nil {
			rows.Close()
			return counters, err
		}
		if request.StorageKind == policystore.StorageFull {
			counters.Full++
		}
		if request.StorageKind == policystore.StorageFull && request.State.Active() {
			counters.Active++
			activeByPrincipal[request.Principal]++
		}
		if isMatrix2A(request) {
			rejectionRows[request.Principal]++
			if err := addCounterMap(rejectionBytes, request.Principal, rejectionFloor(&request)); err != nil {
				rows.Close()
				return counters, err
			}
			if request.CreatedAt > time.Now().UTC().Unix()-policystore.RejectionWindowSeconds {
				recentRejections[request.Principal] = append(recentRejections[request.Principal], request.CreatedAt)
			}
		}
		requestCopy := request
		requests[request.Key()] = &requestCopy
	}
	if err := rows.Close(); err != nil {
		return counters, err
	}

	voteRows, err := queryer.QueryContext(ctx, `SELECT `+policyColumnNames(policystore.VoteColumns[:])+` FROM policy_votes ORDER BY principal,request_id,operator`)
	if err != nil {
		return counters, fmt.Errorf("scan policy votes: %w", err)
	}
	votesPerRequest := make(map[policystore.Key]uint64)
	for voteRows.Next() {
		fields, err := scanPolicyFields(voteRows, policystore.VoteColumns[:])
		if err != nil {
			voteRows.Close()
			return counters, err
		}
		vote, err := policystore.VoteFromFields(fields)
		if err != nil {
			voteRows.Close()
			return counters, err
		}
		request := requests[vote.Key()]
		if err := validatePolicyVoteRecord(&vote, request); err != nil {
			voteRows.Close()
			return counters, err
		}
		charge, err := policystore.VoteLogicalCharge(fields)
		if err != nil {
			voteRows.Close()
			return counters, err
		}
		if vote.LogicalBytes != charge {
			voteRows.Close()
			return counters, fmt.Errorf("%w: vote logical_bytes=%d recomputed=%d", policystore.ErrCorrupt, vote.LogicalBytes, charge)
		}
		if err := addCounter(&counters.Used, charge); err != nil {
			voteRows.Close()
			return counters, err
		}
		votesPerRequest[vote.Key()]++
		if votesPerRequest[vote.Key()] > policystore.MaxVotesPerRequest {
			voteRows.Close()
			return counters, fmt.Errorf("%w: more than 256 votes", policystore.ErrCorrupt)
		}
	}
	if err := voteRows.Close(); err != nil {
		return counters, err
	}
	for _, request := range requests {
		remaining, err := expectedRequestRemaining(ctx, queryer, request)
		if err != nil {
			return counters, err
		}
		if request.ReservedBytes != remaining {
			return counters, fmt.Errorf("%w: request %s/%s reserved_bytes=%d recomputed=%d",
				policystore.ErrCorrupt, request.Principal, request.RequestID, request.ReservedBytes, remaining)
		}
	}

	headRows, err := queryer.QueryContext(ctx, `SELECT `+policyColumnNames(policystore.HeadColumns[:])+` FROM policy_heads ORDER BY authority_id,host_key_fp`)
	if err != nil {
		return counters, fmt.Errorf("scan policy heads: %w", err)
	}
	for headRows.Next() {
		fields, err := scanPolicyFields(headRows, policystore.HeadColumns[:])
		if err != nil {
			headRows.Close()
			return counters, err
		}
		head, err := policystore.HeadFromFields(fields)
		if err != nil {
			headRows.Close()
			return counters, err
		}
		if err := validatePolicyHeadRecord(&head, meta.AuthorityID); err != nil {
			headRows.Close()
			return counters, err
		}
		if err := requireBoundPolicyKey(ctx, queryer, head.SignerKeyID, head.SignerPublicKey, meta.AuthorityID); err != nil {
			headRows.Close()
			return counters, err
		}
		charge, err := policystore.HeadLogicalCharge(fields)
		if err != nil {
			headRows.Close()
			return counters, err
		}
		if head.LogicalBytes != charge {
			headRows.Close()
			return counters, fmt.Errorf("%w: head logical_bytes=%d recomputed=%d", policystore.ErrCorrupt, head.LogicalBytes, charge)
		}
		if err := addCounter(&counters.Used, charge); err != nil {
			headRows.Close()
			return counters, err
		}
		counters.Heads++
	}
	if err := headRows.Close(); err != nil {
		return counters, err
	}

	if counters.Full > meta.MaxRequests || counters.Heads > meta.MaxHeads || counters.Active > meta.MaxActiveGlobal || counters.Used > meta.MaxLogicalBytes || counters.Reserved > meta.MaxLogicalBytes-counters.Used {
		return counters, fmt.Errorf("%w: policy ledger exceeds bound", policystore.ErrCorrupt)
	}
	for principal, count := range activeByPrincipal {
		if count > meta.MaxActivePerPrincipal {
			return counters, fmt.Errorf("%w: principal %q active count %d", policystore.ErrCorrupt, principal, count)
		}
	}
	for principal, count := range rejectionRows {
		if count > policystore.RejectionRetainedRowLimit {
			return counters, fmt.Errorf("%w: principal %q rejection rows %d", policystore.ErrCorrupt, principal, count)
		}
	}
	for principal, count := range recentRejections {
		if len(count) > policystore.RejectionWindowLimit {
			return counters, fmt.Errorf("%w: principal %q rejection window %d", policystore.ErrCorrupt, principal, len(count))
		}
	}
	for principal, count := range rejectionBytes {
		if count > meta.MaxRejectionReservedBytesPerPrincipal {
			return counters, fmt.Errorf("%w: principal %q rejection bytes %d", policystore.ErrCorrupt, principal, count)
		}
	}
	if enforceStoredCounters {
		if err := counters.check(meta); err != nil {
			return counters, err
		}
	}
	return counters, nil
}

func validatePolicyRequestRecord(request *policystore.Request, meta policyMeta) error {
	if request == nil || request.AuthoritySingleton != 1 || request.AuthorityID != meta.AuthorityID || request.CompactionDeleteGuard {
		return fmt.Errorf("%w: invalid policy request binding", policystore.ErrCorrupt)
	}
	if err := policystore.ValidateIdentity(request.Principal); err != nil {
		return fmt.Errorf("%w: %v", policystore.ErrCorrupt, err)
	}
	if err := policystore.ValidateIdentity(request.RequesterPrincipal); err != nil {
		return fmt.Errorf("%w: %v", policystore.ErrCorrupt, err)
	}
	if !request.State.Valid() || (request.StorageKind != policystore.StorageFull && request.StorageKind != policystore.StorageTombstone) || request.StateVersion == 0 {
		return fmt.Errorf("%w: invalid request state/storage", policystore.ErrCorrupt)
	}
	if err := validatePolicyKey(request.Key()); err != nil || len(request.ReviewID) != 35 || request.ReviewID[:3] != "pr_" || !lowerHex(request.ReviewID[3:]) {
		return fmt.Errorf("%w: invalid request/review ID", policystore.ErrCorrupt)
	}
	if request.Purpose != policywire.Purpose || request.CreatedAt > request.UpdatedAt || request.StateVersion > math.MaxInt64 ||
		request.RecoveryLeaseGeneration > math.MaxInt64 {
		return fmt.Errorf("%w: invalid request chronology or version", policystore.ErrCorrupt)
	}
	if request.StorageKind == policystore.StorageTombstone && (!request.State.Terminal() || request.ArchiveRef() == nil) {
		return fmt.Errorf("%w: invalid tombstone", policystore.ErrCorrupt)
	}
	if request.State.Terminal() && request.ReservedBytes != rejectionFloor(request) {
		return fmt.Errorf("%w: terminal reservation is %d; floor is %d", policystore.ErrCorrupt, request.ReservedBytes, rejectionFloor(request))
	}
	if request.StorageKind == policystore.StorageTombstone {
		if err := request.ArchiveRef().Validate(); err != nil {
			return fmt.Errorf("%w: %v", policystore.ErrCorrupt, err)
		}
		if request.ArchiveID.Value != meta.ArchiveID {
			return fmt.Errorf("%w: tombstone archive namespace", policystore.ErrCorrupt)
		}
		return validatePolicyTombstoneRecord(request, meta)
	}
	decoded, err := policywire.DecodeRequest(request.CanonicalRequest)
	if err != nil || !bytes.Equal(decoded.Payload, request.Payload) {
		return fmt.Errorf("%w: canonical policy request", policystore.ErrCorrupt)
	}
	payloadSHA, baseDigest, err := policywire.PayloadDigests(request.Payload)
	if err != nil || payloadSHA != request.PayloadSHA256 || baseDigest != request.BaseDigest {
		return fmt.Errorf("%w: request payload digests", policystore.ErrCorrupt)
	}
	tuple := policyauthority.RequestTuple{RequestID: decoded.Wire.RequestID, Purpose: policywire.Purpose,
		HostKeyFP: decoded.Wire.HostKeyFP, ExpectedSignerKeyID: decoded.Wire.ExpectedSignerKeyID,
		PayloadSHA256: payloadSHA, ExpectedHeadDigest: decoded.Wire.ExpectedHeadDigest, Bootstrap: decoded.Wire.Bootstrap}
	if !policyTupleMatches(request, tuple) {
		return fmt.Errorf("%w: request tuple", policystore.ErrCorrupt)
	}
	manifest := decoded.Manifest
	if !bytes.Equal(request.EpochBE, uint64BigEndian(manifest.Epoch)) || !bytes.Equal(request.RevisionBE, uint64BigEndian(manifest.Revision)) ||
		request.MissAction != string(manifest.MissAction) || request.Growth != string(manifest.Growth) ||
		request.EntryCount != int64(len(manifest.Entries)) || request.RevocationCount != int64(len(manifest.RevokedPermitIDs)) {
		return fmt.Errorf("%w: request manifest projection", policystore.ErrCorrupt)
	}
	if err := validatePolicyPredecessors(request); err != nil {
		return err
	}
	var trustedManifest *policy.BaseManifest
	if !request.Bootstrap {
		verified, verifyErr := policy.VerifyBaseManifest(request.TrustedHeadEnvelope, ed25519.PublicKey(request.TrustedHeadPublicKey))
		if verifyErr != nil {
			return fmt.Errorf("%w: trusted review predecessor", policystore.ErrCorrupt)
		}
		trustedManifest = &verified
	}
	if request.NoOp {
		if request.LogicalChangeCount != 0 || request.Bootstrap || request.TrustedHeadEnvelope == nil {
			return fmt.Errorf("%w: no-op change count", policystore.ErrCorrupt)
		}
	} else if changes, changesErr := policyreview.Changes(trustedManifest, manifest); changesErr == nil {
		if request.LogicalChangeCount != int64(changes.LogicalChanges) {
			return fmt.Errorf("%w: logical change count", policystore.ErrCorrupt)
		}
	} else if !isMatrix2A(*request) {
		return fmt.Errorf("%w: admitted review changes: %v", policystore.ErrCorrupt, changesErr)
	}
	if request.FrozenSignerKeyID.Valid || request.FrozenSignerPublicKey != nil {
		if !request.FrozenSignerKeyID.Valid || len(request.FrozenSignerPublicKey) != ed25519.PublicKeySize {
			return fmt.Errorf("%w: partial frozen signer pair", policystore.ErrCorrupt)
		}
		derived, err := policy.SignerKeyID(ed25519.PublicKey(request.FrozenSignerPublicKey))
		if err != nil || derived != request.FrozenSignerKeyID.Value {
			return fmt.Errorf("%w: frozen signer key mismatch", policystore.ErrCorrupt)
		}
	}
	accepted := !isMatrix2A(*request)
	if accepted && (!request.FrozenSignerKeyID.Valid || request.FrozenSignerKeyID.Value != request.ExpectedSignerKeyID) {
		return fmt.Errorf("%w: accepted request signer snapshot", policystore.ErrCorrupt)
	}
	if accepted {
		if err := validatePolicyReviewRecord(request, meta); err != nil {
			return err
		}
		if request.PendingResponse == nil {
			return fmt.Errorf("%w: accepted request lacks pending response", policystore.ErrCorrupt)
		}
		if request.EligibleVotersJSON == nil || !request.EligibleVotersSHA256.Valid || !request.EligibleVoterCount.Valid {
			return fmt.Errorf("%w: accepted request lacks frozen electorate", policystore.ErrCorrupt)
		}
		pending, err := policywire.DecodeResponse(request.PendingResponse)
		if err != nil || pending.Wire.Status != policywire.StatusPending || !policyResponseMatchesRequest(pending, request) {
			return fmt.Errorf("%w: pending response", policystore.ErrCorrupt)
		}
	} else if request.ReviewJSON != nil {
		if err := validatePolicyReviewRecord(request, meta); err != nil {
			return err
		}
	}
	if request.EligibleVotersJSON != nil {
		var voters []string
		if err := json.Unmarshal(request.EligibleVotersJSON, &voters); err != nil {
			return fmt.Errorf("%w: eligible voters: %v", policystore.ErrCorrupt, err)
		}
		canonical, _ := json.Marshal(voters)
		if !bytes.Equal(canonical, request.EligibleVotersJSON) || !sort.StringsAreSorted(voters) {
			return fmt.Errorf("%w: noncanonical eligible voters", policystore.ErrCorrupt)
		}
		for index := range voters {
			if index > 0 && voters[index] == voters[index-1] {
				return fmt.Errorf("%w: duplicate eligible voter", policystore.ErrCorrupt)
			}
		}
		if err := policystore.ValidateIdentities(voters); err != nil {
			return fmt.Errorf("%w: %v", policystore.ErrCorrupt, err)
		}
		if !request.EligibleVoterCount.Valid || int64(len(voters)) != request.EligibleVoterCount.Value {
			return fmt.Errorf("%w: eligible voter count", policystore.ErrCorrupt)
		}
		digest := sha256.Sum256(request.EligibleVotersJSON)
		if !request.EligibleVotersSHA256.Valid || hex.EncodeToString(digest[:]) != request.EligibleVotersSHA256.Value {
			return fmt.Errorf("%w: eligible voter digest", policystore.ErrCorrupt)
		}
	}
	if err := validateFrozenPolicyConfig(request, meta); err != nil {
		return err
	}
	if request.ResultEnvelope != nil {
		if digestBytes(request.ResultEnvelope) != request.ResultSHA256 || !request.FrozenSignerKeyID.Valid {
			return fmt.Errorf("%w: result digest", policystore.ErrCorrupt)
		}
		resultPayload, _, err := policy.DecodeBaseManifestEnvelope(request.ResultEnvelope)
		if err != nil || !bytes.Equal(resultPayload, request.Payload) {
			return fmt.Errorf("%w: result payload", policystore.ErrCorrupt)
		}
		if _, err := policy.VerifyBaseManifest(request.ResultEnvelope, ed25519.PublicKey(request.FrozenSignerPublicKey)); err != nil {
			return fmt.Errorf("%w: result signature", policystore.ErrCorrupt)
		}
	}
	if err := validateStoredPolicyFailure(request); err != nil {
		return err
	}
	if request.State.Terminal() {
		terminal, err := policywire.DecodeResponse(request.TerminalResponse)
		if err != nil || !policyResponseMatchesRequest(terminal, request) {
			return fmt.Errorf("%w: terminal response", policystore.ErrCorrupt)
		}
		wantStatus := policywire.StatusError
		wantHTTP := int64(0)
		switch request.State {
		case policystore.StateApproved:
			wantStatus, wantHTTP = policywire.StatusApproved, 200
			if !bytes.Equal(terminal.ManifestEnvelope, request.ResultEnvelope) {
				return fmt.Errorf("%w: terminal approval result", policystore.ErrCorrupt)
			}
		case policystore.StateDenied:
			wantStatus, wantHTTP = policywire.StatusDenied, 200
		case policystore.StateError:
			mappedHTTP, mapErr := policystore.HTTPStatusForError(request.FailureCode)
			wantHTTP, err = int64(mappedHTTP), mapErr
			if err != nil || terminal.Wire.ErrorCode != request.FailureCode {
				return fmt.Errorf("%w: terminal error mapping", policystore.ErrCorrupt)
			}
		}
		if terminal.Wire.Status != wantStatus || !request.TerminalHTTPStatus.Valid || request.TerminalHTTPStatus.Value != wantHTTP ||
			!request.ResolvedAt.Valid || request.ResolvedAt.Value > request.UpdatedAt {
			return fmt.Errorf("%w: terminal status", policystore.ErrCorrupt)
		}
	}
	return nil
}

func validatePolicyPredecessors(request *policystore.Request) error {
	trusted, err := trustedHeadFromRequest(request)
	if request.Bootstrap {
		trustedPresent := request.TrustedHeadEnvelope != nil || request.TrustedHeadDigest.Valid || request.TrustedHeadKeyID.Valid ||
			request.TrustedHeadPublicKey != nil || request.TrustedHeadEpochBE != nil || request.TrustedHeadRevisionBE != nil || request.TrustedHeadRowVersion.Valid
		claimedPresent := request.ClaimedHeadEnvelope != nil || request.ClaimedHeadDigest.Valid || request.ClaimedHeadKeyID.Valid ||
			request.ClaimedHeadPublicKey != nil || request.ClaimedHeadEpochBE != nil || request.ClaimedHeadRevisionBE != nil || request.ClaimedHeadRowVersion.Valid
		if err != nil || trusted != nil || trustedPresent || request.ExpectedHeadDigest != "" || claimedPresent {
			return fmt.Errorf("%w: bootstrap predecessor", policystore.ErrCorrupt)
		}
		return nil
	}
	if err != nil || trusted == nil || trusted.BaseDigest != request.ExpectedHeadDigest {
		return fmt.Errorf("%w: trusted predecessor", policystore.ErrCorrupt)
	}
	if err := validatePolicyHeadRecord(trusted, request.AuthorityID); err != nil {
		return err
	}
	claimedPresent := request.ClaimedHeadEnvelope != nil || request.ClaimedHeadDigest.Valid || request.ClaimedHeadKeyID.Valid ||
		request.ClaimedHeadPublicKey != nil || request.ClaimedHeadEpochBE != nil || request.ClaimedHeadRevisionBE != nil || request.ClaimedHeadRowVersion.Valid
	if claimedPresent {
		if !request.ClaimedHeadDigest.Valid || !request.ClaimedHeadKeyID.Valid || !request.ClaimedHeadRowVersion.Valid ||
			!headMatchesTrusted(request, &policystore.Head{ManifestEnvelope: request.ClaimedHeadEnvelope,
				BaseDigest: request.ClaimedHeadDigest.Value, SignerKeyID: request.ClaimedHeadKeyID.Value,
				SignerPublicKey: request.ClaimedHeadPublicKey, EpochBE: request.ClaimedHeadEpochBE,
				RevisionBE: request.ClaimedHeadRevisionBE, RowVersion: uint64(request.ClaimedHeadRowVersion.Value)}) {
			return fmt.Errorf("%w: claimed predecessor", policystore.ErrCorrupt)
		}
	}
	return nil
}

func validatePolicyTombstoneRecord(request *policystore.Request, meta policyMeta) error {
	if err := validateFrozenPolicyConfig(request, meta); err != nil {
		return err
	}
	if err := validateStoredPolicyFailure(request); err != nil {
		return err
	}
	if !request.TerminalHTTPStatus.Valid || !request.ResolvedAt.Valid || request.ResolvedAt.Value > request.UpdatedAt ||
		len(request.EpochBE) != 8 || len(request.RevisionBE) != 8 {
		return fmt.Errorf("%w: tombstone terminal metadata", policystore.ErrCorrupt)
	}
	switch request.State {
	case policystore.StateApproved:
		if request.ErrorFamily != policystore.ErrorFamilyNone || request.ResultSHA256 == "" || request.TerminalHTTPStatus.Value != 200 ||
			(request.NoOp && !request.TerminalAudited) || (!request.NoOp && (!request.PreMintAudited || !request.ResultAudited)) {
			return fmt.Errorf("%w: approved tombstone", policystore.ErrCorrupt)
		}
	case policystore.StateDenied:
		if request.ErrorFamily != policystore.ErrorFamilyNone || request.ResultSHA256 != "" || !request.TerminalAudited || request.TerminalHTTPStatus.Value != 200 {
			return fmt.Errorf("%w: denied tombstone", policystore.ErrCorrupt)
		}
	case policystore.StateError:
		status, err := policystore.HTTPStatusForError(request.FailureCode)
		if err != nil || int64(status) != request.TerminalHTTPStatus.Value || !request.TerminalAudited {
			return fmt.Errorf("%w: error tombstone", policystore.ErrCorrupt)
		}
	default:
		return fmt.Errorf("%w: nonterminal tombstone", policystore.ErrCorrupt)
	}
	return nil
}

func validateFrozenPolicyConfig(request *policystore.Request, meta policyMeta) error {
	methodsDigest := sha256.Sum256(request.VoteAuthMethodsJSON)
	if hex.EncodeToString(methodsDigest[:]) != request.VoteAuthMethodsSHA256 ||
		request.VoteStepUpRequired != meta.VoteStepUpRequired || !bytes.Equal(request.VoteAuthMethodsJSON, meta.VoteAuthMethodsJSON) ||
		request.RequiredApprovals != int64(meta.RequiredApprovals) || request.DenyVeto != meta.DenyVeto || request.AllowSelfApprove != meta.AllowSelfApprove {
		return fmt.Errorf("%w: frozen vote policy", policystore.ErrCorrupt)
	}
	return nil
}

func validatePolicyReviewRecord(request *policystore.Request, meta policyMeta) error {
	if request.ReviewJSON == nil || !json.Valid(request.ReviewJSON) || !request.ReviewSHA256.Valid ||
		request.ReviewSHA256.Value != digestBytes(request.ReviewJSON) || !request.ReviewRenderedBytes.Valid ||
		request.ReviewRenderedBytes.Value != int64(len(request.ReviewJSON)) || !request.ReviewItemCount.Valid ||
		request.ReviewItemCount.Value < 0 || request.ReviewItemCount.Value > 40 ||
		!request.ReviewRendererVersion.Valid || request.ReviewRendererVersion.Value != meta.ReviewRendererVersion ||
		!request.ReviewRulesDigest.Valid || request.ReviewRulesDigest.Value != meta.ReviewRulesDigest {
		return fmt.Errorf("%w: review record", policystore.ErrCorrupt)
	}
	return nil
}

func validateStoredPolicyFailure(request *policystore.Request) error {
	if request.ErrorFamily == policystore.ErrorFamilyNone {
		if request.FailureCode != "" {
			return fmt.Errorf("%w: empty error family with code", policystore.ErrCorrupt)
		}
		return nil
	}
	if err := policystore.ValidateErrorFamilyCode(request.ErrorFamily, request.FailureCode); err != nil {
		return fmt.Errorf("%w: %v", policystore.ErrCorrupt, err)
	}
	return nil
}

func policyResponseMatchesRequest(response policywire.DecodedResponse, request *policystore.Request) bool {
	return response.Wire.RequestID == request.RequestID && response.Wire.AuthorityID == request.AuthorityID &&
		response.Wire.Purpose == request.Purpose && response.Wire.PayloadSHA256 == request.PayloadSHA256 &&
		response.Wire.BaseDigest == request.BaseDigest && response.Wire.SignerKeyID == terminalPolicySignerKeyID(request)
}

func validatePolicyVoteRecord(vote *policystore.Vote, request *policystore.Request) error {
	if vote == nil || request == nil || request.StorageKind != policystore.StorageFull {
		return fmt.Errorf("%w: vote parent", policystore.ErrCorrupt)
	}
	if err := policystore.ValidateIdentity(vote.Principal); err != nil {
		return err
	}
	if err := policystore.ValidateIdentity(vote.Operator); err != nil {
		return err
	}
	if vote.Decision != policystore.DecisionApprove && vote.Decision != policystore.DecisionDeny {
		return fmt.Errorf("%w: vote decision", policystore.ErrCorrupt)
	}
	if vote.AuthnMethod != policystore.AuthnSession && vote.AuthnMethod != policystore.AuthnTOTP {
		return fmt.Errorf("%w: vote auth method", policystore.ErrCorrupt)
	}
	if vote.AuditStateVersion == 0 || vote.AuditStateVersion > request.StateVersion {
		return fmt.Errorf("%w: vote audit version", policystore.ErrCorrupt)
	}
	var voters []string
	if err := json.Unmarshal(request.EligibleVotersJSON, &voters); err != nil || !slices.Contains(voters, vote.Operator) {
		return fmt.Errorf("%w: vote operator outside frozen electorate", policystore.ErrCorrupt)
	}
	if (request.VoteStepUpRequired && vote.AuthnMethod != policystore.AuthnTOTP) ||
		(!request.VoteStepUpRequired && vote.AuthnMethod != policystore.AuthnSession) {
		return fmt.Errorf("%w: vote authentication differs from frozen method", policystore.ErrCorrupt)
	}
	if vote.TupleDigest != request.TupleDigest || vote.Purpose != request.Purpose || vote.PayloadSHA256 != request.PayloadSHA256 || vote.CandidateDigest != request.BaseDigest || vote.HeadDigest != request.ExpectedHeadDigest || !request.FrozenSignerKeyID.Valid || vote.SignerKeyID != request.FrozenSignerKeyID.Value {
		return fmt.Errorf("%w: vote frozen tuple mismatch", policystore.ErrCorrupt)
	}
	return nil
}

func verifyRequestPolicyKeys(ctx context.Context, queryer policyQueryer, request *policystore.Request, authorityID string) error {
	if request.FrozenSignerKeyID.Valid {
		if err := requireBoundPolicyKey(ctx, queryer, request.FrozenSignerKeyID.Value, request.FrozenSignerPublicKey, authorityID); err != nil {
			return err
		}
	}
	if request.TrustedHeadKeyID.Valid {
		if err := requireBoundPolicyKey(ctx, queryer, request.TrustedHeadKeyID.Value, request.TrustedHeadPublicKey, authorityID); err != nil {
			return err
		}
	}
	if request.ClaimedHeadKeyID.Valid {
		if err := requireBoundPolicyKey(ctx, queryer, request.ClaimedHeadKeyID.Value, request.ClaimedHeadPublicKey, authorityID); err != nil {
			return err
		}
	}
	return nil
}

func requireBoundPolicyKey(ctx context.Context, queryer policyQueryer, keyID string, publicKey []byte, authorityID string) error {
	var count int
	if err := queryer.QueryRowContext(ctx, `SELECT count(*) FROM policy_authority_key_bindings WHERE signer_key_id=? AND signer_public_key=? AND authority_id=?`, keyID, publicKey, authorityID).Scan(&count); err != nil {
		return fmt.Errorf("verify request policy key binding: %w", err)
	}
	if count != 1 {
		return fmt.Errorf("%w: policy row references an unbound signer key", policystore.ErrCorrupt)
	}
	return nil
}

func validatePolicyHeadRecord(head *policystore.Head, authorityID string) error {
	if head == nil || head.AuthoritySingleton != 1 || head.AuthorityID != authorityID || head.RowVersion == 0 || len(head.EpochBE) != 8 || len(head.RevisionBE) != 8 {
		return fmt.Errorf("%w: head shape", policystore.ErrCorrupt)
	}
	derived, err := policy.SignerKeyID(head.SignerPublicKey)
	if err != nil || derived != head.SignerKeyID {
		return fmt.Errorf("%w: head signer key", policystore.ErrCorrupt)
	}
	manifest, err := policy.VerifyBaseManifest(head.ManifestEnvelope, head.SignerPublicKey)
	if err != nil || manifest.Host != head.HostKeyFP {
		return fmt.Errorf("%w: head envelope", policystore.ErrCorrupt)
	}
	payload, _, err := policy.DecodeBaseManifestEnvelope(head.ManifestEnvelope)
	if err != nil {
		return fmt.Errorf("%w: head envelope payload", policystore.ErrCorrupt)
	}
	payloadSHA, baseDigest, err := policywire.PayloadDigests(payload)
	if err != nil || payloadSHA != head.PayloadSHA256 || baseDigest != head.BaseDigest {
		return fmt.Errorf("%w: head digests", policystore.ErrCorrupt)
	}
	if !bytes.Equal(head.EpochBE, uint64BigEndian(manifest.Epoch)) || !bytes.Equal(head.RevisionBE, uint64BigEndian(manifest.Revision)) {
		return fmt.Errorf("%w: head epoch/revision", policystore.ErrCorrupt)
	}
	return nil
}

func isMatrix2A(request policystore.Request) bool {
	return request.ErrorFamily == policystore.ErrorFamilySemantic && request.FailureCode != policywire.ErrorQuorumUnattainable
}

func rejectionFloor(request *policystore.Request) uint64 {
	if request == nil || !isMatrix2A(*request) {
		return 0
	}
	if request.StorageKind == policystore.StorageTombstone {
		return request.ReservedBytes
	}
	return uint64(len(request.CanonicalRequest)) + uint64(len(request.Payload))
}

func addCounter(counter *uint64, value uint64) error {
	if math.MaxUint64-*counter < value {
		return fmt.Errorf("%w: policy accounting overflow", policystore.ErrCorrupt)
	}
	*counter += value
	return nil
}

func addCounterMap(counts map[string]uint64, key string, value uint64) error {
	current := counts[key]
	if math.MaxUint64-current < value {
		return fmt.Errorf("%w: policy accounting overflow", policystore.ErrCorrupt)
	}
	counts[key] = current + value
	return nil
}

func boolInteger(value bool) int64 {
	if value {
		return 1
	}
	return 0
}

func uint64BigEndian(value uint64) []byte {
	return []byte{byte(value >> 56), byte(value >> 48), byte(value >> 40), byte(value >> 32), byte(value >> 24), byte(value >> 16), byte(value >> 8), byte(value)}
}
