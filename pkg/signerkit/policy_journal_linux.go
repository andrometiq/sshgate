//go:build linux

package signerkit

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/karthikeyan5/sshgate/internal/securestate"
	"github.com/karthikeyan5/sshgate/src/policy"
	"github.com/karthikeyan5/sshgate/src/policyauthority"
	"github.com/karthikeyan5/sshgate/src/policyreview"
	"github.com/karthikeyan5/sshgate/src/policywire"
	"golang.org/x/sys/unix"
)

const (
	policyJournalSchema   = 1
	policyJournalFile     = "authority.json"
	maxPolicyHeads        = 256
	maxPolicyRequests     = 1024
	maxPolicyJournalBytes = 256 << 20

	// A received record already owns its base64 payload. Finishing it can add
	// one base64 envelope to the request and one to a new/replaced head. These
	// are whole-lifecycle budgets: policyRemainingReserve subtracts the exact
	// JSON growth already persisted so body+reserve never rises after admission.
	policyTerminalReserve           = 2*base64EncodedPolicyEnvelopeMax + 512<<10
	policyUnexposedRemainingReserve = base64EncodedPolicyEnvelopeMax + 256<<10
	policyNoMintRemainingReserve    = 64 << 10
	base64EncodedPolicyEnvelopeMax  = (policy.MaxPolicyEnvelopeBytes + 2) / 3 * 4

	maxPolicyActorBytes      = 256
	maxPolicyAuthMethodBytes = 64
	maxBootstrapEntries      = policyreview.MaxBootstrapEntries
)

var (
	errPolicyJournalFull = errors.New("policy journal full")
	errPolicyConflict    = errors.New("policy journal conflict")
)

type policyRequestState string

type policyRequestMode string

const (
	policyModeLocalTelegram policyRequestMode = "local-telegram"
	policyModeHosted        policyRequestMode = "hosted-pass-through"
)

const (
	policyStateReceivedUnaudited            policyRequestState = "received_unaudited"
	policyStateNotifying                    policyRequestState = "notifying"
	policyStatePending                      policyRequestState = "pending"
	policyStateApprovalReceived             policyRequestState = "approval_received"
	policyStateDenialReceived               policyRequestState = "denial_received"
	policyStateTimeoutReceived              policyRequestState = "timeout_received"
	policyStateInterruptionReceived         policyRequestState = "interruption_received"
	policyStateNotificationErrorReceived    policyRequestState = "notification_error_received"
	policyStateApprovedMaterializing        policyRequestState = "approved_materializing"
	policyStateApprovedUnexposed            policyRequestState = "approved_unexposed"
	policyStateMaterializationErrorReceived policyRequestState = "materialization_error_received"
	policyStateHostedTerminalUnexposed      policyRequestState = "hosted_terminal_unexposed"
	policyStateApproved                     policyRequestState = "approved"
	policyStateDenied                       policyRequestState = "denied"
	policyStateTimedOut                     policyRequestState = "timed_out"
	policyStateInterrupted                  policyRequestState = "interrupted"
	policyStateError                        policyRequestState = "error"
	policyStateSignerKeyChanged             policyRequestState = "signer_key_changed"
	policyStateStalePolicyHead              policyRequestState = "stale_policy_head"
)

type policyJournalDisk struct {
	Schema      int                   `json:"schema"`
	AuthorityID string                `json:"authority_id"`
	Heads       []policyHeadRecord    `json:"heads"`
	Requests    []policyRequestRecord `json:"requests"`
}

type policyHeadRecord struct {
	Host                string `json:"host"`
	ManifestEnvelopeB64 string `json:"manifest_envelope_b64"`
	BaseDigest          string `json:"base_digest"`
	Epoch               uint64 `json:"epoch"`
	Revision            uint64 `json:"revision"`
	SignerKeyID         string `json:"signer_key_id"`
	SignerPublicKeyB64  string `json:"signer_public_key_b64"`
}

type policyRequestRecord struct {
	RequestID           string               `json:"request_id"`
	Purpose             string               `json:"purpose"`
	HostKeyFP           string               `json:"host_key_fp"`
	ExpectedSignerKeyID string               `json:"expected_signer_key_id"`
	PayloadB64          string               `json:"payload_b64"`
	PayloadSHA256       string               `json:"payload_sha256"`
	BaseDigest          string               `json:"base_digest"`
	ExpectedHeadDigest  string               `json:"expected_head_digest,omitempty"`
	TrustedHeadDigest   string               `json:"trusted_head_digest,omitempty"`
	Bootstrap           bool                 `json:"bootstrap,omitempty"`
	TupleDigest         string               `json:"tuple_digest"`
	Epoch               uint64               `json:"epoch"`
	Revision            uint64               `json:"revision"`
	MissAction          string               `json:"miss_action"`
	Growth              string               `json:"growth"`
	EntryCount          int                  `json:"entry_count"`
	RevocationCount     int                  `json:"revocation_count"`
	SubmittedUnixNano   int64                `json:"submitted_unix_nano"`
	Mode                policyRequestMode    `json:"mode"`
	State               policyRequestState   `json:"state"`
	StateVersion        uint64               `json:"state_version"`
	FrozenPublicKeyB64  string               `json:"frozen_public_key_b64,omitempty"`
	HostedAuthorityID   string               `json:"hosted_authority_id,omitempty"`
	CallbackChallenge   string               `json:"callback_challenge,omitempty"`
	ApprovedBy          string               `json:"approved_by,omitempty"`
	OperatorAuthMethod  string               `json:"operator_auth_method,omitempty"`
	FailureCode         policywire.ErrorCode `json:"failure_code,omitempty"`
	ResultEnvelopeB64   string               `json:"result_envelope_b64,omitempty"`
	ResultSHA256        string               `json:"result_sha256,omitempty"`
	NoOp                bool                 `json:"no_op,omitempty"`
	Response            *policywire.Response `json:"response,omitempty"`
}

type policyBeginResult struct {
	Record   policyRequestRecord
	Existing bool
	Terminal *policywire.Response
}

type policyJournalError struct {
	Code policywire.ErrorCode
	Err  error
}

func (e *policyJournalError) Error() string {
	if e.Err == nil {
		return string(e.Code)
	}
	return e.Err.Error()
}

func (e *policyJournalError) Unwrap() error { return e.Err }

type localPolicyJournal struct {
	store *securestate.Store

	// opMu closes the otherwise tiny window between a Store.Update returning a
	// post-rename uncertainty error and this journal poisoning itself. Once an
	// update is uncertain, this open instance must expose nothing until it is
	// closed and reopened (which revalidates and fsyncs the directory).
	opMu      sync.Mutex
	poisonErr error

	// afterStoreUpdate is a test-only seam that simulates a write becoming
	// visible while its final durability acknowledgement is lost.
	afterStoreUpdate func() error
}

func openLocalPolicyJournal(root string) (*localPolicyJournal, error) {
	if !filepath.IsAbs(root) {
		return nil, errors.New("policy journal root must be absolute")
	}
	clean := filepath.Clean(root)
	if clean == string(filepath.Separator) {
		return nil, errors.New("policy journal root cannot be filesystem root")
	}
	parentPath, leaf := filepath.Split(clean)
	leaf = strings.TrimSuffix(leaf, string(filepath.Separator))
	if leaf == "" {
		return nil, errors.New("policy journal root has empty final component")
	}
	parentFD, err := openDirectoryPathNoSymlinks(filepath.Clean(parentPath))
	if err != nil {
		return nil, err
	}
	defer unix.Close(parentFD)
	store, err := securestate.OpenAt(parentFD, leaf, uint32(os.Geteuid()), true)
	if err != nil {
		return nil, fmt.Errorf("open policy journal: %w", err)
	}
	j := &localPolicyJournal{store: store}
	if err := j.initialize(); err != nil {
		_ = store.Close()
		return nil, err
	}
	return j, nil
}

func openDirectoryPathNoSymlinks(path string) (int, error) {
	if !filepath.IsAbs(path) {
		return -1, errors.New("secure directory walk requires absolute path")
	}
	fd, err := unix.Open(string(filepath.Separator), unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return -1, fmt.Errorf("open filesystem root: %w", err)
	}
	components := strings.Split(strings.TrimPrefix(filepath.Clean(path), string(filepath.Separator)), string(filepath.Separator))
	for _, component := range components {
		if component == "" || component == "." {
			continue
		}
		next, err := unix.Openat(fd, component, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
		if err != nil {
			_ = unix.Close(fd)
			return -1, fmt.Errorf("open policy journal parent component %q: %w", component, err)
		}
		_ = unix.Close(fd)
		fd = next
	}
	return fd, nil
}

func (j *localPolicyJournal) initialize() error {
	return j.store.Update(func(tx *securestate.Transaction) error {
		var disk policyJournalDisk
		_, err := tx.ReadCanonicalJSON(policyJournalFile, maxPolicyJournalBytes, &disk)
		if err == nil {
			return validatePolicyJournal(&disk)
		}
		if !errors.Is(err, securestate.ErrNotFound) {
			return err
		}
		authorityID, err := newAuthorityID()
		if err != nil {
			return err
		}
		disk = policyJournalDisk{
			Schema:      policyJournalSchema,
			AuthorityID: authorityID,
			Heads:       []policyHeadRecord{},
			Requests:    []policyRequestRecord{},
		}
		_, err = tx.WriteCanonicalJSON(policyJournalFile, disk, maxPolicyJournalBytes)
		return err
	})
}

func (j *localPolicyJournal) Close() error {
	j.opMu.Lock()
	defer j.opMu.Unlock()
	return j.store.Close()
}

func (j *localPolicyJournal) view(fn func(*policyJournalDisk) error) error {
	j.opMu.Lock()
	defer j.opMu.Unlock()
	if j.poisonErr != nil {
		return j.poisonErr
	}
	return j.store.View(func(tx *securestate.Transaction) error {
		var disk policyJournalDisk
		if _, err := tx.ReadCanonicalJSON(policyJournalFile, maxPolicyJournalBytes, &disk); err != nil {
			return err
		}
		if err := validatePolicyJournal(&disk); err != nil {
			return err
		}
		return fn(&disk)
	})
}

func (j *localPolicyJournal) update(fn func(*policyJournalDisk) error) error {
	j.opMu.Lock()
	defer j.opMu.Unlock()
	if j.poisonErr != nil {
		return j.poisonErr
	}
	err := j.store.Update(func(tx *securestate.Transaction) error {
		var disk policyJournalDisk
		if _, err := tx.ReadCanonicalJSON(policyJournalFile, maxPolicyJournalBytes, &disk); err != nil {
			return err
		}
		if err := validatePolicyJournal(&disk); err != nil {
			return err
		}
		if err := fn(&disk); err != nil {
			return err
		}
		sortPolicyJournal(&disk)
		if err := validatePolicyJournal(&disk); err != nil {
			return err
		}
		encoded, err := json.Marshal(disk)
		if err != nil {
			return err
		}
		if len(encoded) > maxPolicyJournalBytes {
			return errPolicyJournalFull
		}
		_, err = tx.WriteCanonicalJSON(policyJournalFile, disk, maxPolicyJournalBytes)
		return err
	})
	if err == nil && j.afterStoreUpdate != nil {
		if injected := j.afterStoreUpdate(); injected != nil {
			err = fmt.Errorf("%w: injected policy journal acknowledgement loss: %v", securestate.ErrCommitUncertain, injected)
		}
	}
	if errors.Is(err, securestate.ErrCommitUncertain) {
		j.poisonErr = fmt.Errorf("policy journal poisoned after uncertain commit; close and reopen to revalidate: %w", err)
		return j.poisonErr
	}
	return err
}

func newAuthorityID() (string, error) {
	var raw [16]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", fmt.Errorf("generate authority id: %w", err)
	}
	return "pauth_" + hex.EncodeToString(raw[:]), nil
}

func newCallbackChallenge() (string, error) {
	var raw [8]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", fmt.Errorf("generate policy callback challenge: %w", err)
	}
	return hex.EncodeToString(raw[:]), nil
}

func (d *policyJournalDisk) requestIndex(requestID string) int {
	return sort.Search(len(d.Requests), func(i int) bool { return d.Requests[i].RequestID >= requestID })
}

func (d *policyJournalDisk) request(requestID string) (*policyRequestRecord, bool) {
	i := d.requestIndex(requestID)
	if i >= len(d.Requests) || d.Requests[i].RequestID != requestID {
		return nil, false
	}
	return &d.Requests[i], true
}

func (d *policyJournalDisk) headIndex(host string) int {
	return sort.Search(len(d.Heads), func(i int) bool { return d.Heads[i].Host >= host })
}

func (d *policyJournalDisk) head(host string) (*policyHeadRecord, bool) {
	i := d.headIndex(host)
	if i >= len(d.Heads) || d.Heads[i].Host != host {
		return nil, false
	}
	return &d.Heads[i], true
}

func sortPolicyJournal(d *policyJournalDisk) {
	sort.Slice(d.Heads, func(i, k int) bool { return d.Heads[i].Host < d.Heads[k].Host })
	sort.Slice(d.Requests, func(i, k int) bool { return d.Requests[i].RequestID < d.Requests[k].RequestID })
}

func validatePolicyJournal(d *policyJournalDisk) error {
	if d.Schema != policyJournalSchema {
		return fmt.Errorf("policy journal: unsupported schema %d", d.Schema)
	}
	if len(d.AuthorityID) != len("pauth_")+32 || !strings.HasPrefix(d.AuthorityID, "pauth_") || !validLowerHexString(d.AuthorityID[len("pauth_"):]) {
		return errors.New("policy journal: invalid authority_id")
	}
	if d.Heads == nil || d.Requests == nil {
		return errors.New("policy journal: null collections")
	}
	if len(d.Heads) > maxPolicyHeads || len(d.Requests) > maxPolicyRequests {
		return errPolicyJournalFull
	}
	for i := range d.Heads {
		if i > 0 && d.Heads[i-1].Host >= d.Heads[i].Host {
			return errors.New("policy journal: heads are not uniquely sorted")
		}
		if err := validatePolicyHead(&d.Heads[i]); err != nil {
			return fmt.Errorf("policy journal head %q: %w", d.Heads[i].Host, err)
		}
	}
	nonterminalHosts := make(map[string]string)
	activeChallenges := make(map[string]string)
	for i := range d.Requests {
		if i > 0 && d.Requests[i-1].RequestID >= d.Requests[i].RequestID {
			return errors.New("policy journal: requests are not uniquely sorted")
		}
		if err := validatePolicyRequestRecord(&d.Requests[i], d.AuthorityID); err != nil {
			return fmt.Errorf("policy journal request %q: %w", d.Requests[i].RequestID, err)
		}
		record := &d.Requests[i]
		if !policyStateIsTerminal(record.State) {
			if prior, exists := nonterminalHosts[record.HostKeyFP]; exists {
				return fmt.Errorf("policy journal: requests %s and %s are both nonterminal for host %s", prior, record.RequestID, record.HostKeyFP)
			}
			nonterminalHosts[record.HostKeyFP] = record.RequestID
		}
		if record.CallbackChallenge != "" {
			if prior, exists := activeChallenges[record.CallbackChallenge]; exists {
				return fmt.Errorf("policy journal: requests %s and %s share active callback challenge", prior, record.RequestID)
			}
			activeChallenges[record.CallbackChallenge] = record.RequestID
		}
	}
	encoded, err := json.Marshal(d)
	if err != nil {
		return fmt.Errorf("policy journal: re-marshal for aggregate quota: %w", err)
	}
	if len(encoded)+policyOutstandingReserve(d) > maxPolicyJournalBytes || policyReservedHeadCount(d) > maxPolicyHeads {
		return errPolicyJournalFull
	}
	return nil
}

func validatePolicyHead(h *policyHeadRecord) error {
	publicKey, err := decodeJournalBytes(h.SignerPublicKeyB64, ed25519.PublicKeySize, ed25519.PublicKeySize)
	if err != nil {
		return fmt.Errorf("public key: %w", err)
	}
	keyID, err := policy.SignerKeyID(ed25519.PublicKey(publicKey))
	if err != nil || keyID != h.SignerKeyID {
		return errors.New("signer key id mismatch")
	}
	envelope, err := decodeJournalBytes(h.ManifestEnvelopeB64, 1, policy.MaxPolicyEnvelopeBytes)
	if err != nil {
		return fmt.Errorf("envelope: %w", err)
	}
	manifest, err := policy.VerifyBaseManifest(envelope, ed25519.PublicKey(publicKey))
	if err != nil {
		return err
	}
	if manifest.Host != h.Host || manifest.Epoch != h.Epoch || manifest.Revision != h.Revision {
		return errors.New("manifest metadata mismatch")
	}
	payload, _, err := policy.DecodeBaseManifestEnvelope(envelope)
	if err != nil {
		return err
	}
	_, digest, err := policywire.PayloadDigests(payload)
	if err != nil || digest != h.BaseDigest {
		return errors.New("base digest mismatch")
	}
	return nil
}

func validatePolicyRequestRecord(r *policyRequestRecord, localAuthorityID string) error {
	payload, err := decodeJournalBytes(r.PayloadB64, 1, policy.MaxPolicyPayloadBytes)
	if err != nil {
		return fmt.Errorf("payload: %w", err)
	}
	wireReq, err := policywire.NewRequest(r.RequestID, r.HostKeyFP, r.ExpectedSignerKeyID, payload, r.ExpectedHeadDigest, r.Bootstrap)
	if err != nil || wireReq.Kind != r.Purpose {
		return errors.New("invalid immutable request tuple")
	}
	manifest, err := policy.ParseBaseManifest(payload)
	if err != nil {
		return err
	}
	payloadSHA, baseDigest, err := policywire.PayloadDigests(payload)
	if err != nil || payloadSHA != r.PayloadSHA256 || baseDigest != r.BaseDigest {
		return errors.New("request digest mismatch")
	}
	if manifest.Epoch != r.Epoch || manifest.Revision != r.Revision || string(manifest.MissAction) != r.MissAction || string(manifest.Growth) != r.Growth || len(manifest.Entries) != r.EntryCount || len(manifest.RevokedPermitIDs) != r.RevocationCount {
		return errors.New("request manifest metadata mismatch")
	}
	if policyTupleDigest(r) != r.TupleDigest {
		return errors.New("tuple digest mismatch")
	}
	if r.TrustedHeadDigest != "" && (!validLowerHexString(r.TrustedHeadDigest) || len(r.TrustedHeadDigest) != 64) {
		return errors.New("invalid trusted head digest")
	}
	if r.SubmittedUnixNano <= 0 {
		return errors.New("invalid submitted time")
	}
	if r.Mode != policyModeLocalTelegram && r.Mode != policyModeHosted {
		return errors.New("invalid request mode")
	}
	if r.Mode == policyModeHosted {
		if !policyauthority.ValidAuthorityID(r.HostedAuthorityID) {
			return errors.New("invalid hosted authority_id")
		}
	} else if r.HostedAuthorityID != "" {
		return errors.New("local request carries hosted authority_id")
	}
	if r.StateVersion == 0 || !validPolicyRequestState(r.State) {
		return errors.New("invalid request state")
	}
	publicKey, err := decodeJournalBytes(r.FrozenPublicKeyB64, ed25519.PublicKeySize, ed25519.PublicKeySize)
	if err != nil {
		return fmt.Errorf("request frozen public key: %w", err)
	}
	keyID, err := policy.SignerKeyID(ed25519.PublicKey(publicKey))
	if err != nil || keyID != r.ExpectedSignerKeyID {
		return errors.New("request signer key mismatch")
	}
	if r.CallbackChallenge != "" && (len(r.CallbackChallenge) != 16 || !validLowerHexString(r.CallbackChallenge)) {
		return errors.New("invalid callback challenge")
	}
	if err := validatePolicyActor(r.ApprovedBy, maxPolicyActorBytes); err != nil {
		return fmt.Errorf("approved_by: %w", err)
	}
	if err := validatePolicyActor(r.OperatorAuthMethod, maxPolicyAuthMethodBytes); err != nil {
		return fmt.Errorf("operator_auth_method: %w", err)
	}
	if r.ApprovedBy == "" && r.OperatorAuthMethod != "" {
		return errors.New("operator auth method without approved_by")
	}
	if r.ResultEnvelopeB64 != "" {
		envelope, err := decodeJournalBytes(r.ResultEnvelopeB64, 1, policy.MaxPolicyEnvelopeBytes)
		if err != nil {
			return fmt.Errorf("result envelope: %w", err)
		}
		manifest, err := policy.VerifyBaseManifest(envelope, ed25519.PublicKey(publicKey))
		if err != nil || manifest.Host != r.HostKeyFP || manifest.Epoch != r.Epoch || manifest.Revision != r.Revision {
			return errors.New("result envelope verification/metadata mismatch")
		}
		resultPayload, _, err := policy.DecodeBaseManifestEnvelope(envelope)
		if err != nil || !bytes.Equal(resultPayload, payload) {
			return errors.New("result envelope payload mismatch")
		}
		digest := sha256.Sum256(envelope)
		if hex.EncodeToString(digest[:]) != r.ResultSHA256 {
			return errors.New("result envelope hash mismatch")
		}
	} else if r.ResultSHA256 != "" && (r.Response == nil || r.Response.Status != policywire.StatusApproved) {
		return errors.New("result hash without unexposed envelope or approved response")
	}
	if r.Response != nil {
		if _, err := policywire.MarshalResponse(*r.Response); err != nil {
			return fmt.Errorf("response: %w", err)
		}
		expectedAuthorityID := localAuthorityID
		if r.State == policyStateHostedTerminalUnexposed {
			expectedAuthorityID = r.HostedAuthorityID
		}
		if r.Response.RequestID != r.RequestID || r.Response.Purpose != r.Purpose ||
			r.Response.AuthorityID != expectedAuthorityID ||
			r.Response.PayloadSHA256 != r.PayloadSHA256 || r.Response.BaseDigest != r.BaseDigest ||
			r.Response.SignerKeyID != r.ExpectedSignerKeyID {
			return errors.New("terminal response immutable fields mismatch")
		}
		if r.Response.Status == policywire.StatusApproved {
			if r.ResultEnvelopeB64 != "" && r.Response.ManifestEnvelopeB64 != r.ResultEnvelopeB64 {
				return errors.New("approved response/result envelope mismatch")
			}
			envelope, err := decodeJournalBytes(r.Response.ManifestEnvelopeB64, 1, policy.MaxPolicyEnvelopeBytes)
			if err != nil {
				return err
			}
			verified, err := policy.VerifyBaseManifest(envelope, ed25519.PublicKey(publicKey))
			if err != nil || verified.Host != r.HostKeyFP || verified.Epoch != r.Epoch || verified.Revision != r.Revision {
				return errors.New("approved response envelope verification/metadata mismatch")
			}
			resultPayload, _, err := policy.DecodeBaseManifestEnvelope(envelope)
			if err != nil || !bytes.Equal(resultPayload, payload) {
				return errors.New("approved response envelope payload mismatch")
			}
			digest := sha256.Sum256(envelope)
			if hex.EncodeToString(digest[:]) != r.ResultSHA256 {
				return errors.New("approved response envelope hash mismatch")
			}
		} else if r.ResultEnvelopeB64 != "" && !(r.Mode == policyModeHosted && r.FailureCode == policywire.ErrorSignerKeyChanged) {
			return errors.New("non-approved response with result envelope")
		}
	}
	return validatePolicyStateFields(r)
}

func validatePolicyActor(value string, maxBytes int) error {
	if len(value) > maxBytes || !utf8.ValidString(value) {
		return fmt.Errorf("must be valid UTF-8 no longer than %d bytes", maxBytes)
	}
	for _, b := range []byte(value) {
		if b < 0x20 || b == 0x7f {
			return errors.New("contains control bytes")
		}
	}
	return nil
}

func validatePolicyStateFields(r *policyRequestRecord) error {
	hasChallenge := r.CallbackChallenge != ""
	hasActor := r.ApprovedBy != ""
	hasAuth := r.OperatorAuthMethod != ""
	hasResult := r.ResultEnvelopeB64 != ""
	hasResponse := r.Response != nil
	if r.NoOp && r.FailureCode != "" {
		return errors.New("no-op cannot also carry failure_code")
	}
	if r.FailureCode != "" && !validStoredPolicyErrorCode(r.FailureCode) {
		return errors.New("invalid stored failure_code")
	}
	requireLocalChallenge := func() error {
		if r.Mode == policyModeLocalTelegram && !hasChallenge {
			return errors.New("local notifying/pending state requires callback challenge")
		}
		if r.Mode == policyModeHosted && hasChallenge {
			return errors.New("hosted state cannot carry callback challenge")
		}
		return nil
	}
	requireClean := func() error {
		if hasChallenge || hasActor || hasResult || hasResponse {
			return errors.New("state carries fields that belong to a later phase")
		}
		return nil
	}
	switch r.State {
	case policyStateReceivedUnaudited:
		if r.Mode == policyModeHosted && (r.NoOp || r.FailureCode != "") {
			return errors.New("hosted received state cannot carry local classification")
		}
		return requireClean()
	case policyStateNotifying, policyStatePending:
		if r.NoOp || r.FailureCode != "" || hasActor || hasResult || hasResponse {
			return errors.New("notifying/pending state carries verdict or terminal fields")
		}
		return requireLocalChallenge()
	case policyStateApprovalReceived:
		if r.Mode != policyModeLocalTelegram || !hasActor || !hasAuth || hasChallenge || hasResult || hasResponse || r.FailureCode != "" || r.NoOp {
			return errors.New("invalid approval_received fields")
		}
	case policyStateDenialReceived:
		if r.Mode != policyModeLocalTelegram || !hasActor || !hasAuth || hasChallenge || hasResult || hasResponse || r.FailureCode != "" || r.NoOp {
			return errors.New("invalid denial_received fields")
		}
	case policyStateTimeoutReceived, policyStateInterruptionReceived:
		if r.Mode != policyModeLocalTelegram || hasActor || hasAuth || hasChallenge || hasResult || hasResponse || r.FailureCode != "" || r.NoOp {
			return errors.New("invalid timeout/interruption received fields")
		}
	case policyStateNotificationErrorReceived:
		if r.Mode != policyModeLocalTelegram || hasActor || hasAuth || hasChallenge || hasResult || hasResponse || r.FailureCode != policywire.ErrorPolicyNotificationFailed || r.NoOp {
			return errors.New("invalid notification_error_received fields")
		}
	case policyStateApprovedMaterializing:
		if r.Mode != policyModeLocalTelegram || !hasActor || !hasAuth || hasChallenge || hasResult || hasResponse || r.FailureCode != "" || r.NoOp {
			return errors.New("invalid approved_materializing fields")
		}
	case policyStateApprovedUnexposed:
		localPrompted := r.Mode == policyModeLocalTelegram && !r.NoOp && hasActor && hasAuth
		localNoOp := r.Mode == policyModeLocalTelegram && r.NoOp && !hasActor && !hasAuth
		hostedApproval := r.Mode == policyModeHosted && !r.NoOp && !hasActor && !hasAuth
		if (!localPrompted && !localNoOp && !hostedApproval) || hasChallenge || !hasResult || hasResponse || r.FailureCode != "" {
			return errors.New("invalid approved_unexposed fields")
		}
	case policyStateMaterializationErrorReceived:
		promptedFailure := hasActor && hasAuth && !r.NoOp
		noOpFailure := !hasActor && !hasAuth && r.NoOp
		hostedStale := r.Mode == policyModeHosted && !hasActor && !hasAuth && !r.NoOp && r.FailureCode == policywire.ErrorSignerKeyChanged
		localFailure := r.Mode == policyModeLocalTelegram && (promptedFailure || noOpFailure) &&
			(r.FailureCode == policywire.ErrorPolicyMaterializationFailed || r.FailureCode == policywire.ErrorSignerKeyChanged || r.FailureCode == policywire.ErrorStalePolicyHead)
		if (!localFailure && !hostedStale) || hasChallenge || hasResponse || (hasResult && !hostedStale) {
			return errors.New("invalid materialization_error_received fields")
		}
	case policyStateHostedTerminalUnexposed:
		if r.Mode != policyModeHosted || hasChallenge || hasActor || hasAuth || hasResult || !hasResponse || r.NoOp {
			return errors.New("invalid hosted_terminal_unexposed fields")
		}
		if r.Response.Status == policywire.StatusApproved || r.Response.Status == policywire.StatusPending {
			return errors.New("hosted terminal staging carries nonterminal/approved response")
		}
		if r.Response.Status == policywire.StatusError && r.FailureCode != r.Response.ErrorCode {
			return errors.New("hosted terminal staged error/code mismatch")
		}
	case policyStateApproved:
		if hasChallenge || hasResult || r.ResultSHA256 == "" || !hasResponse || r.Response.Status != policywire.StatusApproved || r.FailureCode != "" ||
			(r.Mode == policyModeLocalTelegram && !r.NoOp && (!hasActor || !hasAuth)) ||
			(r.Mode == policyModeLocalTelegram && r.NoOp && (hasActor || hasAuth)) ||
			(r.Mode == policyModeHosted && (r.NoOp || hasActor || hasAuth)) {
			return errors.New("invalid approved terminal fields")
		}
	case policyStateDenied:
		if (r.Mode == policyModeLocalTelegram && (!hasActor || !hasAuth)) || (r.Mode == policyModeHosted && (hasActor || hasAuth)) || hasChallenge || hasResult || !hasResponse || r.Response.Status != policywire.StatusDenied || r.FailureCode != "" || r.NoOp {
			return errors.New("invalid denied terminal fields")
		}
	case policyStateTimedOut:
		if hasActor || hasAuth || hasChallenge || hasResult || !hasResponse || r.Response.Status != policywire.StatusTimeout || r.FailureCode != "" || r.NoOp {
			return errors.New("invalid timed_out terminal fields")
		}
	case policyStateInterrupted:
		if hasActor || hasAuth || hasChallenge || hasResult || !hasResponse || r.Response.Status != policywire.StatusInterrupted || r.FailureCode != "" || r.NoOp {
			return errors.New("invalid interrupted terminal fields")
		}
	case policyStateError, policyStateSignerKeyChanged, policyStateStalePolicyHead:
		hostedRetainedStale := r.Mode == policyModeHosted && r.State == policyStateSignerKeyChanged && r.FailureCode == policywire.ErrorSignerKeyChanged
		if hasChallenge || (hasResult && !hostedRetainedStale) || !hasResponse || r.Response.Status != policywire.StatusError || r.Response.ErrorCode != r.FailureCode || r.NoOp ||
			(r.Mode == policyModeHosted && (hasActor || hasAuth)) || (hasActor != hasAuth) {
			return errors.New("invalid error terminal fields")
		}
		if r.State == policyStateSignerKeyChanged && r.FailureCode != policywire.ErrorSignerKeyChanged {
			return errors.New("signer_key_changed state/code mismatch")
		}
		if r.State == policyStateStalePolicyHead && r.FailureCode != policywire.ErrorStalePolicyHead {
			return errors.New("stale_policy_head state/code mismatch")
		}
	}
	return nil
}

func validStoredPolicyErrorCode(code policywire.ErrorCode) bool {
	switch code {
	case policywire.ErrorInvalidPolicyRequest, policywire.ErrorPolicyNotSupported,
		policywire.ErrorIdempotencyConflict, policywire.ErrorPolicyRequestInProgress,
		policywire.ErrorSignerKeyChanged, policywire.ErrorStalePolicyHead,
		policywire.ErrorPolicyKeyTransitionRequired, policywire.ErrorQuorumUnattainable,
		policywire.ErrorPolicyJournalFull,
		policywire.ErrorPolicyNotificationFailed, policywire.ErrorPolicyMaterializationFailed:
		return true
	default:
		return false
	}
}

func validPolicyRequestState(state policyRequestState) bool {
	switch state {
	case policyStateReceivedUnaudited, policyStateNotifying, policyStatePending,
		policyStateApprovalReceived, policyStateDenialReceived, policyStateTimeoutReceived,
		policyStateInterruptionReceived, policyStateNotificationErrorReceived,
		policyStateApprovedMaterializing, policyStateApprovedUnexposed,
		policyStateMaterializationErrorReceived, policyStateHostedTerminalUnexposed, policyStateApproved,
		policyStateDenied, policyStateTimedOut, policyStateInterrupted,
		policyStateError, policyStateSignerKeyChanged, policyStateStalePolicyHead:
		return true
	default:
		return false
	}
}

func decodeJournalBytes(encoded string, minBytes, maxBytes int) ([]byte, error) {
	if encoded == "" || len(encoded) > base64.StdEncoding.EncodedLen(maxBytes) {
		return nil, errors.New("missing or oversized base64")
	}
	decoded, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil || base64.StdEncoding.EncodeToString(decoded) != encoded || len(decoded) < minBytes || len(decoded) > maxBytes {
		return nil, errors.New("non-canonical or out-of-bounds base64")
	}
	return decoded, nil
}

func validLowerHexString(value string) bool {
	if value == "" {
		return false
	}
	for i := range len(value) {
		if (value[i] < '0' || value[i] > '9') && (value[i] < 'a' || value[i] > 'f') {
			return false
		}
	}
	return true
}

func clonePolicyResponse(resp *policywire.Response) *policywire.Response {
	if resp == nil {
		return nil
	}
	copy := *resp
	return &copy
}

func policyHeadEnvelope(h *policyHeadRecord) ([]byte, error) {
	return decodeJournalBytes(h.ManifestEnvelopeB64, 1, policy.MaxPolicyEnvelopeBytes)
}

func policyHeadPublicKey(h *policyHeadRecord) (ed25519.PublicKey, error) {
	raw, err := decodeJournalBytes(h.SignerPublicKeyB64, ed25519.PublicKeySize, ed25519.PublicKeySize)
	return ed25519.PublicKey(raw), err
}

func policyRequestPayload(r *policyRequestRecord) ([]byte, error) {
	return decodeJournalBytes(r.PayloadB64, 1, policy.MaxPolicyPayloadBytes)
}

func policyRequestPublicKey(r *policyRequestRecord) (ed25519.PublicKey, error) {
	raw, err := decodeJournalBytes(r.FrozenPublicKeyB64, ed25519.PublicKeySize, ed25519.PublicKeySize)
	return ed25519.PublicKey(raw), err
}

func samePolicyTuple(record *policyRequestRecord, decoded policywire.DecodedRequest) bool {
	payloadSHA, _, err := policywire.PayloadDigests(decoded.Payload)
	return err == nil && record.RequestID == decoded.Wire.RequestID && record.Purpose == policywire.Purpose &&
		record.HostKeyFP == decoded.Wire.HostKeyFP && record.ExpectedSignerKeyID == decoded.Wire.ExpectedSignerKeyID &&
		record.PayloadSHA256 == payloadSHA && record.ExpectedHeadDigest == decoded.Wire.ExpectedHeadDigest &&
		record.Bootstrap == decoded.Wire.Bootstrap
}

func comparePolicyBytes(a, b []byte) bool { return bytes.Equal(a, b) }

func clonePolicyRecord(record policyRequestRecord) policyRequestRecord {
	copy := record
	copy.Response = clonePolicyResponse(record.Response)
	return copy
}

func policyTupleDigest(record *policyRequestRecord) string {
	return policyTupleDigestFields(
		record.RequestID,
		record.Purpose,
		record.HostKeyFP,
		record.ExpectedSignerKeyID,
		record.PayloadSHA256,
		record.ExpectedHeadDigest,
		record.Bootstrap,
	)
}

func policyTupleDigestDecoded(decoded policywire.DecodedRequest) string {
	payloadSHA, _, err := policywire.PayloadDigests(decoded.Payload)
	if err != nil {
		return ""
	}
	return policyTupleDigestFields(
		decoded.Wire.RequestID,
		policywire.Purpose,
		decoded.Wire.HostKeyFP,
		decoded.Wire.ExpectedSignerKeyID,
		payloadSHA,
		decoded.Wire.ExpectedHeadDigest,
		decoded.Wire.Bootstrap,
	)
}

func policyTupleDigestFields(requestID, purpose, host, keyID, payloadSHA, head string, bootstrap bool) string {
	return policyauthority.TupleDigest(policyauthority.RequestTuple{
		RequestID: requestID, Purpose: purpose, HostKeyFP: host,
		ExpectedSignerKeyID: keyID, PayloadSHA256: payloadSHA,
		ExpectedHeadDigest: head, Bootstrap: bootstrap,
	})
}

func (j *localPolicyJournal) lookup(decoded policywire.DecodedRequest) (policyBeginResult, bool, error) {
	var out policyBeginResult
	found := false
	err := j.view(func(disk *policyJournalDisk) error {
		record, ok := disk.request(decoded.Wire.RequestID)
		if !ok {
			return nil
		}
		found = true
		if !samePolicyTuple(record, decoded) {
			return &policyJournalError{Code: policywire.ErrorIdempotencyConflict, Err: errPolicyConflict}
		}
		out.Record = clonePolicyRecord(*record)
		out.Existing = true
		if policyStateIsTerminal(record.State) {
			out.Terminal = clonePolicyResponse(record.Response)
		}
		return nil
	})
	return out, found, err
}

func (j *localPolicyJournal) begin(decoded policywire.DecodedRequest, mode policyRequestMode, publicKey ed25519.PublicKey, submitted time.Time, hostedAuthorityIDs ...string) (policyBeginResult, error) {
	var out policyBeginResult
	if submitted.IsZero() {
		return out, errors.New("policy journal: zero submission time")
	}
	hostedAuthorityID := ""
	if mode == policyModeHosted {
		if len(hostedAuthorityIDs) != 1 || !policyauthority.ValidAuthorityID(hostedAuthorityIDs[0]) {
			return out, errors.New("policy journal: hosted authority pair is required")
		}
		hostedAuthorityID = hostedAuthorityIDs[0]
	} else if len(hostedAuthorityIDs) != 0 && (len(hostedAuthorityIDs) != 1 || hostedAuthorityIDs[0] != "") {
		return out, errors.New("policy journal: local request cannot carry hosted authority")
	}
	payloadSHA, baseDigest, err := policywire.PayloadDigests(decoded.Payload)
	if err != nil {
		return out, err
	}
	err = j.update(func(disk *policyJournalDisk) error {
		if existing, ok := disk.request(decoded.Wire.RequestID); ok {
			if !samePolicyTuple(existing, decoded) {
				return &policyJournalError{Code: policywire.ErrorIdempotencyConflict, Err: errPolicyConflict}
			}
			out = policyBeginResult{Record: clonePolicyRecord(*existing), Existing: true}
			if policyStateIsTerminal(existing.State) {
				out.Terminal = clonePolicyResponse(existing.Response)
			}
			return nil
		}
		keyID, err := policy.SignerKeyID(publicKey)
		if err != nil {
			return err
		}
		if keyID != decoded.Wire.ExpectedSignerKeyID {
			return &policyJournalError{Code: policywire.ErrorSignerKeyChanged, Err: ErrSignerKeyChanged}
		}

		for i := range disk.Requests {
			other := &disk.Requests[i]
			if other.HostKeyFP == decoded.Wire.HostKeyFP && !policyStateIsTerminal(other.State) {
				return &policyJournalError{Code: policywire.ErrorPolicyRequestInProgress, Err: errors.New("another policy request is nonterminal for this host")}
			}
		}
		if len(disk.Requests) >= maxPolicyRequests {
			return &policyJournalError{Code: policywire.ErrorPolicyJournalFull, Err: errPolicyJournalFull}
		}

		head, hasHead := disk.head(decoded.Wire.HostKeyFP)
		if !hasHead && len(disk.Heads) >= maxPolicyHeads {
			return &policyJournalError{Code: policywire.ErrorPolicyJournalFull, Err: errPolicyJournalFull}
		}
		noOp, failureCode := false, policywire.ErrorCode("")
		if mode == policyModeLocalTelegram {
			noOp, failureCode = classifyPolicyCandidate(decoded, head, hasHead, publicKey)
		}
		trustedHeadDigest := ""
		if hasHead {
			trustedHeadDigest = head.BaseDigest
		}
		record := policyRequestRecord{
			RequestID:           decoded.Wire.RequestID,
			Purpose:             policywire.Purpose,
			HostKeyFP:           decoded.Wire.HostKeyFP,
			ExpectedSignerKeyID: decoded.Wire.ExpectedSignerKeyID,
			PayloadB64:          base64.StdEncoding.EncodeToString(decoded.Payload),
			PayloadSHA256:       payloadSHA,
			BaseDigest:          baseDigest,
			ExpectedHeadDigest:  decoded.Wire.ExpectedHeadDigest,
			TrustedHeadDigest:   trustedHeadDigest,
			Bootstrap:           decoded.Wire.Bootstrap,
			Epoch:               decoded.Manifest.Epoch,
			Revision:            decoded.Manifest.Revision,
			MissAction:          string(decoded.Manifest.MissAction),
			Growth:              string(decoded.Manifest.Growth),
			EntryCount:          len(decoded.Manifest.Entries),
			RevocationCount:     len(decoded.Manifest.RevokedPermitIDs),
			SubmittedUnixNano:   submitted.UnixNano(),
			Mode:                mode,
			State:               policyStateReceivedUnaudited,
			StateVersion:        1,
			FrozenPublicKeyB64:  base64.StdEncoding.EncodeToString(publicKey),
			HostedAuthorityID:   hostedAuthorityID,
			FailureCode:         failureCode,
			NoOp:                noOp,
		}
		record.TupleDigest = policyTupleDigest(&record)
		disk.Requests = append(disk.Requests, record)
		sortPolicyJournal(disk)
		body, err := json.Marshal(disk)
		if err != nil {
			return err
		}
		if len(body)+policyOutstandingReserve(disk) > maxPolicyJournalBytes || policyReservedHeadCount(disk) > maxPolicyHeads {
			return &policyJournalError{Code: policywire.ErrorPolicyJournalFull, Err: errPolicyJournalFull}
		}
		out = policyBeginResult{Record: clonePolicyRecord(record)}
		return nil
	})
	return out, err
}

func (j *localPolicyJournal) trustedHeadDigest(host string) (string, error) {
	var digest string
	err := j.view(func(disk *policyJournalDisk) error {
		if head, ok := disk.head(host); ok {
			digest = head.BaseDigest
		}
		return nil
	})
	return digest, err
}

func (j *localPolicyJournal) authorityID() (string, error) {
	var authorityID string
	err := j.view(func(disk *policyJournalDisk) error {
		authorityID = disk.AuthorityID
		return nil
	})
	return authorityID, err
}

func policyOutstandingReserve(disk *policyJournalDisk) int {
	total := 0
	for i := range disk.Requests {
		remaining := policyRemainingReserve(&disk.Requests[i])
		// The journal only needs to distinguish "within 256 MiB" from "over".
		// Saturate above that boundary so aggregate reservations cannot wrap on
		// 32-bit Linux even when many maximum-size requests are present.
		if remaining > maxPolicyJournalBytes || total > maxPolicyJournalBytes-remaining {
			return maxPolicyJournalBytes + 1
		}
		total += remaining
	}
	return total
}

func policyRemainingReserve(record *policyRequestRecord) int {
	if policyStateIsTerminal(record.State) {
		return 0
	}
	budget := policyTerminalReserve
	switch {
	case record.State == policyStateDenialReceived,
		record.State == policyStateTimeoutReceived,
		record.State == policyStateInterruptionReceived,
		record.State == policyStateNotificationErrorReceived,
		record.State == policyStateMaterializationErrorReceived,
		record.State == policyStateHostedTerminalUnexposed:
		budget = policyNoMintRemainingReserve
	case record.FailureCode != "":
		budget = policyNoMintRemainingReserve
	case record.NoOp:
		budget = policyUnexposedRemainingReserve
	}

	// Measure lifecycle growth from the immutable admitted record rather than
	// assigning the same reserve to every state. Challenge, actor/auth, state
	// name/version, classifications, staged envelope, and staged response bytes
	// are therefore paid from the reservation as soon as they are persisted.
	// For every nonterminal path, len(record JSON)+remaining is bounded by
	// len(admission-baseline JSON)+budget; a request admitted at the exact quota
	// boundary cannot be stranded by a later required transition.
	baseline := *record
	baseline.State = policyStateReceivedUnaudited
	baseline.StateVersion = 1
	baseline.CallbackChallenge = ""
	baseline.ApprovedBy = ""
	baseline.OperatorAuthMethod = ""
	baseline.FailureCode = ""
	baseline.ResultEnvelopeB64 = ""
	baseline.ResultSHA256 = ""
	baseline.NoOp = false
	baseline.Response = nil
	currentJSON, _ := json.Marshal(record)
	baselineJSON, _ := json.Marshal(&baseline)
	consumed := len(currentJSON) - len(baselineJSON)
	remaining := budget - consumed
	if remaining < 0 {
		return 0
	}
	return remaining
}

func policyReservedHeadCount(disk *policyJournalDisk) int {
	hosts := make(map[string]struct{}, len(disk.Heads)+len(disk.Requests))
	for i := range disk.Heads {
		hosts[disk.Heads[i].Host] = struct{}{}
	}
	for i := range disk.Requests {
		record := &disk.Requests[i]
		if !policyStateIsTerminal(record.State) && !record.NoOp && record.FailureCode == "" {
			hosts[record.HostKeyFP] = struct{}{}
		}
	}
	return len(hosts)
}

func classifyPolicyCandidate(decoded policywire.DecodedRequest, head *policyHeadRecord, hasHead bool, publicKey ed25519.PublicKey) (bool, policywire.ErrorCode) {
	var authorityHead *policyauthority.Head
	if hasHead {
		headPublic, err := policyHeadPublicKey(head)
		if err != nil || !bytes.Equal(headPublic, publicKey) {
			return false, policywire.ErrorPolicyKeyTransitionRequired
		}
		headEnvelope, err := policyHeadEnvelope(head)
		if err != nil {
			return false, policywire.ErrorInvalidPolicyRequest
		}
		authorityHead = &policyauthority.Head{
			ManifestEnvelope: headEnvelope,
			BaseDigest:       head.BaseDigest,
			SignerKeyID:      head.SignerKeyID,
			SignerPublicKey:  append(ed25519.PublicKey(nil), headPublic...),
		}
	}
	classification := policyauthority.Classify(decoded, authorityHead, publicKey)
	return classification.NoOp, classification.ErrorCode
}

func policyStateIsTerminal(state policyRequestState) bool {
	switch state {
	case policyStateApproved, policyStateDenied, policyStateTimedOut, policyStateInterrupted,
		policyStateError, policyStateSignerKeyChanged, policyStateStalePolicyHead:
		return true
	default:
		return false
	}
}

func (j *localPolicyJournal) record(requestID string) (policyRequestRecord, error) {
	var out policyRequestRecord
	err := j.view(func(disk *policyJournalDisk) error {
		record, ok := disk.request(requestID)
		if !ok {
			return securestate.ErrNotFound
		}
		out = clonePolicyRecord(*record)
		return nil
	})
	return out, err
}

// trustedHeadEnvelopeForRequest returns the exact validated signer-owned head
// bound to requestID. Bootstrap requests have no predecessor and return nil.
// Hosted pass-through deliberately receives no local mirror: only the hosted
// authority may classify a new hosted request against its current head.
func (j *localPolicyJournal) trustedHeadEnvelopeForRequest(requestID string) ([]byte, error) {
	var out []byte
	err := j.view(func(disk *policyJournalDisk) error {
		record, ok := disk.request(requestID)
		if !ok {
			return securestate.ErrNotFound
		}
		if record.Mode != policyModeLocalTelegram || record.TrustedHeadDigest == "" {
			return nil
		}
		head, ok := disk.head(record.HostKeyFP)
		if !ok || head.BaseDigest != record.TrustedHeadDigest || record.ExpectedHeadDigest != record.TrustedHeadDigest ||
			head.SignerKeyID != record.ExpectedSignerKeyID || head.SignerPublicKeyB64 != record.FrozenPublicKeyB64 {
			return errPolicyConflict
		}
		envelope, err := policyHeadEnvelope(head)
		if err != nil {
			return err
		}
		out = append([]byte(nil), envelope...)
		return nil
	})
	return out, err
}

func (j *localPolicyJournal) mutateRequest(requestID string, allowed []policyRequestState, mutate func(*policyRequestRecord) error) (policyRequestRecord, error) {
	var out policyRequestRecord
	err := j.update(func(disk *policyJournalDisk) error {
		record, ok := disk.request(requestID)
		if !ok {
			return securestate.ErrNotFound
		}
		allowedState := false
		for _, state := range allowed {
			if record.State == state {
				allowedState = true
				break
			}
		}
		if !allowedState {
			return fmt.Errorf("%w: request %s state %s", errPolicyConflict, requestID, record.State)
		}
		before := record.StateVersion
		if err := mutate(record); err != nil {
			return err
		}
		if record.StateVersion != before {
			return errors.New("policy journal mutation changed state_version directly")
		}
		record.StateVersion++
		out = clonePolicyRecord(*record)
		return nil
	})
	return out, err
}

func (j *localPolicyJournal) markNotifying(requestID, challenge string) (policyRequestRecord, error) {
	var out policyRequestRecord
	err := j.update(func(disk *policyJournalDisk) error {
		record, ok := disk.request(requestID)
		if !ok || record.State != policyStateReceivedUnaudited {
			return errPolicyConflict
		}
		if record.NoOp || record.FailureCode != "" {
			return errors.New("policy journal: no-op/rejected request cannot notify")
		}
		if record.Mode == policyModeLocalTelegram {
			if len(challenge) != 16 || !validLowerHexString(challenge) {
				return errors.New("policy journal: invalid callback challenge")
			}
			for i := range disk.Requests {
				other := &disk.Requests[i]
				if other.RequestID != requestID && other.CallbackChallenge == challenge {
					return errors.New("policy journal: callback challenge collision")
				}
			}
			record.CallbackChallenge = challenge
		} else if challenge != "" {
			return errors.New("policy journal: hosted request cannot carry challenge")
		}
		record.State = policyStateNotifying
		record.StateVersion++
		out = clonePolicyRecord(*record)
		return nil
	})
	return out, err
}

func (j *localPolicyJournal) activateLocal(requestID, challenge string) (policyRequestRecord, error) {
	return j.mutateRequest(requestID, []policyRequestState{policyStateNotifying}, func(record *policyRequestRecord) error {
		if record.Mode != policyModeLocalTelegram || record.CallbackChallenge != challenge {
			return errPolicyConflict
		}
		record.State = policyStatePending
		return nil
	})
}

func (j *localPolicyJournal) activateHosted(requestID string) (policyRequestRecord, error) {
	return j.mutateRequest(requestID, []policyRequestState{policyStateNotifying}, func(record *policyRequestRecord) error {
		if record.Mode != policyModeHosted {
			return errPolicyConflict
		}
		record.State = policyStatePending
		return nil
	})
}

func (j *localPolicyJournal) commitLocalVerdict(requestID, challenge string, result BaseManifestApprovalResult) (policyRequestRecord, error) {
	return j.mutateRequest(requestID, []policyRequestState{policyStatePending}, func(record *policyRequestRecord) error {
		if record.Mode != policyModeLocalTelegram || record.CallbackChallenge != challenge || result.Kind != BaseManifestResultLocalDecision {
			return errPolicyConflict
		}
		if len(result.ManifestEnvelope) != 0 || result.ErrorCode != "" || result.Retryable {
			return errors.New("policy journal: local verdict carries remote/error material")
		}
		if err := validatePolicyActor(result.ApprovedBy, maxPolicyActorBytes); err != nil {
			return err
		}
		if err := validatePolicyActor(result.OperatorAuthMethod, maxPolicyAuthMethodBytes); err != nil {
			return err
		}
		record.CallbackChallenge = "" // atomically disables every stale callback
		switch result.Status {
		case policywire.StatusApproved:
			if result.ApprovedBy == "" || result.OperatorAuthMethod == "" {
				return errors.New("policy journal: approval requires verified operator and auth method")
			}
			record.State = policyStateApprovalReceived
		case policywire.StatusDenied:
			if result.ApprovedBy == "" || result.OperatorAuthMethod == "" {
				return errors.New("policy journal: denial requires verified operator and auth method")
			}
			record.State = policyStateDenialReceived
		case policywire.StatusTimeout:
			if result.ApprovedBy != "" || result.OperatorAuthMethod != "" {
				return errors.New("policy journal: timeout cannot carry operator")
			}
			record.State = policyStateTimeoutReceived
		case policywire.StatusInterrupted:
			if result.ApprovedBy != "" || result.OperatorAuthMethod != "" {
				return errors.New("policy journal: interruption cannot carry operator")
			}
			record.State = policyStateInterruptionReceived
		default:
			return errors.New("policy journal: invalid local verdict status")
		}
		record.ApprovedBy = result.ApprovedBy
		record.OperatorAuthMethod = result.OperatorAuthMethod
		return nil
	})
}

func (j *localPolicyJournal) acknowledgeLocalVerdict(requestID string, result BaseManifestApprovalResult) error {
	if result.Kind != BaseManifestResultLocalDecision || result.ErrorCode != "" || result.Retryable || len(result.ManifestEnvelope) != 0 {
		return errPolicyConflict
	}
	record, err := j.record(requestID)
	if err != nil {
		return err
	}
	if record.Mode != policyModeLocalTelegram || record.CallbackChallenge != "" ||
		record.ApprovedBy != result.ApprovedBy || record.OperatorAuthMethod != result.OperatorAuthMethod {
		return errPolicyConflict
	}
	if !policyRecordHasVerdict(record, result.Status) {
		return errPolicyConflict
	}
	return nil
}

func policyRecordHasVerdict(record policyRequestRecord, status policywire.Status) bool {
	switch status {
	case policywire.StatusApproved:
		return record.State == policyStateApprovalReceived || record.State == policyStateApprovedMaterializing ||
			record.State == policyStateApprovedUnexposed || record.State == policyStateApproved ||
			record.State == policyStateMaterializationErrorReceived || record.State == policyStateError ||
			record.State == policyStateSignerKeyChanged || record.State == policyStateStalePolicyHead
	case policywire.StatusDenied:
		return record.State == policyStateDenialReceived || record.State == policyStateDenied
	case policywire.StatusTimeout:
		return record.State == policyStateTimeoutReceived || record.State == policyStateTimedOut
	case policywire.StatusInterrupted:
		return record.State == policyStateInterruptionReceived || record.State == policyStateInterrupted
	default:
		return false
	}
}

func (j *localPolicyJournal) markNotificationError(requestID string) (policyRequestRecord, error) {
	return j.mutateRequest(requestID, []policyRequestState{policyStateNotifying}, func(record *policyRequestRecord) error {
		if record.Mode != policyModeLocalTelegram {
			return errPolicyConflict
		}
		record.CallbackChallenge = ""
		record.FailureCode = policywire.ErrorPolicyNotificationFailed
		record.State = policyStateNotificationErrorReceived
		return nil
	})
}

func (j *localPolicyJournal) rejectReceived(requestID string, code policywire.ErrorCode) (policyRequestRecord, error) {
	if !validStoredPolicyErrorCode(code) {
		return policyRequestRecord{}, errors.New("policy journal: invalid rejection code")
	}
	return j.mutateRequest(requestID, []policyRequestState{policyStateReceivedUnaudited}, func(record *policyRequestRecord) error {
		if record.NoOp || record.FailureCode != "" {
			return errPolicyConflict
		}
		record.FailureCode = code
		return nil
	})
}

func (j *localPolicyJournal) interruptLocal(requestID string) (policyRequestRecord, error) {
	return j.mutateRequest(requestID, []policyRequestState{policyStateNotifying, policyStatePending}, func(record *policyRequestRecord) error {
		if record.Mode != policyModeLocalTelegram {
			return errPolicyConflict
		}
		record.CallbackChallenge = ""
		record.State = policyStateInterruptionReceived
		return nil
	})
}

func (j *localPolicyJournal) reconcileLocalStartup() ([]string, error) {
	var interrupted []string
	err := j.update(func(disk *policyJournalDisk) error {
		for i := range disk.Requests {
			record := &disk.Requests[i]
			if record.Mode != policyModeLocalTelegram || (record.State != policyStateNotifying && record.State != policyStatePending) {
				continue
			}
			record.CallbackChallenge = ""
			record.State = policyStateInterruptionReceived
			record.StateVersion++
			interrupted = append(interrupted, record.RequestID)
		}
		return nil
	})
	return interrupted, err
}

func (j *localPolicyJournal) recoverableRequestIDs() ([]string, error) {
	var ids []string
	err := j.view(func(disk *policyJournalDisk) error {
		for i := range disk.Requests {
			record := &disk.Requests[i]
			switch record.State {
			case policyStateNotifying, policyStatePending,
				policyStateApprovalReceived, policyStateDenialReceived, policyStateTimeoutReceived,
				policyStateInterruptionReceived, policyStateNotificationErrorReceived,
				policyStateApprovedMaterializing, policyStateApprovedUnexposed,
				policyStateMaterializationErrorReceived, policyStateHostedTerminalUnexposed:
				ids = append(ids, record.RequestID)
			}
		}
		return nil
	})
	return ids, err
}

func (j *localPolicyJournal) setApprovedMaterializing(requestID string) (policyRequestRecord, error) {
	return j.mutateRequest(requestID, []policyRequestState{policyStateApprovalReceived}, func(record *policyRequestRecord) error {
		if record.Mode != policyModeLocalTelegram {
			return errPolicyConflict
		}
		record.State = policyStateApprovedMaterializing
		return nil
	})
}

func (j *localPolicyJournal) persistApprovedUnexposed(requestID string, envelope []byte) (policyRequestRecord, error) {
	return j.mutateRequest(requestID, []policyRequestState{policyStateApprovedMaterializing, policyStatePending, policyStateNotifying}, func(record *policyRequestRecord) error {
		if record.Mode == policyModeLocalTelegram && record.State != policyStateApprovedMaterializing {
			return errPolicyConflict
		}
		if record.Mode == policyModeHosted && record.State == policyStateNotifying {
			// A hosted POST may durably finish before its local caller records the
			// polling state. Treat that terminal import as stronger than pending.
		} else if record.Mode == policyModeHosted && record.State != policyStatePending {
			return errPolicyConflict
		}
		publicKey, err := policyRequestPublicKey(record)
		if err != nil {
			return err
		}
		manifest, err := policy.VerifyBaseManifest(envelope, publicKey)
		if err != nil || manifest.Host != record.HostKeyFP || manifest.Epoch != record.Epoch || manifest.Revision != record.Revision {
			return errors.New("policy journal: approved envelope verification/metadata mismatch")
		}
		payload, _, err := policy.DecodeBaseManifestEnvelope(envelope)
		if err != nil {
			return err
		}
		expectedPayload, err := policyRequestPayload(record)
		if err != nil || !bytes.Equal(payload, expectedPayload) {
			return errors.New("policy journal: approved envelope payload substitution")
		}
		digest := sha256.Sum256(envelope)
		record.ResultEnvelopeB64 = base64.StdEncoding.EncodeToString(envelope)
		record.ResultSHA256 = hex.EncodeToString(digest[:])
		record.State = policyStateApprovedUnexposed
		return nil
	})
}

func (j *localPolicyJournal) setMaterializationError(requestID string, code policywire.ErrorCode) (policyRequestRecord, error) {
	if code != policywire.ErrorPolicyMaterializationFailed && code != policywire.ErrorSignerKeyChanged && code != policywire.ErrorStalePolicyHead {
		return policyRequestRecord{}, errors.New("policy journal: invalid materialization failure code")
	}
	return j.mutateRequest(requestID, []policyRequestState{policyStateApprovedMaterializing, policyStateApprovedUnexposed}, func(record *policyRequestRecord) error {
		if record.Mode != policyModeLocalTelegram {
			return errPolicyConflict
		}
		record.ResultEnvelopeB64 = ""
		record.ResultSHA256 = ""
		record.FailureCode = code
		record.State = policyStateMaterializationErrorReceived
		return nil
	})
}

func (j *localPolicyJournal) stageHostedTerminal(requestID string, response policywire.Response) (policyRequestRecord, error) {
	if response.Status == policywire.StatusApproved || response.Status == policywire.StatusPending {
		return policyRequestRecord{}, errors.New("policy journal: hosted non-approval terminal required")
	}
	return j.mutateRequest(requestID, []policyRequestState{policyStateNotifying, policyStatePending}, func(record *policyRequestRecord) error {
		if record.Mode != policyModeHosted {
			return errPolicyConflict
		}
		if err := validateResponseForPolicyRecord(record, response); err != nil {
			return err
		}
		record.Response = clonePolicyResponse(&response)
		if response.Status == policywire.StatusError {
			record.FailureCode = response.ErrorCode
		}
		record.State = policyStateHostedTerminalUnexposed
		return nil
	})
}

func (j *localPolicyJournal) stageHostedSignerKeyChanged(requestID string) (policyRequestRecord, error) {
	return j.mutateRequest(requestID, []policyRequestState{
		policyStateNotifying, policyStatePending, policyStateApprovedUnexposed, policyStateHostedTerminalUnexposed,
	}, func(record *policyRequestRecord) error {
		if record.Mode != policyModeHosted {
			return errPolicyConflict
		}
		record.CallbackChallenge = ""
		record.ApprovedBy = ""
		record.OperatorAuthMethod = ""
		record.Response = nil
		record.FailureCode = policywire.ErrorSignerKeyChanged
		record.State = policyStateMaterializationErrorReceived
		return nil
	})
}

func validateResponseForPolicyRecord(record *policyRequestRecord, response policywire.Response) error {
	if _, err := policywire.MarshalResponse(response); err != nil {
		return err
	}
	if response.RequestID != record.RequestID || response.Purpose != record.Purpose ||
		response.AuthorityID != record.HostedAuthorityID ||
		response.PayloadSHA256 != record.PayloadSHA256 || response.BaseDigest != record.BaseDigest ||
		response.SignerKeyID != record.ExpectedSignerKeyID {
		return errors.New("policy journal: hosted response immutable fields mismatch")
	}
	return nil
}

func (j *localPolicyJournal) finalizeNoMint(requestID string) (policyRequestRecord, error) {
	authorityID, err := j.authorityID()
	if err != nil {
		return policyRequestRecord{}, err
	}
	return j.mutateRequest(requestID, []policyRequestState{
		policyStateDenialReceived, policyStateTimeoutReceived, policyStateInterruptionReceived,
		policyStateNotificationErrorReceived, policyStateMaterializationErrorReceived,
		policyStateReceivedUnaudited, policyStateHostedTerminalUnexposed,
	}, func(record *policyRequestRecord) error {
		if record.State == policyStateHostedTerminalUnexposed {
			status := record.Response.Status
			code := record.Response.ErrorCode
			switch status {
			case policywire.StatusDenied:
				record.State = policyStateDenied
			case policywire.StatusTimeout:
				record.State = policyStateTimedOut
			case policywire.StatusInterrupted:
				// This is an authenticated terminal imported from the hosted
				// authority, not the forbidden local restart synthesis.
				record.State = policyStateInterrupted
			case policywire.StatusError:
				record.State = terminalErrorState(code)
			default:
				return errors.New("policy journal: invalid staged hosted terminal")
			}
			response, err := buildPolicyResponse(record, authorityID, status, code, nil)
			if err != nil {
				return err
			}
			record.Response = &response
			return nil
		}

		var status policywire.Status
		var code policywire.ErrorCode
		switch record.State {
		case policyStateDenialReceived:
			status = policywire.StatusDenied
			record.State = policyStateDenied
		case policyStateTimeoutReceived:
			status = policywire.StatusTimeout
			record.State = policyStateTimedOut
		case policyStateInterruptionReceived:
			status = policywire.StatusInterrupted
			record.State = policyStateInterrupted
		case policyStateNotificationErrorReceived, policyStateMaterializationErrorReceived:
			status, code = policywire.StatusError, record.FailureCode
			// A staged no-op can fail its final custody/head recheck. Its received
			// error keeps NoOp=true so the audit explains what failed; the terminal
			// error itself is no longer a no-op approval.
			record.NoOp = false
			record.State = terminalErrorState(code)
		case policyStateReceivedUnaudited:
			if record.NoOp || record.FailureCode == "" {
				return errors.New("policy journal: received request has no terminal rejection")
			}
			status, code = policywire.StatusError, record.FailureCode
			record.State = terminalErrorState(code)
		}
		response, err := buildPolicyResponse(record, authorityID, status, code, nil)
		if err != nil {
			return err
		}
		record.Response = &response
		return nil
	})
}

func terminalErrorState(code policywire.ErrorCode) policyRequestState {
	switch code {
	case policywire.ErrorSignerKeyChanged:
		return policyStateSignerKeyChanged
	case policywire.ErrorStalePolicyHead:
		return policyStateStalePolicyHead
	default:
		return policyStateError
	}
}

func buildPolicyResponse(record *policyRequestRecord, authorityID string, status policywire.Status, code policywire.ErrorCode, envelope []byte) (policywire.Response, error) {
	response := policywire.Response{
		RequestID:     record.RequestID,
		AuthorityID:   authorityID,
		Purpose:       policywire.Purpose,
		Status:        status,
		PayloadSHA256: record.PayloadSHA256,
		BaseDigest:    record.BaseDigest,
		SignerKeyID:   record.ExpectedSignerKeyID,
		ErrorCode:     code,
	}
	if status == policywire.StatusError {
		response.Retryable = code == policywire.ErrorPolicyNotificationFailed || code == policywire.ErrorPolicyMaterializationFailed
	}
	if status == policywire.StatusApproved {
		response.ManifestEnvelopeB64 = base64.StdEncoding.EncodeToString(envelope)
	}
	if _, err := policywire.MarshalResponse(response); err != nil {
		return policywire.Response{}, err
	}
	return response, nil
}

func (j *localPolicyJournal) stageNoOp(requestID string) (policyRequestRecord, error) {
	var out policyRequestRecord
	err := j.update(func(disk *policyJournalDisk) error {
		record, ok := disk.request(requestID)
		if !ok || record.Mode != policyModeLocalTelegram || record.State != policyStateReceivedUnaudited || !record.NoOp || record.FailureCode != "" {
			return errPolicyConflict
		}
		head, ok := disk.head(record.HostKeyFP)
		if !ok || head.BaseDigest != record.ExpectedHeadDigest || head.SignerKeyID != record.ExpectedSignerKeyID || head.SignerPublicKeyB64 != record.FrozenPublicKeyB64 {
			return &policyJournalError{Code: policywire.ErrorStalePolicyHead, Err: errPolicyConflict}
		}
		envelope, err := policyHeadEnvelope(head)
		if err != nil {
			return err
		}
		payload, _, err := policy.DecodeBaseManifestEnvelope(envelope)
		if err != nil {
			return err
		}
		requested, err := policyRequestPayload(record)
		if err != nil || !bytes.Equal(payload, requested) {
			return &policyJournalError{Code: policywire.ErrorStalePolicyHead, Err: errPolicyConflict}
		}
		digest := sha256.Sum256(envelope)
		record.ResultEnvelopeB64 = base64.StdEncoding.EncodeToString(envelope)
		record.ResultSHA256 = hex.EncodeToString(digest[:])
		record.State = policyStateApprovedUnexposed
		record.StateVersion++
		out = clonePolicyRecord(*record)
		return nil
	})
	return out, err
}

func (j *localPolicyJournal) commitApproved(requestID string) (policyRequestRecord, error) {
	var out policyRequestRecord
	err := j.update(func(disk *policyJournalDisk) error {
		record, ok := disk.request(requestID)
		if !ok || record.State != policyStateApprovedUnexposed {
			return errPolicyConflict
		}
		if err := verifyPolicyHeadCAS(disk, record); err != nil {
			return err
		}
		envelope, err := decodeJournalBytes(record.ResultEnvelopeB64, 1, policy.MaxPolicyEnvelopeBytes)
		if err != nil {
			return err
		}
		publicKey, err := policyRequestPublicKey(record)
		if err != nil {
			return err
		}
		manifest, err := policy.VerifyBaseManifest(envelope, publicKey)
		if err != nil {
			return err
		}
		head := policyHeadRecord{
			Host:                record.HostKeyFP,
			ManifestEnvelopeB64: record.ResultEnvelopeB64,
			BaseDigest:          record.BaseDigest,
			Epoch:               manifest.Epoch,
			Revision:            manifest.Revision,
			SignerKeyID:         record.ExpectedSignerKeyID,
			SignerPublicKeyB64:  record.FrozenPublicKeyB64,
		}
		idx := disk.headIndex(record.HostKeyFP)
		if idx < len(disk.Heads) && disk.Heads[idx].Host == record.HostKeyFP {
			disk.Heads[idx] = head
		} else {
			disk.Heads = append(disk.Heads, policyHeadRecord{})
			copy(disk.Heads[idx+1:], disk.Heads[idx:])
			disk.Heads[idx] = head
		}
		response, err := buildPolicyResponse(record, disk.AuthorityID, policywire.StatusApproved, "", envelope)
		if err != nil {
			return err
		}
		record.Response = &response
		record.ResultEnvelopeB64 = ""
		record.State = policyStateApproved
		record.StateVersion++
		out = clonePolicyRecord(*record)
		return nil
	})
	return out, err
}

func verifyPolicyHeadCAS(disk *policyJournalDisk, record *policyRequestRecord) error {
	if record.Mode == policyModeHosted {
		// The P6 service is the authority for hosted lineage. This snapshot is a
		// verified continuity mirror only; a missing/stale mirror must never make
		// a new hosted ID short-circuit or contradict the remote terminal result.
		return nil
	}
	head, hasHead := disk.head(record.HostKeyFP)
	if record.Bootstrap {
		if hasHead || record.ExpectedHeadDigest != "" {
			return &policyJournalError{Code: policywire.ErrorStalePolicyHead, Err: errPolicyConflict}
		}
		return nil
	}
	if !hasHead || head.BaseDigest != record.ExpectedHeadDigest || head.SignerKeyID != record.ExpectedSignerKeyID || head.SignerPublicKeyB64 != record.FrozenPublicKeyB64 {
		return &policyJournalError{Code: policywire.ErrorStalePolicyHead, Err: errPolicyConflict}
	}
	return nil
}
