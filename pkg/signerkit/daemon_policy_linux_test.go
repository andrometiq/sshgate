//go:build linux

package signerkit

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/karthikeyan5/sshgate/src/policy"
	"github.com/karthikeyan5/sshgate/src/policywire"
)

type localPolicyTestBackend struct {
	StubBackend
	mu       sync.Mutex
	requests []BaseManifestApprovalRequest
	status   policywire.Status
}

type hostedPolicyTestBackend struct {
	StubBackend
	private      ed25519.PrivateKey
	mu           sync.Mutex
	requests     int
	stallFirst   bool
	firstStarted chan struct{}
}

func (*hostedPolicyTestBackend) HostedBaseManifestAuthority() {}

func (b *hostedPolicyTestBackend) BaseManifestAuthorityPublicKey() ([]byte, error) {
	return append([]byte(nil), b.private.Public().(ed25519.PublicKey)...), nil
}

func (b *hostedPolicyTestBackend) RequestBaseManifest(_ context.Context, request BaseManifestApprovalRequest) (<-chan BaseManifestApprovalResult, error) {
	b.mu.Lock()
	b.requests++
	call := b.requests
	b.mu.Unlock()
	if request.DecisionHooks != nil || len(request.FrozenPublicKey) != ed25519.PublicKeySize {
		return nil, errors.New("hosted request carried local hooks or missing frozen key")
	}
	if b.stallFirst && call == 1 {
		close(b.firstStarted)
		return make(chan BaseManifestApprovalResult), nil
	}
	manifest, err := policy.ParseBaseManifest(request.Payload)
	if err != nil {
		return nil, err
	}
	envelope, err := policy.SignBaseManifest(b.private, manifest)
	if err != nil {
		return nil, err
	}
	ch := make(chan BaseManifestApprovalResult, 1)
	ch <- BaseManifestApprovalResult{Status: policywire.StatusApproved, Kind: BaseManifestResultRemoteEnvelope, ManifestEnvelope: envelope}
	close(ch)
	return ch, nil
}

func (b *hostedPolicyTestBackend) requestCount() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.requests
}

func (b *localPolicyTestBackend) RequestBaseManifest(ctx context.Context, request BaseManifestApprovalRequest) (<-chan BaseManifestApprovalResult, error) {
	b.mu.Lock()
	b.requests = append(b.requests, request)
	b.mu.Unlock()
	if request.DecisionHooks == nil {
		return nil, errors.New("missing durable decision hooks")
	}
	if err := request.DecisionHooks.Activate(ctx); err != nil {
		return nil, err
	}
	result := BaseManifestApprovalResult{Status: b.status, Kind: BaseManifestResultLocalDecision}
	if b.status == policywire.StatusApproved || b.status == policywire.StatusDenied {
		result.ApprovedBy = "operator-1"
		result.OperatorAuthMethod = "telegram"
	}
	if err := request.DecisionHooks.CommitVerdict(ctx, result); err != nil {
		return nil, err
	}
	if err := request.DecisionHooks.AcknowledgeVerdict(ctx, result); err != nil {
		return nil, err
	}
	ch := make(chan BaseManifestApprovalResult, 1)
	ch <- result
	close(ch)
	return ch, nil
}

func (b *localPolicyTestBackend) requestCount() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return len(b.requests)
}

type policyAuditAttempt struct {
	phase      string
	eventID    string
	resultSHA  string
	headDigest string
	outcome    string
	failed     bool
}

type policyTestAuditSink struct {
	mu             sync.Mutex
	attempts       []policyAuditAttempt
	failPhase      string
	failOccurrence int
	phaseCounts    map[string]int
}

func (s *policyTestAuditSink) record(metadata *PolicyAuditMetadata) error {
	if metadata == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.phaseCounts == nil {
		s.phaseCounts = make(map[string]int)
	}
	s.phaseCounts[metadata.Phase]++
	failed := metadata.Phase == s.failPhase && s.phaseCounts[metadata.Phase] == s.failOccurrence
	s.attempts = append(s.attempts, policyAuditAttempt{
		phase: metadata.Phase, eventID: metadata.EventID, resultSHA: metadata.ResultSHA256,
		headDigest: metadata.HeadDigest, outcome: metadata.Outcome, failed: failed,
	})
	if failed {
		return errors.New("injected policy audit failure")
	}
	return nil
}

func (s *policyTestAuditSink) Call(_ context.Context, event AuditCall) error {
	return s.record(event.Policy)
}

func (s *policyTestAuditSink) Verdict(_ context.Context, event AuditVerdict) error {
	return s.record(event.Policy)
}

func (s *policyTestAuditSink) disableFailure() {
	s.mu.Lock()
	s.failPhase = ""
	s.mu.Unlock()
}

func (s *policyTestAuditSink) idsForPhase(phase string) []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	var ids []string
	for _, attempt := range s.attempts {
		if attempt.phase == phase {
			ids = append(ids, attempt.eventID)
		}
	}
	return ids
}

func (s *policyTestAuditSink) attemptsForPhase(phase string) []policyAuditAttempt {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []policyAuditAttempt
	for _, attempt := range s.attempts {
		if attempt.phase == phase {
			out = append(out, attempt)
		}
	}
	return out
}

type countingPolicySigner struct {
	private ed25519.PrivateKey
	mu      sync.Mutex
	count   int
}

func (s *countingPolicySigner) Public() crypto.PublicKey { return s.private.Public() }

func (s *countingPolicySigner) Sign(random io.Reader, message []byte, opts crypto.SignerOpts) ([]byte, error) {
	s.mu.Lock()
	s.count++
	s.mu.Unlock()
	return s.private.Sign(random, message, opts)
}

func (s *countingPolicySigner) signCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.count
}

func policyRequestLineForTest(t testing.TB, private ed25519.PrivateKey, requestID string) []byte {
	t.Helper()
	host := testPolicyFingerprint(0x42)
	manifest := testBootstrapManifest(host)
	decoded := testPolicyDecoded(t, private, requestID, host, manifest, "", true)
	line, err := policywire.MarshalRequestLine(decoded.Wire)
	if err != nil {
		t.Fatal(err)
	}
	return line
}

func runPolicyRequest(t testing.TB, service *Service, line []byte) ([]byte, error) {
	t.Helper()
	conn := &rwBuf{in: bytes.NewReader(line), out: &bytes.Buffer{}}
	err := service.HandleSignRequest(context.Background(), conn)
	return append([]byte(nil), conn.out.Bytes()...), err
}

func TestDaemonPolicyLocalApprovalAndLostResponseAreIdempotent(t *testing.T) {
	_, private, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	backend := &localPolicyTestBackend{status: policywire.StatusApproved}
	sink := &policyTestAuditSink{}
	service, err := New(Config{
		Signer: private, Backend: backend, Audit: sink,
		PolicyJournalRoot: t.TempDir() + "/policy-requests",
		NowFunc:           func() time.Time { return time.Unix(100, 0) },
	})
	if err != nil {
		t.Fatal(err)
	}
	defer service.Close()
	line := policyRequestLineForTest(t, private, "pm_10000000000000000000000000000001")
	first, err := runPolicyRequest(t, service, line)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := policywire.DecodeResponseLine(first)
	if err != nil || decoded.Wire.Status != policywire.StatusApproved {
		t.Fatalf("approved response = %#v, %v", decoded, err)
	}
	second, err := runPolicyRequest(t, service, line)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(first, second) {
		t.Fatalf("lost-response retry changed bytes:\nfirst=%q\nsecond=%q", first, second)
	}
	if backend.requestCount() != 1 {
		t.Fatalf("backend prompted %d times; want 1", backend.requestCount())
	}
	for _, phase := range []string{policyAuditPhaseSubmission, policyAuditPhaseHumanVerdict, policyAuditPhaseMaterialization} {
		if len(sink.idsForPhase(phase)) == 0 {
			t.Fatalf("missing %s audit", phase)
		}
	}
	host := testPolicyFingerprint(0x42)
	changed := testBootstrapManifest(host)
	changed.MissAction = policy.MissActionDeny
	conflict := testPolicyDecoded(t, private, "pm_10000000000000000000000000000001", host, changed, "", true)
	conflictLine, err := policywire.MarshalRequestLine(conflict.Wire)
	if err != nil {
		t.Fatal(err)
	}
	conflictResponse, err := runPolicyRequest(t, service, conflictLine)
	if err != nil {
		t.Fatal(err)
	}
	conflictDecoded, err := policywire.DecodeResponseLine(conflictResponse)
	if err != nil || conflictDecoded.Wire.ErrorCode != policywire.ErrorIdempotencyConflict {
		t.Fatalf("same-ID changed-tuple response = %#v, %v", conflictDecoded, err)
	}
	if backend.requestCount() != 1 {
		t.Fatalf("same-ID conflict re-prompted backend: %d", backend.requestCount())
	}
}

func TestServicePolicyDispatchPrecedesOrdinaryAuditAndBackendGuards(t *testing.T) {
	_, private, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	sink := &policyTestAuditSink{}
	service, err := New(Config{Signer: private, Audit: sink}) // no ordinary Backend, no *AuditLog
	if err != nil {
		t.Fatal(err)
	}
	line := policyRequestLineForTest(t, private, "pm_54000000000000000000000000000001")
	response, err := runPolicyRequest(t, service, line)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := policywire.DecodeResponseLine(response)
	if err != nil || decoded.Wire.ErrorCode != policywire.ErrorPolicyNotSupported {
		t.Fatalf("policy dispatch response = %#v, %v", decoded, err)
	}
	if len(sink.idsForPhase(policyAuditPhaseSubmission)) != 1 || len(sink.idsForPhase(policyAuditPhaseTerminalNoMint)) != 1 {
		t.Fatal("policy request did not use dedicated fail-closed audit before ordinary guards")
	}

	malformed := append([]byte(" "), line...)
	badResponse, err := runPolicyRequest(t, service, malformed)
	if err == nil || len(badResponse) != 0 {
		t.Fatalf("noncanonical policy frame response=%q err=%v", badResponse, err)
	}
	truncatedResponse, err := runPolicyRequest(t, service, line[:len(line)/2])
	if err == nil || len(truncatedResponse) != 0 {
		t.Fatalf("truncated policy frame response=%q err=%v", truncatedResponse, err)
	}
}

func TestUnsupportedPolicyAuditFailureExposesNoTypedTerminal(t *testing.T) {
	_, private, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	sink := &policyTestAuditSink{failPhase: policyAuditPhaseSubmission, failOccurrence: 1}
	service, err := New(Config{Signer: private, Audit: sink})
	if err != nil {
		t.Fatal(err)
	}
	line := policyRequestLineForTest(t, private, "pm_54000000000000000000000000000002")
	response, err := runPolicyRequest(t, service, line)
	if err == nil || len(response) != 0 {
		t.Fatalf("audit-failed unsupported policy response=%q err=%v", response, err)
	}
}

func TestHostedPendingCancellationRemainsResumableAndRepostsSameID(t *testing.T) {
	_, private, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	backend := &hostedPolicyTestBackend{private: private, stallFirst: true, firstStarted: make(chan struct{})}
	sink := &policyTestAuditSink{}
	service, err := New(Config{Signer: private, Backend: backend, Audit: sink, PolicyJournalRoot: t.TempDir() + "/policy-requests"})
	if err != nil {
		t.Fatal(err)
	}
	defer service.Close()
	line := policyRequestLineForTest(t, private, "pm_55000000000000000000000000000001")
	ctx, cancel := context.WithCancel(context.Background())
	conn := &rwBuf{in: bytes.NewReader(line), out: &bytes.Buffer{}}
	firstDone := make(chan error, 1)
	go func() { firstDone <- service.HandleSignRequest(ctx, conn) }()
	<-backend.firstStarted
	cancel()
	if err := <-firstDone; err == nil || conn.out.Len() != 0 {
		t.Fatalf("canceled hosted pending response=%q err=%v", conn.out.Bytes(), err)
	}
	record, err := service.daemon.policyJournal.record("pm_55000000000000000000000000000001")
	if err != nil || record.State != policyStatePending || record.Mode != policyModeHosted {
		t.Fatalf("hosted pending was synthesized away: %#v, %v", record, err)
	}
	response, err := runPolicyRequest(t, service, line)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := policywire.DecodeResponseLine(response)
	if err != nil || decoded.Wire.Status != policywire.StatusApproved {
		t.Fatalf("hosted resumed response = %#v, %v", decoded, err)
	}
	if backend.requestCount() != 2 {
		t.Fatalf("hosted POST/poll attempts = %d; want 2", backend.requestCount())
	}
}

func TestPolicyJournalUnsafeStartupFailsBeforeServiceConstruction(t *testing.T) {
	_, private, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	parent := t.TempDir()
	target := t.TempDir()
	link := parent + "/policy-requests"
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if service, err := New(Config{Signer: private, Audit: &policyTestAuditSink{}, PolicyJournalRoot: link}); err == nil || service != nil {
		t.Fatalf("unsafe symlink journal constructed service=%v err=%v", service, err)
	}

	root := parent + "/real-policy-requests"
	journal, err := openLocalPolicyJournal(root)
	if err != nil {
		t.Fatal(err)
	}
	if err := journal.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(root+"/"+policyJournalFile, 0o644); err != nil {
		t.Fatal(err)
	}
	if service, err := New(Config{Signer: private, Audit: &policyTestAuditSink{}, PolicyJournalRoot: root}); err == nil || service != nil {
		t.Fatalf("insecure-mode journal constructed service=%v err=%v", service, err)
	}
}

func TestPolicyRecoveryAuditFailureDisablesOnlyPolicyPath(t *testing.T) {
	publicKey, private, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	root := t.TempDir() + "/policy-requests"
	journal, err := openLocalPolicyJournal(root)
	if err != nil {
		t.Fatal(err)
	}
	host := testPolicyFingerprint(0x56)
	decoded := testPolicyDecoded(t, private, "pm_56000000000000000000000000000001", host, testBootstrapManifest(host), "", true)
	if _, err := journal.begin(decoded, policyModeLocalTelegram, publicKey, time.Unix(300, 0)); err != nil {
		t.Fatal(err)
	}
	if _, err := journal.markNotifying(decoded.Wire.RequestID, "5656565656565656"); err != nil {
		t.Fatal(err)
	}
	if _, err := journal.activateLocal(decoded.Wire.RequestID, "5656565656565656"); err != nil {
		t.Fatal(err)
	}
	if err := journal.Close(); err != nil {
		t.Fatal(err)
	}

	sink := &policyTestAuditSink{failPhase: policyAuditPhaseHumanVerdict, failOccurrence: 1}
	backend := &localPolicyTestBackend{status: policywire.StatusApproved}
	service, err := New(Config{Signer: private, Backend: backend, Audit: sink, PolicyJournalRoot: root})
	if err != nil {
		t.Fatal(err)
	}
	defer service.Close()
	if service.PolicyRecoveryError() == nil {
		t.Fatal("startup reconciliation audit failure did not disable policy")
	}

	ordinaryAudit, err := NewMemAuditLog()
	if err != nil {
		t.Fatal(err)
	}
	defer ordinaryAudit.Close()
	service.daemon.Audit = ordinaryAudit
	ordinary := []byte(`{"kind":"sign","request_id":"ordinary","commands":[{"server":"srv","cmd":"true","ttl_seconds":60}]}` + "\n")
	ordinaryConn := &rwBuf{in: bytes.NewReader(ordinary), out: &bytes.Buffer{}}
	if err := service.HandleSignRequest(context.Background(), ordinaryConn); err != nil {
		t.Fatalf("ordinary frozen path was globally disabled: %v", err)
	}
	var ordinaryResponse signResponse
	if err := json.Unmarshal(bytes.TrimSpace(ordinaryConn.out.Bytes()), &ordinaryResponse); err != nil || ordinaryResponse.Status != "denied" {
		t.Fatalf("ordinary response = %#v, %v", ordinaryResponse, err)
	}

	sink.disableFailure()
	line, err := policywire.MarshalRequestLine(decoded.Wire)
	if err != nil {
		t.Fatal(err)
	}
	response, err := runPolicyRequest(t, service, line)
	if err != nil {
		t.Fatal(err)
	}
	policyResponse, err := policywire.DecodeResponseLine(response)
	if err != nil || policyResponse.Wire.Status != policywire.StatusInterrupted {
		t.Fatalf("recovered policy interruption = %#v, %v", policyResponse, err)
	}
	if backend.requestCount() != 0 {
		t.Fatalf("startup pending recovery re-prompted %d times", backend.requestCount())
	}
}

func TestDaemonPolicyJournalFullIsAuditedBeforeTypedRejectionAndNeverPrompts(t *testing.T) {
	journal, root := testPolicyJournal(t)
	publicKey, private, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	host := testPolicyFingerprint(0x57)
	manifest := testBootstrapManifest(host)
	decoded := testPolicyDecoded(t, private, "pm_57000000000000000000000000000001", host, manifest, "", true)
	if _, err := journal.begin(decoded, policyModeLocalTelegram, publicKey, time.Unix(400, 0)); err != nil {
		t.Fatal(err)
	}
	challenge := "5757575757575757"
	if _, err := journal.markNotifying(decoded.Wire.RequestID, challenge); err != nil {
		t.Fatal(err)
	}
	if _, err := journal.activateLocal(decoded.Wire.RequestID, challenge); err != nil {
		t.Fatal(err)
	}
	verdict := BaseManifestApprovalResult{Status: policywire.StatusApproved, Kind: BaseManifestResultLocalDecision, ApprovedBy: "operator", OperatorAuthMethod: "telegram"}
	if _, err := journal.commitLocalVerdict(decoded.Wire.RequestID, challenge, verdict); err != nil {
		t.Fatal(err)
	}
	if _, err := journal.setApprovedMaterializing(decoded.Wire.RequestID); err != nil {
		t.Fatal(err)
	}
	envelope, err := policy.SignBaseManifest(private, manifest)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := journal.persistApprovedUnexposed(decoded.Wire.RequestID, envelope); err != nil {
		t.Fatal(err)
	}
	if _, err := journal.commitApproved(decoded.Wire.RequestID); err != nil {
		t.Fatal(err)
	}
	var full policyJournalDisk
	if err := journal.view(func(disk *policyJournalDisk) error {
		full.Schema, full.AuthorityID = disk.Schema, disk.AuthorityID
		full.Heads = append([]policyHeadRecord(nil), disk.Heads...)
		template := clonePolicyRecord(disk.Requests[0])
		full.Requests = make([]policyRequestRecord, maxPolicyRequests)
		for i := range full.Requests {
			record := clonePolicyRecord(template)
			record.RequestID = fmt.Sprintf("pm_%032x", i+1)
			record.SubmittedUnixNano += int64(i)
			record.TupleDigest = policyTupleDigest(&record)
			record.Response.RequestID = record.RequestID
			full.Requests[i] = record
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if err := validatePolicyJournal(&full); err != nil {
		t.Fatalf("constructed full journal invalid: %v", err)
	}
	body, err := json.Marshal(full)
	if err != nil {
		t.Fatal(err)
	}
	if err := journal.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(root+"/"+policyJournalFile, body, 0o600); err != nil {
		t.Fatal(err)
	}

	backend := &localPolicyTestBackend{status: policywire.StatusApproved}
	sink := &policyTestAuditSink{failPhase: policyAuditPhaseTerminalNoMint, failOccurrence: 1}
	service, err := New(Config{Signer: private, Backend: backend, Audit: sink, PolicyJournalRoot: root})
	if err != nil {
		t.Fatal(err)
	}
	defer service.Close()
	newHost := testPolicyFingerprint(0x58)
	newRequest := testPolicyDecoded(t, private, "pm_ffffffffffffffffffffffffffffffff", newHost, testBootstrapManifest(newHost), "", true)
	line, err := policywire.MarshalRequestLine(newRequest.Wire)
	if err != nil {
		t.Fatal(err)
	}
	firstResponse, err := runPolicyRequest(t, service, line)
	if err == nil || len(firstResponse) != 0 {
		t.Fatalf("audit-failed journal-full response=%q err=%v", firstResponse, err)
	}
	if backend.requestCount() != 0 {
		t.Fatalf("audit-failed journal-full request prompted %d times", backend.requestCount())
	}
	sink.disableFailure()
	response, err := runPolicyRequest(t, service, line)
	if err != nil {
		t.Fatal(err)
	}
	result, err := policywire.DecodeResponseLine(response)
	if err != nil || result.Wire.ErrorCode != policywire.ErrorPolicyJournalFull {
		t.Fatalf("journal-full response = %#v, %v", result, err)
	}
	if backend.requestCount() != 0 {
		t.Fatalf("journal-full request prompted %d times", backend.requestCount())
	}
	submissionIDs := sink.idsForPhase(policyAuditPhaseSubmission)
	terminalIDs := sink.idsForPhase(policyAuditPhaseTerminalNoMint)
	if len(submissionIDs) != 2 || submissionIDs[0] != submissionIDs[1] || len(terminalIDs) != 2 || terminalIDs[0] != terminalIDs[1] {
		t.Fatal("journal-full rejection was not fully audited")
	}
}

func TestDaemonPolicyAuditFailureBeforeSubmissionNeverPromptsAndRetriesSameEvent(t *testing.T) {
	_, private, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	backend := &localPolicyTestBackend{status: policywire.StatusApproved}
	sink := &policyTestAuditSink{failPhase: policyAuditPhaseSubmission, failOccurrence: 1}
	service, err := New(Config{Signer: private, Backend: backend, Audit: sink, PolicyJournalRoot: t.TempDir() + "/policy-requests"})
	if err != nil {
		t.Fatal(err)
	}
	defer service.Close()
	line := policyRequestLineForTest(t, private, "pm_10000000000000000000000000000002")
	first, err := runPolicyRequest(t, service, line)
	if err == nil || len(first) != 0 || backend.requestCount() != 0 {
		t.Fatalf("submission audit failure: response=%q err=%v prompts=%d", first, err, backend.requestCount())
	}
	sink.disableFailure()
	second, err := runPolicyRequest(t, service, line)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := policywire.DecodeResponseLine(second); err != nil {
		t.Fatal(err)
	}
	ids := sink.idsForPhase(policyAuditPhaseSubmission)
	if len(ids) < 2 || ids[0] != ids[1] {
		t.Fatalf("submission retry event IDs = %v; want identical", ids)
	}
	if backend.requestCount() != 1 {
		t.Fatalf("backend prompted %d times; want 1", backend.requestCount())
	}
}

func TestDaemonPolicyApprovedUnexposedAuditRetryDoesNotRemint(t *testing.T) {
	_, private, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	signer := &countingPolicySigner{private: private}
	backend := &localPolicyTestBackend{status: policywire.StatusApproved}
	sink := &policyTestAuditSink{failPhase: policyAuditPhaseMaterialization, failOccurrence: 2}
	service, err := New(Config{Signer: signer, Backend: backend, Audit: sink, PolicyJournalRoot: t.TempDir() + "/policy-requests"})
	if err != nil {
		t.Fatal(err)
	}
	defer service.Close()
	line := policyRequestLineForTest(t, private, "pm_10000000000000000000000000000003")
	first, err := runPolicyRequest(t, service, line)
	if err == nil || len(first) != 0 || signer.signCount() != 1 {
		t.Fatalf("post-mint audit failure: response=%q err=%v mints=%d", first, err, signer.signCount())
	}
	sink.disableFailure()
	second, err := runPolicyRequest(t, service, line)
	if err != nil {
		t.Fatal(err)
	}
	if decoded, err := policywire.DecodeResponseLine(second); err != nil || decoded.Wire.Status != policywire.StatusApproved {
		t.Fatalf("recovered response = %#v, %v", decoded, err)
	}
	if signer.signCount() != 1 || backend.requestCount() != 1 {
		t.Fatalf("recovery reminted/reprompted: mints=%d prompts=%d", signer.signCount(), backend.requestCount())
	}
	ids := sink.idsForPhase(policyAuditPhaseMaterialization)
	if len(ids) < 3 || ids[1] != ids[2] {
		t.Fatalf("unexposed result retry event IDs = %v; want failed/retry IDs equal", ids)
	}
}

func TestDaemonPolicyVerdictAndPreMintAuditFailuresStayUnexposed(t *testing.T) {
	for _, phase := range []string{policyAuditPhaseHumanVerdict, policyAuditPhaseMaterialization} {
		t.Run(phase, func(t *testing.T) {
			_, private, err := ed25519.GenerateKey(nil)
			if err != nil {
				t.Fatal(err)
			}
			signer := &countingPolicySigner{private: private}
			backend := &localPolicyTestBackend{status: policywire.StatusApproved}
			sink := &policyTestAuditSink{failPhase: phase, failOccurrence: 1}
			service, err := New(Config{Signer: signer, Backend: backend, Audit: sink, PolicyJournalRoot: t.TempDir() + "/policy-requests"})
			if err != nil {
				t.Fatal(err)
			}
			defer service.Close()
			line := policyRequestLineForTest(t, private, "pm_53000000000000000000000000000001")
			first, err := runPolicyRequest(t, service, line)
			if err == nil || len(first) != 0 || signer.signCount() != 0 {
				t.Fatalf("%s audit failure: response=%q err=%v mints=%d", phase, first, err, signer.signCount())
			}
			sink.disableFailure()
			second, err := runPolicyRequest(t, service, line)
			if err != nil {
				t.Fatal(err)
			}
			decoded, err := policywire.DecodeResponseLine(second)
			if err != nil || decoded.Wire.Status != policywire.StatusApproved {
				t.Fatalf("recovered response = %#v, %v", decoded, err)
			}
			if signer.signCount() != 1 || backend.requestCount() != 1 {
				t.Fatalf("recovery counts: mints=%d prompts=%d", signer.signCount(), backend.requestCount())
			}
			ids := sink.idsForPhase(phase)
			if len(ids) < 2 || ids[0] != ids[1] {
				t.Fatalf("%s retry event IDs = %v", phase, ids)
			}
		})
	}
}

func TestDaemonPolicyTerminalNoMintAuditFailureDoesNotExposeDenial(t *testing.T) {
	_, private, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	backend := &localPolicyTestBackend{status: policywire.StatusDenied}
	sink := &policyTestAuditSink{failPhase: policyAuditPhaseTerminalNoMint, failOccurrence: 1}
	service, err := New(Config{Signer: private, Backend: backend, Audit: sink, PolicyJournalRoot: t.TempDir() + "/policy-requests"})
	if err != nil {
		t.Fatal(err)
	}
	defer service.Close()
	line := policyRequestLineForTest(t, private, "pm_10000000000000000000000000000004")
	first, err := runPolicyRequest(t, service, line)
	if err == nil || len(first) != 0 {
		t.Fatalf("terminal audit failure exposed response=%q err=%v", first, err)
	}
	sink.disableFailure()
	second, err := runPolicyRequest(t, service, line)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := policywire.DecodeResponseLine(second)
	if err != nil || decoded.Wire.Status != policywire.StatusDenied {
		t.Fatalf("recovered denial = %#v, %v", decoded, err)
	}
	if backend.requestCount() != 1 {
		t.Fatalf("denial retry prompted %d times", backend.requestCount())
	}
}

func TestPolicyAuditEventIDSeparatesPrincipalAndLengthBoundaries(t *testing.T) {
	base := PolicyAuditMetadata{
		Purpose: policywire.Purpose, Principal: "ab", RequestID: "c", TupleDigest: "d",
		Phase: policyAuditPhaseSubmission, StateVersion: 1,
	}
	first := policyAuditEventID(base)
	const golden = "8464c8cb354ab7048425ec8c85cd57d83f8b8f9aef2980960d6184a8ff857cd3"
	if first != golden {
		t.Fatalf("policy audit event-id golden drifted: got %q want %q", first, golden)
	}
	secondInput := base
	secondInput.Principal = "a"
	secondInput.RequestID = "bc"
	second := policyAuditEventID(secondInput)
	if first == second || len(first) != 64 || len(second) != 64 {
		t.Fatalf("length-delimited event ids collided/invalid: %q %q", first, second)
	}
	if first != policyAuditEventID(base) {
		t.Fatal("event id is not deterministic")
	}
}

func TestPolicyApprovedExposurePinsCustodyAgainstConcurrentRotation(t *testing.T) {
	journal, _ := testPolicyJournal(t)
	publicKey, private, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	host := testPolicyFingerprint(0x52)
	manifest := testBootstrapManifest(host)
	decoded := testPolicyDecoded(t, private, "pm_52000000000000000000000000000001", host, manifest, "", true)
	if _, err := journal.begin(decoded, policyModeLocalTelegram, publicKey, time.Unix(200, 0)); err != nil {
		t.Fatal(err)
	}
	challenge := "5252525252525252"
	if _, err := journal.markNotifying(decoded.Wire.RequestID, challenge); err != nil {
		t.Fatal(err)
	}
	if _, err := journal.activateLocal(decoded.Wire.RequestID, challenge); err != nil {
		t.Fatal(err)
	}
	verdict := BaseManifestApprovalResult{Status: policywire.StatusApproved, Kind: BaseManifestResultLocalDecision, ApprovedBy: "operator", OperatorAuthMethod: "telegram"}
	if _, err := journal.commitLocalVerdict(decoded.Wire.RequestID, challenge, verdict); err != nil {
		t.Fatal(err)
	}
	if _, err := journal.setApprovedMaterializing(decoded.Wire.RequestID); err != nil {
		t.Fatal(err)
	}
	envelope, err := policy.SignBaseManifest(private, manifest)
	if err != nil {
		t.Fatal(err)
	}
	record, err := journal.persistApprovedUnexposed(decoded.Wire.RequestID, envelope)
	if err != nil {
		t.Fatal(err)
	}

	entered := make(chan struct{})
	release := make(chan struct{})
	daemon := &Daemon{Signer: private, policyJournal: journal, policyBeforeCommit: func() {
		close(entered)
		<-release
	}}
	commitDone := make(chan error, 1)
	go func() {
		_, err := daemon.commitLocalPolicyApprovedUnderCustody(decoded.Wire.RequestID, record)
		commitDone <- err
	}()
	<-entered
	_, rotatedPrivate, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	rotateDone := make(chan error, 1)
	go func() { rotateDone <- daemon.RotateTo(rotatedPrivate) }()
	select {
	case err := <-rotateDone:
		t.Fatalf("rotation crossed uncommitted approved exposure: %v", err)
	case <-time.After(50 * time.Millisecond):
	}
	close(release)
	if err := <-commitDone; err != nil {
		t.Fatal(err)
	}
	if err := <-rotateDone; err != nil {
		t.Fatal(err)
	}
	terminal, err := journal.record(decoded.Wire.RequestID)
	if err != nil || terminal.State != policyStateApproved {
		t.Fatalf("terminal after linearized commit/rotation = %#v, %v", terminal, err)
	}
}

func TestPolicyRecoveryUsesSameFlightAsActiveApproval(t *testing.T) {
	_, private, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	signer := &countingPolicySigner{private: private}
	backend := &localPolicyTestBackend{status: policywire.StatusApproved}
	sink := &policyTestAuditSink{}
	service, err := New(Config{
		Signer: signer, Backend: backend, Audit: sink,
		PolicyJournalRoot: t.TempDir() + "/policy-requests",
		NowFunc:           func() time.Time { return time.Unix(300, 0) },
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = service.Close() })

	entered := make(chan struct{})
	release := make(chan struct{})
	service.daemon.policyBeforeCommit = func() {
		close(entered)
		<-release
	}
	line := policyRequestLineForTest(t, private, "pm_53000000000000000000000000000001")
	type result struct {
		body []byte
		err  error
	}
	run := func(done chan<- result) {
		conn := &rwBuf{in: bytes.NewReader(line), out: &bytes.Buffer{}}
		err := service.HandleSignRequest(context.Background(), conn)
		done <- result{body: append([]byte(nil), conn.out.Bytes()...), err: err}
	}
	firstDone := make(chan result, 1)
	go run(firstDone)
	select {
	case <-entered:
	case <-time.After(3 * time.Second):
		t.Fatal("active approval did not reach pinned commit")
	}
	secondDone := make(chan result, 1)
	go run(secondDone)
	select {
	case got := <-secondDone:
		t.Fatalf("same-ID retry escaped active flight early: %#v", got)
	case <-time.After(50 * time.Millisecond):
	}
	close(release)
	first := <-firstDone
	second := <-secondDone
	if first.err != nil || second.err != nil {
		t.Fatalf("active/retry errors = %v / %v", first.err, second.err)
	}
	if !bytes.Equal(first.body, second.body) {
		t.Fatalf("joined retry response mismatch:\nfirst  %q\nsecond %q", first.body, second.body)
	}
	if backend.requestCount() != 1 || signer.signCount() != 1 {
		t.Fatalf("flight arbitration duplicated decision/mint: backend=%d signs=%d", backend.requestCount(), signer.signCount())
	}
	if got := len(sink.attemptsForPhase(policyAuditPhaseMaterialization)); got != 2 {
		t.Fatalf("materialization audit attempts = %d; want pre-mint + result only", got)
	}
}

func TestPolicyNoOpAuditBindsResultAndPinsCustodyThroughCommit(t *testing.T) {
	_, private, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	backend := &localPolicyTestBackend{status: policywire.StatusApproved}
	sink := &policyTestAuditSink{}
	service, err := New(Config{
		Signer: private, Backend: backend, Audit: sink,
		PolicyJournalRoot: t.TempDir() + "/policy-requests",
		NowFunc:           func() time.Time { return time.Unix(400, 0) },
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = service.Close() })
	host := testPolicyFingerprint(0x53)
	manifest := testBootstrapManifest(host)
	bootstrap := testPolicyDecoded(t, private, "pm_53000000000000000000000000000002", host, manifest, "", true)
	bootstrapLine, err := policywire.MarshalRequestLine(bootstrap.Wire)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := runPolicyRequest(t, service, bootstrapLine); err != nil {
		t.Fatal(err)
	}
	_, headDigest, err := policywire.PayloadDigests(bootstrap.Payload)
	if err != nil {
		t.Fatal(err)
	}

	// A stale caller value must never be reported as the trusted signer head.
	staleDigest := strings.Repeat("f", 64)
	if staleDigest == headDigest {
		staleDigest = strings.Repeat("e", 64)
	}
	stale := testPolicyDecoded(t, private, "pm_53000000000000000000000000000003", host, manifest, staleDigest, false)
	staleLine, err := policywire.MarshalRequestLine(stale.Wire)
	if err != nil {
		t.Fatal(err)
	}
	staleBody, err := runPolicyRequest(t, service, staleLine)
	if err != nil {
		t.Fatal(err)
	}
	staleResponse, err := policywire.DecodeResponseLine(staleBody)
	if err != nil || staleResponse.Wire.ErrorCode != policywire.ErrorStalePolicyHead {
		t.Fatalf("stale response = %#v, %v", staleResponse, err)
	}
	terminalAttempts := sink.attemptsForPhase(policyAuditPhaseTerminalNoMint)
	if got := terminalAttempts[len(terminalAttempts)-1].headDigest; got != headDigest {
		t.Fatalf("stale audit trusted head = %q; want actual %q (caller sent %q)", got, headDigest, staleDigest)
	}

	noOp := testPolicyDecoded(t, private, "pm_53000000000000000000000000000004", host, manifest, headDigest, false)
	noOpLine, err := policywire.MarshalRequestLine(noOp.Wire)
	if err != nil {
		t.Fatal(err)
	}
	entered := make(chan struct{})
	release := make(chan struct{})
	service.daemon.policyBeforeCommit = func() {
		close(entered)
		<-release
	}
	type result struct {
		body []byte
		err  error
	}
	done := make(chan result, 1)
	go func() {
		body, err := runPolicyRequest(t, service, noOpLine)
		done <- result{body: body, err: err}
	}()
	select {
	case <-entered:
	case <-time.After(3 * time.Second):
		t.Fatal("no-op did not reach pinned commit")
	}
	_, rotated, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	rotateDone := make(chan error, 1)
	go func() { rotateDone <- service.RotateTo(rotated) }()
	select {
	case err := <-rotateDone:
		t.Fatalf("rotation crossed no-op audit/commit: %v", err)
	case <-time.After(50 * time.Millisecond):
	}
	close(release)
	noOpResult := <-done
	if noOpResult.err != nil {
		t.Fatal(noOpResult.err)
	}
	if err := <-rotateDone; err != nil {
		t.Fatal(err)
	}
	decodedNoOp, err := policywire.DecodeResponseLine(noOpResult.body)
	if err != nil || decodedNoOp.Wire.Status != policywire.StatusApproved {
		t.Fatalf("no-op response = %#v, %v", decodedNoOp, err)
	}
	terminalAttempts = sink.attemptsForPhase(policyAuditPhaseTerminalNoMint)
	last := terminalAttempts[len(terminalAttempts)-1]
	if last.outcome != "approved-no-op" || len(last.resultSHA) != 64 || last.headDigest != headDigest {
		t.Fatalf("no-op terminal audit = %#v; want result-bound trusted-head event", last)
	}
	if backend.requestCount() != 1 {
		t.Fatalf("no-op prompted backend; request count = %d", backend.requestCount())
	}
	// ID-first terminal replay remains byte-identical after the later rotation.
	replayed, err := runPolicyRequest(t, service, noOpLine)
	if err != nil || !bytes.Equal(replayed, noOpResult.body) {
		t.Fatalf("rotated no-op replay = %q, %v; want %q", replayed, err, noOpResult.body)
	}
}

func TestExistingPolicyNonterminalNeverGetsEphemeralUnsupportedTerminal(t *testing.T) {
	publicKey, private, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	backend := &localPolicyTestBackend{status: policywire.StatusApproved}
	sink := &policyTestAuditSink{}
	service, err := New(Config{
		Signer: private, Backend: backend, Audit: sink,
		PolicyJournalRoot: t.TempDir() + "/policy-requests",
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = service.Close() })
	host := testPolicyFingerprint(0x54)
	manifest := testBootstrapManifest(host)
	decoded := testPolicyDecoded(t, private, "pm_54000000000000000000000000000003", host, manifest, "", true)
	if _, err := service.daemon.policyJournal.begin(decoded, policyModeLocalTelegram, publicKey, time.Unix(500, 0)); err != nil {
		t.Fatal(err)
	}
	line, err := policywire.MarshalRequestLine(decoded.Wire)
	if err != nil {
		t.Fatal(err)
	}
	service.daemon.Backend = StubBackend{}
	body, err := runPolicyRequest(t, service, line)
	if err == nil || len(body) != 0 {
		t.Fatalf("missing backend response=%q err=%v; want transport-unavailable", body, err)
	}
	record, err := service.daemon.policyJournal.record(decoded.Wire.RequestID)
	if err != nil || record.State != policyStateReceivedUnaudited || record.Response != nil {
		t.Fatalf("missing backend changed durable request = %#v, %v", record, err)
	}
	if got := len(sink.attempts); got != 0 {
		t.Fatalf("missing backend fabricated audit/terminal attempts: %d", got)
	}
	service.daemon.Backend = backend
	body, err = runPolicyRequest(t, service, line)
	if err != nil {
		t.Fatal(err)
	}
	approved, err := policywire.DecodeResponseLine(body)
	if err != nil || approved.Wire.Status != policywire.StatusApproved {
		t.Fatalf("restored backend response = %#v, %v", approved, err)
	}
}

var _ Backend = (*localPolicyTestBackend)(nil)
var _ BaseManifestApprovalBackend = (*localPolicyTestBackend)(nil)
var _ crypto.Signer = (*countingPolicySigner)(nil)
