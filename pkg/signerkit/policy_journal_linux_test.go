//go:build linux

package signerkit

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/karthikeyan5/sshgate/internal/securestate"
	"github.com/karthikeyan5/sshgate/src/policy"
	"github.com/karthikeyan5/sshgate/src/policywire"
)

func testPolicyJournal(t testing.TB) (*localPolicyJournal, string) {
	t.Helper()
	root := filepath.Join(t.TempDir(), "policy-requests")
	journal, err := openLocalPolicyJournal(root)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = journal.Close() })
	return journal, root
}

func testPolicyFingerprint(fill byte) string {
	return "SHA256:" + base64.RawStdEncoding.EncodeToString(bytes.Repeat([]byte{fill}, 32))
}

func testPolicyDecoded(t testing.TB, privateKey ed25519.PrivateKey, requestID, host string, manifest policy.BaseManifest, expectedHead string, bootstrap bool) policywire.DecodedRequest {
	t.Helper()
	payload, err := policy.MarshalBaseManifest(manifest)
	if err != nil {
		t.Fatal(err)
	}
	keyID, err := policy.SignerKeyID(privateKey.Public().(ed25519.PublicKey))
	if err != nil {
		t.Fatal(err)
	}
	wire, err := policywire.NewRequest(requestID, host, keyID, payload, expectedHead, bootstrap)
	if err != nil {
		t.Fatal(err)
	}
	body, err := policywire.MarshalRequest(wire)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := policywire.DecodeRequest(body)
	if err != nil {
		t.Fatal(err)
	}
	return decoded
}

func testBootstrapManifest(host string) policy.BaseManifest {
	return policy.BaseManifest{
		Schema: policy.SchemaV1, Host: host, Epoch: 1, Revision: 1,
		MissAction: policy.MissActionClassifier, Growth: policy.GrowthNone,
	}
}

func TestPolicyJournalStableAuthorityAndExactOwnerModes(t *testing.T) {
	journal, root := testPolicyJournal(t)
	var first string
	if err := journal.view(func(disk *policyJournalDisk) error {
		first = disk.AuthorityID
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if err := journal.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := openLocalPolicyJournal(root)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	var second string
	if err := reopened.view(func(disk *policyJournalDisk) error {
		second = disk.AuthorityID
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if first == "" || first != second {
		t.Fatalf("authority id changed across reopen: %q -> %q", first, second)
	}
	rootInfo, err := os.Stat(root)
	if err != nil || rootInfo.Mode().Perm() != 0o700 {
		t.Fatalf("journal root mode = %v, %v; want 0700", rootInfo.Mode(), err)
	}
	fileInfo, err := os.Stat(filepath.Join(root, policyJournalFile))
	if err != nil || fileInfo.Mode().Perm() != 0o600 {
		t.Fatalf("authority snapshot mode = %v, %v; want 0600", fileInfo.Mode(), err)
	}
}

func TestPolicyJournalRejectsInvalidAuthorityIDPrefix(t *testing.T) {
	disk := policyJournalDisk{
		Schema:      policyJournalSchema,
		AuthorityID: "XAUTH_" + strings.Repeat("a", 32),
		Heads:       []policyHeadRecord{},
		Requests:    []policyRequestRecord{},
	}
	if err := validatePolicyJournal(&disk); err == nil || err.Error() != "policy journal: invalid authority_id" {
		t.Fatalf("validatePolicyJournal() error = %v; want policy journal: invalid authority_id", err)
	}
}

func TestPolicyJournalReopenRejectsCorruptHostedAuthorityPair(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mutate func(*policyRequestRecord)
	}{
		{name: "missing authority", mutate: func(record *policyRequestRecord) { record.HostedAuthorityID = "" }},
		{name: "malformed authority", mutate: func(record *policyRequestRecord) { record.HostedAuthorityID = "pauth_ABC" }},
		{name: "derived key id", mutate: func(record *policyRequestRecord) { record.ExpectedSignerKeyID = strings.Repeat("0", 64) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			journal, root := testPolicyJournal(t)
			publicKey, privateKey, err := ed25519.GenerateKey(nil)
			if err != nil {
				t.Fatal(err)
			}
			host := testPolicyFingerprint(0x19)
			decoded := testPolicyDecoded(t, privateKey, "pm_19000000000000000000000000000001", host, testBootstrapManifest(host), "", true)
			if _, err := journal.begin(decoded, policyModeHosted, publicKey, time.Unix(19, 0), policyTestHostedAuthorityID); err != nil {
				t.Fatal(err)
			}
			var disk policyJournalDisk
			if err := journal.view(func(current *policyJournalDisk) error {
				disk = *current
				disk.Heads = append([]policyHeadRecord(nil), current.Heads...)
				disk.Requests = append([]policyRequestRecord(nil), current.Requests...)
				return nil
			}); err != nil {
				t.Fatal(err)
			}
			tc.mutate(&disk.Requests[0])
			body, err := json.Marshal(disk)
			if err != nil {
				t.Fatal(err)
			}
			if err := journal.Close(); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(root, policyJournalFile), body, 0o600); err != nil {
				t.Fatal(err)
			}
			if reopened, err := openLocalPolicyJournal(root); err == nil {
				reopened.Close()
				t.Fatal("corrupt hosted authority pair reopened")
			}
		})
	}
}

func TestPolicyJournalLocalApprovalIsDurableAndIdempotent(t *testing.T) {
	journal, _ := testPolicyJournal(t)
	publicKey, privateKey, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	host := testPolicyFingerprint(1)
	manifest := testBootstrapManifest(host)
	decoded := testPolicyDecoded(t, privateKey, "pm_00000000000000000000000000000001", host, manifest, "", true)

	begin, err := journal.begin(decoded, policyModeLocalTelegram, publicKey, time.Unix(10, 0))
	if err != nil || begin.Record.State != policyStateReceivedUnaudited || begin.Record.StateVersion != 1 {
		t.Fatalf("begin = %#v, %v", begin, err)
	}
	challenge := "0123456789abcdef"
	if _, err := journal.markNotifying(decoded.Wire.RequestID, challenge); err != nil {
		t.Fatal(err)
	}
	if _, err := journal.activateLocal(decoded.Wire.RequestID, challenge); err != nil {
		t.Fatal(err)
	}
	verdict := BaseManifestApprovalResult{
		Status: policywire.StatusApproved, Kind: BaseManifestResultLocalDecision,
		ApprovedBy: "operator-1", OperatorAuthMethod: "telegram",
	}
	if _, err := journal.commitLocalVerdict(decoded.Wire.RequestID, challenge, verdict); err != nil {
		t.Fatal(err)
	}
	if err := journal.acknowledgeLocalVerdict(decoded.Wire.RequestID, verdict); err != nil {
		t.Fatal(err)
	}
	if _, err := journal.setApprovedMaterializing(decoded.Wire.RequestID); err != nil {
		t.Fatal(err)
	}
	envelope, err := policy.SignBaseManifest(privateKey, manifest)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := journal.persistApprovedUnexposed(decoded.Wire.RequestID, envelope); err != nil {
		t.Fatal(err)
	}
	terminal, err := journal.commitApproved(decoded.Wire.RequestID)
	if err != nil {
		t.Fatal(err)
	}
	if terminal.State != policyStateApproved || terminal.Response == nil || terminal.Response.Status != policywire.StatusApproved {
		t.Fatalf("terminal record = %#v", terminal)
	}

	retry, found, err := journal.lookup(decoded)
	if err != nil || !found || retry.Terminal == nil {
		t.Fatalf("terminal retry = %#v, found=%t, err=%v", retry, found, err)
	}
	firstBytes, err := policywire.MarshalResponse(*terminal.Response)
	if err != nil {
		t.Fatal(err)
	}
	retryBytes, err := policywire.MarshalResponse(*retry.Terminal)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(firstBytes, retryBytes) {
		t.Fatalf("cached response changed: %q != %q", firstBytes, retryBytes)
	}
	rotatedPublic, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	rotatedRetry, err := journal.begin(decoded, policyModeLocalTelegram, rotatedPublic, time.Unix(11, 0))
	if err != nil || rotatedRetry.Terminal == nil {
		t.Fatalf("terminal replay lost to current-key rotation: %#v, %v", rotatedRetry, err)
	}
}

func TestPolicyJournalTrustedHeadEnvelopeIsExactAndLocalOnly(t *testing.T) {
	journal, _ := testPolicyJournal(t)
	publicKey, privateKey, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	host := testPolicyFingerprint(0x31)
	bootstrap := testBootstrapManifest(host)
	first := testPolicyDecoded(t, privateKey, "pm_31000000000000000000000000000001", host, bootstrap, "", true)
	if _, err := journal.begin(first, policyModeLocalTelegram, publicKey, time.Unix(10, 0)); err != nil {
		t.Fatal(err)
	}
	if got, err := journal.trustedHeadEnvelopeForRequest(first.Wire.RequestID); err != nil || got != nil {
		t.Fatalf("bootstrap predecessor = %x, %v; want nil", got, err)
	}
	challenge := "3131313131313131"
	if _, err := journal.markNotifying(first.Wire.RequestID, challenge); err != nil {
		t.Fatal(err)
	}
	if _, err := journal.activateLocal(first.Wire.RequestID, challenge); err != nil {
		t.Fatal(err)
	}
	approved := BaseManifestApprovalResult{Status: policywire.StatusApproved, Kind: BaseManifestResultLocalDecision, ApprovedBy: "id:1", OperatorAuthMethod: "telegram"}
	if _, err := journal.commitLocalVerdict(first.Wire.RequestID, challenge, approved); err != nil {
		t.Fatal(err)
	}
	if _, err := journal.setApprovedMaterializing(first.Wire.RequestID); err != nil {
		t.Fatal(err)
	}
	envelope, err := policy.SignBaseManifest(privateKey, bootstrap)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := journal.persistApprovedUnexposed(first.Wire.RequestID, envelope); err != nil {
		t.Fatal(err)
	}
	if _, err := journal.commitApproved(first.Wire.RequestID); err != nil {
		t.Fatal(err)
	}
	payload, _, err := policy.DecodeBaseManifestEnvelope(envelope)
	if err != nil {
		t.Fatal(err)
	}
	_, headDigest, err := policywire.PayloadDigests(payload)
	if err != nil {
		t.Fatal(err)
	}
	successor := bootstrap
	successor.Revision = 2
	successor.MissAction = policy.MissActionDeny
	second := testPolicyDecoded(t, privateKey, "pm_31000000000000000000000000000002", host, successor, headDigest, false)
	if _, err := journal.begin(second, policyModeLocalTelegram, publicKey, time.Unix(11, 0)); err != nil {
		t.Fatal(err)
	}
	got, err := journal.trustedHeadEnvelopeForRequest(second.Wire.RequestID)
	if err != nil || !bytes.Equal(got, envelope) {
		t.Fatalf("local predecessor changed: equal=%t err=%v", bytes.Equal(got, envelope), err)
	}
	secondChallenge := "3232323232323232"
	if _, err := journal.markNotifying(second.Wire.RequestID, secondChallenge); err != nil {
		t.Fatal(err)
	}
	if _, err := journal.activateLocal(second.Wire.RequestID, secondChallenge); err != nil {
		t.Fatal(err)
	}
	denied := BaseManifestApprovalResult{Status: policywire.StatusDenied, Kind: BaseManifestResultLocalDecision, ApprovedBy: "id:1", OperatorAuthMethod: "telegram"}
	if _, err := journal.commitLocalVerdict(second.Wire.RequestID, secondChallenge, denied); err != nil {
		t.Fatal(err)
	}
	if _, err := journal.finalizeNoMint(second.Wire.RequestID); err != nil {
		t.Fatal(err)
	}
	third := testPolicyDecoded(t, privateKey, "pm_31000000000000000000000000000003", host, successor, headDigest, false)
	if _, err := journal.begin(third, policyModeHosted, publicKey, time.Unix(12, 0), policyTestHostedAuthorityID); err != nil {
		t.Fatal(err)
	}
	if got, err := journal.trustedHeadEnvelopeForRequest(third.Wire.RequestID); err != nil || got != nil {
		t.Fatalf("hosted request received local predecessor = %x, %v", got, err)
	}
}

func TestPolicyJournalSameIDConflictAndOneNonterminalPerHost(t *testing.T) {
	journal, _ := testPolicyJournal(t)
	publicKey, privateKey, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	host := testPolicyFingerprint(2)
	manifest := testBootstrapManifest(host)
	first := testPolicyDecoded(t, privateKey, "pm_00000000000000000000000000000002", host, manifest, "", true)
	if _, err := journal.begin(first, policyModeLocalTelegram, publicKey, time.Unix(20, 0)); err != nil {
		t.Fatal(err)
	}

	changed := manifest
	changed.MissAction = policy.MissActionDeny
	conflict := testPolicyDecoded(t, privateKey, first.Wire.RequestID, host, changed, "", true)
	if _, _, err := journal.lookup(conflict); err == nil {
		t.Fatal("same request id with changed payload did not conflict")
	} else {
		var protocolErr *policyJournalError
		if !errors.As(err, &protocolErr) || protocolErr.Code != policywire.ErrorIdempotencyConflict {
			t.Fatalf("conflict error = %v", err)
		}
	}

	second := testPolicyDecoded(t, privateKey, "pm_00000000000000000000000000000003", host, manifest, "", true)
	if _, err := journal.begin(second, policyModeLocalTelegram, publicKey, time.Unix(21, 0)); err == nil {
		t.Fatal("second nonterminal request for host was accepted")
	} else {
		var protocolErr *policyJournalError
		if !errors.As(err, &protocolErr) || protocolErr.Code != policywire.ErrorPolicyRequestInProgress {
			t.Fatalf("second request error = %v", err)
		}
	}
}

func TestPolicyJournalRestartInterruptsOnlyLocalPromptedStates(t *testing.T) {
	journal, _ := testPolicyJournal(t)
	publicKey, privateKey, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	makeRequest := func(id string, fill byte, mode policyRequestMode) policywire.DecodedRequest {
		host := testPolicyFingerprint(fill)
		decoded := testPolicyDecoded(t, privateKey, id, host, testBootstrapManifest(host), "", true)
		hostedAuthorityID := ""
		if mode == policyModeHosted {
			hostedAuthorityID = policyTestHostedAuthorityID
		}
		if _, err := journal.begin(decoded, mode, publicKey, time.Unix(int64(fill), 0), hostedAuthorityID); err != nil {
			t.Fatal(err)
		}
		return decoded
	}
	received := makeRequest("pm_00000000000000000000000000000004", 4, policyModeLocalTelegram)
	local := makeRequest("pm_00000000000000000000000000000005", 5, policyModeLocalTelegram)
	hosted := makeRequest("pm_00000000000000000000000000000006", 6, policyModeHosted)
	if _, err := journal.markNotifying(local.Wire.RequestID, "1111111111111111"); err != nil {
		t.Fatal(err)
	}
	if _, err := journal.activateLocal(local.Wire.RequestID, "1111111111111111"); err != nil {
		t.Fatal(err)
	}
	if _, err := journal.markNotifying(hosted.Wire.RequestID, ""); err != nil {
		t.Fatal(err)
	}
	beforeHostedPending, err := journal.recoverableRequestIDs()
	if err != nil || len(beforeHostedPending) != 2 || beforeHostedPending[0] != local.Wire.RequestID || beforeHostedPending[1] != hosted.Wire.RequestID {
		t.Fatalf("recoverable IDs with hosted notifying = %v, %v", beforeHostedPending, err)
	}
	if _, err := journal.activateHosted(hosted.Wire.RequestID); err != nil {
		t.Fatal(err)
	}
	ids, err := journal.reconcileLocalStartup()
	if err != nil {
		t.Fatal(err)
	}
	if len(ids) != 1 || ids[0] != local.Wire.RequestID {
		t.Fatalf("interrupted ids = %v", ids)
	}
	for _, check := range []struct {
		id   string
		want policyRequestState
	}{{received.Wire.RequestID, policyStateReceivedUnaudited}, {local.Wire.RequestID, policyStateInterruptionReceived}, {hosted.Wire.RequestID, policyStatePending}} {
		record, err := journal.record(check.id)
		if err != nil || record.State != check.want {
			t.Fatalf("record %s state = %s, %v; want %s", check.id, record.State, err, check.want)
		}
	}
	recoverable, err := journal.recoverableRequestIDs()
	if err != nil || len(recoverable) != 2 || recoverable[0] != local.Wire.RequestID || recoverable[1] != hosted.Wire.RequestID {
		t.Fatalf("recoverable IDs after startup = %v, %v", recoverable, err)
	}
}

func TestPolicyJournalHostedNewIDNeverTrustsLocalMirrorForNoOpOrStaleDecision(t *testing.T) {
	journal, _ := testPolicyJournal(t)
	publicKey, privateKey, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	host := testPolicyFingerprint(0x61)
	manifest := testBootstrapManifest(host)
	bootstrap := testPolicyDecoded(t, privateKey, "pm_61000000000000000000000000000001", host, manifest, "", true)
	if _, err := journal.begin(bootstrap, policyModeLocalTelegram, publicKey, time.Unix(61, 0)); err != nil {
		t.Fatal(err)
	}
	if _, err := journal.markNotifying(bootstrap.Wire.RequestID, "6161616161616161"); err != nil {
		t.Fatal(err)
	}
	if _, err := journal.activateLocal(bootstrap.Wire.RequestID, "6161616161616161"); err != nil {
		t.Fatal(err)
	}
	verdict := BaseManifestApprovalResult{Status: policywire.StatusApproved, Kind: BaseManifestResultLocalDecision, ApprovedBy: "operator", OperatorAuthMethod: "telegram"}
	if _, err := journal.commitLocalVerdict(bootstrap.Wire.RequestID, "6161616161616161", verdict); err != nil {
		t.Fatal(err)
	}
	if _, err := journal.setApprovedMaterializing(bootstrap.Wire.RequestID); err != nil {
		t.Fatal(err)
	}
	envelope, err := policy.SignBaseManifest(privateKey, manifest)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := journal.persistApprovedUnexposed(bootstrap.Wire.RequestID, envelope); err != nil {
		t.Fatal(err)
	}
	terminal, err := journal.commitApproved(bootstrap.Wire.RequestID)
	if err != nil {
		t.Fatal(err)
	}

	newID := testPolicyDecoded(t, privateKey, "pm_61000000000000000000000000000002", host, manifest, terminal.BaseDigest, false)
	begin, err := journal.begin(newID, policyModeHosted, publicKey, time.Unix(62, 0), policyTestHostedAuthorityID)
	if err != nil {
		t.Fatal(err)
	}
	if begin.Record.NoOp || begin.Record.FailureCode != "" {
		t.Fatalf("hosted new ID trusted local mirror: no_op=%t failure=%q", begin.Record.NoOp, begin.Record.FailureCode)
	}
	if err := journal.update(func(disk *policyJournalDisk) error {
		record, _ := disk.request(newID.Wire.RequestID)
		record.NoOp = true
		return nil
	}); err == nil {
		t.Fatal("hosted received record accepted local no-op classification corruption")
	}
	if _, err := journal.markNotifying(newID.Wire.RequestID, ""); err != nil {
		t.Fatal(err)
	}
	if _, err := journal.activateHosted(newID.Wire.RequestID); err != nil {
		t.Fatal(err)
	}
	if _, err := journal.persistApprovedUnexposed(newID.Wire.RequestID, envelope); err != nil {
		t.Fatal(err)
	}
	if _, err := journal.commitApproved(newID.Wire.RequestID); err != nil {
		t.Fatal(err)
	}
	if err := journal.update(func(disk *policyJournalDisk) error {
		record, _ := disk.request(newID.Wire.RequestID)
		record.NoOp = true
		return nil
	}); err == nil {
		t.Fatal("hosted approved terminal accepted local no-op classification corruption")
	}

	staleJournal, _ := testPolicyJournal(t)
	staleHost := testPolicyFingerprint(0x62)
	staleManifest := testBootstrapManifest(staleHost)
	staleBootstrap := testPolicyDecoded(t, privateKey, "pm_62000000000000000000000000000001", staleHost, staleManifest, "", true)
	if _, err := staleJournal.begin(staleBootstrap, policyModeLocalTelegram, publicKey, time.Unix(63, 0)); err != nil {
		t.Fatal(err)
	}
	if _, err := staleJournal.markNotifying(staleBootstrap.Wire.RequestID, "6262626262626262"); err != nil {
		t.Fatal(err)
	}
	if _, err := staleJournal.activateLocal(staleBootstrap.Wire.RequestID, "6262626262626262"); err != nil {
		t.Fatal(err)
	}
	if _, err := staleJournal.commitLocalVerdict(staleBootstrap.Wire.RequestID, "6262626262626262", verdict); err != nil {
		t.Fatal(err)
	}
	if _, err := staleJournal.setApprovedMaterializing(staleBootstrap.Wire.RequestID); err != nil {
		t.Fatal(err)
	}
	staleEnvelope, err := policy.SignBaseManifest(privateKey, staleManifest)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := staleJournal.persistApprovedUnexposed(staleBootstrap.Wire.RequestID, staleEnvelope); err != nil {
		t.Fatal(err)
	}
	if _, err := staleJournal.commitApproved(staleBootstrap.Wire.RequestID); err != nil {
		t.Fatal(err)
	}
	staleManifest.Revision++
	staleNewID := testPolicyDecoded(t, privateKey, "pm_62000000000000000000000000000002", staleHost, staleManifest, strings.Repeat("a", 64), false)
	staleBegin, err := staleJournal.begin(staleNewID, policyModeHosted, publicKey, time.Unix(64, 0), policyTestHostedAuthorityID)
	if err != nil {
		t.Fatal(err)
	}
	if staleBegin.Record.NoOp || staleBegin.Record.FailureCode != "" {
		t.Fatalf("hosted new ID trusted stale local head: no_op=%t failure=%q", staleBegin.Record.NoOp, staleBegin.Record.FailureCode)
	}
}

func TestPolicyJournalImportsAuthenticatedHostedInterruptedTerminal(t *testing.T) {
	journal, _ := testPolicyJournal(t)
	publicKey, privateKey, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	host := testPolicyFingerprint(0x63)
	manifest := testBootstrapManifest(host)
	decoded := testPolicyDecoded(t, privateKey, "pm_63000000000000000000000000000001", host, manifest, "", true)
	begin, err := journal.begin(decoded, policyModeHosted, publicKey, time.Unix(65, 0), policyTestHostedAuthorityID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := journal.markNotifying(decoded.Wire.RequestID, ""); err != nil {
		t.Fatal(err)
	}
	response := policywire.Response{
		RequestID: decoded.Wire.RequestID, AuthorityID: policyTestHostedAuthorityID, Purpose: policywire.Purpose, Status: policywire.StatusInterrupted,
		PayloadSHA256: begin.Record.PayloadSHA256, BaseDigest: begin.Record.BaseDigest,
		SignerKeyID: begin.Record.ExpectedSignerKeyID,
	}
	if _, err := journal.stageHostedTerminal(decoded.Wire.RequestID, response); err != nil {
		t.Fatal(err)
	}
	terminal, err := journal.finalizeNoMint(decoded.Wire.RequestID)
	if err != nil {
		t.Fatal(err)
	}
	localAuthorityID, err := journal.authorityID()
	if err != nil {
		t.Fatal(err)
	}
	if terminal.State != policyStateInterrupted || terminal.Response == nil || terminal.Response.Status != policywire.StatusInterrupted ||
		terminal.Response.AuthorityID != localAuthorityID || terminal.Response.AuthorityID == terminal.HostedAuthorityID {
		t.Fatalf("authenticated hosted interruption was not preserved: %#v", terminal)
	}
}

func TestPolicyJournalRejectsCallbackCollisionWithoutMutatingSecondRequest(t *testing.T) {
	journal, _ := testPolicyJournal(t)
	publicKey, privateKey, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	ids := []string{"pm_62000000000000000000000000000001", "pm_62000000000000000000000000000002"}
	for i, id := range ids {
		host := testPolicyFingerprint(byte(0x62 + i))
		decoded := testPolicyDecoded(t, privateKey, id, host, testBootstrapManifest(host), "", true)
		if _, err := journal.begin(decoded, policyModeLocalTelegram, publicKey, time.Unix(70+int64(i), 0)); err != nil {
			t.Fatal(err)
		}
	}
	challenge := "6262626262626262"
	if _, err := journal.markNotifying(ids[0], challenge); err != nil {
		t.Fatal(err)
	}
	if _, err := journal.markNotifying(ids[1], challenge); err == nil {
		t.Fatal("duplicate active callback challenge accepted")
	}
	second, err := journal.record(ids[1])
	if err != nil || second.State != policyStateReceivedUnaudited || second.CallbackChallenge != "" {
		t.Fatalf("collision mutated second request: %#v, %v", second, err)
	}
}

func TestPolicyJournalOpenRejectsCanonicalTwoNonterminalsForOneHost(t *testing.T) {
	journal, root := testPolicyJournal(t)
	publicKey, privateKey, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	host := testPolicyFingerprint(0x64)
	decoded := testPolicyDecoded(t, privateKey, "pm_64000000000000000000000000000001", host, testBootstrapManifest(host), "", true)
	if _, err := journal.begin(decoded, policyModeLocalTelegram, publicKey, time.Unix(80, 0)); err != nil {
		t.Fatal(err)
	}
	var hostile policyJournalDisk
	if err := journal.view(func(disk *policyJournalDisk) error {
		hostile = *disk
		hostile.Heads = append([]policyHeadRecord(nil), disk.Heads...)
		hostile.Requests = append([]policyRequestRecord(nil), disk.Requests...)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	duplicate := hostile.Requests[0]
	duplicate.RequestID = "pm_64000000000000000000000000000002"
	duplicate.TupleDigest = policyTupleDigest(&duplicate)
	hostile.Requests = append(hostile.Requests, duplicate)
	sortPolicyJournal(&hostile)
	body, err := json.Marshal(hostile)
	if err != nil {
		t.Fatal(err)
	}
	if err := journal.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, policyJournalFile), body, 0o600); err != nil {
		t.Fatal(err)
	}
	if reopened, err := openLocalPolicyJournal(root); err == nil {
		reopened.Close()
		t.Fatal("canonical hostile snapshot with two host nonterminals opened")
	}
}

func TestPolicyJournalStrictStateFieldsRejectUnsafeVerdictWithoutMutation(t *testing.T) {
	journal, _ := testPolicyJournal(t)
	publicKey, privateKey, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	host := testPolicyFingerprint(7)
	decoded := testPolicyDecoded(t, privateKey, "pm_00000000000000000000000000000007", host, testBootstrapManifest(host), "", true)
	if _, err := journal.begin(decoded, policyModeLocalTelegram, publicKey, time.Unix(30, 0)); err != nil {
		t.Fatal(err)
	}
	challenge := "2222222222222222"
	if _, err := journal.markNotifying(decoded.Wire.RequestID, challenge); err != nil {
		t.Fatal(err)
	}
	if _, err := journal.activateLocal(decoded.Wire.RequestID, challenge); err != nil {
		t.Fatal(err)
	}
	bad := BaseManifestApprovalResult{
		Status: policywire.StatusApproved, Kind: BaseManifestResultLocalDecision,
		ApprovedBy: strings.Repeat("x", maxPolicyActorBytes+1), OperatorAuthMethod: "telegram",
	}
	if _, err := journal.commitLocalVerdict(decoded.Wire.RequestID, challenge, bad); err == nil {
		t.Fatal("oversized operator was persisted")
	}
	record, err := journal.record(decoded.Wire.RequestID)
	if err != nil || record.State != policyStatePending || record.CallbackChallenge != challenge {
		t.Fatalf("failed verdict mutated durable pending state: %#v, %v", record, err)
	}

	if err := journal.update(func(disk *policyJournalDisk) error {
		record, _ := disk.request(decoded.Wire.RequestID)
		record.Response = &policywire.Response{}
		return nil
	}); err == nil {
		t.Fatal("state-specific response corruption was accepted")
	}
	good := BaseManifestApprovalResult{Status: policywire.StatusApproved, Kind: BaseManifestResultLocalDecision, ApprovedBy: "operator", OperatorAuthMethod: "telegram"}
	if _, err := journal.commitLocalVerdict(decoded.Wire.RequestID, challenge, good); err != nil {
		t.Fatal(err)
	}
	badAck := good
	badAck.Retryable = true
	if err := journal.acknowledgeLocalVerdict(decoded.Wire.RequestID, badAck); err == nil {
		t.Fatal("verdict acknowledgement accepted contradictory retryable shape")
	}
	badAck = good
	badAck.Kind = BaseManifestResultRemoteEnvelope
	if err := journal.acknowledgeLocalVerdict(decoded.Wire.RequestID, badAck); err == nil {
		t.Fatal("verdict acknowledgement accepted remote custody kind")
	}
	if err := journal.acknowledgeLocalVerdict(decoded.Wire.RequestID, good); err != nil {
		t.Fatalf("exact verdict acknowledgement failed: %v", err)
	}
	if err := journal.update(func(disk *policyJournalDisk) error {
		record, _ := disk.request(decoded.Wire.RequestID)
		record.OperatorAuthMethod = ""
		return nil
	}); err == nil {
		t.Fatal("approval_received without verified auth method was accepted")
	}
}

func TestPolicyJournalReviewAndTerminalReserveBounds(t *testing.T) {
	if policyTerminalReserve <= 2*policy.MaxPolicyEnvelopeBytes {
		t.Fatalf("terminal reserve %d did not account for base64 JSON expansion", policyTerminalReserve)
	}
	_, privateKey, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	host := testPolicyFingerprint(8)
	manifest := testBootstrapManifest(host)
	for i := 0; i < maxBootstrapEntries+1; i++ {
		identity, err := policy.NewShellExactIdentity([]byte("true"))
		if err != nil {
			t.Fatal(err)
		}
		manifest.Entries = append(manifest.Entries, policy.BaseEntry{
			ID:       "pa_oob_" + strings.Repeat(string("0123456789abcdef"[i%16]), 32),
			Identity: identity, Source: policy.EntrySourceOutOfBand,
		})
	}
	// Make IDs unique while preserving their frozen random-looking grammar.
	for i := range manifest.Entries {
		manifest.Entries[i].ID = "pa_oob_" + strings.Repeat("0", 30) + string("0123456789abcdef"[i/16]) + string("0123456789abcdef"[i%16])
	}
	decoded := testPolicyDecoded(t, privateKey, "pm_00000000000000000000000000000008", host, manifest, "", true)
	publicKey := privateKey.Public().(ed25519.PublicKey)
	journal, _ := testPolicyJournal(t)
	begin, err := journal.begin(decoded, policyModeLocalTelegram, publicKey, time.Unix(40, 0))
	if err != nil {
		t.Fatal(err)
	}
	if begin.Record.FailureCode != policywire.ErrorInvalidPolicyRequest {
		t.Fatalf("oversized full review failure = %q", begin.Record.FailureCode)
	}
}

func TestPolicyCandidateBootstrapSuccessorAndTombstoneMatrix(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	host := testPolicyFingerprint(0x73)
	identityA, err := policy.NewShellExactIdentity([]byte("echo alpha"))
	if err != nil {
		t.Fatal(err)
	}
	identityB, err := policy.NewShellExactIdentity([]byte("echo beta"))
	if err != nil {
		t.Fatal(err)
	}
	entryA := policy.BaseEntry{ID: "pa_oob_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", Identity: identityA, Source: policy.EntrySourceOutOfBand}
	entryB := policy.BaseEntry{ID: "pa_oob_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", Identity: identityB, Source: policy.EntrySourceOutOfBand}
	headManifest := testBootstrapManifest(host)
	headManifest.Entries = []policy.BaseEntry{entryA}
	headManifest.RevokedPermitIDs = []string{"pa_old_dead"}
	headEnvelope, err := policy.SignBaseManifest(privateKey, headManifest)
	if err != nil {
		t.Fatal(err)
	}
	headPayload, _, err := policy.DecodeBaseManifestEnvelope(headEnvelope)
	if err != nil {
		t.Fatal(err)
	}
	_, headDigest, err := policywire.PayloadDigests(headPayload)
	if err != nil {
		t.Fatal(err)
	}
	keyID, err := policy.SignerKeyID(publicKey)
	if err != nil {
		t.Fatal(err)
	}
	head := &policyHeadRecord{
		Host: host, ManifestEnvelopeB64: base64.StdEncoding.EncodeToString(headEnvelope), BaseDigest: headDigest,
		Epoch: headManifest.Epoch, Revision: headManifest.Revision, SignerKeyID: keyID,
		SignerPublicKeyB64: base64.StdEncoding.EncodeToString(publicKey),
	}

	nextID := 0
	classify := func(t *testing.T, candidate policy.BaseManifest, expected string, bootstrap bool, key ed25519.PrivateKey, current ed25519.PublicKey, currentHead *policyHeadRecord, hasHead bool) (bool, policywire.ErrorCode) {
		t.Helper()
		nextID++
		requestID := fmt.Sprintf("pm_%032x", nextID)
		decoded := testPolicyDecoded(t, key, requestID, host, candidate, expected, bootstrap)
		return classifyPolicyCandidate(decoded, currentHead, hasHead, current)
	}
	clone := func(m policy.BaseManifest) policy.BaseManifest {
		m.Entries = append([]policy.BaseEntry(nil), m.Entries...)
		m.RevokedPermitIDs = append([]string(nil), m.RevokedPermitIDs...)
		return m
	}
	tests := []struct {
		name      string
		candidate policy.BaseManifest
		expected  string
		bootstrap bool
		noOp      bool
		code      policywire.ErrorCode
	}{
		{"exact-no-op", clone(headManifest), headDigest, false, true, ""},
		{"stale-head", clone(headManifest), strings.Repeat("f", 64), false, false, policywire.ErrorStalePolicyHead},
		{"bootstrap-over-existing", clone(headManifest), "", true, false, policywire.ErrorInvalidPolicyRequest},
		{"epoch-cutover", func() policy.BaseManifest { m := clone(headManifest); m.Epoch = 2; m.Revision = 2; return m }(), headDigest, false, false, policywire.ErrorPolicyKeyTransitionRequired},
		{"revision-skip", func() policy.BaseManifest {
			m := clone(headManifest)
			m.Revision = 3
			m.MissAction = policy.MissActionDeny
			return m
		}(), headDigest, false, false, policywire.ErrorInvalidPolicyRequest},
		{"same-version-fork", func() policy.BaseManifest { m := clone(headManifest); m.MissAction = policy.MissActionDeny; return m }(), headDigest, false, false, policywire.ErrorInvalidPolicyRequest},
		{"axes-successor", func() policy.BaseManifest {
			m := clone(headManifest)
			m.Revision = 2
			m.MissAction = policy.MissActionDeny
			return m
		}(), headDigest, false, false, ""},
		{"retained-entry-mutation", func() policy.BaseManifest {
			m := clone(headManifest)
			m.Revision = 2
			m.Entries[0].Identity = identityB
			return m
		}(), headDigest, false, false, policywire.ErrorInvalidPolicyRequest},
		{"remove-without-tombstone", func() policy.BaseManifest { m := clone(headManifest); m.Revision = 2; m.Entries = nil; return m }(), headDigest, false, false, policywire.ErrorInvalidPolicyRequest},
		{"remove-with-tombstone", func() policy.BaseManifest {
			m := clone(headManifest)
			m.Revision = 2
			m.Entries = nil
			m.RevokedPermitIDs = append(m.RevokedPermitIDs, entryA.ID)
			return m
		}(), headDigest, false, false, ""},
		{"tombstone-deletion", func() policy.BaseManifest {
			m := clone(headManifest)
			m.Revision = 2
			m.RevokedPermitIDs = nil
			m.MissAction = policy.MissActionDeny
			return m
		}(), headDigest, false, false, policywire.ErrorInvalidPolicyRequest},
		{"new-non-oob-id", func() policy.BaseManifest {
			m := clone(headManifest)
			m.Revision = 2
			bad := entryB
			bad.ID = "pa_manual_entry"
			m.Entries = append(m.Entries, bad)
			return m
		}(), headDigest, false, false, policywire.ErrorInvalidPolicyRequest},
		{"new-oob-entry", func() policy.BaseManifest {
			m := clone(headManifest)
			m.Revision = 2
			m.Entries = append(m.Entries, entryB)
			return m
		}(), headDigest, false, false, ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			noOp, code := classify(t, tc.candidate, tc.expected, tc.bootstrap, privateKey, publicKey, head, true)
			if noOp != tc.noOp || code != tc.code {
				t.Fatalf("classification = noOp:%t code:%q; want noOp:%t code:%q", noOp, code, tc.noOp, tc.code)
			}
		})
	}

	t.Run("no-head-bootstrap", func(t *testing.T) {
		candidate := testBootstrapManifest(host)
		noOp, code := classify(t, candidate, "", true, privateKey, publicKey, nil, false)
		if noOp || code != "" {
			t.Fatalf("classification = noOp:%t code:%q", noOp, code)
		}
	})
	t.Run("no-head-nonbootstrap", func(t *testing.T) {
		candidate := testBootstrapManifest(host)
		noOp, code := classify(t, candidate, strings.Repeat("a", 64), false, privateKey, publicKey, nil, false)
		if noOp || code != policywire.ErrorInvalidPolicyRequest {
			t.Fatalf("classification = noOp:%t code:%q", noOp, code)
		}
	})
	t.Run("signer-key-transition", func(t *testing.T) {
		rotatedPublic, rotatedPrivate, err := ed25519.GenerateKey(nil)
		if err != nil {
			t.Fatal(err)
		}
		candidate := clone(headManifest)
		candidate.Revision = 2
		candidate.MissAction = policy.MissActionDeny
		noOp, code := classify(t, candidate, headDigest, false, rotatedPrivate, rotatedPublic, head, true)
		if noOp || code != policywire.ErrorPolicyKeyTransitionRequired {
			t.Fatalf("classification = noOp:%t code:%q", noOp, code)
		}
	})
	t.Run("revision-overflow", func(t *testing.T) {
		maxHeadManifest := clone(headManifest)
		maxHeadManifest.Revision = ^uint64(0)
		envelope, err := policy.SignBaseManifest(privateKey, maxHeadManifest)
		if err != nil {
			t.Fatal(err)
		}
		payload, _, err := policy.DecodeBaseManifestEnvelope(envelope)
		if err != nil {
			t.Fatal(err)
		}
		_, digest, err := policywire.PayloadDigests(payload)
		if err != nil {
			t.Fatal(err)
		}
		maxHead := *head
		maxHead.ManifestEnvelopeB64 = base64.StdEncoding.EncodeToString(envelope)
		maxHead.BaseDigest = digest
		maxHead.Revision = maxHeadManifest.Revision
		candidate := clone(maxHeadManifest)
		candidate.MissAction = policy.MissActionDeny
		noOp, code := classify(t, candidate, digest, false, privateKey, publicKey, &maxHead, true)
		if noOp || code != policywire.ErrorInvalidPolicyRequest {
			t.Fatalf("classification = noOp:%t code:%q", noOp, code)
		}
	})
}

func TestPolicyJournalAggregateReserveAndFutureHeadSlots(t *testing.T) {
	disk := policyJournalDisk{
		Heads: make([]policyHeadRecord, maxPolicyHeads-1),
		Requests: []policyRequestRecord{
			{HostKeyFP: testPolicyFingerprint(0x70), State: policyStateReceivedUnaudited},
			{HostKeyFP: testPolicyFingerprint(0x71), State: policyStateReceivedUnaudited},
		},
	}
	for i := range disk.Heads {
		disk.Heads[i].Host = "existing-" + strings.Repeat("0", 4) + string(rune(i+1))
	}
	if got := policyOutstandingReserve(&disk); got != 2*policyTerminalReserve {
		t.Fatalf("aggregate reserve = %d; want %d", got, 2*policyTerminalReserve)
	}
	if got := policyReservedHeadCount(&disk); got != maxPolicyHeads+1 {
		t.Fatalf("reserved head slots = %d; want %d", got, maxPolicyHeads+1)
	}
	overfull := policyJournalDisk{Requests: make([]policyRequestRecord, maxPolicyRequests)}
	for i := range overfull.Requests {
		overfull.Requests[i].State = policyStateReceivedUnaudited
	}
	if got := policyOutstandingReserve(&overfull); got != maxPolicyJournalBytes+1 {
		t.Fatalf("overfull aggregate reserve = %d; want saturated %d", got, maxPolicyJournalBytes+1)
	}
}

func TestPolicyJournalRemainingReserveNeverDoubleCountsPersistedEnvelope(t *testing.T) {
	received := policyRequestRecord{State: policyStateReceivedUnaudited}
	before := policyJournalDisk{Requests: []policyRequestRecord{received}}
	beforeJSON, err := json.Marshal(before)
	if err != nil {
		t.Fatal(err)
	}
	beforeBudget := len(beforeJSON) + policyOutstandingReserve(&before)

	unexposed := received
	unexposed.State = policyStateApprovedUnexposed
	unexposed.ResultEnvelopeB64 = strings.Repeat("A", base64EncodedPolicyEnvelopeMax)
	after := policyJournalDisk{Requests: []policyRequestRecord{unexposed}}
	afterJSON, err := json.Marshal(after)
	if err != nil {
		t.Fatal(err)
	}
	afterBudget := len(afterJSON) + policyOutstandingReserve(&after)
	if afterBudget > beforeBudget {
		t.Fatalf("accepted request reservation grew after persisting envelope: before=%d after=%d", beforeBudget, afterBudget)
	}
	noOpReceived := received
	noOpReceived.NoOp = true
	noOpBefore := policyJournalDisk{Requests: []policyRequestRecord{noOpReceived}}
	noOpBeforeJSON, err := json.Marshal(noOpBefore)
	if err != nil {
		t.Fatal(err)
	}
	noOpAdmittedBudget := len(noOpBeforeJSON) + policyOutstandingReserve(&noOpBefore)
	noOpUnexposed := noOpReceived
	noOpUnexposed.State = policyStateApprovedUnexposed
	noOpUnexposed.ResultEnvelopeB64 = strings.Repeat("A", base64EncodedPolicyEnvelopeMax)
	noOpAfter := policyJournalDisk{Requests: []policyRequestRecord{noOpUnexposed}}
	noOpAfterJSON, err := json.Marshal(noOpAfter)
	if err != nil {
		t.Fatal(err)
	}
	if got := len(noOpAfterJSON) + policyOutstandingReserve(&noOpAfter); got > noOpAdmittedBudget {
		t.Fatalf("no-op reservation grew after staging existing envelope: before=%d after=%d", noOpAdmittedBudget, got)
	}

	noMint := received
	noMint.State = policyStateDenialReceived
	noMintBudget := policyRemainingReserve(&noMint)
	if noMintBudget <= 0 || noMintBudget >= policyTerminalReserve {
		t.Fatalf("no-mint remaining reserve = %d; want bounded metadata-only reserve", noMintBudget)
	}
}

func TestPolicyJournalAdmittedBudgetNeverGrowsThroughApprovalLifecycle(t *testing.T) {
	journal, _ := testPolicyJournal(t)
	publicKey, privateKey, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	host := testPolicyFingerprint(0x73)
	manifest := testBootstrapManifest(host)
	decoded := testPolicyDecoded(t, privateKey, "pm_73000000000000000000000000000001", host, manifest, "", true)
	if _, err := journal.begin(decoded, policyModeLocalTelegram, publicKey, time.Unix(73, 0)); err != nil {
		t.Fatal(err)
	}

	budget := func(label string) int {
		t.Helper()
		var got int
		if err := journal.view(func(disk *policyJournalDisk) error {
			body, err := json.Marshal(disk)
			if err != nil {
				return err
			}
			got = len(body) + policyOutstandingReserve(disk)
			return nil
		}); err != nil {
			t.Fatalf("%s budget: %v", label, err)
		}
		return got
	}
	admitted := budget("received")
	assertWithinAdmission := func(label string) {
		t.Helper()
		if got := budget(label); got > admitted {
			t.Fatalf("%s lifecycle budget = %d; admitted boundary = %d", label, got, admitted)
		}
	}

	challenge := "7373737373737373"
	if _, err := journal.markNotifying(decoded.Wire.RequestID, challenge); err != nil {
		t.Fatal(err)
	}
	assertWithinAdmission("notifying")
	if _, err := journal.activateLocal(decoded.Wire.RequestID, challenge); err != nil {
		t.Fatal(err)
	}
	assertWithinAdmission("pending")
	verdict := BaseManifestApprovalResult{
		Status:             policywire.StatusApproved,
		Kind:               BaseManifestResultLocalDecision,
		ApprovedBy:         strings.Repeat("\\", maxPolicyActorBytes),
		OperatorAuthMethod: strings.Repeat("\\", maxPolicyAuthMethodBytes),
	}
	if _, err := journal.commitLocalVerdict(decoded.Wire.RequestID, challenge, verdict); err != nil {
		t.Fatal(err)
	}
	assertWithinAdmission("approval_received")
	if _, err := journal.setApprovedMaterializing(decoded.Wire.RequestID); err != nil {
		t.Fatal(err)
	}
	assertWithinAdmission("approved_materializing")
	envelope, err := policy.SignBaseManifest(privateKey, manifest)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := journal.persistApprovedUnexposed(decoded.Wire.RequestID, envelope); err != nil {
		t.Fatal(err)
	}
	assertWithinAdmission("approved_unexposed")
	if _, err := journal.commitApproved(decoded.Wire.RequestID); err != nil {
		t.Fatal(err)
	}
	assertWithinAdmission("approved")
}

func TestPolicyJournalCommitUncertaintyPoisonsUntilReopen(t *testing.T) {
	journal, root := testPolicyJournal(t)
	publicKey, privateKey, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	host := testPolicyFingerprint(0x72)
	decoded := testPolicyDecoded(t, privateKey, "pm_72000000000000000000000000000001", host, testBootstrapManifest(host), strings.Repeat("a", 64), false)
	begin, err := journal.begin(decoded, policyModeLocalTelegram, publicKey, time.Unix(60, 0))
	if err != nil {
		t.Fatal(err)
	}
	if begin.Record.FailureCode != policywire.ErrorInvalidPolicyRequest {
		t.Fatalf("precondition failure code = %q", begin.Record.FailureCode)
	}
	peer, err := openLocalPolicyJournal(root)
	if err != nil {
		t.Fatal(err)
	}
	defer peer.Close()
	injected := errors.New("lost directory fsync acknowledgement")
	journal.afterStoreUpdate = func() error { return injected }
	if _, err := journal.finalizeNoMint(decoded.Wire.RequestID); !errors.Is(err, securestate.ErrCommitUncertain) {
		t.Fatalf("uncertain finalize = %v; want ErrCommitUncertain", err)
	}
	if _, err := journal.record(decoded.Wire.RequestID); !errors.Is(err, securestate.ErrCommitUncertain) {
		t.Fatalf("poisoned journal read = %v; want ErrCommitUncertain", err)
	}
	// The peer was already open when the rename became uncertain. Its View
	// takes the shared inode-stable flock and fsyncs the directory before the
	// callback, thereby confirming durability before it can expose the terminal.
	peerRecord, err := peer.record(decoded.Wire.RequestID)
	if err != nil || peerRecord.State != policyStateError || peerRecord.Response == nil {
		t.Fatalf("peer-confirmed installed terminal = %#v, %v", peerRecord, err)
	}
	if err := journal.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := openLocalPolicyJournal(root)
	if err != nil {
		t.Fatalf("reopen/revalidate uncertain journal: %v", err)
	}
	defer reopened.Close()
	record, err := reopened.record(decoded.Wire.RequestID)
	if err != nil || record.State != policyStateError || record.Response == nil {
		t.Fatalf("revalidated installed terminal = %#v, %v", record, err)
	}
}

func TestPolicyJournalIndependentInstancesSerializeBegin(t *testing.T) {
	first, root := testPolicyJournal(t)
	second, err := openLocalPolicyJournal(root)
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()
	publicKey, privateKey, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	host := testPolicyFingerprint(9)
	manifest := testBootstrapManifest(host)
	requests := []policywire.DecodedRequest{
		testPolicyDecoded(t, privateKey, "pm_00000000000000000000000000000009", host, manifest, "", true),
		testPolicyDecoded(t, privateKey, "pm_0000000000000000000000000000000a", host, manifest, "", true),
	}
	journals := []*localPolicyJournal{first, second}
	errs := make([]error, 2)
	var wg sync.WaitGroup
	for i := range journals {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			_, errs[i] = journals[i].begin(requests[i], policyModeLocalTelegram, publicKey, time.Unix(50+int64(i), 0))
		}(i)
	}
	wg.Wait()
	succeeded, blocked := 0, 0
	for _, err := range errs {
		if err == nil {
			succeeded++
			continue
		}
		var protocolErr *policyJournalError
		if errors.As(err, &protocolErr) && protocolErr.Code == policywire.ErrorPolicyRequestInProgress {
			blocked++
		}
	}
	if succeeded != 1 || blocked != 1 {
		t.Fatalf("concurrent begin results = %v; succeeded=%d blocked=%d", errs, succeeded, blocked)
	}
}

func TestValidStoredPolicyErrorCodeAcceptsQuorumUnattainable(t *testing.T) {
	if !validStoredPolicyErrorCode(policywire.ErrorQuorumUnattainable) {
		t.Fatal("local journal rejected quorum_unattainable from its independent allowlist")
	}
	if validStoredPolicyErrorCode("quorum-unattainable") {
		t.Fatal("local journal accepted an alternate quorum error spelling")
	}
}
