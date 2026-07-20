package backend

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/karthikeyan5/sshgate/pkg/signerkit"
	"github.com/karthikeyan5/sshgate/src/policy"
	"github.com/karthikeyan5/sshgate/src/policywire"
	"github.com/karthikeyan5/sshgate/src/redact"
)

type policyReviewHooks struct{}

func (policyReviewHooks) Activate(context.Context) error { return nil }
func (policyReviewHooks) CommitVerdict(context.Context, signerkit.BaseManifestApprovalResult) error {
	return nil
}
func (policyReviewHooks) AcknowledgeVerdict(context.Context, signerkit.BaseManifestApprovalResult) error {
	return nil
}

func policyReviewRequest(t *testing.T, literal []byte) signerkit.BaseManifestApprovalRequest {
	t.Helper()
	public, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	host := "SHA256:" + base64.RawStdEncoding.EncodeToString(bytes.Repeat([]byte{0x42}, 32))
	identity, err := policy.NewShellExactIdentity(literal)
	if err != nil {
		t.Fatal(err)
	}
	manifest := policy.BaseManifest{
		Schema: policy.SchemaV1, Host: host, Epoch: 1, Revision: 1,
		MissAction: policy.MissActionAsk, Growth: policy.GrowthOutOfBand,
		Entries: []policy.BaseEntry{{
			ID: "pa_oob_0123456789abcdef0123456789abcdef", Identity: identity,
			Source: policy.EntrySourceOutOfBand,
		}},
	}
	payload, err := policy.MarshalBaseManifest(manifest)
	if err != nil {
		t.Fatal(err)
	}
	keyID, err := policy.SignerKeyID(public)
	if err != nil {
		t.Fatal(err)
	}
	return signerkit.BaseManifestApprovalRequest{
		RequestID: "pm_0123456789abcdef0123456789abcdef", HostKeyFP: host,
		ExpectedSignerKeyID: keyID, Payload: payload, FrozenPublicKey: public,
		Bootstrap: true, CallbackChallenge: "0123456789abcdef", DecisionHooks: policyReviewHooks{},
	}
}

func policyReviewRequestWithLiteralSizes(t *testing.T, sizes []int) signerkit.BaseManifestApprovalRequest {
	t.Helper()
	req := policyReviewRequest(t, []byte("true"))
	manifest, err := policy.ParseBaseManifest(req.Payload)
	if err != nil {
		t.Fatal(err)
	}
	manifest.Entries = make([]policy.BaseEntry, len(sizes))
	for i, size := range sizes {
		identity, err := policy.NewShellExactIdentity(bytes.Repeat([]byte{'x'}, size))
		if err != nil {
			t.Fatal(err)
		}
		manifest.Entries[i] = policy.BaseEntry{
			ID: fmt.Sprintf("pa_oob_%032x", i+1), Identity: identity, Source: policy.EntrySourceOutOfBand,
		}
	}
	req.Payload, err = policy.MarshalBaseManifest(manifest)
	if err != nil {
		t.Fatal(err)
	}
	return req
}

func policyReviewRevisionRequestWithLiteralSizes(t *testing.T, sizes []int) signerkit.BaseManifestApprovalRequest {
	t.Helper()
	public, private, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	host := "SHA256:" + base64.RawStdEncoding.EncodeToString(bytes.Repeat([]byte{0x73}, 32))
	head := policy.BaseManifest{
		Schema: policy.SchemaV1, Host: host, Epoch: 1, Revision: 1,
		MissAction: policy.MissActionAsk, Growth: policy.GrowthOutOfBand,
	}
	headEnvelope, err := policy.SignBaseManifest(private, head)
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
	candidate := head
	candidate.Revision = 2
	candidate.Entries = make([]policy.BaseEntry, len(sizes))
	for i, size := range sizes {
		identity, err := policy.NewShellExactIdentity(bytes.Repeat([]byte{'x'}, size))
		if err != nil {
			t.Fatal(err)
		}
		candidate.Entries[i] = policy.BaseEntry{
			ID: fmt.Sprintf("pa_oob_%032x", i+1), Identity: identity, Source: policy.EntrySourceOutOfBand,
		}
	}
	payload, err := policy.MarshalBaseManifest(candidate)
	if err != nil {
		t.Fatal(err)
	}
	keyID, err := policy.SignerKeyID(public)
	if err != nil {
		t.Fatal(err)
	}
	return signerkit.BaseManifestApprovalRequest{
		RequestID: "pm_73737373737373737373737373737373", HostKeyFP: host,
		ExpectedSignerKeyID: keyID, Payload: payload, FrozenPublicKey: public,
		TrustedHeadEnvelope: headEnvelope, ExpectedHeadDigest: headDigest,
		CallbackChallenge: "7373737373737373", DecisionHooks: policyReviewHooks{},
	}
}

func TestPolicyCallbackParserIsStrict(t *testing.T) {
	valid := "p:a:pm_0123456789abcdef0123456789abcdef:0123456789abcdef"
	action, requestID, challenge, ok := parsePolicyCallbackData(valid)
	if !ok || action != "a" || requestID != "pm_0123456789abcdef0123456789abcdef" || challenge != "0123456789abcdef" {
		t.Fatalf("valid parse = %q %q %q %t", action, requestID, challenge, ok)
	}
	for _, bad := range []string{
		"p:approve:pm_0123456789abcdef0123456789abcdef:0123456789abcdef",
		"p:a:pm_0123456789ABCDEF0123456789abcdef:0123456789abcdef",
		"p:a:pm_0123456789abcdef0123456789abcdef:0123456789abcde",
		valid + ":suffix", "approve:pm_0123456789abcdef0123456789abcdef",
	} {
		if _, _, _, ok := parsePolicyCallbackData(bad); ok {
			t.Errorf("accepted malformed callback %q", bad)
		}
	}
}

func TestPolicyRendererBannersPresetAndFailClosedPreview(t *testing.T) {
	secret := "supersecret12345"
	literal := append(bytes.Repeat([]byte{'x'}, 600), []byte(" token="+secret)...)
	req := policyReviewRequest(t, literal)
	rules := []redact.Rule{redact.CompileRule("test-token", "test", `token=([A-Za-z0-9]+)`, []string{"token="}, 1, 1, 100)}
	review, err := renderPolicyReview(req, time.Minute, [32]byte{1}, rules)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(review.DecisionCard, "Preset: strict") {
		t.Fatalf("decision card has wrong preset: %q", review.DecisionCard)
	}
	for i, part := range review.DetailParts {
		if !strings.HasPrefix(part, policyPermanentAuthorityTitle+"\n") || len(part) >= policyTelegramPartBytes {
			t.Errorf("part %d lacks permanent banner or exceeds bound (%d bytes)", i+1, len(part))
		}
		if !strings.Contains(part, req.RequestID) || !strings.Contains(part, req.HostKeyFP) || strings.Contains(part, secret) {
			t.Errorf("part %d is unbound or leaked a secret", i+1)
		}
	}
	joined := strings.Join(review.DetailParts, "\n")
	if !strings.Contains(joined, "Preview: <omitted") ||
		!strings.Contains(joined, fmt.Sprintf("Hidden original bytes: %d", len(literal))) ||
		!strings.Contains(joined, policySourceExactWarning) {
		t.Fatalf("fail-closed review fields missing: %q", joined)
	}
}

func TestPolicyRendererOmitsPreviewOnRedactorFailureOrPanic(t *testing.T) {
	const sentinel = "raw-policy-secret-sentinel"
	rules := []redact.Rule{redact.CompileRule("test", "test", `(sentinel)`, []string{"sentinel"}, 1, 1, 100)}
	for _, tc := range []struct {
		name string
		fn   func(string, [32]byte, []redact.Rule) (string, bool)
	}{
		{"failure", func(value string, _ [32]byte, _ []redact.Rule) (string, bool) { return value, false }},
		{"panic", func(string, [32]byte, []redact.Rule) (string, bool) { panic("injected redactor panic") }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			original := policyRedactString
			policyRedactString = tc.fn
			defer func() { policyRedactString = original }()
			review, err := renderPolicyReview(policyReviewRequest(t, []byte(sentinel)), time.Minute, [32]byte{1}, rules)
			if err != nil {
				t.Fatal(err)
			}
			joined := strings.Join(review.DetailParts, "\n")
			if strings.Contains(joined, sentinel) || !strings.Contains(joined, "Preview: <omitted") ||
				!strings.Contains(joined, fmt.Sprintf("Hidden original bytes: %d", len(sentinel))) {
				t.Fatalf("redactor %s did not fail closed: %q", tc.name, joined)
			}
		})
	}
}

func TestPolicyRendererRejectsBoundaryViolationsBeforeSend(t *testing.T) {
	req := policyReviewRequest(t, bytes.Repeat([]byte{'x'}, policyReviewMaxLiteral+1))
	if _, err := renderPolicyReview(req, time.Minute, [32]byte{}, nil); err == nil || !strings.Contains(err.Error(), "per-entry") {
		t.Fatalf("oversize literal error = %v", err)
	}
	req = policyReviewRequest(t, []byte("true"))
	manifest, err := policy.ParseBaseManifest(req.Payload)
	if err != nil {
		t.Fatal(err)
	}
	manifest.Revision = 2
	req.Payload, err = policy.MarshalBaseManifest(manifest)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := renderPolicyReview(req, time.Minute, [32]byte{}, nil); err == nil || !strings.Contains(err.Error(), "bootstrap exceeds") {
		t.Fatalf("bad bootstrap version error = %v", err)
	}
}

func TestPolicyRendererBootstrapReviewBoundsExactAndPlusOne(t *testing.T) {
	entryLimit := make([]int, policyReviewMaxChanges)
	for i := range entryLimit {
		entryLimit[i] = 1
	}
	if _, err := renderPolicyReview(policyReviewRequestWithLiteralSizes(t, entryLimit), time.Minute, [32]byte{}, nil); err != nil {
		t.Fatalf("exact entry bound rejected: %v", err)
	}
	if _, err := renderPolicyReview(policyReviewRequestWithLiteralSizes(t, append(entryLimit, 1)), time.Minute, [32]byte{}, nil); err == nil {
		t.Fatal("entry bound +1 accepted")
	}
	aggregateLimit := []int{policyReviewMaxLiteral, policyReviewMaxLiteral, policyReviewMaxLiteral,
		policyReviewMaxLiteral, policyReviewMaxLiteral, policyReviewMaxLiteral}
	if _, err := renderPolicyReview(policyReviewRequestWithLiteralSizes(t, aggregateLimit), time.Minute, [32]byte{}, nil); err != nil {
		t.Fatalf("exact aggregate bound rejected: %v", err)
	}
	if _, err := renderPolicyReview(policyReviewRequestWithLiteralSizes(t, append(aggregateLimit, 1)), time.Minute, [32]byte{}, nil); err == nil || !strings.Contains(err.Error(), "aggregate") {
		t.Fatalf("aggregate bound +1 error = %v", err)
	}
}

func TestPolicyRendererRevisionLogicalChangesExactAndPlusOne(t *testing.T) {
	exact := make([]int, policyReviewMaxChanges)
	for i := range exact {
		exact[i] = 1
	}
	review, err := renderPolicyReview(policyReviewRevisionRequestWithLiteralSizes(t, exact), time.Minute, [32]byte{}, nil)
	if err != nil {
		t.Fatalf("exact %d-change revision rejected: %v", policyReviewMaxChanges, err)
	}
	if review.LogicalChange != policyReviewMaxChanges {
		t.Fatalf("logical changes = %d, want %d", review.LogicalChange, policyReviewMaxChanges)
	}
	if _, err := renderPolicyReview(policyReviewRevisionRequestWithLiteralSizes(t, append(exact, 1)), time.Minute, [32]byte{}, nil); err == nil || !strings.Contains(err.Error(), "logical-change") {
		t.Fatalf("%d-change revision error = %v", policyReviewMaxChanges+1, err)
	}
}

func TestPolicyRendererRevisionNewLiteralBytesExactAndPlusOne(t *testing.T) {
	// Revision literals may exceed bootstrap's 4 KiB per-entry bound; only the
	// aggregate of newly-added bytes is capped at 24 KiB. Split evenly so this
	// test exercises 12 KiB entries without coupling to base64 preflight edge
	// behavior at the model's separate absolute per-literal maximum.
	exact := []int{policyReviewMaxLiteralBytes / 2, policyReviewMaxLiteralBytes / 2}
	if _, err := renderPolicyReview(policyReviewRevisionRequestWithLiteralSizes(t, exact), time.Minute, [32]byte{}, nil); err != nil {
		t.Fatalf("exact %d-byte revision rejected: %v", policyReviewMaxLiteralBytes, err)
	}
	plusOne := append([]int(nil), exact...)
	plusOne[len(plusOne)-1]++
	if _, err := renderPolicyReview(policyReviewRevisionRequestWithLiteralSizes(t, plusOne), time.Minute, [32]byte{}, nil); err == nil || !strings.Contains(err.Error(), "aggregate") {
		t.Fatalf("%d-byte revision error = %v", policyReviewMaxLiteralBytes+1, err)
	}
}

func TestPolicyLiteralPreviewEscapedWindowExactAndPlusOne(t *testing.T) {
	rules := []redact.Rule{redact.CompileRule("unused", "unused", `token=([A-Za-z0-9]+)`, []string{"token="}, 1, 1, 100)}
	preview, hidden, changed, ok := policyLiteralPreview(bytes.Repeat([]byte{'x'}, policyTelegramPreviewBytes), [32]byte{1}, rules)
	if !ok || changed || len(preview) != policyTelegramPreviewBytes || hidden != 0 {
		t.Fatalf("exact preview = len %d hidden %d changed=%t ok=%t", len(preview), hidden, changed, ok)
	}
	preview, hidden, changed, ok = policyLiteralPreview(bytes.Repeat([]byte{'x'}, policyTelegramPreviewBytes+1), [32]byte{1}, rules)
	if !ok || changed || len(preview) != policyTelegramPreviewBytes || hidden != 1 {
		t.Fatalf("preview +1 = len %d hidden %d changed=%t ok=%t", len(preview), hidden, changed, ok)
	}
	preview, hidden, _, ok = policyLiteralPreview([]byte{'a', '\n', 0xff}, [32]byte{1}, rules)
	if !ok || preview != `a\x0a\xff` || hidden != 0 {
		t.Fatalf("escaped preview = %q hidden=%d ok=%t", preview, hidden, ok)
	}
}

func TestPolicyDetailPartCountAndNumberingBounds(t *testing.T) {
	req := policyReviewRequest(t, []byte("true"))
	block := strings.Repeat("x", policyTelegramPartBodyBytes)
	ten := make([]string, 10)
	for i := range ten {
		ten[i] = block
	}
	parts, err := packPolicyDetailParts(req.RequestID, req.HostKeyFP, ten)
	if err != nil {
		t.Fatal(err)
	}
	if len(parts) != 10 || !strings.Contains(parts[8], "PART 9/10") || !strings.Contains(parts[9], "PART 10/10") {
		t.Fatalf("digit-transition numbering failed: parts=%d", len(parts))
	}
	exact := make([]string, policyTelegramMaxMessages-1)
	for i := range exact {
		exact[i] = block
	}
	parts, err = packPolicyDetailParts(req.RequestID, req.HostKeyFP, exact)
	if err != nil || len(parts)+1 != policyTelegramMaxMessages {
		t.Fatalf("exact message-count bound: details=%d err=%v", len(parts), err)
	}
	if _, err := packPolicyDetailParts(req.RequestID, req.HostKeyFP, append(exact, block)); err == nil {
		t.Fatal("message-count bound +1 accepted")
	}
	// There is intentionally no direct 128 KiB exact/+1 renderer fixture.
	// Production admits at most 32 logical changes; each atomic block has at
	// most a 512-byte escaped preview plus fixed/bounded IDs and labels. That
	// bound is materially below 128 KiB before the stricter 39-detail-message
	// and <3900-byte part limits apply, so the aggregate rejection seam is
	// unreachable through a valid review request.
}

func TestPolicyPresetRatifiedMapping(t *testing.T) {
	cases := []struct {
		miss policy.MissAction
		grow policy.Growth
		want string
	}{
		{policy.MissActionClassifier, policy.GrowthNone, "auto"},
		{policy.MissActionAsk, policy.GrowthOutOfBand, "strict"},
		{policy.MissActionAsk, policy.GrowthSignToAdd, "ask"},
		{policy.MissActionDeny, policy.GrowthNone, "custom"},
	}
	for _, tc := range cases {
		if got := policyPreset(tc.miss, tc.grow); got != tc.want {
			t.Errorf("policyPreset(%s,%s) = %q, want %q", tc.miss, tc.grow, got, tc.want)
		}
	}
}

func TestPolicyRendererRevisionSemanticDiffUsesVerifiedHead(t *testing.T) {
	public, private, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	host := "SHA256:" + base64.RawStdEncoding.EncodeToString(bytes.Repeat([]byte{0x63}, 32))
	identity := func(value string) policy.CommandIdentity {
		t.Helper()
		got, err := policy.NewShellExactIdentity([]byte(value))
		if err != nil {
			t.Fatal(err)
		}
		return got
	}
	const (
		removedID  = "pa_oob_11111111111111111111111111111111"
		retainedID = "pa_oob_22222222222222222222222222222222"
		addedID    = "pa_oob_33333333333333333333333333333333"
		oldTomb    = "pa_old_44444444444444444444444444444444"
		newTomb    = "pa_new_55555555555555555555555555555555"
	)
	head := policy.BaseManifest{
		Schema: policy.SchemaV1, Host: host, Epoch: 3, Revision: 7,
		MissAction: policy.MissActionAsk, Growth: policy.GrowthSignToAdd,
		Entries: []policy.BaseEntry{
			{ID: removedID, Identity: identity("remove me"), Source: policy.EntrySourceOutOfBand},
			{ID: retainedID, Identity: identity("keep me"), Source: policy.EntrySourceOutOfBand},
		}, RevokedPermitIDs: []string{oldTomb},
	}
	headEnvelope, err := policy.SignBaseManifest(private, head)
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
	candidate := policy.BaseManifest{
		Schema: policy.SchemaV1, Host: host, Epoch: 3, Revision: 8,
		MissAction: policy.MissActionAsk, Growth: policy.GrowthOutOfBand,
		Entries: []policy.BaseEntry{
			{ID: retainedID, Identity: identity("keep me"), Source: policy.EntrySourceOutOfBand},
			{ID: addedID, Identity: identity("add me"), Source: policy.EntrySourceOutOfBand},
		}, RevokedPermitIDs: []string{oldTomb, removedID, newTomb},
	}
	payload, err := policy.MarshalBaseManifest(candidate)
	if err != nil {
		t.Fatal(err)
	}
	keyID, err := policy.SignerKeyID(public)
	if err != nil {
		t.Fatal(err)
	}
	req := signerkit.BaseManifestApprovalRequest{
		RequestID: "pm_66666666666666666666666666666666", HostKeyFP: host,
		ExpectedSignerKeyID: keyID, Payload: payload, FrozenPublicKey: public,
		TrustedHeadEnvelope: headEnvelope, ExpectedHeadDigest: headDigest,
		CallbackChallenge: "6666666666666666", DecisionHooks: policyReviewHooks{},
	}
	review, err := renderPolicyReview(req, time.Minute, [32]byte{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if review.LogicalChange != 4 {
		t.Fatalf("logical changes = %d, want 4", review.LogicalChange)
	}
	joined := strings.Join(review.DetailParts, "\n")
	if strings.Count(joined, "REMOVED AND REVOKED ENTRY") != 1 ||
		!strings.Contains(joined, removedID) || !strings.Contains(joined, addedID) || !strings.Contains(joined, newTomb) ||
		strings.Contains(joined, retainedID) || strings.Contains(joined, oldTomb) {
		t.Fatalf("revision diff is incomplete, duplicated, or includes unchanged material: %q", joined)
	}
	deletedTombstone := candidate
	deletedTombstone.RevokedPermitIDs = []string{removedID, newTomb}
	req.Payload, err = policy.MarshalBaseManifest(deletedTombstone)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := renderPolicyReview(req, time.Minute, [32]byte{}, nil); err == nil || !strings.Contains(err.Error(), "tombstone") {
		t.Fatalf("deleted predecessor tombstone was reviewable: %v", err)
	}
	malformedID := candidate
	malformedID.Entries = append([]policy.BaseEntry(nil), candidate.Entries...)
	malformedID.Entries[1].ID = "pa_bad_33333333333333333333333333333333"
	req.Payload, err = policy.MarshalBaseManifest(malformedID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := renderPolicyReview(req, time.Minute, [32]byte{}, nil); err == nil || !strings.Contains(err.Error(), "out-of-band") {
		t.Fatalf("malformed base-entry id was reviewable: %v", err)
	}
}
