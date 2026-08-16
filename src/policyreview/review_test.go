package policyreview

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
	"testing"

	"github.com/karthikeyan5/sshgate/src/policy"
	"github.com/karthikeyan5/sshgate/src/redact"
)

func reviewEntry(t testing.TB, number int, size int) policy.BaseEntry {
	t.Helper()
	identity, err := policy.NewShellExactIdentity(bytes.Repeat([]byte{'x'}, size))
	if err != nil {
		t.Fatal(err)
	}
	return policy.BaseEntry{ID: fmt.Sprintf("pa_oob_%032x", number), Identity: identity, Source: policy.EntrySourceOutOfBand}
}

func TestLiteralPreviewEscapesBoundsAndFailsClosed(t *testing.T) {
	rules := []redact.Rule{redact.CompileRule("test", "test", `token=([a-z]+)`, []string{"token="}, 1, 1, 100)}
	identity := func(value string, _ [32]byte, _ []redact.Rule) (string, bool) { return value, true }
	preview, hidden, changed, ok := LiteralPreview([]byte{'a', '\n', 0xff}, 9, [32]byte{}, rules, identity)
	if !ok || changed || preview != `a\x0a\xff` || hidden != 0 {
		t.Fatalf("escaped preview = %q hidden=%d changed=%t ok=%t", preview, hidden, changed, ok)
	}
	preview, hidden, changed, ok = LiteralPreview(bytes.Repeat([]byte{'x'}, 5), 4, [32]byte{}, rules, identity)
	if !ok || changed || preview != "xxxx" || hidden != 1 {
		t.Fatalf("bounded preview = %q hidden=%d changed=%t ok=%t", preview, hidden, changed, ok)
	}
	panicRedactor := func(string, [32]byte, []redact.Rule) (string, bool) { panic("boom") }
	if preview, _, _, ok := LiteralPreview([]byte("secret"), 20, [32]byte{}, rules, panicRedactor); ok || preview != "" {
		t.Fatal("redactor panic exposed a preview")
	}
}

func TestBootstrapReviewBoundsExactAndPlusOne(t *testing.T) {
	manifest := policy.BaseManifest{Entries: make([]policy.BaseEntry, MaxBootstrapEntries)}
	for index := range manifest.Entries {
		manifest.Entries[index] = reviewEntry(t, index+1, 1)
	}
	if err := ValidateBootstrap(manifest); err != nil {
		t.Fatalf("exact entry bound rejected: %v", err)
	}
	manifest.Entries = append(manifest.Entries, reviewEntry(t, MaxBootstrapEntries+1, 1))
	if err := ValidateBootstrap(manifest); err == nil {
		t.Fatal("entry bound +1 accepted")
	}
	manifest.Entries = []policy.BaseEntry{reviewEntry(t, 1, MaxBootstrapLiteralBytes+1)}
	if err := ValidateBootstrap(manifest); err == nil {
		t.Fatal("literal bound +1 accepted")
	}
}

func TestChangesAreSortedAndRejectMutationOrResurrection(t *testing.T) {
	head := policy.BaseManifest{
		MissAction: policy.MissActionAsk, Growth: policy.GrowthSignToAdd,
		Entries:          []policy.BaseEntry{reviewEntry(t, 2, 1), reviewEntry(t, 1, 1)},
		RevokedPermitIDs: []string{"pa_old_44444444444444444444444444444444"},
	}
	candidate := head
	candidate.Growth = policy.GrowthOutOfBand
	candidate.Entries = []policy.BaseEntry{head.Entries[0], reviewEntry(t, 3, 1), reviewEntry(t, 4, 1)}
	candidate.RevokedPermitIDs = append(candidate.RevokedPermitIDs, head.Entries[1].ID, "pa_new_55555555555555555555555555555555")
	changes, err := Changes(&head, candidate)
	if err != nil {
		t.Fatal(err)
	}
	if !changes.AxesChanged || changes.LogicalChanges != 5 || changes.RemovedIDs[0] != head.Entries[1].ID || changes.AddedEntries[0].ID > changes.AddedEntries[1].ID {
		t.Fatalf("unexpected changes: %#v", changes)
	}
	mutated := candidate
	mutated.Entries = append([]policy.BaseEntry(nil), candidate.Entries...)
	mutated.Entries[0].Source = policy.EntrySourceOutOfBand
	mutated.Entries[0].Identity = reviewEntry(t, 9, 2).Identity
	if _, err := Changes(&head, mutated); err == nil {
		t.Fatal("retained entry mutation accepted")
	}
}

func TestReviewV2DocumentGoldenOrderShapesAndCounts(t *testing.T) {
	host := "SHA256:" + strings.Repeat("A", 43)
	identity, err := policy.NewShellExactIdentity([]byte("echo <safe>"))
	if err != nil {
		t.Fatal(err)
	}
	candidate := policy.BaseManifest{
		Schema: policy.SchemaV1, Host: host, Epoch: 1, Revision: 1,
		MissAction: policy.MissActionAsk, Growth: policy.GrowthSignToAdd,
		Entries:          []policy.BaseEntry{{ID: "pa_oob_0123456789abcdef0123456789abcdef", Identity: identity, Source: policy.EntrySourceOutOfBand}},
		RevokedPermitIDs: []string{"pa_revoked_1"},
	}
	rules := []redact.Rule{redact.CompileRule("unused", "unused", `(never)`, []string{"never"}, 1, 1, 10)}
	rendered, err := RenderDocument(DocumentInput{
		Purpose: "base_manifest_sign_v1", Principal: "machine",
		RequestID: "pm_0123456789abcdef0123456789abcdef", ReviewID: "pr_0123456789abcdef0123456789abcdef",
		AuthorityID: "pauth_0123456789abcdef0123456789abcdef", Bootstrap: true,
		Candidate: candidate, Rules: rules,
		RedactString: func(value string, _ [32]byte, _ []redact.Rule) (string, bool) { return value, true },
	})
	if err != nil {
		t.Fatal(err)
	}
	want := fmt.Sprintf(`{"contract":"sshgate-policy-review-v2","purpose":"base_manifest_sign_v1","principal":"machine","request_id":"pm_0123456789abcdef0123456789abcdef","review_id":"pr_0123456789abcdef0123456789abcdef","authority_id":"pauth_0123456789abcdef0123456789abcdef","host":"%s","bootstrap":true,"epoch":"1","revision":"1","miss_action":"ask","growth":"sign-to-add","entry_count":"1","revocation_count":"1","logical_change_count":"3","axes_changed":true,"items":[{"kind":"added","id":"pa_oob_0123456789abcdef0123456789abcdef","identity_digest":"%s","literal_length":"11","hidden_bytes":"0","preview":{"text":"echo \u003csafe\u003e","redacted":false}},{"kind":"revoked","id":"pa_revoked_1"},{"kind":"axes"}],"warnings":["%s"]}`,
		host, hex.EncodeToString(identity.Digest[:]), SourceExactWarning)
	if string(rendered.JSON) != want || rendered.ItemCount != 3 {
		t.Fatalf("review document = %s (items=%d)\nwant = %s", rendered.JSON, rendered.ItemCount, want)
	}
	digest := sha256.Sum256(rendered.JSON)
	if len(rendered.JSON) != 1002 || hex.EncodeToString(digest[:]) != "1b8fc2ba5c8acbc8361854da154eef59a1bc4e8650310a4648295005fe0aaed4" {
		t.Fatalf("review bytes/hash = %d/%x", len(rendered.JSON), digest)
	}
	if RulesDigest() != "d7e9074da072759bcae896fe120c156ca3c1a3800d5633e0f3d481176648c6dc" {
		t.Fatalf("review rules digest = %s", RulesDigest())
	}
}

func TestReviewV2OmittedPreviewRetainsHiddenBytesAndNoOpIsEmpty(t *testing.T) {
	host := "SHA256:" + strings.Repeat("A", 43)
	entry := reviewEntry(t, 1, 7)
	candidate := policy.BaseManifest{Schema: 1, Host: host, Epoch: 1, Revision: 1,
		MissAction: policy.MissActionAsk, Growth: policy.GrowthSignToAdd, Entries: []policy.BaseEntry{entry}}
	rendered, err := RenderDocument(DocumentInput{
		Purpose: "base_manifest_sign_v1", Principal: "machine", RequestID: "request", ReviewID: "review",
		AuthorityID: "authority", Bootstrap: true, Candidate: candidate,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(rendered.JSON, []byte(`"hidden_bytes":"7"`)) || bytes.Contains(rendered.JSON, []byte(`"preview"`)) {
		t.Fatalf("omitted preview document = %s", rendered.JSON)
	}
	head := candidate
	noOp, err := RenderDocument(DocumentInput{
		Purpose: "base_manifest_sign_v1", Principal: "machine", RequestID: "request", ReviewID: "review",
		AuthorityID: "authority", Head: &head, Candidate: candidate, NoOp: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if noOp.ItemCount != 0 || !bytes.Contains(noOp.JSON, []byte(`"items":[]`)) || !bytes.Contains(noOp.JSON, []byte(`"warnings":[]`)) {
		t.Fatalf("no-op document = %s", noOp.JSON)
	}
}
