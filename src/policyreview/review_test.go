package policyreview

import (
	"bytes"
	"fmt"
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
