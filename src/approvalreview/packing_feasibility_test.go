package approvalreview

import (
	"strings"
	"testing"
)

// This lower bound excludes all headers, routes, labels and the decision card.
// No packing algorithm can fit the mandatory command displays within K19.
func TestPackingEnvelopeFeasibility(t *testing.T) {
	const atom = "passwd=abcd "
	command := strings.Repeat(atom, 4096/len(atom))
	command += strings.Repeat(" ", 4096-len(command))
	specs := make([]stepSpec, 6)
	for i := range specs {
		specs[i] = signed(command)
	}
	p := withSteps(t, specs...)
	maxRoutes(&p)
	if err := p.Validate(); err != nil {
		t.Fatal(err)
	}
	b := builder{salt: testSalt(), rules: testRules}
	displayBytes := 0
	for _, step := range p.CommandJob.Steps {
		d := b.command("command", step.ExactCommand)
		displayBytes += len(renderDisplay(d))
	}
	if b.err != nil {
		t.Fatal(b.err)
	}
	if displayBytes <= MaxReviewBytes {
		t.Fatalf("counterexample no longer exceeds the byte bound: %d", displayBytes)
	}
	minimumParts := (displayBytes + PartBytes - 2) / (PartBytes - 1)
	t.Logf("validated plan: steps=%d input_bytes=%d display_bytes=%d byte_cap=%d excess=%d minimum_parts_without_headers=%d minimum_messages_with_card=%d", len(specs), len(specs)*len(command), displayBytes, MaxReviewBytes, displayBytes-MaxReviewBytes, minimumParts, minimumParts+1)
	salt := testSalt()
	if _, err := BuildSnapshot(p, &salt, testRules); !isTooLarge(err) {
		t.Fatal("oversized review must return request_too_large")
	}
}
