package harness

import (
	"strings"
	"testing"
)

func testCase() Case {
	return Case{Name: "L-PROOF", Kind: "Effect", Mode: "Execute", ABIs: []string{"native"}, Markers: []string{"EFFECT:write"}, Obligations: []string{"control:write", "jailed:write", "observe:file"}}
}

func TestCaseMinimumObligations(t *testing.T) {
	c := testCase()
	if err := ValidateCases([]Case{c}); err != nil {
		t.Fatal(err)
	}
	for _, obligations := range [][]string{nil, {"jailed:write"}, {"control:write", "jailed:write", "observe:file", "observe:file"}} {
		c.Obligations = obligations
		if ValidateCases([]Case{c}) == nil {
			t.Fatalf("accepted obligations %v", obligations)
		}
	}
}
func TestManifestStrict(t *testing.T) {
	valid := "PROOF-COMPLETE L-PROOF native markers=EFFECT:write\n"
	for _, log := range []string{"", valid + valid, "PROOF-COMPLETE L-PROOF native markers=EFFECT:other\n", "PROOF-OMITTED L-PROOF native fuse-unavailable\n", "PROOF-RESIDUAL L-PROOF native R-NUMA-EFFECT\n"} {
		if _, err := CheckManifest(strings.NewReader(log), []Case{testCase()}, false, true); err == nil {
			t.Fatalf("accepted %q", log)
		}
	}
	if _, err := CheckManifest(strings.NewReader(valid), []Case{testCase()}, false, true); err != nil {
		t.Fatal(err)
	}
	c := testCase()
	c.Root = true
	if _, err := CheckManifest(strings.NewReader("PROOF-OMITTED L-PROOF native root-only\n"), []Case{c}, false, true); err != nil {
		t.Fatal(err)
	}
	nonRoot := testCase()
	nonRoot.NonRoot = true
	omitted := "PROOF-OMITTED L-PROOF native nonroot-only\n"
	if _, err := CheckManifest(strings.NewReader(omitted), []Case{nonRoot}, true, true); err != nil {
		t.Fatal(err)
	}
	if _, err := CheckManifest(strings.NewReader(omitted), []Case{nonRoot}, false, true); err == nil {
		t.Fatal("accepted a non-root-only omission in the non-root lane")
	}
	if _, err := CheckManifest(strings.NewReader(omitted), []Case{testCase()}, true, true); err == nil {
		t.Fatal("accepted a non-root-only omission for a case that does not declare it")
	}
	c.NonRoot = true
	if ValidateCases([]Case{c}) == nil {
		t.Fatal("accepted a case that is both root-only and non-root-only")
	}
}
func TestCaseUnionOmissionsNeverComplete(t *testing.T) {
	c := testCase()
	c.Root = true
	c.Characterisation = c.Markers
	reports := []Report{{CI: true, Proofs: []ProofRecord{{Outcome: "OMITTED", Leg: c.Name, ABI: "native", Code: "root-only"}}}}
	if CheckCaseUnion([]Case{c}, nil, reports) == nil {
		t.Fatal("omission counted as proof")
	}
	reports = append(reports, Report{CI: true, Root: true, Proofs: []ProofRecord{{Outcome: "COMPLETE", Leg: c.Name, ABI: "native"}}})
	if err := CheckCaseUnion([]Case{c}, nil, reports); err != nil {
		t.Fatal(err)
	}
	c.Characterisation = nil
	if CheckCaseUnion([]Case{c}, nil, reports) == nil {
		t.Fatal("unregistered marker accepted")
	}
}
