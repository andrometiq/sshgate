package harness

import (
	"fmt"
	"slices"
)

// Report is a lane's completed, checked outcomes. A report is written only after
// every invocation in that lane has passed Judge.
type Report struct {
	Root     bool
	CI       bool
	Outcomes []Outcome
	Proofs   []ProofRecord
}
type Outcome struct {
	Set, ABI, Leg string
	Red           bool
}

// ProofOutcome is the outcome a judged proof contributes to its lane's report:
// a completion is red when the leg expected markers in that ABI; a per-lane
// residual is green, so the union compares it with the expected markers like
// any other outcome. An omission or a legacy residual contributes none.
func ProofOutcome(set MutationSet, leg Leg, abi string, proof ProofRecord) (Outcome, bool) {
	switch {
	case proof.Outcome == "COMPLETE":
		return Outcome{Set: set.Name(), ABI: abi, Leg: leg.Name, Red: len(leg.ExpectedMarkers(abi)) > 0}, true
	case proof.Outcome == "RESIDUAL" && len(leg.Residuals) == 0:
		return Outcome{Set: set.Name(), ABI: abi, Leg: leg.Name}, true
	}
	return Outcome{}, false
}

// CheckUnion is the phase-end gate over the two CI-mode lane reports.
func CheckUnion(registry []Protection, reports []Report) error {
	lanes := map[bool]bool{}
	for _, report := range reports {
		if !report.CI || lanes[report.Root] {
			return fmt.Errorf("infrastructure: union requires exactly one report per CI lane")
		}
		lanes[report.Root] = true
	}
	if !lanes[false] || !lanes[true] {
		return fmt.Errorf("infrastructure: missing non-root or root CI coverage")
	}
	for _, protection := range registry {
		redByABI := map[string]bool{}
		for _, set := range protection.MutationSets {
			for _, abi := range []string{"native", "abi1"} {
				hasRed := false
				for _, leg := range set.Legs {
					covered := false
					for _, report := range reports {
						eligible := (!leg.Root || report.Root) && (!leg.NonRoot || !report.Root)
						matched := false
						for _, outcome := range report.Outcomes {
							if outcome.Set == set.Name() && outcome.ABI == abi && outcome.Leg == leg.Name {
								if !eligible || outcome.Red != (len(leg.ExpectedMarkers(abi)) > 0) || matched {
									return fmt.Errorf("infrastructure: invalid union outcome %s %s %s", set.Name(), abi, leg.Name)
								}
								matched = true
								covered = true
								hasRed = hasRed || outcome.Red
							}
						}
						// Only a legacy Residual-kind leg is covered by its declaration;
						// a per-lane residual is an outcome, compared above.
						for _, proof := range report.Proofs {
							if proof.Leg == leg.Name && proof.ABI == abi && proof.Outcome == "RESIDUAL" && slices.Contains(leg.Residuals, proof.Code) {
								matched = true
								covered = true
							}
						}
						if eligible && !matched {
							return fmt.Errorf("infrastructure: CI omission %s %s %s (root=%t)", set.Name(), abi, leg.Name, report.Root)
						}
					}
					if !covered {
						return fmt.Errorf("infrastructure: union omitted %s", leg.Name)
					}
				}
				redByABI[abi] = redByABI[abi] || hasRed
			}
		}
		for _, abi := range []string{"native", "abi1"} {
			if !redByABI[abi] {
				return fmt.Errorf("infrastructure: union NOT-RUN %s %s", protection.ID, abi)
			}
		}
	}
	return nil
}
