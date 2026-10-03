package harness

import "fmt"

// Report is a lane's completed, checked outcomes. A report is written only after
// every invocation in that lane has passed Judge.
type Report struct {
	Root     bool
	CI       bool
	Outcomes []Outcome
}
type Outcome struct {
	Set, ABI, Leg string
	Red           bool
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
		for _, set := range protection.MutationSets {
			for _, abi := range []string{"native", "abi1"} {
				hasRed := false
				for _, leg := range set.Legs {
					covered := false
					for _, report := range reports {
						eligible := !leg.Root || report.Root
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
						if eligible && !matched {
							return fmt.Errorf("infrastructure: CI omission %s %s %s (root=%t)", set.Name(), abi, leg.Name, report.Root)
						}
					}
					if !covered {
						return fmt.Errorf("infrastructure: union omitted %s", leg.Name)
					}
				}
				if !hasRed {
					return fmt.Errorf("infrastructure: union NOT-RUN %s %s", set.Name(), abi)
				}
			}
		}
	}
	return nil
}
