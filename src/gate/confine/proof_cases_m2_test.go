package confine

import "github.com/karthikeyan5/sshgate/src/gate/confine/jailmut/harness"

func proofCasesM2() []harness.Case {
	var cases []harness.Case
	add := func(name, kind, mode string, obligations []string, markers ...string) {
		cases = append(cases, harness.Case{Name: name, Package: "./src/gate/confine", ABIs: []string{"native", "abi1"}, Kind: kind, Mode: mode, Obligations: obligations, Markers: markers})
	}
	for _, item := range []struct {
		name    string
		markers []string
	}{
		{"L-SIGNAL-HOST", []string{"EFFECT:signal"}},
		{"L-SIGNAL-SCOPE", []string{"EFFECT:signal"}},
		{"L-ASYNC-OWNER", []string{"EFFECT:errno", "EFFECT:signal"}},
		{"L-ASYNC-SCOPE", []string{"EFFECT:errno", "EFFECT:signal"}},
		{"L-RETUNE", []string{"EFFECT:errno", "EFFECT:retuned"}},
		{"L-RETUNE-SETPARAM", []string{"EFFECT:errno", "EFFECT:retuned"}},
		{"L-PROCESS-MRELEASE", []string{"EFFECT:errno", "EFFECT:memory"}},
		{"L-LIFECYCLE", []string{"EFFECT:alive"}},
	} {
		add(item.name, "Effect", Execute, []string{"control:facility", "jailed:probe", "observe:effects"}, item.markers...)
		c := &cases[len(cases)-1]
		if item.name == "L-LIFECYCLE" {
			c.Mode, c.Modes = Unframed, []string{Cancelled, ShimSignal}
		}
		if item.name == "L-RETUNE-SETPARAM" {
			c.Root, c.CIOnly = true, true
			c.Omissions = []string{"root-only", "ci-only"}
		}
	}
	add("L-SESSION", "Execution", Execute, []string{"jailed:probe"}, "EFFECT:session")
	add("L-SIGNAL-OWN-GROUP", "Execution", Execute, []string{"jailed:probe"})
	add("L-SCHED-USER", "Effect", Execute, []string{"control:retune", "jailed:retune", "observe:retune"}, "EFFECT:retuned")
	cases[len(cases)-1].Root, cases[len(cases)-1].CIOnly = true, true
	cases[len(cases)-1].Omissions = []string{"root-only", "ci-only"}
	for _, name := range []string{"L-CRASH-NO-HELPER", "L-CRASH-LOWER-PIPE"} {
		add(name, "Effect", ExpectedSignal, []string{"control:crash", "jailed:crash", "observe:core"}, "EFFECT:helper-record")
		c := &cases[len(cases)-1]
		c.CIOnly = true
		c.Omissions = []string{"ci-only", "core-pattern-uncontrolled"}
		if name == "L-CRASH-LOWER-PIPE" {
			c.Root = true
			c.Omissions = append(c.Omissions, "root-only")
		}
	}
	for _, name := range []string{"U-Mrelease", "U-Signal", "U-AsyncOwner", "U-Retune"} {
		add(name, "Unit", "", []string{"control:decision"}, "EFFECT:decision")
	}
	for _, name := range []string{"L-NUMA-MIGRATE-PAGES", "L-NUMA-MOVE-PAGES"} {
		add(name, "Residual", "", nil)
		cases[len(cases)-1].Residuals = []string{"R-NUMA-EFFECT"}
	}
	return cases
}
