package confine

import (
	"encoding/json"
	"fmt"
	"github.com/karthikeyan5/sshgate/src/gate/confine/jailmut/harness"
	"slices"
	"strings"
	"testing"
)

var legCases = proofCases()

func proofCases() []harness.Case {
	var cases []harness.Case
	add := func(name, kind, mode string, obligations []string, markers ...string) {
		cases = append(cases, harness.Case{Name: name, Package: "./src/gate/confine", ABIs: []string{"native", "abi1"}, Kind: kind, Mode: mode, Obligations: obligations, Markers: markers})
	}
	effect := func(name, subject string, markers ...string) {
		add(name, "Effect", Execute, []string{"control:" + subject, "jailed:" + subject, "observe:" + subject}, markers...)
	}
	for _, stage := range []string{"private", "setattr", "devnodes", "covers", "scratch"} {
		add("L-FAULT-"+stage, "Abort", SetupAbort, []string{"control:intact", "jailed:attempt"}, "EFFECT:reached-exec")
		cases[len(cases)-1].Modes = []string{Execute}
	}
	for _, ns := range []string{"USER", "MNT"} {
		markers := []string{"ABORT:nsverify", "ABORT:private"}
		if ns == "USER" {
			markers = []string{"ABORT:clone"}
		}
		add("L-CLONE-"+ns, "Abort", SetupAbort, []string{"control:intact", "jailed:attempt", "observe:mounts"}, markers...)
		cases[len(cases)-1].Modes = []string{Execute, LaunchFailure, ControlledHang}
	}
	add("L-DEV-OPEN", "Effect", Execute, []string{"control:ptmx", "control:pty", "control:fuse", "jailed:ptmx", "jailed:pty", "jailed:fuse", "observe:devices"}, "EFFECT:opened", "ABORT:selfcheck")
	cases[len(cases)-1].Modes = []string{SetupAbort}
	add("L-DEVNODE-WRITE", "Effect", Execute, []string{"control:null", "control:urandom", "control:full", "control:zero", "jailed:null", "jailed:urandom", "jailed:full", "jailed:zero", "observe:devices"}, "EFFECT:null-denied")
	add("L-READS-WORK", "Execution", Execute, []string{"jailed:reads"})
	effect("L-TTY-STATE", "tty", "EFFECT:tty-exclusive")
	effect("L-SCRATCH-FILL", "fill", "EFFECT:filled")
	add("L-SCRATCH-PRIVATE", "Effect", Execute, []string{"control:canary", "jailed:private", "observe:canary"})
	effect("L-SCRATCH-NOEXEC", "exec", "EFFECT:executed", "ABORT:selfcheck")
	cases[len(cases)-1].Modes = []string{SetupAbort}
	effect("L-RL-FSIZE", "fsize", "EFFECT:limit")
	add("L-RL-CORE", "Execution", Execute, []string{"control:limit", "jailed:limit", "observe:limit"}, "EFFECT:limit")
	effect("L-RL-NPROC", "forks", "EFFECT:limit")
	cases[len(cases)-1].Root = true
	cases[len(cases)-1].CIOnly = true
	cases[len(cases)-1].Omissions = []string{"root-only", "ci-only"}
	effect("L-FDS", "fd", "EFFECT:inherited-write")
	for _, name := range []string{"U-CloneUSER", "U-CloneMNT", "U-Handled-IOCTL-DEV", "U-Handled-TRUNCATE", "U-Handled-REFER"} {
		add(name, "Unit", "", []string{"control:decision"}, "EFFECT:decision")
	}
	add("U-DevNodesLiteral", "Unit", "", []string{"control:literal"})
	for _, item := range []struct {
		name, control, observe string
		markers                []string
	}{
		{"L-COVER-LOOP", "canary", "directory", []string{"EFFECT:visible", "EFFECT:nonempty"}},
		{"L-AUTOFS", "trigger", "mounts", []string{"EFFECT:triggered"}},
		{"L-BINFMT-FIXED-CHAR", "interpreter", "read", nil},
		{"L-TRACEFS", "drain", "marker", []string{"EFFECT:trace-consumed"}},
	} {
		add(item.name, "Effect", Execute, []string{"control:" + item.control, "jailed:probe", "observe:" + item.observe}, item.markers...)
		c := &cases[len(cases)-1]
		c.Root = true
		c.CIOnly = true
		c.Omissions = []string{"root-only", "ci-only"}
	}
	for _, item := range []struct {
		name    string
		markers []string
	}{
		{"L-FUSE-IOCTL", []string{"EFFECT:fuse-ioctl"}},
		{"L-COVER-NESTED", nil},
		{"L-COVER-CWD", []string{"EFFECT:fuse-ioctl", "ABORT:selfcheck"}},
		{"L-COVER-STACKED", []string{"EFFECT:fuse-ioctl", "ABORT:selfcheck"}},
		{"L-COVER-OVERLAY", []string{"EFFECT:delegated-read"}},
		{"L-SC-SYNC", []string{"EFFECT:sync-writeback"}},
		{"L-SHIM-PROC", []string{"EFFECT:shim-proc"}},
		{"L-SELFCHECK-MOUNTS", []string{"ABORT:selfcheck"}},
		{"L-PRIVATE-PROPAGATION", []string{"EFFECT:fuse-ioctl", "EFFECT:write"}},
	} {
		add(item.name, "Effect", Execute, []string{"control:facility", "jailed:probe", "observe:effects"}, item.markers...)
		c := &cases[len(cases)-1]
		c.Modes = []string{SetupAbort, Interactive}
		c.Omissions = []string{"fuse-unavailable"}
		if item.name == "L-COVER-OVERLAY" || item.name == "L-SC-SYNC" {
			c.Root = true
			c.Omissions = append(c.Omissions, "root-only")
		}
		if item.name == "L-SHIM-PROC" {
			c.AcceptFactsABI0 = true
		}
	}
	add("L-COVER-UNKNOWN", "Execution", Execute, []string{"jailed:probe"}, "EFFECT:covered")
	for _, variant := range []string{"absolute", "cwd", "rename-same-uid", "rename-other-uid"} {
		markers := []string{}
		if variant == "absolute" || variant == "cwd" {
			markers = []string{"EFFECT:fuse-ioctl-" + variant}
		}
		add("L-COVER-WALKDENIED/"+variant, "Effect", Interactive, []string{"control:facility", "jailed:probe", "observe:effects"}, markers...)
		c := &cases[len(cases)-1]
		c.Modes = []string{SetupAbort, Execute}
		c.Omissions = []string{"fuse-unavailable"}
		if variant == "rename-other-uid" {
			c.Root = true
			c.Omissions = append(c.Omissions, "root-only")
		}
	}
	for _, variant := range []string{"tmpfs", "fuse"} {
		add("L-SELFCHECK-DENIED-SAFE/"+variant, "Execution", Execute, []string{"jailed:probe"})
		cases[len(cases)-1].Modes = []string{SetupAbort}
		cases[len(cases)-1].Omissions = []string{"fuse-unavailable"}
	}
	for i := range cases {
		c := &cases[i]
		if strings.HasPrefix(c.Name, "L-COVER-") || c.Name == "L-FUSE-IOCTL" || c.Name == "L-BINFMT-FIXED-CHAR" || c.Name == "L-SELFCHECK-MOUNTS" || c.Name == "L-SELFCHECK-DENIED-SAFE/tmpfs" || c.Name == "L-SELFCHECK-DENIED-SAFE/fuse" || c.Name == "L-PRIVATE-PROPAGATION" || c.Name == "L-SHIM-PROC" {
			if !slices.Contains(c.Omissions, "fuse-unavailable") {
				c.Omissions = append(c.Omissions, "fuse-unavailable")
			}
		}
		if strings.HasPrefix(c.Name, "L-COVER-WALKDENIED/rename-") {
			c.CharacterisationOutcome = "R16-outside-owner-rename"
		}
		if c.Name == "L-BINFMT-FIXED-CHAR" {
			c.CharacterisationOutcome = "R18-fixed-interpreter"
		}
		if c.Name == "L-SC-SYNC" {
			c.Omissions = append(c.Omissions, "writeback-window-unavailable")
		}
	}
	return cases
}
func TestProofCasesJSON(t *testing.T) {
	if err := harness.ValidateCases(legCases); err != nil {
		t.Fatal(err)
	}
	data, err := json.Marshal(legCases)
	if err != nil {
		t.Fatal(err)
	}
	fmt.Printf("JAIL-PROOF-CASES %s\n", data)
}

func TestProofCaseMarkerCoverage(t *testing.T) {
	report := harness.Report{Root: true, CI: true}
	for _, c := range legCases {
		for _, abi := range c.ABIs {
			report.Proofs = append(report.Proofs, harness.ProofRecord{Outcome: "COMPLETE", Leg: c.Name, ABI: abi})
		}
	}
	if err := harness.CheckCaseUnion(legCases, completeRegistry(), []harness.Report{report}); err != nil {
		t.Fatal(err)
	}
}
