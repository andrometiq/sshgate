package main

import (
	"encoding/json"
	"os"
	"os/exec"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/karthikeyan5/sshgate/src/gate/confine"
	"github.com/karthikeyan5/sshgate/src/gate/confine/jailmut"
	"github.com/karthikeyan5/sshgate/src/gate/confine/jailmut/harness"
)

const gateProofPackage = "./src/gate/cmd/sshgate-gate"

// gateProofCases is a literal copy of the confine manifest's cases for this
// package (proofCasesPhase2, proofCasesPhase3); TestGateProofCasesMatchManifest
// keeps the two equal.
func gateProofCases() []harness.Case {
	var cases []harness.Case
	in := func(phase string) func(name, kind, mode string, modes, obligations, markers, omissions []string) {
		return func(name, kind, mode string, modes, obligations, markers, omissions []string) {
			root := "TestJailMatrix" + phase + "/"
			if kind == "Unit" {
				root = "Test" + phase + "Tables/"
			}
			cases = append(cases, harness.Case{
				Name: name, Package: gateProofPackage, Kind: kind, Mode: mode, Modes: modes, ABIs: []string{"native", "abi1"},
				Names:       map[string]string{"native": root + "native/" + name, "abi1": root + "abi1/" + name},
				Obligations: obligations, Markers: markers, Omissions: omissions,
			})
		}
	}
	add := in("Phase2")
	for _, name := range []string{"U-ExecReadConfineRequired", "U-SpecStrictSources"} {
		add(name, "Unit", "", nil, []string{"control:decision"}, []string{"EFFECT:decision"}, nil)
	}
	add("G-CONFINE-REQUIRED-ABSENT", "Effect", "Execute", []string{"SetupAbort"}, []string{"control:edit", "jailed:edit", "observe:target"}, []string{"EFFECT:ran-unconfined"}, nil)
	add("G-CONFINE-REQUIRED-LANE2", "Effect", "Execute", nil, []string{"control:lane2", "jailed:lane2", "observe:lane2"}, []string{"EFFECT:lane2-ran"}, nil)
	for _, name := range []string{"G-STRICT-UNMET-FUSE", "G-NET-STRICT-UNMET-FUSE"} {
		add(name, "Effect", "Execute", []string{"SetupAbort"}, []string{"control:facility", "jailed:probe", "observe:effects"}, []string{"ABORT:selfcheck", "EFFECT:fuse-ioctl"}, []string{"fuse-unavailable"})
	}
	add("G-UNPINNED-UNMET-FUSE", "Effect", "Execute", nil, []string{"control:facility", "jailed:probe", "observe:effects"}, []string{"EFFECT:fuse-ioctl"}, []string{"fuse-unavailable"})
	add("G-NSDROP-MNT", "Abort", "SetupAbort", []string{"Execute"}, []string{"control:intact", "jailed:attempt", "observe:mounts"}, []string{"ABORT:nsverify"}, nil)
	add("G-FAULT", "Abort", "SetupAbort", nil, []string{"control:intact", "jailed:attempt"}, nil, nil)
	add("G-FAULT-ABSENT", "Execution", "Execute", nil, []string{"jailed:fallback", "observe:target"}, nil, nil)
	add("G-INET-DENY", "Effect", "Execute", nil, []string{"control:connect", "jailed:connect", "observe:listener"}, []string{"EFFECT:connected"}, nil)
	add("G-INET-ALLOW", "Execution", "Execute", nil, []string{"jailed:connect", "observe:listener"}, nil, nil)
	add("U-SealReads", "Unit", "", nil, []string{"control:decision"}, []string{"EFFECT:decision"}, nil)
	add("G-GATE-SEAL", "Effect", "Execute", nil, []string{"control:gate-proc", "jailed:read", "observe:gate-proc"}, []string{"EFFECT:gate-environ", "EFFECT:gate-fd"}, []string{"nonroot-only"})
	cases[len(cases)-1].NonRoot = true
	add("G-SEAL-GUARD", "Effect", "Execute", []string{"SetupAbort"}, []string{"control:first-read", "jailed:second-read", "observe:output"}, []string{"EFFECT:second-ran"}, []string{"root-only"})
	cases[len(cases)-1].Root = true
	add("U-LabelContract", "Unit", "", nil, []string{"control:decision", "unit:switch"}, []string{"EFFECT:label"}, nil)
	add("G-JAILVERB-LABEL", "Execution", "Execute", nil, []string{"jailed:verb", "observe:json"}, []string{"EFFECT:label"}, nil)
	add("U-JailVerbNoExec", "Unit", "", nil, []string{"control:decision"}, []string{"EFFECT:exec"}, nil)
	add("G-JAILVERB-NOEXEC", "Effect", "Execute", nil, []string{"control:payload", "jailed:verb", "observe:output"}, []string{"EFFECT:agent-bytes"}, nil)
	add("U-SelftestRefusesUnjailed", "Unit", "", nil, []string{"control:decision"}, []string{"EFFECT:decision"}, nil)
	add("G-SELFTEST-UNJAILED", "Effect", "Execute", nil, []string{"control:write", "jailed:selftest", "observe:fixtures"}, []string{"EFFECT:selftest-unjailed"}, nil)
	add("G-SELFTEST-JAILED", "Execution", "Execute", nil, []string{"jailed:selftest", "observe:fixtures"}, nil, nil)
	add("U-PinRequiresRehearsal", "Unit", "", nil, []string{"control:decision"}, []string{"EFFECT:decision"}, nil)
	add("G-PIN-REFUSED", "Effect", "Execute", nil, []string{"control:pin", "jailed:rehearsal", "observe:pinfile"}, []string{"EFFECT:pin-written"}, nil)
	add = in("Phase3")
	for _, name := range []string{"U-Lane2Grammar", "U-Lane2RedirectList", "U-Lane2ELFSearchTags", "U-Lane2Interp"} {
		add(name, "Unit", "", nil, []string{"control:decision"}, []string{"EFFECT:decision"}, nil)
	}
	add("G-L2-GRAMMAR", "Effect", "Execute", nil, []string{"control:argv", "jailed:lane2", "observe:output"}, []string{"EFFECT:grammar-flag"}, nil)
	add("G-L2-REDIRECT", "Effect", "Execute", nil, []string{"control:argv", "jailed:lane2", "observe:output"}, []string{"EFFECT:redirect-flag"}, nil)
	add("G-L2-ADMIT-WRITABLE-DIR", "Effect", "Execute", nil, []string{"control:exec", "jailed:lane2", "observe:output"}, []string{"EFFECT:untrusted-ran"}, nil)
	for _, name := range []string{"G-L2-ADMIT-RUNPATH-ORIGIN", "G-L2-ADMIT-RUNPATH-UNTRUSTED"} {
		add(name, "Effect", "Execute", nil, []string{"control:exec", "jailed:lane2", "observe:output"}, []string{"EFFECT:lib-ran"}, nil)
	}
	add("G-L2-ADMIT-ENDPOINT", "Effect", "Execute", nil, []string{"control:connect", "jailed:lane2", "observe:listener"}, []string{"EFFECT:endpoint-accepted"}, []string{"root-only"})
	cases[len(cases)-1].Root = true
	add("G-L2-INTERP-UNTRUSTED", "Effect", "Execute", nil, []string{"control:exec", "jailed:lane2", "observe:output"}, []string{"EFFECT:interp-ran"}, nil)
	// P3.2: daemon reads run in the jail. The residual lanes follow this host's
	// Landlock ABI, as the registry's expected markers do.
	hostABI := confine.ReadHostFacts().LandlockABI
	add("U-Lane2SpecNet", "Unit", "", nil, []string{"control:decision"}, []string{"EFFECT:decision"}, nil)
	add("G-LANE2-PLUGIN-NOEXEC", "Effect", "Execute", nil, []string{"control:exec", "jailed:lane2", "observe:output"}, []string{"EFFECT:plugin-ran"}, nil)
	add("G-L2-MEMFD-NOEXEC", "Effect", "Execute", nil, []string{"control:exec", "jailed:lane2", "observe:output"}, []string{"EFFECT:memfd-ran"}, nil)
	add("G-L2-SOCK-PIN", "Effect", "Execute", nil, []string{"control:connect", "jailed:lane2", "observe:listener"}, []string{"EFFECT:unpinned-connected"}, nil)
	cases[len(cases)-1].ResidualABIs = harness.ResidualBelowABI("R-L2-SOCKET-BELOW-ABI9", hostABI, 9)
	add("G-L2-SOCK-SWAP-AFTER-OPEN", "Effect", "Execute", nil, []string{"control:connect", "jailed:lane2", "observe:listener"}, []string{"EFFECT:swapped-connected"}, nil)
	cases[len(cases)-1].ResidualABIs = harness.ResidualBelowABI("R-L2-SOCKET-BELOW-ABI9", hostABI, 9)
	add("G-L2-NET-OFF", "Effect", "Execute", []string{"SetupAbort"}, []string{"control:connect", "jailed:lane2", "observe:listener"}, []string{"ABORT:spec", "EFFECT:tcp-connected"}, nil)
	add("G-L2-ENV", "Effect", "Execute", nil, []string{"control:env", "jailed:lane2", "observe:report"}, []string{"EFFECT:env-leaked"}, nil)
	for _, name := range []string{"G-L2-IDENTITY-BINARY", "G-L2-IDENTITY-INTERP"} {
		add(name, "Effect", "Execute", nil, []string{"control:exec", "jailed:lane2", "observe:output"}, []string{"EFFECT:replaced-ran"}, nil)
	}
	add("G-L2-IDENTITY-SOCKET", "Effect", "Execute", nil, []string{"control:connect", "jailed:lane2", "observe:listener"}, []string{"EFFECT:replaced-accepted"}, nil)
	add("C-L2-LOADER", "Execution", "Execute", nil, []string{"jailed:loader"}, nil, nil)
	cases[len(cases)-1].ResidualABIs = map[string]string{"native": "R-L2-LOADER-ROUTE", "abi1": "R-L2-LOADER-ROUTE"}
	add("C-L2-REEXEC", "Execution", "Execute", nil, []string{"jailed:reexec"}, nil, nil)
	add("C-L2-MEMFD-SECRET", "Execution", "Execute", nil, []string{"jailed:memfd-secret"}, nil, nil)
	add("C-L2-ABSTRACT", "Execution", "Execute", nil, []string{"jailed:abstract"}, nil, nil)
	cases[len(cases)-1].ResidualABIs = harness.ResidualBelowABI("R-L2-ABSTRACT-BELOW-ABI6", hostABI, 6)
	add("C-L2-UNIX-DGRAM", "Execution", "Execute", nil, []string{"jailed:dgram"}, nil, nil)
	add = in("Phase4")
	for _, name := range []string{"U-EnvelopeParse", "U-EnvelopeFlags", "U-EnvelopeExpectNet", "U-DaemonReadNetRefused"} {
		add(name, "Unit", "", nil, []string{"control:decision"}, []string{"EFFECT:decision"}, nil)
	}
	add("G-ENVELOPE-GRAMMAR", "Effect", "Execute", []string{"SetupAbort"}, []string{"control:effect", "jailed:attempt", "observe:effect"}, []string{"EFFECT:agent-bytes"}, nil)
	add("G-ENVELOPE-NO-NET-UNPINNED", "Effect", "Execute", []string{"SetupAbort"}, []string{"control:effect", "jailed:attempt", "observe:effect"}, []string{"EFFECT:connected"}, nil)
	add("G-ENVELOPE-NO-NET-DENY", "Effect", "Execute", []string{"SetupAbort"}, []string{"control:effect", "jailed:attempt", "observe:effect"}, []string{"EFFECT:connected"}, nil)
	add("G-ENVELOPE-PIN-SNAPSHOT", "Effect", "Execute", []string{"SetupAbort"}, []string{"control:effect", "jailed:attempt", "observe:effect"}, []string{"EFFECT:ran-without-network"}, nil)
	add("G-NET-LANE2-AVAILABLE", "Effect", "Execute", []string{"SetupAbort"}, []string{"control:effect", "jailed:attempt", "observe:effect"}, []string{"EFFECT:lane2-ran"}, nil)
	add("G-ENVELOPE-ABSENT", "Effect", "Execute", []string{"SetupAbort"}, []string{"control:effect", "jailed:attempt", "observe:effect"}, []string{"EFFECT:ran-unconfined"}, nil)
	add("G-ENVELOPE-NET-ALLOW", "Execution", "Execute", nil, []string{"jailed:attempt", "observe:effect"}, nil, nil)
	add("G-ENVELOPE-ABSENT-TWIN", "Execution", "Execute", nil, []string{"jailed:attempt", "observe:effect"}, nil, nil)
	add("G-ENVELOPE-NEW-GATE", "Execution", "Execute", nil, []string{"jailed:attempt", "observe:effect"}, nil, nil)
	add("G-ENVELOPE-OLD-GATE", "Execution", "Execute", nil, []string{"jailed:attempt", "observe:effect"}, nil, nil)
	add("G-ENVELOPE-UNMET", "Effect", "Execute", []string{"SetupAbort"}, []string{"control:facility", "jailed:probe", "observe:effects"}, []string{"ABORT:selfcheck", "EFFECT:fuse-ioctl"}, []string{"fuse-unavailable"})
	return cases
}

// gateHooks are the protections whose mutation may show an effect here.
var gateHooks = []string{"P-G-ENVELOPE", "P-G-ENVELOPE-NO-NET", "P-G-ENVELOPE-EXPECT-NET", "P-G-NET-DAEMON-READ", "P-G-CONFINE-REQUIRED", "P-G-STRICT", "P-G-NET-STRICT", "P-COVERS", "P-CLONE-MNT", "P-SC-NET", "P-G-SEAL", "P-G-SEAL-GUARD", "P-G-LABEL-SWITCH", "P-G-JAILVERB-NOEXEC", "P-G-SELFTEST-JAILED", "P-G-PIN-REHEARSAL", "P-L2-GRAMMAR", "P-L2-REDIRECT", "P-L2-ADMIT", "P-L2-INTERP", "P-L2-EXEC-NARROW", "P-L2-MEMFD", "P-L2-SOCK-PIN", "P-L2-NET-OFF", "P-L2-SPEC-NET", "P-L2-ENV", "P-L2-IDENTITY"}

// gateProof is the gate package's proof: one case, its obligations, and the
// markers its legs observed. Finish prints the one PROOF-COMPLETE line.
type gateProof struct {
	t        *testing.T
	abi      string
	caseDef  harness.Case
	done     map[string]bool
	markers  []string
	finished bool
}

func newProof(t *testing.T, name string) *gateProof {
	t.Helper()
	index := slices.IndexFunc(gateProofCases(), func(c harness.Case) bool { return c.Name == name })
	if index < 0 {
		t.Fatalf("SETUP: unknown gate proof %s", name)
	}
	c := gateProofCases()[index]
	abi := ""
	for _, part := range strings.Split(t.Name(), "/") {
		if slices.Contains(c.ABIs, part) {
			if abi != "" {
				t.Fatal("SETUP: ambiguous proof ABI")
			}
			abi = part
		}
	}
	if abi == "" || c.Names[abi] != t.Name() {
		t.Fatalf("SETUP: proof %s runs as %s", name, t.Name())
	}
	p := &gateProof{t: t, abi: abi, caseDef: c, done: map[string]bool{}}
	t.Cleanup(func() {
		if !p.finished {
			t.Error("SETUP: proof not finished")
		}
	})
	return p
}

// Control, Jailed, Unit and Observed complete an obligation; an invalid one fails
// the leg.
func (p *gateProof) Control(name string, valid bool) {
	p.t.Helper()
	p.complete("control:"+name, valid)
}
func (p *gateProof) Jailed(name string, valid bool) { p.t.Helper(); p.complete("jailed:"+name, valid) }
func (p *gateProof) Unit(name string, valid bool)   { p.t.Helper(); p.complete("unit:"+name, valid) }
func (p *gateProof) Observed(name string, valid bool) {
	p.t.Helper()
	p.complete("observe:"+name, valid)
}

func (p *gateProof) complete(key string, valid bool) {
	p.t.Helper()
	if p.finished || !slices.Contains(p.caseDef.Obligations, key) || p.done[key] {
		p.t.Fatalf("SETUP: invalid or duplicate obligation %s", key)
	}
	if !valid {
		p.t.Fatalf("SETUP: %s failed", key)
	}
	p.done[key] = true
}

// Effect and Abort record a protection's observed effect or setup abort.
func (p *gateProof) Effect(assertion string, observed bool) { p.mark("EFFECT:"+assertion, observed) }
func (p *gateProof) Abort(stage string, observed bool)      { p.mark("ABORT:"+stage, observed) }

func (p *gateProof) mark(marker string, observed bool) {
	if observed && !slices.Contains(p.markers, marker) {
		p.markers = append(p.markers, marker)
	}
}

// Omit finishes the case with a declared omission instead of evidence.
func (p *gateProof) Omit(code string) {
	p.t.Helper()
	line := "PROOF-OMITTED " + p.caseDef.Name + " " + p.abi + " " + code
	record, err := harness.ParseProof(line)
	if err == nil {
		err = harness.CheckProof(p.caseDef, record, os.Getuid() == 0, os.Getenv("SSHGATE_JAIL_CI") == "1")
	}
	if err != nil {
		p.t.Fatal(err)
	}
	p.finished = true
	p.t.Log(line)
}

// Residual finishes the case with the residual its lane declares, after the
// same evidence Finish requires and with no markers.
func (p *gateProof) Residual(code string) {
	p.t.Helper()
	if p.finished || len(p.markers) > 0 || code == "" || p.caseDef.ResidualABIs[p.abi] != code {
		p.t.Fatalf("SETUP: undeclared residual %s in %s", code, p.abi)
	}
	for _, key := range p.caseDef.Obligations {
		if !p.done[key] {
			p.t.Fatalf("SETUP: unfinished obligation %s", key)
		}
	}
	if p.t.Failed() {
		return
	}
	line := "PROOF-RESIDUAL " + p.caseDef.Name + " " + p.abi + " " + code
	record, err := harness.ParseProof(line)
	if err == nil {
		err = harness.CheckProof(p.caseDef, record, os.Getuid() == 0, os.Getenv("SSHGATE_JAIL_CI") == "1")
	}
	if err != nil {
		p.t.Fatal(err)
	}
	p.finished = true
	p.t.Log(line)
}

func (p *gateProof) Finish() {
	p.t.Helper()
	if p.finished {
		p.t.Fatal("SETUP: duplicate proof finalization")
	}
	for _, key := range p.caseDef.Obligations {
		if !p.done[key] {
			p.t.Fatalf("SETUP: unfinished obligation %s", key)
		}
	}
	if p.t.Failed() {
		return
	}
	mutated := slices.ContainsFunc(gateHooks, jailmut.On)
	if len(p.markers) > 0 && !mutated {
		p.t.Fatalf("protection effects observed in a normal build: %v", p.markers)
	}
	slices.Sort(p.markers)
	line := "PROOF-COMPLETE " + p.caseDef.Name + " " + p.abi + " markers=" + strings.Join(p.markers, ",")
	record, err := harness.ParseProof(line)
	if err != nil {
		p.t.Fatal(err)
	}
	if err := harness.CheckProof(p.caseDef, record, os.Getuid() == 0, os.Getenv("SSHGATE_JAIL_CI") == "1"); err != nil {
		p.t.Fatal(err)
	}
	p.finished = true
	p.t.Log(line)
}

// TestGateProofCasesMatchManifest: this package's proof cases are exactly the
// confine manifest's cases for this package, so the jail runner's manifest
// check and these legs cannot drift apart.
func TestGateProofCasesMatchManifest(t *testing.T) {
	if err := harness.ValidateCases(gateProofCases()); err != nil {
		t.Fatal(err)
	}
	output, err := exec.Command("go", "test", "-count=1", "-run", "^TestProofCasesJSON$", "-v", "../../confine").CombinedOutput()
	if err != nil {
		t.Fatalf("read the confine manifest: %v\n%s", err, output)
	}
	var manifest []harness.Case
	for _, line := range strings.Split(string(output), "\n") {
		if data, ok := strings.CutPrefix(line, "JAIL-PROOF-CASES "); ok {
			if err := json.Unmarshal([]byte(data), &manifest); err != nil {
				t.Fatal(err)
			}
		}
	}
	var ours []harness.Case
	for _, c := range manifest {
		if c.Package == gateProofPackage {
			ours = append(ours, c)
		}
	}
	if !reflect.DeepEqual(ours, gateProofCases()) {
		t.Fatalf("manifest cases for %s:\n%+v\nadapter copy:\n%+v", gateProofPackage, ours, gateProofCases())
	}
}
