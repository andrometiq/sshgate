//go:build linux

package gate

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"slices"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/karthikeyan5/sshgate/src/gate/confine"
	"github.com/karthikeyan5/sshgate/src/gate/confine/jailmut"
	"github.com/karthikeyan5/sshgate/src/gate/confine/jailmut/harness"
)

type executorProof struct {
	t        *testing.T
	abi      string
	caseDef  harness.Case
	done     map[string]bool
	results  []*executorJailedResult
	markers  []string
	finished bool
}
type executorRunPlan struct{ mode string }
type executorJailedResult struct {
	owner               *executorProof
	mode                string
	validated, consumed bool
}
type executorObservation struct{ sealed, conclusive, valid bool }

func newProof(t *testing.T, name string) *executorProof {
	t.Helper()
	if name != "L-NSVERIFY" {
		t.Fatalf("SETUP: unknown executor proof %s", name)
	}
	c := harness.Case{Name: name, Package: "./src/gate", ABIs: []string{"native", "abi1"}, Kind: "Abort", Mode: "SetupAbort", Modes: []string{"Execute"}, Obligations: []string{"control:intact", "jailed:attempt", "observe:mounts"}, Markers: []string{"ABORT:private"}}
	if err := harness.ValidateCases([]harness.Case{c}); err != nil {
		t.Fatal(err)
	}
	abi := ""
	for _, part := range strings.Split(t.Name(), "/") {
		if slices.Contains(c.ABIs, part) {
			if abi != "" {
				t.Fatal("SETUP: ambiguous proof ABI")
			}
			abi = part
		}
	}
	if abi == "" {
		t.Fatal("SETUP: missing proof ABI")
	}
	p := &executorProof{t: t, abi: abi, caseDef: c, done: map[string]bool{}}
	t.Cleanup(func() {
		if !p.finished {
			t.Error("SETUP: proof not finished")
		}
	})
	return p
}

func (p *executorProof) complete(key string) {
	p.t.Helper()
	if p.finished || !slices.Contains(p.caseDef.Obligations, key) || p.done[key] {
		p.t.Fatalf("SETUP: invalid or duplicate obligation %s", key)
	}
	p.done[key] = true
}
func (p *executorProof) consume(result *executorJailedResult, mode string) {
	if result == nil || result.owner != p || !result.validated || result.consumed || result.mode != mode {
		p.t.Fatal("SETUP: invalid executor evidence")
	}
	result.consumed = true
}
func (p *executorProof) Control(name string, result *executorJailedResult) {
	p.consume(result, "Execute")
	p.complete("control:" + name)
}
func (p *executorProof) Jailed(name string, result *executorJailedResult) {
	p.consume(result, "SetupAbort")
	p.complete("jailed:" + name)
}
func (p *executorProof) Observed(name string, value executorObservation) {
	if !value.sealed || !value.conclusive || !value.valid {
		p.t.Fatal("SETUP: host mountinfo changed or observation unsealed")
	}
	p.complete("observe:" + name)
}

func runJailed(t *testing.T, p *executorProof, spec confine.Spec, plan executorRunPlan) *executorJailedResult {
	t.Helper()
	if p == nil || p.finished || (plan.mode != p.caseDef.Mode && !slices.Contains(p.caseDef.Modes, plan.mode)) {
		t.Fatal("SETUP: undeclared executor mode")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	result, err := ExecWithRedaction(ctx, "printf 'OP-BEGIN exec\\n'; ( printf EXECUTOR_CANARY ); proof_status=$?; printf '\\nOP-END %s\\n' \"$proof_status\"; printf 'exec-done\\n'; exit 0", ExecOpts{Confine: &spec, CaptureLimit: 4096})
	if ctx.Err() != nil || result.Cancelled || result.CleanupError != "" || result.Transport.SourceTruncated != "" || result.Transport.DeliveryError != "" || result.Transport.Abandoned || result.Transport.DroppedBytes != 0 {
		t.Fatalf("SETUP: executor incomplete: %v %+v", ctx.Err(), result)
	}
	switch plan.mode {
	case "Execute":
		if err != nil || result.ExitCode != 0 || result.Stderr != "" || result.Stdout != "OP-BEGIN exec\nEXECUTOR_CANARY\nOP-END 0\nexec-done\n" {
			t.Fatalf("SETUP: intact executor report: %+v %v", result, err)
		}
	case "SetupAbort":
		stage := "nsverify"
		if jailmut.On("P-NSVERIFY") {
			stage = "private"
		}
		var setup *confine.SetupError
		if !errors.As(err, &setup) || setup.Stage != stage || setup.Errno != syscall.EPERM || result.ExitCode != -1 || result.Stdout != "" || result.Stderr != "gate-jail: setup failed at "+stage+": operation not permitted\n" {
			t.Fatalf("SETUP: expected %s EPERM without execution: %+v %v", stage, result, err)
		}
		if stage == "private" {
			p.markers = append(p.markers, "ABORT:private")
		}
	default:
		t.Fatalf("SETUP: unknown executor mode %s", plan.mode)
	}
	evidence := &executorJailedResult{owner: p, mode: plan.mode, validated: true}
	p.results = append(p.results, evidence)
	return evidence
}

func (p *executorProof) Finish() {
	p.t.Helper()
	if p.finished {
		p.t.Fatal("SETUP: duplicate proof finalization")
	}
	for _, key := range p.caseDef.Obligations {
		if !p.done[key] {
			p.t.Fatalf("SETUP: unfinished obligation %s", key)
		}
	}
	for _, result := range p.results {
		if !result.consumed {
			p.t.Fatal("SETUP: unconsumed executor evidence")
		}
	}
	if p.t.Failed() {
		return
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
	// The only marker is possible under this compiled-in mutation hook.
	if len(p.markers) > 0 && !jailmut.On("P-NSVERIFY") {
		p.t.Error("protection effects observed in a normal build")
	}
}

func TestExecutorProofContract(t *testing.T) {
	for _, scenario := range []string{"complete", "unfinished", "missing", "duplicate", "unsealed", "marker", "unconsumed", "owner", "mode", "duplicate-marker"} {
		t.Run(scenario, func(t *testing.T) {
			command := exec.Command(os.Args[0], "-test.run=^TestExecutorProofFixture$")
			command.Env = append(os.Environ(), "SSHGATE_EXECUTOR_PROOF_FIXTURE="+scenario)
			output, err := command.CombinedOutput()
			if (err == nil) != (scenario == "complete") {
				t.Fatalf("scenario %s: %v %s", scenario, err, output)
			}
			if scenario != "complete" && strings.Contains(string(output), "PROOF-COMPLETE") {
				t.Fatalf("invalid evidence published: %s", output)
			}
		})
	}
}

func TestExecutorProofFixture(t *testing.T) {
	scenario := os.Getenv("SSHGATE_EXECUTOR_PROOF_FIXTURE")
	if scenario == "" {
		return
	}
	t.Run("native", func(t *testing.T) {
		p := newProof(t, "L-NSVERIFY")
		if scenario == "unfinished" {
			return
		}
		control := &executorJailedResult{owner: p, mode: "Execute", validated: true}
		attempt := &executorJailedResult{owner: p, mode: "SetupAbort", validated: true}
		p.results = []*executorJailedResult{control, attempt}
		if scenario == "owner" {
			control.owner = nil
		}
		if scenario == "mode" {
			control.mode = "SetupAbort"
		}
		p.Control("intact", control)
		if scenario == "duplicate" {
			p.Control("intact", control)
		}
		if scenario != "missing" {
			p.Jailed("attempt", attempt)
		}
		p.Observed("mounts", executorObservation{sealed: scenario != "unsealed", conclusive: true, valid: true})
		if scenario == "marker" {
			p.markers = []string{"EFFECT:undeclared"}
		}
		if scenario == "duplicate-marker" {
			p.markers = []string{"ABORT:private", "ABORT:private"}
		}
		if scenario == "unconsumed" {
			p.results = append(p.results, &executorJailedResult{owner: p, mode: "Execute", validated: true})
		}
		p.Finish()
	})
}
