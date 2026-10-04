package confine

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"testing"

	"github.com/karthikeyan5/sshgate/src/gate/confine/jailmut/harness"
)

func TestProofAPIRejectsIncompleteEvidence(t *testing.T) {
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		mode, diagnostic string
		pass             bool
	}{
		{"complete", "PROOF-COMPLETE", true},
		{"empty-declaration", "obligations below", false},
		{"noop", "unfinished obligation", false},
		{"unfinished", "proof not finished", false},
		{"fatal-body", "proof not finished", false},
		{"duplicate", "duplicate obligation", false},
		{"marker", "PROOF-COMPLETE", proofMutationBuild},
		{"observer-stop", "observer fixture stop", false},
		{"observer-health", "observer fixture:", false},
		{"unsealed", "inconclusive or invalid observation", false},
		{"inconclusive", "inconclusive or invalid observation", false},
		{"delayed-effect", "inconclusive or invalid observation", false},
		{"observer-racing-error", "observer fixture stop", false},
	}
	for _, test := range tests {
		t.Run(test.mode, func(t *testing.T) {
			command := exec.Command(executable, "-test.run=^TestProofAPIFixture$", "-test.v")
			command.Env = append(os.Environ(), "SSHGATE_PROOF_FIXTURE="+test.mode)
			output, err := command.CombinedOutput()
			if (err == nil) != test.pass {
				t.Fatalf("pass=%t want %t: %v\n%s", err == nil, test.pass, err, output)
			}
			if !strings.Contains(string(output), test.diagnostic) {
				t.Fatalf("missing diagnostic %q:\n%s", test.diagnostic, output)
			}
			if !test.pass && test.mode != "marker" && strings.Contains(string(output), "PROOF-COMPLETE") {
				t.Fatalf("failed proof published completion:\n%s", output)
			}
		})
	}
}

// This runs only in a child so Fatal and Cleanup execute exactly as in a leg.
func TestProofAPIFixture(t *testing.T) {
	mode := os.Getenv("SSHGATE_PROOF_FIXTURE")
	if mode == "" {
		return
	}
	c := harness.Case{Name: "U-PROOF-FIXTURE", Kind: "Unit", ABIs: []string{"native"}, Obligations: []string{"control:decision"}, Markers: []string{"EFFECT:write"}}
	if mode == "empty-declaration" {
		c.Obligations = nil
	}
	observation := mode == "unsealed" || mode == "inconclusive" || mode == "delayed-effect"
	if observation {
		c.Obligations = append(c.Obligations, "observe:absence")
	}
	p := beginProof(t, c)
	switch mode {
	case "noop":
		p.Finish()
		return
	case "unfinished":
		return
	case "fatal-body":
		t.Fatal("fixture failed before obligation")
	}
	p.Control("decision", ControlResult{Valid: true})
	if mode == "duplicate" {
		p.Control("decision", ControlResult{Valid: true})
	}
	if mode == "marker" {
		p.record("EFFECT", c.Name, "write")
	}
	observer := &proofFixtureObserver{}
	if strings.HasPrefix(mode, "observer-") {
		p.ObserveWith("fixture", observer)
		switch mode {
		case "observer-stop":
			observer.stopErr = errors.New("worker failure")
		case "observer-health":
			observer.healthErr = errors.New("producer died")
		case "observer-racing-error":
			observer.stopHook = func() { observer.stopErr = errors.New("worker failure at join") }
		}
	}
	if observation {
		p.ObserveWith("fixture", observer)
		mark := observer.Mark()
		if mode == "delayed-effect" {
			observer.pending = []string{"IOCTL 42"}
		}
		if mode != "unsealed" {
			if err := observer.Seal(ProducerSync{Complete: mode != "inconclusive", Kind: "request-barrier"}); err != nil && mode != "inconclusive" {
				t.Fatal(err)
			}
		}
		records := observer.Since(mark)
		p.Observed("absence", Observation{Conclusive: records.Conclusive, Sealed: records.Sealed, Valid: len(records.Records) == 0 && records.Err == nil, Detail: "fixture negative observation"})
	}
	p.Finish()
}

type proofFixtureObserver struct {
	records, pending   []string
	sealed             bool
	healthErr, stopErr error
	stopHook           func()
}

func (*proofFixtureObserver) Start(*testing.T)     {}
func (o *proofFixtureObserver) Mark() ObserverMark { return ObserverMark(len(o.records)) }
func (o *proofFixtureObserver) Since(mark ObserverMark) ObservationRecords {
	return ObservationRecords{Records: append([]string(nil), o.records[int(mark):]...), Sealed: o.sealed, Conclusive: o.sealed && o.healthErr == nil, Err: o.healthErr}
}
func (o *proofFixtureObserver) Healthy() error { return o.healthErr }
func (o *proofFixtureObserver) Seal(sync ProducerSync) error {
	if !sync.Complete {
		return fmt.Errorf("producer synchronization unavailable")
	}
	o.records = append(o.records, o.pending...)
	o.pending = nil
	o.sealed = true
	return nil
}
func (o *proofFixtureObserver) Stop() error {
	if o.stopHook != nil {
		o.stopHook()
	}
	return o.stopErr
}

func TestProofFramedReports(t *testing.T) {
	ops := []ProofOp{{Name: "write", Command: "probe write", Outcomes: []OpOutcome{{Stdout: "write-done\n", Exit: 0}}}}
	complete := "OP-BEGIN write\nwrite-done\n\nOP-END 0\nwrite-done\n"
	for _, test := range []struct {
		name, stdout, stderr string
		exit                 int
		valid                bool
	}{
		{"complete", complete, "", 0, true},
		{"missing-frame-end", "OP-BEGIN write\nwrite-done\n", "", 0, false},
		{"missing-probe-terminal", "OP-BEGIN write\n\nOP-END 0\nwrite-done\n", "", 0, false},
		{"missing-wrapper-terminal", "OP-BEGIN write\nwrite-done\n\nOP-END 0\n", "", 0, false},
		{"crashed-probe", "OP-BEGIN write\nwrite-done\n\nOP-END 139\nwrite-done\n", "", 0, false},
		{"crashed-shell", complete, "", 139, false},
		{"unexpected-stderr", complete, "probe crashed", 0, false},
		{"extra-output", complete + "unframed\n", "", 0, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			_, err := validateFramed(jailResult{stdout: test.stdout, stderr: test.stderr, exit: test.exit}, ops)
			if (err == nil) != test.valid {
				t.Fatalf("valid=%t want %t: %v", err == nil, test.valid, err)
			}
		})
	}
}

func TestProofSealingIncludesDelayedSuccessfulEffect(t *testing.T) {
	observer := &proofFixtureObserver{}
	mark := observer.Mark()
	observer.pending = []string{"IOCTL 42"}
	if records := observer.Since(mark); records.Sealed || records.Conclusive {
		t.Fatal("unsealed observation became conclusive")
	}
	if err := observer.Seal(ProducerSync{Complete: true, Kind: "request-barrier"}); err != nil {
		t.Fatal(err)
	}
	records := observer.Since(mark)
	if !records.Sealed || !records.Conclusive || len(records.Records) != 1 || records.Records[0] != "IOCTL 42" {
		t.Fatalf("delayed successful effect lost: %+v", records)
	}
}

func TestProofExpectedSignalRejectsExit139(t *testing.T) {
	plan := RunPlan{Mode: ExpectedSignal, Signal: syscall.SIGSEGV, Validate: func(stdout, stderr string, exit int) error {
		if stdout != "pid=42\nready-for-signal\n" || stderr != "" || exit != 139 {
			return fmt.Errorf("invalid pre-signal report")
		}
		return nil
	}}
	for _, test := range []struct {
		name   string
		worker WorkerStatus
		stdout string
		valid  bool
	}{
		{"genuine-signal", WorkerStatus{Known: true, Signal: syscall.SIGSEGV}, "pid=42\nready-for-signal\n", true},
		{"exit139-spoof", WorkerStatus{Known: true, Exited: true, Code: 139}, "pid=42\nready-for-signal\n", false},
		{"unavailable", WorkerStatus{Unavailable: "not published"}, "pid=42\nready-for-signal\n", false},
		{"wrong-signal", WorkerStatus{Known: true, Signal: syscall.SIGKILL}, "pid=42\nready-for-signal\n", false},
		{"incomplete-report", WorkerStatus{Known: true, Signal: syscall.SIGSEGV}, "pid=42\n", false},
	} {
		t.Run(test.name, func(t *testing.T) {
			result := JailedResult{jailResult: jailResult{exit: 139, stdout: test.stdout}, Worker: test.worker}
			err := validateExpectedSignal(result, plan)
			if (err == nil) != test.valid {
				t.Fatalf("valid=%t want %t: %v", err == nil, test.valid, err)
			}
		})
	}
}
