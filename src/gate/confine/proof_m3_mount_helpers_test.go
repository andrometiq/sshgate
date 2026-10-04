//go:build linux && jail_e2e

package confine

import (
	"bytes"
	"fmt"
	"os/exec"
	"strings"
	"testing"

	"github.com/karthikeyan5/sshgate/src/gate/confine/jailmut"
	"github.com/karthikeyan5/sshgate/src/gate/confine/jailmut/harness"
	"golang.org/x/sys/unix"
)

func mountProbePlan(command string, values []string, fields ...string) RunPlan {
	return RunPlan{Mode: Execute, Ops: []ProofOp{{Name: "probe", Command: command, Validate: func(stdout, stderr string, exit int) error {
		result := jailResult{stdout: stdout, stderr: stderr, exit: exit}
		if err := validateProbeOutput(result, fields, probeExitMixed); err != nil {
			return err
		}
		allowed := map[string]bool{}
		for _, field := range fields {
			allowed[field] = true
		}
		for _, line := range strings.Split(strings.TrimSuffix(stdout, "\n"), "\n") {
			field, value, _ := strings.Cut(line, "=")
			validValue := false
			for _, want := range values {
				validValue = validValue || value == want
			}
			if !validValue {
				return fmt.Errorf("undeclared outcome %q", line)
			}
			if !allowed[field] {
				return fmt.Errorf("undeclared report %q", field)
			}
		}
		return nil
	}}}}
}

// Synchronous kernel state is sampled only after the framed producer has ended.
type mountStateObserver struct {
	sample     func() []string
	records    []string
	sealed     bool
	generation ObserverMark
}

func (*mountStateObserver) Start(*testing.T) {}
func (o *mountStateObserver) Mark() ObserverMark {
	o.generation++
	o.sealed = false
	o.records = nil
	return o.generation
}
func (o *mountStateObserver) Healthy() error { return nil }
func (o *mountStateObserver) Seal(sync ProducerSync) error {
	if !sync.Complete || sync.Kind != "framed-op-ended" {
		return fmt.Errorf("missing framed producer completion")
	}
	o.records = o.sample()
	o.sealed = true
	return nil
}
func (o *mountStateObserver) Since(mark ObserverMark) ObservationRecords {
	valid := o.sealed && (mark == 0 || mark == o.generation)
	return ObservationRecords{Records: append([]string(nil), o.records...), Sealed: valid, Conclusive: valid}
}
func (*mountStateObserver) Stop() error { return nil }

func sealMountState(t *testing.T, observer *mountStateObserver, mark ObserverMark) ObservationRecords {
	t.Helper()
	mutationSetup(t, observer.Seal(ProducerSync{Complete: true, Kind: "framed-op-ended"}))
	records := observer.Since(mark)
	if records.Err != nil || !records.Sealed || !records.Conclusive {
		t.Fatalf("SETUP: incomplete mount observation: %+v", records)
	}
	return records
}

// FIFO writes finish synchronously; a nonblocking drain after producer completion
// sees every byte without a timing window or a helper process.
type mountFIFOObserver struct {
	fd         int
	generation ObserverMark
	records    []string
	sealed     bool
	err        error
}

func (*mountFIFOObserver) Start(*testing.T) {}
func (o *mountFIFOObserver) Mark() ObserverMark {
	o.generation++
	o.sealed = false
	o.records = nil
	return o.generation
}
func (o *mountFIFOObserver) Healthy() error { return o.err }
func (o *mountFIFOObserver) Seal(sync ProducerSync) error {
	if !sync.Complete || (sync.Kind != "framed-op-ended" && sync.Kind != "process-exited") {
		return fmt.Errorf("FIFO producer is not complete")
	}
	buffer := make([]byte, 4096)
	for {
		n, err := unix.Read(o.fd, buffer)
		if n > 0 {
			o.records = append(o.records, string(buffer[:n]))
		}
		if err == unix.EAGAIN || err == nil && n == 0 {
			break
		}
		if err != nil {
			o.err = err
			return err
		}
	}
	o.sealed = true
	return nil
}
func (o *mountFIFOObserver) Since(mark ObserverMark) ObservationRecords {
	valid := o.sealed && (mark == 0 || mark == o.generation) && o.err == nil
	return ObservationRecords{Records: append([]string(nil), o.records...), Sealed: valid, Conclusive: valid, Err: o.err}
}
func (o *mountFIFOObserver) Stop() error { return unix.Close(o.fd) }

func TestM3MountObservationSeal(t *testing.T) {
	state := "before"
	observer := &mountStateObserver{sample: func() []string { return []string{state} }}
	mark := observer.Mark()
	if observer.Since(mark).Conclusive {
		t.Fatal("unsealed snapshot accepted")
	}
	state = "after"
	if err := observer.Seal(ProducerSync{Complete: false, Kind: "framed-op-ended"}); err == nil {
		t.Fatal("incomplete producer accepted")
	}
	records := sealMountState(t, observer, mark)
	if len(records.Records) != 1 || records.Records[0] != "after" {
		t.Fatalf("late effect lost: %+v", records)
	}
	observer.Mark()
	if observer.Since(mark).Conclusive {
		t.Fatal("stale window accepted")
	}
}

func TestM3FIFOObservationSeal(t *testing.T) {
	path := t.TempDir() + "/fifo"
	mutationSetup(t, unix.Mkfifo(path, 0600))
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	mutationSetup(t, err)
	observer := &mountFIFOObserver{fd: fd}
	defer func() { mutationSetup(t, observer.Stop()) }()
	mark := observer.Mark()
	writer, err := unix.Open(path, unix.O_WRONLY|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	mutationSetup(t, err)
	_, err = unix.Write(writer, []byte("x"))
	mutationSetup(t, err)
	mutationSetup(t, unix.Close(writer))
	if observer.Since(mark).Conclusive {
		t.Fatal("unsealed FIFO accepted")
	}
	mutationSetup(t, observer.Seal(ProducerSync{Complete: true, Kind: "framed-op-ended"}))
	records := observer.Since(mark)
	if !observer.Since(0).Conclusive {
		t.Fatal("proof cannot consume current FIFO window")
	}
	if !records.Conclusive || strings.Join(records.Records, "") != "x" {
		t.Fatalf("delivery lost: %+v", records)
	}
	mark = observer.Mark()
	mutationSetup(t, observer.Seal(ProducerSync{Complete: true, Kind: "framed-op-ended"}))
	if got := observer.Since(mark); !got.Conclusive || len(got.Records) != 0 {
		t.Fatalf("empty sealed FIFO: %+v", got)
	}
}

func mountWriteOutcomes() []string {
	if jailmut.On("P-RO") {
		return []string{"13", "ok"}
	}
	return []string{"30"}
}

func TestM3ObserverProofIntegration(t *testing.T) {
	p := beginProof(t, harness.Case{Name: "U-M3-OBSERVER", Kind: "Unit", ABIs: []string{"native"}, Obligations: []string{"control:fixture", "observe:state"}})
	observer := &mountStateObserver{sample: func() []string { return []string{"state"} }}
	p.ObserveWith("state", observer)
	mark := observer.Mark()
	records := sealMountState(t, observer, mark)
	p.Control("fixture", ControlResult{Valid: true})
	p.Observed("state", Observation{Conclusive: records.Conclusive, Sealed: records.Sealed, Valid: len(records.Records) == 1})
	p.Finish()
}

func mountControl(t *testing.T, command *exec.Cmd, wantExit int) []byte {
	t.Helper()
	var stdout, stderr bytes.Buffer
	command.Stdout = &stdout
	command.Stderr = &stderr
	err := command.Run()
	if proofExit(err) != wantExit || stderr.Len() != 0 {
		t.Fatalf("SETUP: control exit=%d want=%d stderr=%q", proofExit(err), wantExit, stderr.String())
	}
	return stdout.Bytes()
}

func TestM3MountProbeOutcomes(t *testing.T) {
	validate := mountProbePlan("probe", []string{"30"}, "write").Ops[0].Validate
	for _, test := range []struct {
		report string
		exit   int
		valid  bool
	}{{"write=30\n", 1, true}, {"write=5\n", 1, false}, {"write=30\nextra=30\n", 1, false}, {"write=30\n", 0, false}, {"", 1, false}} {
		if err := validate(test.report, "", test.exit); (err == nil) != test.valid {
			t.Fatalf("report=%q exit=%d valid=%t: %v", test.report, test.exit, test.valid, err)
		}
	}
}
