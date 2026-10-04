//go:build linux && jail_e2e

package confine

import (
	"bytes"
	"fmt"
	"os/exec"
	"syscall"
	"testing"
)

type userRetuneVictim struct {
	command         *exec.Cmd
	stderr          bytes.Buffer
	sealed, stopped bool
	stopErr         error
}

func newUserRetuneVictim(t *testing.T) *userRetuneVictim {
	t.Helper()
	v := &userRetuneVictim{command: exec.Command("sleep", "3600")}
	v.command.Stderr = &v.stderr
	mutationSetup(t, v.command.Start())
	t.Cleanup(func() {
		if err := v.Stop(); err != nil {
			t.Errorf("SETUP: USER victim: %v", err)
		}
	})
	return v
}
func (v *userRetuneVictim) Start(t *testing.T) { t.Helper(); mutationSetup(t, v.Healthy()) }
func (v *userRetuneVictim) Mark() ObserverMark { v.sealed = false; return 0 }
func (v *userRetuneVictim) Since(ObserverMark) ObservationRecords {
	err := v.Healthy()
	return ObservationRecords{Sealed: v.sealed, Conclusive: err == nil && v.sealed, Err: err}
}
func (v *userRetuneVictim) Healthy() error {
	if v.stopped {
		return v.stopErr
	}
	return v.command.Process.Signal(syscall.Signal(0))
}
func (v *userRetuneVictim) Seal(sync ProducerSync) error {
	if !sync.Complete || sync.Kind != "framed-op-ended" {
		return fmt.Errorf("USER victim requires completed retune operations")
	}
	if err := v.Healthy(); err != nil {
		return err
	}
	v.sealed = true
	return nil
}
func (v *userRetuneVictim) Stop() error {
	if v.stopped {
		return v.stopErr
	}
	v.stopped = true
	if err := v.command.Process.Kill(); err != nil {
		v.stopErr = err
	}
	err := v.command.Wait()
	if v.command.ProcessState == nil {
		v.stopErr = fmt.Errorf("USER victim wait did not return process state: %v", err)
		return v.stopErr
	}
	status, ok := v.command.ProcessState.Sys().(syscall.WaitStatus)
	if !ok || !status.Signaled() || status.Signal() != syscall.SIGKILL || v.stderr.Len() != 0 {
		v.stopErr = fmt.Errorf("USER victim termination: %v stderr=%q", err, v.stderr.String())
	}
	return v.stopErr
}

func TestM2UserVictimSealing(t *testing.T) {
	victim := newUserRetuneVictim(t)
	victim.Start(t)
	mark := victim.Mark()
	if records := victim.Since(mark); records.Sealed || records.Conclusive {
		t.Fatal("unsealed victim accepted")
	}
	if err := victim.Seal(ProducerSync{Complete: true, Kind: "sleep"}); err == nil {
		t.Fatal("unrelated synchronization accepted")
	}
	if err := victim.Seal(ProducerSync{Complete: true, Kind: "framed-op-ended"}); err != nil {
		t.Fatal(err)
	}
	if records := victim.Since(mark); !records.Sealed || !records.Conclusive || records.Err != nil {
		t.Fatalf("sealed victim rejected: %+v", records)
	}
	if err := victim.Stop(); err != nil {
		t.Fatal(err)
	}
	if err := victim.Stop(); err != nil {
		t.Fatal(err)
	}
}

func TestM2DisposableProofTransport(t *testing.T) {
	const valid = "    source.go:42: PROOF-COMPLETE L-SCHED-USER native markers=EFFECT:retuned\n"
	for _, test := range []struct {
		name, output string
		valid        bool
	}{
		{"complete", valid, true},
		{"missing", "PASS\n", false},
		{"duplicate", valid + valid, false},
		{"malformed", "PROOF-COMPLETE L-SCHED-USER native markers=bad\n", false},
		{"foreign", "PROOF-COMPLETE L-OTHER native markers=\n", false},
		{"omitted", "PROOF-OMITTED L-SCHED-USER native root-only\n", false},
	} {
		t.Run(test.name, func(t *testing.T) {
			_, _, err := parseDisposableProof([]byte(test.output), "L-SCHED-USER")
			if (err == nil) != test.valid {
				t.Fatalf("valid=%v error=%v", test.valid, err)
			}
		})
	}
}
