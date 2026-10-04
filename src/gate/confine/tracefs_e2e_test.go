//go:build linux && jail_e2e

package confine

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

func legTracefs(t *testing.T, spec Spec) {
	if os.Geteuid() != 0 || os.Getenv("SSHGATE_JAIL_CI") != "1" {
		t.Fatal("SETUP: tracefs requires disposable root CI")
	}
	if !coverNamespace(t, false) {
		return
	}
	p := newProof(t, "L-TRACEFS")
	point := filepath.Join(t.TempDir(), "tracefs")
	mutationSetup(t, os.Mkdir(point, 0755))
	mutationSetup(t, unix.Mount("tracefs", point, "tracefs", unix.MS_NOSUID|unix.MS_NODEV, ""))
	t.Cleanup(func() {
		if err := unix.Unmount(point, unix.MNT_DETACH); err != nil {
			unexpected(t, "tracefs unmount: %v", err)
		}
	})
	instance := filepath.Join(point, "instances", fmt.Sprintf("sshgate-%d", os.Getpid()))
	mutationSetup(t, os.Mkdir(instance, 0700))
	t.Cleanup(func() {
		if err := os.Remove(instance); err != nil {
			unexpected(t, "trace instance cleanup: %v", err)
		}
	})
	mutationSetup(t, os.WriteFile(filepath.Join(instance, "tracing_on"), []byte("1"), 0600))
	marker := fmt.Sprintf("sshgate-trace-canary-%d", os.Getpid())
	mutationSetup(t, os.WriteFile(filepath.Join(instance, "trace_marker"), []byte(marker+"\n"), 0600))
	readTrace := func() string {
		data, err := os.ReadFile(filepath.Join(instance, "trace"))
		mutationSetup(t, err)
		return string(data)
	}
	if !strings.Contains(readTrace(), marker) {
		t.Fatal("SETUP: trace marker not recorded")
	}
	observer := &traceObserver{path: filepath.Join(instance, "trace")}
	p.ObserveWith("trace", observer)
	mark := observer.Mark()
	probe := buildProbe(t)
	pipe := filepath.Join(instance, "trace_pipe")
	result := runJailed(t, p, spec, RunPlan{Mode: Execute, Ops: []ProofOp{{Name: "trace", Command: coverQuote(probe) + " trace-drain " + coverQuote(pipe), Validate: func(stdout, stderr string, exit int) error {
		denied := stdout == "open=2\n" && exit == 1
		drained := strings.HasPrefix(stdout, "open=ok\nread=ok\n") && strings.Contains(stdout, marker) && strings.HasSuffix(stdout, "\n") && exit == 0
		if stderr != "" || (!denied && !drained) {
			return fmt.Errorf("trace completion exit=%d stderr=%q report=%q", exit, stderr, stdout)
		}
		return nil
	}}}})
	p.Jailed("probe", result)
	coverRan(t, result.jailResult)
	mutationSetup(t, observer.Seal(ProducerSync{Complete: true, Kind: "framed-op-ended"}))
	records := observer.Since(mark)
	consumed := !strings.Contains(strings.Join(records.Records, "\n"), marker)
	mutationEffect(t, "L-TRACEFS", "trace-consumed", consumed)
	p.Observed("marker", Observation{Conclusive: true, Sealed: true, Valid: (!consumed || strings.Contains(result.stdout, marker)), Detail: "trace state after synchronous drain returned"})
	if consumed {
		if !strings.Contains(result.stdout, marker) {
			unexpected(t, "marker disappeared without being read by jail")
		}
		mutationSetup(t, os.WriteFile(filepath.Join(instance, "trace_marker"), []byte(marker+"\n"), 0600))
	} else if !strings.Contains(result.stdout, "open=2\n") {
		unexpected(t, "trace pipe not hidden: %+v", result)
	}
	control, err := exec.Command(probe, "trace-drain", pipe).CombinedOutput()
	mutationSetup(t, err)
	if !strings.Contains(string(control), marker) || strings.Contains(readTrace(), marker) {
		t.Fatalf("SETUP: trace pipe control did not consume marker: %s", control)
	}
	p.Control("drain", ControlResult{Valid: strings.Contains(string(control), marker) && !strings.Contains(readTrace(), marker), Detail: "unconfined drain consumed marker"})
	p.Finish()
}

type traceObserver struct {
	path    string
	records []string
	sealed  bool
}

func (o *traceObserver) Start(t *testing.T) { t.Helper(); mutationSetup(t, o.Healthy()) }
func (o *traceObserver) Mark() ObserverMark { o.sealed = false; return 0 }
func (o *traceObserver) Since(mark ObserverMark) ObservationRecords {
	if mark != 0 || !o.sealed {
		return ObservationRecords{Err: fmt.Errorf("inconclusive trace window")}
	}
	return ObservationRecords{Records: append([]string(nil), o.records...), Sealed: true, Conclusive: true}
}
func (o *traceObserver) Healthy() error { _, err := os.ReadFile(o.path); return err }
func (o *traceObserver) Seal(sync ProducerSync) error {
	if !sync.Complete || sync.Kind != "framed-op-ended" {
		return fmt.Errorf("inconclusive trace producer completion")
	}
	data, err := os.ReadFile(o.path)
	if err != nil {
		return err
	}
	o.records = strings.Split(string(data), "\n")
	o.sealed = true
	return nil
}
func (o *traceObserver) Stop() error { return o.Healthy() }

func TestTraceObserverSealFixture(t *testing.T) {
	path := filepath.Join(t.TempDir(), "trace")
	mutationSetup(t, os.WriteFile(path, []byte("marker\n"), 0600))
	observer := &traceObserver{path: path}
	observer.Start(t)
	mark := observer.Mark()
	if records := observer.Since(mark); records.Conclusive || records.Err == nil {
		t.Fatal("unsealed trace accepted")
	}
	if err := observer.Seal(ProducerSync{Complete: true, Kind: "shutdown"}); err == nil {
		t.Fatal("shutdown accepted as producer synchronization")
	}
	mutationSetup(t, observer.Seal(ProducerSync{Complete: true, Kind: "framed-op-ended"}))
	mutationSetup(t, os.WriteFile(path, []byte("later\n"), 0600))
	records := observer.Since(mark)
	if !records.Conclusive || !records.Sealed || strings.Join(records.Records, "\n") != "marker\n" {
		t.Fatalf("sealed trace changed: %+v", records)
	}
	mutationSetup(t, observer.Stop())
}
