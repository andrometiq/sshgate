//go:build linux && jail_e2e

package confine

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

// An unjailed fixture owns its pipes and joins the producer before exposing output.
type m1Holder struct {
	command    *exec.Cmd
	input      io.WriteCloser
	output     proofOutput
	diagnostic bytes.Buffer
	done       chan error
	cancel     context.CancelFunc
	joined     bool
	err        error
}

func startM1Holder(t *testing.T, program string, arguments ...string) *m1Holder {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	holder := &m1Holder{command: exec.CommandContext(ctx, program, arguments...), done: make(chan error, 1), cancel: cancel}
	holder.output.ready = make(chan struct{})
	holder.command.Stdout = &holder.output
	holder.command.Stderr = &holder.diagnostic
	// The test owns both pipe ends: Wait closes a StdinPipe writer itself, which
	// races the release write's own Close once the fixture exits.
	reader, writer, err := os.Pipe()
	mutationSetup(t, err)
	holder.command.Stdin, holder.input = reader, writer
	go func() { holder.done <- holder.command.Run() }()
	t.Cleanup(func() {
		holder.cancel()
		holder.input.Close()
		if !holder.joined {
			holder.err = <-holder.done
			holder.joined = true
		}
		reader.Close()
	})
	select {
	case <-holder.output.ready:
	case err := <-holder.done:
		holder.joined = true
		holder.err = err
		t.Fatalf("SETUP: fixture ended before READY: %v %s", err, holder.diagnostic.String())
	case <-ctx.Done():
		t.Fatal("SETUP: fixture READY timeout")
	}
	return holder
}
func (holder *m1Holder) finish(t *testing.T) jailResult {
	t.Helper()
	if holder.joined {
		t.Fatal("SETUP: fixture already joined")
	}
	_, err := io.WriteString(holder.input, "go\n")
	mutationSetup(t, err)
	mutationSetup(t, holder.input.Close())
	holder.err = <-holder.done
	holder.joined = true
	holder.cancel()
	return jailResult{stdout: holder.output.snapshot(), stderr: holder.diagnostic.String(), exit: proofExit(holder.err)}
}
func validateM1Flock(stdout, stderr string, exit int) error {
	if strings.Count(stdout, "READY\n") != 1 {
		return fmt.Errorf("missing or duplicate holder READY")
	}
	return validateM1Reports(jailResult{stdout: strings.Replace(stdout, "READY\n", "", 1), stderr: stderr, exit: exit}, []string{"open", "flock", "release"})
}

func startM1SignalRecipient(t *testing.T) *m1Holder {
	// A single-threaded shell dispatches its pending trap before acknowledging the
	// pipe barrier. An interrupted read retries until the producer sends "go".
	return startM1Holder(t, "/bin/sh", "-c", `seen=0; trap 'seen=1' USR1; printf 'READY\n'; while :; do read -r token; if [ "$token" = go ]; then break; fi; done; printf 'signal=%s\n' "$seen"`)
}

type m1RecipientObserver struct {
	holder *m1Holder
	t      *testing.T
	sealed bool
	report string
	err    error
}

func (observer *m1RecipientObserver) Start(t *testing.T) { observer.t = t }
func (observer *m1RecipientObserver) Mark() ObserverMark { observer.sealed = false; return 0 }
func (observer *m1RecipientObserver) Since(mark ObserverMark) ObservationRecords {
	return ObservationRecords{Records: []string{observer.report}, Sealed: observer.sealed, Conclusive: observer.sealed && observer.err == nil, Err: observer.err}
}
func (observer *m1RecipientObserver) Healthy() error { return observer.err }
func (observer *m1RecipientObserver) Seal(sync ProducerSync) error {
	if !sync.Complete || sync.Kind != "framed-op-ended" || observer.sealed {
		return fmt.Errorf("recipient lacks producer completion")
	}
	result := observer.holder.finish(observer.t)
	if result.exit != 0 || result.stderr != "" || result.stdout != "READY\nsignal=0\n" && result.stdout != "READY\nsignal=1\n" {
		observer.err = fmt.Errorf("recipient completion: %+v", result)
		return observer.err
	}
	observer.report = strings.TrimSuffix(strings.TrimPrefix(result.stdout, "READY\n"), "\n")
	observer.sealed = true
	return nil
}
func (observer *m1RecipientObserver) Stop() error {
	if !observer.sealed {
		observer.holder.cancel()
		return fmt.Errorf("recipient not sealed")
	}
	return observer.err
}
