package hosted

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log"
	"os"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/karthikeyan5/sshgate/pkg/signerkit"
)

func TestApprovalV2AdmissionCancellationJoins(t *testing.T) {
	for _, actor := range []string{"flusher", "worker"} {
		t.Run(actor, func(t *testing.T) {
			e, db, clock := approvalEngineFixture(t, false)
			approvalWorkerSink(e)
			submitApproval(t, e, 1)
			if actor == "worker" {
				if e.flushPass(context.Background()) {
					t.Fatal("initial flush")
				}
				clock.Advance(6 * time.Second)
			}
			e.writerAdmission <- struct{}{}
			defer func() { <-e.writerAdmission }()
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			done := make(chan error, 1)
			go func() { done <- e.Run(ctx) }()
			// Observe the actual blocked mutation, not merely delivery or row selection.
			target := ".flushPass("
			if actor == "worker" {
				target = ".reconcileRow("
			}
			awaitApprovalState(t, func() bool {
				buf := make([]byte, 1<<20)
				stacks := string(buf[:runtime.Stack(buf, true)])
				for _, stack := range strings.Split(stacks, "\n\n") {
					if strings.Contains(stack, ".transact(") && strings.Contains(stack, target) {
						return true
					}
				}
				return false
			})
			cancel()
			select {
			case err := <-done:
				if !errors.Is(err, context.Canceled) {
					t.Fatal(err)
				}
			case <-time.After(time.Second):
				t.Fatal("Run did not join while writer admission was held")
			}
			if actor == "flusher" && readApproval(t, db, 1).Record.Header.AuditedThrough != 0 {
				t.Fatal("canceled Flush committed")
			}
		})
	}
}

func TestProcessAuditSinkUnreadableFileTail(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("requires unprivileged process")
	}
	path := t.TempDir() + "/audit"
	if err := os.WriteFile(path, []byte("torn"), 0200); err != nil {
		t.Fatal(err)
	}
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_APPEND, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	if reader, err := os.Open(fmt.Sprintf("/proc/self/fd/%d", file.Fd())); err == nil {
		reader.Close()
		t.Fatal("fixture can reopen for reading")
	}
	sink, err := NewProcessAuditSink(file)
	if err != nil {
		t.Fatal(err)
	}
	trackAuditTestSink(t, sink)
	if err := sink.Call(context.Background(), signerkit.AuditCall{}); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0600); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.HasPrefix(data, []byte("torn\n{\"kind\":\"call\"")) {
		t.Fatalf("no separator: %q", data)
	}
}

func TestApprovalV2DiagnosticFloodDrainsOutbox(t *testing.T) {
	e, db, _ := approvalEngineFixture(t, false)
	approvalWorkerSink(e)
	submitApproval(t, e, 1)
	var sink *ProcessAuditSink
	var stopped atomic.Bool
	var once sync.Once
	entered, release := make(chan struct{}), make(chan struct{})
	sink = newAuditTestSink(t, auditWriterFunc(func(p []byte) (int, error) {
		// Every diagnostic replenishes its queue: it never becomes empty.
		if bytes.HasPrefix(p, []byte("diagnostic")) {
			once.Do(func() { close(entered); <-release })
			if !stopped.Load() {
				sink.Write([]byte("diagnostic\n"))
			}
			time.Sleep(time.Millisecond)
		}
		return len(p), nil
	}))
	defer func() {
		stopped.Store(true)
		awaitApprovalState(t, func() bool { sink.mu.Lock(); defer sink.mu.Unlock(); return !sink.busy })
	}()
	e.config.AuditSink = sink
	sink.Write([]byte("diagnostic\n"))
	<-entered
	var releaseOnce sync.Once
	defer func() { releaseOnce.Do(func() { close(release) }) }()
	done := make(chan bool, 1)
	go func() { done <- e.flushPass(context.Background()) }()
	// Ensure the audit has reserved priority before allowing diagnostics to drain.
	awaitApprovalState(t, func() bool { sink.mu.Lock(); defer sink.mu.Unlock(); return sink.auditPending != nil })
	releaseOnce.Do(func() { close(release) })
	select {
	case failed := <-done:
		if failed {
			t.Fatal("diagnostics prevented flush")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("outbox missed drain bound")
	}
	if readApproval(t, db, 1).Record.Header.AuditedThrough == 0 {
		t.Fatal("outbox not acknowledged")
	}
}

func TestApprovalV2CorruptLegacyEvidenceSkipsAndRecovers(t *testing.T) {
	e, db, _ := approvalEngineFixture(t, false)
	approvalWorkerSink(e)
	var logs bytes.Buffer
	e.config.Logger = log.New(&logs, "", 0)
	tx, err := db.BeginV2(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	// More than one page proves corrupt evidence cannot pin the front of the queue.
	for i := 0; i < 257; i++ {
		evidence := "broken"
		if i == 256 {
			evidence = "[]"
		}
		if _, err = tx.Exec(`INSERT INTO legacy_expiry_outbox(event_key,request_id,resolved_at,evidence) VALUES(?,?,1,?)`, fmt.Sprintf("key:%03d", i), fmt.Sprint(i), evidence); err != nil {
			t.Fatal(err)
		}
	}
	if err = tx.Commit(); err != nil {
		t.Fatal(err)
	}
	var calls []string
	e.config.AuditSink = approvalSinkFunc(func(_ context.Context, c signerkit.AuditCall) error {
		calls = append(calls, c.LegacyExpiry.EventKey)
		return nil
	})
	for i := 0; i < 2; i++ {
		if e.flushPass(context.Background()) {
			t.Fatal("corruption treated as sink failure")
		}
	}
	if len(calls) != 1 || calls[0] != "key:256" {
		t.Fatalf("later evidence blocked: %v", calls)
	}
	if !strings.Contains(logs.String(), "legacy audit evidence corrupt; retained for repair") || strings.Contains(logs.String(), "sink unavailable") {
		t.Fatalf("wrong diagnostic: %s", logs.String())
	}
	tx, err = db.BeginV2(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	var evidence string
	if err = tx.QueryRow(`SELECT evidence FROM legacy_expiry_outbox WHERE event_key='key:000'`).Scan(&evidence); err != nil || evidence != "broken" {
		t.Fatalf("evidence lost: %q %v", evidence, err)
	}
	if _, err = tx.Exec(`UPDATE legacy_expiry_outbox SET evidence='[]' WHERE event_key='key:000'`); err != nil {
		t.Fatal(err)
	}
	if err = tx.Commit(); err != nil {
		t.Fatal(err)
	}
	if e.flushPass(context.Background()) || len(calls) != 2 || calls[1] != "key:000" {
		t.Fatalf("repair not recoverable: %v", calls)
	}
}
