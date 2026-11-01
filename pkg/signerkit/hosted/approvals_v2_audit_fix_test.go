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

// Ruling 31: malformed evidence is audited as evidence_malformed and flushed,
// so it can neither pin the outbox nor disappear without a line.
func TestApprovalV2MalformedLegacyEvidenceIsFlushedMarked(t *testing.T) {
	e, db, _ := approvalEngineFixture(t, false)
	approvalWorkerSink(e)
	var logs bytes.Buffer
	e.config.Logger = log.New(&logs, "", 0)
	tx, err := db.BeginV2(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	cases := map[string]string{
		"legacy-cancel:a:1": `{"v":1,"reason":"canceled","admin":"root","votes":[{"RequestID":"a","Operator":"operator","Decision":"deny","AuthnMethod":"totp","TS":"1970-01-01T00:00:01Z","Audited":true}]}`,
		"legacy-cancel:b:1": `[]`,
		"legacy-cancel:c:1": `{"v":2,"reason":"canceled","admin":"root","votes":[]}`,
		"legacy-cancel:d:1": `{"v":1,"reason":"canceled","admin":"","votes":[]}`,
		"legacy-cancel:e:1": `{"v":1,"reason":"canceled","admin":"root","votes":[],"extra":1}`,
		"legacy-cancel:f:1": `{"v":1,"reason":"canceled","admin":"root","votes":[null]}`,
		"legacy-expiry:g:1": `null`,
		"legacy-expiry:h:1": `{"v":1,"reason":"canceled","admin":"root","votes":[]}`,
		"legacy-expiry:i:1": `[null]`,
		"legacy-expiry:j:1": `[{"Operator":"operator","Decision":"approve"}]`,
		"legacy-expiry:k:1": `[]`,
		// Unknown namespaces fail closed even with well-formed v0 evidence.
		"legacy-other:l:1": `[]`,
	}
	// More than one page proves malformed evidence cannot pin the front of the queue.
	for i := 0; i < 257; i++ {
		evidence := "broken"
		if i == 256 {
			evidence = "[]"
		}
		cases[fmt.Sprintf("key:%03d", i)] = evidence
	}
	for key, evidence := range cases {
		if _, err = tx.Exec(`INSERT INTO legacy_expiry_outbox(event_key,request_id,resolved_at,evidence) VALUES(?,?,1,?)`, key, key, evidence); err != nil {
			t.Fatal(err)
		}
	}
	if err = tx.Commit(); err != nil {
		t.Fatal(err)
	}
	calls := map[string]signerkit.AuditCall{}
	e.config.AuditSink = approvalSinkFunc(func(_ context.Context, c signerkit.AuditCall) error {
		calls[c.LegacyExpiry.EventKey] = c
		return nil
	})
	for i := 0; i < 2; i++ {
		if e.flushPass(context.Background()) {
			t.Fatal("malformed evidence treated as sink failure")
		}
	}
	if len(calls) != len(cases) {
		t.Fatalf("flushed %d of %d", len(calls), len(cases))
	}
	for key := range cases {
		call := calls[key]
		wantLifecycle, wantReason := "legacy-expired", "evidence_malformed"
		if strings.HasPrefix(key, "legacy-cancel:") {
			wantLifecycle = "legacy-canceled"
		}
		switch key {
		case "legacy-cancel:a:1":
			wantReason = "canceled"
		case "legacy-expiry:g:1", "legacy-expiry:j:1", "legacy-expiry:k:1":
			wantReason = ""
		}
		if call.Lifecycle != wantLifecycle || call.Reason != wantReason || call.RequestID != key {
			t.Fatalf("%s: lifecycle %q reason %q request %q", key, call.Lifecycle, call.Reason, call.RequestID)
		}
		if (call.Operator != nil) != (key == "legacy-cancel:a:1") {
			t.Fatalf("%s: operator %+v", key, call.Operator)
		}
		if wantReason == "evidence_malformed" && len(call.LegacyExpiry.Votes) != 0 {
			t.Fatalf("%s: malformed votes surfaced: %+v", key, call.LegacyExpiry.Votes)
		}
	}
	canceled := calls["legacy-cancel:a:1"]
	if *canceled.Operator != (signerkit.Operator{ID: "root", DisplayName: "root", Verified: true}) || len(canceled.LegacyExpiry.Votes) != 1 || canceled.LegacyExpiry.Votes[0] != (signerkit.LegacyExpiryAuditVote{Operator: "operator", Decision: "deny", AuthnMethod: "totp", Time: time.Unix(1, 0).UTC(), Audited: true}) {
		t.Fatalf("cancel line: %+v %+v", canceled.Operator, canceled.LegacyExpiry)
	}
	if !strings.Contains(logs.String(), "legacy audit evidence malformed; flushed as evidence_malformed") || strings.Contains(logs.String(), "sink unavailable") {
		t.Fatalf("wrong diagnostic: %s", logs.String())
	}
	tx, err = db.BeginV2(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	var left int
	if err = tx.QueryRow(`SELECT count(*) FROM legacy_expiry_outbox`).Scan(&left); err != nil || left != 0 {
		t.Fatalf("outbox left %d %v", left, err)
	}
}
