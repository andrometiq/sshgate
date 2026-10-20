package hosted

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log"
	"os"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/karthikeyan5/sshgate/pkg/signerkit"
	"github.com/karthikeyan5/sshgate/pkg/signerkit/store"
)

type auditWriterFunc func([]byte) (int, error)

func (f auditWriterFunc) Write(p []byte) (int, error) { return f(p) }

func TestProcessAuditSinkFraming(t *testing.T) {
	for _, failSeparator := range []bool{false, true} {
		t.Run(map[bool]string{false: "partial", true: "separator"}[failSeparator], func(t *testing.T) {
			var output bytes.Buffer
			writes := 0
			sink := newAuditTestSink(t, auditWriterFunc(func(p []byte) (int, error) {
				writes++
				if writes == 1 {
					output.Write(p[:3])
					return 3, io.ErrUnexpectedEOF
				}
				if failSeparator && writes == 2 {
					return 0, io.ErrClosedPipe
				}
				if len(p) > 2 {
					return output.Write(p[:2])
				}
				return output.Write(p)
			}))
			call := signerkit.AuditCall{Lifecycle: "recovered"}
			if sink.Call(context.Background(), call) == nil {
				t.Fatal("prefix acknowledged")
			}
			if failSeparator && sink.Call(context.Background(), call) == nil {
				t.Fatal("failed separator acknowledged")
			}
			if err := sink.Call(context.Background(), call); err != nil {
				t.Fatal(err)
			}
			lines := bytes.Split(output.Bytes(), []byte{'\n'})
			if len(lines) != 3 || !json.Valid(lines[1]) {
				t.Fatalf("unrecovered framing: %q", output.Bytes())
			}
		})
	}
}

func TestProcessAuditSinkStartupSeparator(t *testing.T) {
	for _, prefix := range []string{"", "previous\n", "torn"} {
		t.Run(prefix, func(t *testing.T) {
			path := t.TempDir() + "/audit"
			if err := os.WriteFile(path, []byte(prefix), 0600); err != nil {
				t.Fatal(err)
			}
			file, err := os.OpenFile(path, os.O_WRONLY|os.O_APPEND, 0600)
			if err != nil {
				t.Fatal(err)
			}
			defer file.Close()
			sink, err := NewProcessAuditSink(file)
			if err == nil {
				trackAuditTestSink(t, sink)
			}
			if err != nil {
				t.Fatal(err)
			}
			if err = sink.Call(context.Background(), signerkit.AuditCall{}); err != nil {
				t.Fatal(err)
			}
			data, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			want := prefix
			if prefix == "torn" {
				want += "\n"
			}
			if !bytes.HasPrefix(data, []byte(want+`{"kind":"call"`)) {
				t.Fatalf("startup separator: %q", data)
			}
		})
	}
}

func TestProcessAuditSinkPipeAndSocket(t *testing.T) {
	for _, socket := range []bool{false, true} {
		t.Run(map[bool]string{false: "pipe", true: "socket"}[socket], func(t *testing.T) {
			var reader, writer *os.File
			if socket {
				pair, err := syscall.Socketpair(syscall.AF_UNIX, syscall.SOCK_STREAM, 0)
				if err != nil {
					t.Fatal(err)
				}
				reader = os.NewFile(uintptr(pair[0]), "reader")
				writer = os.NewFile(uintptr(pair[1]), "writer")
			} else {
				var err error
				reader, writer, err = os.Pipe()
				if err != nil {
					t.Fatal(err)
				}
			}
			defer reader.Close()
			defer writer.Close()
			fd := writer.Fd() // inherited stderr is blocking
			before, _, errno := syscall.Syscall(syscall.SYS_FCNTL, fd, syscall.F_GETFL, 0)
			if errno != 0 {
				t.Fatal(errno)
			}
			sink, err := NewProcessAuditSink(writer)
			if err == nil {
				trackAuditTestSink(t, sink)
			}
			if err != nil {
				t.Fatal(err)
			}
			if err = sink.Call(context.Background(), signerkit.AuditCall{}); err != nil {
				t.Fatal(err)
			}
			log.New(sink, "diagnostic: ", 0).Print("works")
			awaitApprovalState(t, func() bool { sink.mu.Lock(); defer sink.mu.Unlock(); return !sink.busy })
			after, _, errno := syscall.Syscall(syscall.SYS_FCNTL, fd, syscall.F_GETFL, 0)
			if errno != 0 || before != after || after&syscall.O_NONBLOCK != 0 {
				t.Fatalf("descriptor flags changed: %x -> %x", before, after)
			}
			buf := make([]byte, 4096)
			n, err := reader.Read(buf)
			if err != nil {
				t.Fatal(err)
			}
			if buf[0] != '{' || !strings.Contains(string(buf[:n]), "diagnostic: works\n") {
				t.Fatalf("framing/log: %q", buf[:n])
			}
		})
	}
}

func TestProcessAuditSinkOutstandingAndDiagnostics(t *testing.T) {
	entered, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	var output bytes.Buffer
	sink := newAuditTestSink(t, auditWriterFunc(func(p []byte) (int, error) { once.Do(func() { close(entered); <-release }); return output.Write(p) }))
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- sink.Call(ctx, signerkit.AuditCall{Lifecycle: "first"}) }()
	<-entered
	cancel()
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if err := sink.Call(context.Background(), signerkit.AuditCall{}); !errors.Is(err, ErrAuditBusy) {
		t.Fatalf("outstanding not busy: %v", err)
	}
	for i := 0; i < 100; i++ {
		log.New(sink, "", 0).Print("diagnostic")
	}
	if sink.DroppedDiagnostics() != 36 {
		t.Fatalf("drops: %d", sink.DroppedDiagnostics())
	}
	close(release)
	awaitApprovalState(t, func() bool { sink.mu.Lock(); defer sink.mu.Unlock(); return !sink.busy })
	if err := sink.Call(context.Background(), signerkit.AuditCall{Lifecycle: "last"}); err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSuffix(output.String(), "\n"), "\n")
	if len(lines) != 66 || !json.Valid([]byte(lines[0])) || !json.Valid([]byte(lines[65])) {
		t.Fatalf("interleaved diagnostic frames: %q", output.String())
	}
}

func TestProcessAuditSinkFiveSecondCap(t *testing.T) {
	entered, release := make(chan struct{}), make(chan struct{})
	sink := newAuditTestSink(t, auditWriterFunc(func(p []byte) (int, error) { close(entered); <-release; return len(p), nil }))
	done := make(chan error, 1)
	go func() { done <- sink.Call(context.Background(), signerkit.AuditCall{}) }()
	<-entered
	select {
	case err := <-done:
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Fatal(err)
		}
	case <-time.After(6 * time.Second):
		t.Fatal("unbounded wait")
	}
	if err := sink.Call(context.Background(), signerkit.AuditCall{}); !errors.Is(err, ErrAuditBusy) {
		t.Fatal(err)
	}
	close(release)
	awaitApprovalState(t, func() bool { sink.mu.Lock(); defer sink.mu.Unlock(); return !sink.busy })
}

func TestApprovalV2MixedOutboxesBlockedDeliveryKeepsClockRunning(t *testing.T) {
	e, db, clock := approvalEngineFixture(t, false)
	approvalWorkerSink(e)
	e.config.LegacyStore = db
	ctx := context.Background()
	end := clock.Wall().Add(time.Second)
	if err := db.Insert(ctx, &store.Request{RequestID: "legacy", ClientID: "client", Status: store.StatusPending, CreatedAt: clock.Wall(), ExpiresAt: &end, Commands: []byte(`[]`)}); err != nil {
		t.Fatal(err)
	}
	submitApproval(t, e, 1)
	entered, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	sink := newAuditTestSink(t, auditWriterFunc(func(p []byte) (int, error) { once.Do(func() { close(entered); <-release }); return len(p), nil }))
	e.config.AuditSink = sink
	runCtx, cancel := context.WithCancel(ctx)
	done := make(chan error, 1)
	go func() { done <- e.Run(runCtx) }()
	<-entered
	clock.Advance(6 * time.Second)
	awaitApprovalState(t, func() bool {
		row, err := db.GetByID(ctx, "legacy")
		return err == nil && row.TerminalReason == "expired" && readApproval(t, db, 1).Record.Header.Assist != nil
	})
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("worker/flusher did not join")
	}
	if readApproval(t, db, 1).Record.Header.AuditedThrough != 0 {
		t.Fatal("blocked line acknowledged")
	}
	close(release)
	awaitApprovalState(t, func() bool { sink.mu.Lock(); defer sink.mu.Unlock(); return !sink.busy })
	// A write completed after cancellation, but no Flush was committed. Retry
	// must deliver the exact same stable event identity.
	var legacyKeys []string
	e.config.AuditSink = approvalSinkFunc(func(_ context.Context, c signerkit.AuditCall) error {
		if c.LegacyExpiry != nil {
			legacyKeys = append(legacyKeys, c.LegacyExpiry.EventKey)
			if len(legacyKeys) == 1 {
				return errors.New("lost acknowledgement")
			}
		}
		return nil
	})
	if !e.flushPass(ctx) {
		t.Fatal("lost ack accepted")
	}
	if e.flushPass(ctx) {
		t.Fatal("retry failed")
	}
	if len(legacyKeys) != 2 || legacyKeys[0] == "" || legacyKeys[0] != legacyKeys[1] {
		t.Fatalf("unstable replay: %v", legacyKeys)
	}
	if e.flushPass(ctx) || len(legacyKeys) != 2 {
		t.Fatal("acknowledged legacy event repeated")
	}
}

func TestWireFrozen_LegacyExpiryAuditAddition(t *testing.T) {
	metadata := &signerkit.LegacyExpiryAuditMetadata{EventKey: "legacy-expiry:key", ResolvedAt: time.Unix(3, 0).UTC(), Votes: []signerkit.LegacyExpiryAuditVote{{Operator: "operator", Decision: "approve", AuthnMethod: "totp", Time: time.Unix(1, 0).UTC(), Audited: false}}}
	data, err := json.Marshal(metadata)
	if err != nil {
		t.Fatal(err)
	}
	const want = `{"event_key":"legacy-expiry:key","resolved_at":"1970-01-01T00:00:03Z","votes":[{"operator":"operator","decision":"approve","authn_method":"totp","time":"1970-01-01T00:00:01Z","audited":false}]}`
	if string(data) != want {
		t.Fatalf("wire: %s", data)
	}
	ordinary, err := json.Marshal(signerkit.AuditCall{})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(ordinary), "legacy_expiry") {
		t.Fatalf("ordinary bytes moved: %s", ordinary)
	}
	call, err := json.Marshal(signerkit.AuditCall{LegacyExpiry: metadata})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasSuffix(string(call), `"legacy_expiry":`+want+`}`) {
		t.Fatalf("wire member: %s", call)
	}
}

func TestApprovalV2BackoffStartsAfterFailure(t *testing.T) {
	e, _, _ := approvalEngineFixture(t, false)
	approvalWorkerSink(e)
	submitApproval(t, e, 1)
	entered, release := make(chan struct{}), make(chan struct{})
	attempts := make(chan time.Time, 2)
	first := true
	e.config.AuditSink = approvalSinkFunc(func(ctx context.Context, _ signerkit.AuditCall) error {
		if first {
			first = false
			close(entered)
			<-release
		}
		select {
		case attempts <- time.Now():
		case <-ctx.Done():
			return ctx.Err()
		}
		return errors.New("unavailable")
	})
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { defer close(done); e.runFlusher(ctx) }()
	defer func() { cancel(); <-done }()
	<-entered
	// Let the old periodic ticker expire while the first write is outstanding.
	<-time.After(1100 * time.Millisecond)
	close(release)
	failedAt := <-attempts
	for i := 0; i < 20; i++ {
		select {
		case e.flushNudge <- struct{}{}:
		default:
		}
	}
	select {
	case retryAt := <-attempts:
		if retryAt.Sub(failedAt) < time.Second {
			t.Fatalf("backoff shortened: %s", retryAt.Sub(failedAt))
		}
	case <-time.After(3 * time.Second):
		t.Fatal("no retry")
	}
}

func TestProcessAuditSinkBlockedPipeLostAcknowledgement(t *testing.T) {
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	defer writer.Close()
	_ = writer.Fd()
	sink, err := NewProcessAuditSink(writer)
	if err == nil {
		trackAuditTestSink(t, sink)
	}
	if err != nil {
		t.Fatal(err)
	}
	call := signerkit.AuditCall{Lifecycle: "legacy-expired", Reason: strings.Repeat("x", 1<<20), LegacyExpiry: &signerkit.LegacyExpiryAuditMetadata{EventKey: "legacy-expiry:stable", Votes: []signerkit.LegacyExpiryAuditVote{}}}
	var expected bytes.Buffer
	if err = signerkit.NewAppendOnlySink(&expected).Call(context.Background(), call); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- sink.Call(ctx, call) }()
	awaitApprovalState(t, func() bool { sink.mu.Lock(); defer sink.mu.Unlock(); return sink.busy })
	cancel()
	if err = <-done; !errors.Is(err, context.Canceled) {
		t.Fatalf("blocked caller: %v", err)
	}
	if err = sink.Call(context.Background(), call); !errors.Is(err, ErrAuditBusy) {
		t.Fatalf("blocked writer: %v", err)
	}
	first := make([]byte, expected.Len())
	if _, err = io.ReadFull(reader, first); err != nil {
		t.Fatal(err)
	}
	awaitApprovalState(t, func() bool { sink.mu.Lock(); defer sink.mu.Unlock(); return !sink.busy })
	go func() { done <- sink.Call(context.Background(), call) }()
	second := make([]byte, expected.Len())
	if _, err = io.ReadFull(reader, second); err != nil {
		t.Fatal(err)
	}
	if err = <-done; err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(first, expected.Bytes()) || !bytes.Equal(first, second) {
		t.Fatal("late completion was not a recognizable complete replay")
	}
}

func newAuditTestSink(t *testing.T, writer io.Writer) *ProcessAuditSink {
	t.Helper()
	sink := newProcessAuditSink(writer, false)
	trackAuditTestSink(t, sink)
	return sink
}

func trackAuditTestSink(t *testing.T, sink *ProcessAuditSink) {
	t.Helper()
	t.Cleanup(func() {
		close(sink.requests)
		select {
		case <-sink.joined:
		case <-time.After(time.Second):
			t.Error("test left process writer blocked")
		}
	})
}

func TestApprovalV2BlockedLegacyDeliveryKeepsClockRunning(t *testing.T) {
	e, db, clock := approvalEngineFixture(t, false)
	approvalWorkerSink(e)
	e.config.LegacyStore = db
	ctx := context.Background()
	submitApproval(t, e, 1)
	if e.flushPass(ctx) {
		t.Fatal("initial v2 flush failed")
	}
	end := clock.Wall().Add(time.Second)
	if err := db.Insert(ctx, &store.Request{RequestID: "legacy", ClientID: "client", Status: store.StatusPending, CreatedAt: clock.Wall(), ExpiresAt: &end, Commands: []byte(`[]`)}); err != nil {
		t.Fatal(err)
	}
	clock.Advance(2 * time.Second)
	if err := e.expireLegacy(ctx); err != nil {
		t.Fatal(err)
	}
	entered, release := make(chan string, 1), make(chan struct{})
	sink := newAuditTestSink(t, auditWriterFunc(func(p []byte) (int, error) { entered <- string(p); <-release; return len(p), nil }))
	e.config.AuditSink = sink
	runCtx, cancel := context.WithCancel(ctx)
	done := make(chan error, 1)
	go func() { done <- e.Run(runCtx) }()
	select {
	case frame := <-entered:
		if !strings.Contains(frame, `"legacy-expired"`) {
			t.Fatalf("wrong blocked event: %s", frame)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("legacy delivery not attempted")
	}
	clock.Advance(6 * time.Second)
	awaitApprovalState(t, func() bool { return readApproval(t, db, 1).Record.Header.Assist != nil })
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("legacy delivery prevented worker join")
	}
	close(release)
	awaitApprovalState(t, func() bool { sink.mu.Lock(); defer sink.mu.Unlock(); return !sink.busy })
	var legacyCalls int
	e.config.AuditSink = approvalSinkFunc(func(_ context.Context, c signerkit.AuditCall) error {
		if c.LegacyExpiry != nil {
			legacyCalls++
		}
		return nil
	})
	if e.flushPass(ctx) || legacyCalls != 1 {
		t.Fatal("canceled legacy delivery deleted evidence")
	}
}

// While a diagnostic write blocks, one audit frame may wait and goes next;
// a second audit submit is refused at once (A10-AUDIT-MODEL amendment).
func TestProcessAuditSinkOneAuditWaitsBehindDiagnostic(t *testing.T) {
	entered, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	var mu sync.Mutex
	var output bytes.Buffer
	sink := newAuditTestSink(t, auditWriterFunc(func(p []byte) (int, error) {
		once.Do(func() { close(entered); <-release })
		mu.Lock()
		defer mu.Unlock()
		return output.Write(p)
	}))
	log.New(sink, "", 0).Print("blocked diagnostic")
	<-entered
	log.New(sink, "", 0).Print("queued diagnostic")
	first := make(chan error, 1)
	go func() { first <- sink.Call(context.Background(), signerkit.AuditCall{Lifecycle: "first"}) }()
	awaitApprovalState(t, func() bool { sink.mu.Lock(); defer sink.mu.Unlock(); return sink.auditPending != nil })
	if err := sink.Call(context.Background(), signerkit.AuditCall{Lifecycle: "second"}); !errors.Is(err, ErrAuditBusy) {
		t.Fatalf("second audit not refused at once: %v", err)
	}
	close(release)
	if err := <-first; err != nil {
		t.Fatal(err)
	}
	awaitApprovalState(t, func() bool { sink.mu.Lock(); defer sink.mu.Unlock(); return !sink.busy })
	mu.Lock()
	lines := strings.Split(strings.TrimSuffix(output.String(), "\n"), "\n")
	mu.Unlock()
	if len(lines) != 3 || lines[0] != "blocked diagnostic" || !strings.Contains(lines[1], `"first"`) || lines[2] != "queued diagnostic" {
		t.Fatalf("audit did not take priority: %q", lines)
	}
}
