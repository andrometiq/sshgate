package hosted

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"testing"
	"time"

	"github.com/karthikeyan5/sshgate/pkg/signerkit"
	"github.com/karthikeyan5/sshgate/pkg/signerkit/store"

	aw "github.com/karthikeyan5/sshgate/src/approvalwire"
)

func TestOrdinaryProductionWiring(t *testing.T) {
	_, db, _ := approvalEngineFixture(t, false)
	s := NewServer("secret", db, log.New(io.Discard, "", 0))
	s.MachineClientID = "client"
	c := OrdinaryConfig{Validity: 6 * time.Hour, Retention: 48 * time.Hour, ReportHorizon: time.Hour, LegacyTTL: time.Second, AssistTimeout: time.Second, MaxFullRows: 8, MaxRows: 20}
	audit := signerkit.NewAppendOnlySink(io.Discard)
	if err := s.StartApprovals(db, nil, audit, c); err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	draft := approvalDraftAt(987, time.Now().UTC())
	response := approvalHTTPRequest(s, http.MethodPost, aw.HostedRoot, approvalHTTPBody(t, aw.HostedSubmitBody{ApprovalProto: 1, Draft: draft}))
	if response.Code != 200 && response.Code != 202 {
		t.Fatalf("submit: %d %s", response.Code, response.Body.String())
	}
	row, err := db.ReadV2(context.Background(), approvalKey(987))
	if err != nil {
		t.Fatal(err)
	}
	if row.Record.Payload == nil {
		t.Fatal("no persisted payload")
	}
	if got := row.Record.Header.RequestExpiresAt.Sub(row.Record.Header.CreatedAt); got != c.Validity {
		t.Fatalf("validity = %s", got)
	}
	// Real worker must expire legacy rows without an HTTP request driving it.
	created := time.Now().Add(-time.Hour).UTC()
	end := created.Add(time.Second)
	request := &store.Request{RequestID: "startup-legacy", ClientID: "client", Status: store.StatusPending, CreatedAt: created, ExpiresAt: &end, Commands: []byte(`[]`), RequiredApprovals: 1}
	if err := db.Insert(context.Background(), request); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(10 * time.Second)
	for {
		record, err := db.GetByID(context.Background(), request.RequestID)
		if err != nil {
			t.Fatal(err)
		}
		if record.Status == store.StatusError {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("ordinary expiry worker did not run")
		}
		time.Sleep(10 * time.Millisecond)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	if !s.ordinaryClosed {
		t.Fatal("ordinary workers not closed")
	}
	if c.MaxRows != s.ordinaryEngine.config.MaxRows || c.Retention != s.ordinaryEngine.config.Settings.Retention || c.LegacyTTL != s.LegacyPendingTTL {
		t.Fatal("configuration not wired")
	}
}

func TestProcessDiagnosticDrainDeadline(t *testing.T) {
	release := make(chan struct{})
	entered := make(chan struct{})
	sink := newProcessAuditSink(startupBlockingWriter{entered, release}, false)
	defer func() { close(release); close(sink.requests); <-sink.joined }()
	_, _ = sink.Write([]byte("diagnostic\n"))
	<-entered
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()
	if err := sink.Drain(ctx); err != context.DeadlineExceeded {
		t.Fatalf("drain: %v", err)
	}
}

type startupBlockingWriter struct{ entered, release chan struct{} }

func (w startupBlockingWriter) Write(p []byte) (int, error) {
	close(w.entered)
	<-w.release
	return len(p), nil
}

func TestOrdinaryRequestedValidity(t *testing.T) {
	for _, seconds := range []int{0, 300, 604800} {
		draft := approvalDraftAt(891, time.Now().UTC())
		want := 24 * time.Hour
		if seconds != 0 {
			draft.RequestedValiditySeconds = &seconds
			want = min(want, time.Duration(seconds)*time.Second)
		}
		plan, err := (ordinaryFreezer{24 * time.Hour}).Freeze(context.Background(), draft, "client", "", time.Now().UTC())
		if err != nil {
			t.Fatal(err)
		}
		if got := plan.RequestExpiresAt.Sub(plan.SubmittedAt); got != want {
			t.Fatalf("requested %d: got %s want %s", seconds, got, want)
		}
	}
}

func TestOrdinaryLegacyTTLIntake(t *testing.T) {
	for _, ttl := range []time.Duration{0, 2 * time.Hour} {
		_, db, _ := approvalEngineFixture(t, false)
		s := NewServer("secret", db, log.New(io.Discard, "", 0))
		s.MachineClientID, s.LegacyPendingTTL = "client", ttl
		_, key, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		core, err := signerkit.New(signerkit.Config{Signer: key, Audit: signerkit.NewAppendOnlySink(io.Discard)})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = core.Close() })
		s.Signer = core
		response := approvalHTTPRequest(s, http.MethodPost, "/v1/sign", []byte(`{"client_id":"client","commands":[{"server":"test","cmd":"true","ttl_seconds":60}]}`))
		if response.Code != http.StatusAccepted {
			t.Fatalf("legacy submit: %d %s", response.Code, response.Body.String())
		}
		var accepted struct {
			RequestID string `json:"request_id"`
		}
		if err := json.Unmarshal(response.Body.Bytes(), &accepted); err != nil {
			t.Fatal(err)
		}
		row, err := db.GetByID(context.Background(), accepted.RequestID)
		if err != nil {
			t.Fatal(err)
		}
		want := ttl
		if want == 0 {
			want = 24 * time.Hour
		}
		if row.ExpiresAt == nil || row.ExpiresAt.Sub(row.CreatedAt) != want {
			t.Fatalf("expiry not frozen: %#v", row)
		}
	}
}
