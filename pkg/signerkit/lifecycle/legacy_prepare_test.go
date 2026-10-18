package lifecycle

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"
	"unsafe"

	"github.com/karthikeyan5/sshgate/pkg/signerkit/assist"
	ap "github.com/karthikeyan5/sshgate/src/approvalplan"
	st "github.com/karthikeyan5/sshgate/src/approvalplan/statetest"
	"github.com/karthikeyan5/sshgate/src/redact/rules"
)

type preparedNotifier struct {
	destination LegacyDestination
	artifact    *PreparedLegacyApproval
	prepared    func(string) (*PreparedLegacyApproval, error)
	deliver     func(context.Context, *PreparedLegacyApproval) (LegacyDelivery, error)
	calls       atomic.Int32
}

func (n *preparedNotifier) Destination() LegacyDestination { return n.destination }
func (n *preparedNotifier) Prepared(id string) (*PreparedLegacyApproval, error) {
	if n.prepared != nil {
		return n.prepared(id)
	}
	return n.artifact, nil
}
func (n *preparedNotifier) Deliver(ctx context.Context, p *PreparedLegacyApproval) (LegacyDelivery, error) {
	n.calls.Add(1)
	if n.deliver != nil {
		return n.deliver(ctx, p)
	}
	return LegacyDelivery{AllDelivered: true}, nil
}
func (n *preparedNotifier) EditStatus(context.Context, *PreparedLegacyApproval, string) error {
	return nil
}
func legacyInstanceID(n int) string { return fmt.Sprintf("%032x", n) }

func preparedFixture(t *testing.T) (*Engine, *preparedNotifier) {
	t.Helper()
	e, _, _, _ := engineFixture(t)
	t.Cleanup(func() { e.Close() })
	n := &preparedNotifier{destination: LegacyDestination{ChatID: 123, TopicID: 456}}
	e.config.LegacyNotifier = n
	return e, n
}
func legacyInput(t *testing.T) assist.Input {
	t.Helper()
	p := ap.ApprovalPlanV1{Kind: ap.KindCommandJob, RationaleOrigin: ap.OriginSynthesizedLegacyV1, Rationale: ap.LegacyRationaleText, CommandJob: &ap.CommandJob{Steps: []ap.Step{{ExactCommand: "echo safe"}}}}
	in, err := assist.RedactForProvider(p, [32]byte{}, rules.Combined())
	if err != nil {
		t.Fatal(err)
	}
	return in
}
func reservePrepared(t *testing.T, e *Engine, id int) *LegacyReservation {
	t.Helper()
	r, err := e.ReserveLegacy(context.Background(), LegacyInstance{ID: legacyInstanceID(id), UID: 7, RequestID: legacyInstanceID(id)}, []byte(`{"snapshot":"authoritative"}`), legacyInput(t))
	if err != nil {
		t.Fatal(err)
	}
	return r
}
func preparedArtifact(t *testing.T, r *LegacyReservation) *PreparedLegacyApproval {
	t.Helper()
	sum := sha256.Sum256([]byte("echo safe"))
	inputs := []ap.LegacySignInput{{Server: "web-1", Command: "echo safe", CommandSHA256: hex.EncodeToString(sum[:]), TTLSeconds: 60, Reason: "why"}}
	digest, _ := ap.LegacySignDigest(r.instance, inputs)
	c := r.RenderContext()
	c.Metadata = []byte(`{"requester":"local-uid:7"}`)
	p, err := NewPreparedLegacyApproval(LegacyPreparedData{Instance: r.instance, Inputs: inputs, SignDigest: digest, Snapshot: r.Snapshot(), Context: c, Payload: []LegacyMessage{{Bytes: []byte("part one")}, {Bytes: []byte("decision"), ApproveLabel: "approve", DenyLabel: "deny"}}})
	if err != nil {
		t.Fatal(err)
	}
	return p
}
func reservationVote(r *LegacyReservation) ap.CastVote {
	c := r.RenderContext()
	return ap.CastVote{Operator: "telegram:1", Decision: ap.VoteApprove, Card: &ap.CardTap{Handle: c.Handle, Challenge: c.Challenge}}
}

func TestPreparedLegacyDeepCopies(t *testing.T) {
	e, _ := preparedFixture(t)
	r := reservePrepared(t, e, 101)
	data := preparedArtifact(t, r).Data()
	result := readyAssist()
	result.Alignment = ap.AlignmentNotAssessed
	result.InputDigest = strings.Repeat("a", 64)
	result.Effects = []string{"effect"}
	result.Concerns = []ap.Concern{{Severity: ap.SeverityHigh, Text: "concern"}}
	data.Context.Assist = assist.Snapshot{State: ap.AssistReady, Result: &result}
	p, err := NewPreparedLegacyApproval(data)
	if err != nil {
		t.Fatal(err)
	}
	want := p.Data()
	mutate := func(d *LegacyPreparedData) {
		d.Inputs[0].Command = "changed"
		d.Snapshot[0] = 'x'
		d.Context.Metadata[0] = 'x'
		d.Context.Assist.Result.Effects[0] = "changed"
		d.Context.Assist.Result.Concerns[0].Text = "changed"
		d.Payload[0].Bytes[0] = 'x'
		d.Payload[1].ApproveLabel = "changed"
		d.Context.Destination.ChatID = 999
	}
	mutate(&data)
	out := p.Data()
	mutate(&out)
	if !reflect.DeepEqual(p.Data(), want) {
		t.Fatal("artifact aliases constructor or getter")
	}
	typ := reflect.TypeOf(*p)
	for i := 0; i < typ.NumField(); i++ {
		if typ.Field(i).IsExported() {
			t.Fatal("exported artifact field")
		}
	}
}

func TestLegacyPreparedActivationAndAudit(t *testing.T) {
	e, n := preparedFixture(t)
	sink := &legacyAuditSink{}
	e.config.AuditWriter = sink
	r := reservePrepared(t, e, 102)
	n.artifact = preparedArtifact(t, r)
	vote := reservationVote(r)
	if r.request.challengeHash != ap.ChallengeHash(vote.Card.Challenge) || r.request.live {
		t.Fatal("reservation active or challenge not hashed")
	}
	check := func() {
		if got := legacyTap(t, e, vote); got.Resolved || got.Answer != LegacyTapRefused {
			t.Fatal(got)
		}
	}
	check()
	n.deliver = func(_ context.Context, p *PreparedLegacyApproval) (LegacyDelivery, error) {
		if !sameLegacyPrepared(p, n.artifact) {
			t.Fatal("payload changed")
		}
		check()
		return LegacyDelivery{AllDelivered: true}, nil
	}
	if err := e.DeliverLegacy(r, n.artifact); err != nil {
		t.Fatal(err)
	}
	if !sameLegacyPrepared(r.request.artifact, n.artifact) {
		t.Fatal("request did not retain exactly its delivered artifact")
	}
	if got := legacyTap(t, e, vote); !got.Resolved {
		t.Fatal(got)
	}
	if got := r.Request().Wait(); got.Status != "approved" {
		t.Fatal(got)
	}
	sink.mu.Lock()
	defer sink.mu.Unlock()
	if len(sink.events) != 2 {
		t.Fatal(sink.events)
	}
	for _, event := range sink.events {
		if event.Transition != "legacy_vote_refused{stale_challenge}" {
			t.Fatal(event)
		}
	}
}

func TestLegacyDeliveryFailuresNeverActivate(t *testing.T) {
	for _, mode := range []string{"part-two", "card", "missing-report", "deadline", "cancel", "close"} {
		t.Run(mode, func(t *testing.T) {
			e, n := preparedFixture(t)
			r := reservePrepared(t, e, 103)
			n.artifact = preparedArtifact(t, r)
			n.deliver = func(_ context.Context, _ *PreparedLegacyApproval) (LegacyDelivery, error) {
				switch mode {
				case "missing-report":
					return LegacyDelivery{}, nil
				case "deadline":
					return LegacyDelivery{}, context.DeadlineExceeded
				case "cancel":
					return LegacyDelivery{}, context.Canceled
				case "close":
					go e.Close()
					<-e.legacy.ctx.Done()
					return LegacyDelivery{AllDelivered: true}, nil
				default:
					return LegacyDelivery{}, errors.New("private transport failure")
				}
			}
			err := e.DeliverLegacy(r, n.artifact)
			if err == nil || strings.Contains(err.Error(), "private") {
				t.Fatal(err)
			}
			if r.Request().Wait().Status == "approved" {
				t.Fatal("failed delivery approved")
			}
			e.mu.Lock()
			live := r.request.live
			e.mu.Unlock()
			if live {
				t.Fatal("failed delivery activated")
			}
			if mode != "close" {
				if err.Error() != "backend: legacy card delivery failed" {
					t.Fatal(err)
				}
				if legacyTap(t, e, reservationVote(r)).Resolved {
					t.Fatal("tap resolved failed delivery")
				}
			}
			if e.DeliverLegacy(r, n.artifact) == nil || n.calls.Load() != 1 {
				t.Fatal("delivery retried")
			}
		})
	}
}

func TestLegacyPreparedMismatch(t *testing.T) {
	for _, field := range []string{"snapshot", "metadata", "assist", "destination", "handle", "challenge", "payload", "label", "instance", "input", "nil", "error"} {
		t.Run(field, func(t *testing.T) {
			e, n := preparedFixture(t)
			r := reservePrepared(t, e, 104)
			p := preparedArtifact(t, r)
			d := p.Data()
			switch field {
			case "snapshot":
				d.Snapshot[0] = 'x'
			case "metadata":
				d.Context.Metadata[0] = 'x'
			case "assist":
				d.Context.Assist.Reason = assist.ReasonBusy
			case "destination":
				d.Context.Destination.TopicID++
			case "handle":
				d.Context.Handle = "abcdefghijkl"
			case "challenge":
				d.Context.Challenge = "0123456789abcdef"
			case "payload":
				d.Payload[0].Bytes[0] = 'x'
			case "label":
				d.Payload[1].ApproveLabel = "different"
			case "instance":
				d.Instance = legacyInstanceID(999)
			case "input":
				d.Inputs[0].Net = true
			}
			if len(d.Inputs) > 0 {
				d.SignDigest, _ = ap.LegacySignDigest(d.Instance, d.Inputs)
			}
			var err error
			n.artifact, err = NewPreparedLegacyApproval(d)
			if err != nil {
				t.Fatal(err)
			}
			if field == "nil" {
				n.artifact = nil
			}
			if field == "error" {
				n.prepared = func(string) (*PreparedLegacyApproval, error) { return nil, errors.New("private") }
			}
			if err = e.DeliverLegacy(r, p); err == nil || n.calls.Load() != 0 {
				t.Fatalf("mismatch sent: %v", err)
			}
			if r.Request().Wait().Status != "error" {
				t.Fatal("mismatch not dropped")
			}
		})
	}
}

func TestLegacyReservationBindingAndDuplicates(t *testing.T) {
	e, n := preparedFixture(t)
	snapshot := []byte("original")
	instance := LegacyInstance{ID: legacyInstanceID(105), UID: 7, RequestID: "same"}
	r, err := e.ReserveLegacy(context.Background(), instance, snapshot, legacyInput(t))
	if err != nil {
		t.Fatal(err)
	}
	snapshot[0] = 'x'
	r.Snapshot()[0] = 'y'
	if string(r.Snapshot()) != "original" {
		t.Fatal("snapshot aliases caller")
	}
	other := instance
	other.ID = legacyInstanceID(106)
	if _, err = e.ReserveLegacy(context.Background(), other, []byte("snapshot"), legacyInput(t)); err == nil || err.Error() != "telegram: request_id already pending — refusing duplicate" {
		t.Fatal(err)
	}
	n.artifact = preparedArtifact(t, r)
	bad := n.artifact.Data()
	bad.Context.Destination.ChatID++
	badArtifact, err := NewPreparedLegacyApproval(bad)
	if err != nil {
		t.Fatal(err)
	}
	n.artifact = badArtifact
	if e.DeliverLegacy(r, badArtifact) == nil || n.calls.Load() != 0 {
		t.Fatal("reservation destination replaced")
	}
	r = reservePrepared(t, e, 107)
	n.artifact = preparedArtifact(t, r)
	if err = e.DeliverLegacy(r, n.artifact); err != nil {
		t.Fatal(err)
	}
	other = LegacyInstance{ID: legacyInstanceID(108), UID: 7, RequestID: legacyInstanceID(107)}
	if _, err = e.ReserveLegacy(context.Background(), other, []byte("snapshot"), legacyInput(t)); err == nil {
		t.Fatal("duplicate live admitted")
	}
	e.CancelLegacy(r)
	if !legacyTap(t, e, reservationVote(r)).Resolved {
		t.Fatal("cancel changed live request")
	}
}

func TestLegacyAssistTerminalBeforeDelivery(t *testing.T) {
	for _, mode := range []string{"ready", "failed", "invalid", "watchdog", "busy", "closed", "recovery"} {
		t.Run(mode, func(t *testing.T) {
			e, n := preparedFixture(t)
			var calls atomic.Int32
			entered := make(chan struct{})
			releaseRecovery := make(chan struct{})
			timer := make(chan time.Time, 1)
			pool := assist.NewPool(1, assist.Timers{Now: e.config.Clock.Wall, After: func(time.Duration) <-chan time.Time { return timer }})
			e.legacy.assistPool.Close()
			e.legacy.assistPool = pool
			e.config.Assessor = assessorFunc(func(ctx context.Context, in assist.Input) (ap.AssistResult, error) {
				calls.Add(1)
				close(entered)
				if mode == "recovery" {
					<-releaseRecovery
				}
				if mode == "watchdog" {
					<-ctx.Done()
					return ap.AssistResult{}, ctx.Err()
				}
				if mode == "failed" {
					return ap.AssistResult{}, errors.New("private")
				}
				a := readyAssist()
				a.Effects = []string{"echoes safe"}
				if mode == "invalid" {
					a.Summary = ""
				}
				return a, nil
			})
			release := make(chan struct{})
			if mode == "busy" {
				pool.TrySubmit(context.Background(), assessorFunc(func(ctx context.Context, _ assist.Input) (ap.AssistResult, error) {
					select {
					case <-release:
					case <-ctx.Done():
					}
					return ap.AssistResult{}, errors.New("busy")
				}), assist.Input{}, st.T0.Add(time.Second), func(assist.Snapshot) {})
			}
			defer close(release)
			if mode == "closed" {
				pool.Close()
			}
			type answer struct {
				r   *LegacyReservation
				err error
			}
			done := make(chan answer, 1)
			go func() {
				r, err := e.ReserveLegacy(context.Background(), LegacyInstance{ID: legacyInstanceID(109), UID: 7, RequestID: "assist"}, []byte("snapshot"), legacyInput(t))
				done <- answer{r, err}
			}()
			if mode == "watchdog" || mode == "recovery" {
				<-entered
				if n.calls.Load() != 0 {
					t.Fatal("sent during assist")
				}
				if mode == "watchdog" {
					timer <- st.T0.Add(5 * time.Second)
				} else {
					e.stop()
					close(releaseRecovery)
				}
			}
			var got answer
			select {
			case got = <-done:
			case <-time.After(3 * time.Second):
				t.Fatal("preparation stuck")
			}
			if mode == "closed" {
				if got.err == nil {
					t.Fatal("closed pool accepted")
				}
				return
			}
			if got.err != nil {
				t.Fatal(got.err)
			}
			a := got.r.RenderContext().Assist
			if mode == "ready" || mode == "recovery" {
				if a.State != ap.AssistReady || a.Result.Alignment != ap.AlignmentNotAssessed || ap.ValidateAssist(*a.Result) != nil {
					t.Fatal(a)
				}
				copy := got.r.RenderContext()
				copy.Assist.Result.Effects[0] = "mutated"
				if got.r.RenderContext().Assist.Result.Effects[0] == "mutated" {
					t.Fatal("reservation aliases assist")
				}
			} else {
				if a.State != ap.AssistUnavailable {
					t.Fatal(a)
				}
				if mode == "watchdog" && a.Reason != assist.ReasonDeadline {
					t.Fatal(a)
				}
				if mode == "busy" && a.Reason != assist.ReasonBusy {
					t.Fatal(a)
				}
			}
			n.artifact = preparedArtifact(t, got.r)
			if err := e.DeliverLegacy(got.r, n.artifact); err != nil {
				t.Fatal(err)
			}
			expected := int32(1)
			if mode == "busy" {
				expected = 0
			}
			if calls.Load() != expected {
				t.Fatal("attempt count", calls.Load())
			}
		})
	}
}

func TestPreparedLegacyValidation(t *testing.T) {
	e, _ := preparedFixture(t)
	r := reservePrepared(t, e, 110)
	base := preparedArtifact(t, r)
	for _, field := range []string{"instance", "snapshot", "handle", "challenge", "destination", "topic", "assist", "digest", "command", "payload", "labels", "part-label"} {
		t.Run(field, func(t *testing.T) {
			d := base.Data()
			switch field {
			case "instance":
				d.Instance = "caller-id"
			case "snapshot":
				d.Snapshot = nil
			case "handle":
				d.Context.Handle = "bad"
			case "challenge":
				d.Context.Challenge = "bad"
			case "destination":
				d.Context.Destination.ChatID = 0
			case "topic":
				d.Context.Destination.TopicID = -1
			case "assist":
				d.Context.Assist = assist.Snapshot{}
			case "digest":
				d.SignDigest = "wrong"
			case "command":
				d.Inputs[0].Command = "different"
			case "payload":
				d.Payload = nil
			case "labels":
				d.Payload[1].DenyLabel = ""
			case "part-label":
				d.Payload[0].ApproveLabel = "approve"
			}
			if _, err := NewPreparedLegacyApproval(d); err == nil {
				t.Fatal("invalid artifact accepted")
			}
		})
	}
	d := base.Data()
	d.Inputs = nil
	d.SignDigest = ""
	if _, err := NewPreparedLegacyApproval(d); err != nil {
		t.Fatal("non-sign artifact refused", err)
	}
}

func TestLegacyDeliverySingleFlightAndCopies(t *testing.T) {
	e, n := preparedFixture(t)
	r := reservePrepared(t, e, 111)
	n.artifact = preparedArtifact(t, r)
	expected := n.artifact.Data()
	entered, release := make(chan struct{}), make(chan struct{})
	n.deliver = func(ctx context.Context, p *PreparedLegacyApproval) (LegacyDelivery, error) {
		*p = PreparedLegacyApproval{} // Even replacement of the adapter's pointer cannot mutate the owner's artifact.
		close(entered)
		select {
		case <-release:
		case <-ctx.Done():
		}
		return LegacyDelivery{AllDelivered: true}, nil
	}
	done := make(chan error, 1)
	go func() { done <- e.DeliverLegacy(r, n.artifact) }()
	<-entered
	if e.DeliverLegacy(r, n.artifact) == nil {
		t.Fatal("concurrent delivery accepted")
	}
	close(release)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	*n.artifact = PreparedLegacyApproval{}
	if !reflect.DeepEqual(r.request.artifact.Data(), expected) || n.calls.Load() != 1 {
		t.Fatal("owner's artifact changed or delivery repeated")
	}
	if !legacyTap(t, e, reservationVote(r)).Resolved {
		t.Fatal("delivered request not live")
	}
}

func TestLegacyPreparationCancellation(t *testing.T) {
	for _, mode := range []string{"disconnect", "close", "abandon"} {
		t.Run(mode, func(t *testing.T) {
			e, n := preparedFixture(t)
			entered, exited := make(chan struct{}), make(chan struct{})
			configureAssist(t, e, assessorFunc(func(ctx context.Context, _ assist.Input) (ap.AssistResult, error) {
				close(entered)
				<-ctx.Done()
				close(exited)
				return ap.AssistResult{}, ctx.Err()
			}))
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			done := make(chan error, 1)
			go func() {
				_, err := e.ReserveLegacy(ctx, LegacyInstance{ID: legacyInstanceID(112), UID: 7, RequestID: "cancel"}, []byte("snapshot"), legacyInput(t))
				done <- err
			}()
			<-entered
			e.mu.Lock()
			var request *LegacyRequest
			for _, r := range e.legacy.requests {
				request = r
			}
			e.mu.Unlock()
			if mode == "close" {
				if err := e.Close(); err != nil {
					t.Fatal(err)
				}
			} else if mode == "abandon" {
				e.CancelLegacy(&LegacyReservation{engine: e, request: request})
			} else {
				cancel()
			}
			select {
			case err := <-done:
				if err == nil {
					t.Fatal("cancellation succeeded")
				}
			case <-time.After(3 * time.Second):
				t.Fatal("cancellation stuck")
			}
			<-exited
			want := "timeout"
			if mode == "abandon" {
				want = "error"
			}
			if request.Wait().Status != want || n.calls.Load() != 0 {
				t.Fatal("cancellation resolved incorrectly")
			}
		})
	}
}

func TestLegacyDeliveryExpiryAndDisconnect(t *testing.T) {
	for _, mode := range []string{"deadline", "disconnect"} {
		t.Run(mode, func(t *testing.T) {
			e, n := preparedFixture(t)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			r, err := e.ReserveLegacy(ctx, LegacyInstance{ID: legacyInstanceID(113), UID: 7, RequestID: "expires"}, []byte("snapshot"), legacyInput(t))
			if err != nil {
				t.Fatal(err)
			}
			n.artifact = preparedArtifact(t, r)
			n.deliver = func(context.Context, *PreparedLegacyApproval) (LegacyDelivery, error) {
				if mode == "disconnect" {
					cancel()
				} else {
					e.mu.Lock()
					r.request.deadline = e.config.Clock.Elapsed()
					e.mu.Unlock()
				}
				return LegacyDelivery{AllDelivered: true}, nil
			}
			if e.DeliverLegacy(r, n.artifact) == nil {
				t.Fatal("expired delivery activated")
			}
			if r.Request().Wait().Status != "timeout" {
				t.Fatal("expiry did not win")
			}
		})
	}
}

func TestLegacyPreparationSurvivesActualV2Recovery(t *testing.T) {
	e, clock, store, _ := engineFixture(t)
	defer e.Close()
	n := &preparedNotifier{destination: LegacyDestination{ChatID: 123}}
	e.config.LegacyNotifier = n
	submitJob(t, e, 1)
	clock.Advance(6 * time.Second)
	entered, release := make(chan struct{}), make(chan struct{})
	var calls atomic.Int32
	configureAssist(t, e, assessorFunc(func(ctx context.Context, _ assist.Input) (ap.AssistResult, error) {
		if calls.Add(1) == 1 {
			close(entered)
			select {
			case <-release:
			case <-ctx.Done():
				return ap.AssistResult{}, ctx.Err()
			}
		}
		result := readyAssist()
		result.Effects = []string{"echoes safe"}
		return result, nil
	}))
	type answer struct {
		r   *LegacyReservation
		err error
	}
	prepared := make(chan answer, 1)
	go func() {
		r, err := e.ReserveLegacy(context.Background(), LegacyInstance{ID: legacyInstanceID(201), UID: 7, RequestID: "in-flight"}, []byte("snapshot"), legacyInput(t))
		prepared <- answer{r, err}
	}()
	receiveNotify(t, entered)
	store.fail = true
	stopped := make(chan error, 1)
	go func() { stopped <- e.Run(context.Background()) }()
	if err := receiveNotify(t, stopped); err == nil {
		t.Fatal("missing storage failure")
	}
	store.fail = false
	reopened, err := New(e.config)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	close(release)
	first := receiveNotify(t, prepared)
	if first.err != nil {
		t.Fatal(first.err)
	}
	for i := 0; i < 2; i++ {
		r := first.r
		if i == 1 {
			r = reservePrepared(t, e, 202)
		}
		if r.RenderContext().Assist.State != ap.AssistReady {
			t.Fatalf("legacy assist interrupted by recovery: %+v", r.RenderContext().Assist)
		}
		n.artifact = preparedArtifact(t, r)
		if err := e.DeliverLegacy(r, n.artifact); err != nil {
			t.Fatal(err)
		}
		if !legacyTap(t, e, reservationVote(r)).Resolved || r.Request().Wait().Status != "approved" {
			t.Fatal("legacy activation lost")
		}
	}
}

func TestLegacyBlockedDeliveryResolution(t *testing.T) {
	for _, mode := range []string{"expiry", "cancel"} {
		t.Run(mode, func(t *testing.T) {
			e, n := preparedFixture(t)
			r := reservePrepared(t, e, 203)
			n.artifact = preparedArtifact(t, r)
			entered := make(chan struct{})
			n.deliver = func(ctx context.Context, _ *PreparedLegacyApproval) (LegacyDelivery, error) {
				close(entered)
				<-ctx.Done()
				// A transport may report success despite cancellation; it cannot activate.
				return LegacyDelivery{AllDelivered: true}, nil
			}
			done := make(chan error, 1)
			go func() { done <- e.DeliverLegacy(r, n.artifact) }()
			receiveNotify(t, entered)
			want := "error"
			if mode == "cancel" {
				e.CancelLegacy(r)
			} else {
				want = "timeout"
				e.mu.Lock()
				r.request.deadline = e.config.Clock.Elapsed()
				e.mu.Unlock()
			}
			if err := receiveNotify(t, done); err == nil {
				t.Fatal("resolved delivery activated")
			}
			if r.Request().Wait().Status != want || legacyTap(t, e, reservationVote(r)).Resolved {
				t.Fatal("resolution lost")
			}
		})
	}
}

func TestPreparedLegacyStringBackingCopies(t *testing.T) {
	e, _ := preparedFixture(t)
	data := preparedArtifact(t, reservePrepared(t, e, 204)).Data()
	result := readyAssist()
	result.Alignment = ap.AlignmentNotAssessed
	result.Concerns = []ap.Concern{{Severity: ap.SeverityHigh, Text: "concern"}}
	result.Effects = []string{"effect"}
	result.InputDigest = strings.Repeat("a", 64)
	data.Context.Assist = assist.Snapshot{State: ap.AssistReady, Result: &result}
	// Give every string (including string-backed enums) writable, distinct storage.
	var buffers [][]byte
	var ownStrings func(reflect.Value)
	ownStrings = func(v reflect.Value) {
		switch v.Kind() {
		case reflect.String:
			if v.Len() != 0 {
				b := []byte(v.String())
				buffers = append(buffers, b)
				v.SetString(unsafe.String(&b[0], len(b)))
			}
		case reflect.Pointer:
			if !v.IsNil() {
				ownStrings(v.Elem())
			}
		case reflect.Struct:
			for i := 0; i < v.NumField(); i++ {
				if v.Field(i).CanSet() {
					ownStrings(v.Field(i))
				}
			}
		case reflect.Slice:
			for i := 0; i < v.Len(); i++ {
				ownStrings(v.Index(i))
			}
		}
	}
	ownStrings(reflect.ValueOf(&data).Elem())
	p, err := NewPreparedLegacyApproval(data)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := json.Marshal(p.Data())
	if err != nil {
		t.Fatal(err)
	}
	var want LegacyPreparedData
	if err := json.Unmarshal(encoded, &want); err != nil {
		t.Fatal(err)
	}
	for _, b := range buffers {
		b[0] ^= 1
	}
	if !reflect.DeepEqual(p.Data(), want) {
		t.Fatal("constructor retained string backing")
	}
	// Each getter must also own all of its string storage.
	out := p.Data()
	var mutateStrings func(reflect.Value)
	mutateStrings = func(v reflect.Value) {
		switch v.Kind() {
		case reflect.String:
			if v.Len() != 0 {
				unsafe.Slice(unsafe.StringData(v.String()), v.Len())[0] ^= 1
			}
		case reflect.Pointer:
			if !v.IsNil() {
				mutateStrings(v.Elem())
			}
		case reflect.Struct:
			for i := 0; i < v.NumField(); i++ {
				if v.Field(i).CanSet() {
					mutateStrings(v.Field(i))
				}
			}
		case reflect.Slice:
			for i := 0; i < v.Len(); i++ {
				mutateStrings(v.Index(i))
			}
		}
	}
	mutateStrings(reflect.ValueOf(&out).Elem())
	if !reflect.DeepEqual(p.Data(), want) {
		t.Fatal("getter retained string backing")
	}
}
