package lifecycle

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	ap "github.com/karthikeyan5/sshgate/src/approvalplan"
	st "github.com/karthikeyan5/sshgate/src/approvalplan/statetest"
)

func storeRecords(t *testing.T, store Store) map[string]ap.R1 {
	t.Helper()
	entries, err := store.List()
	if err != nil {
		t.Fatal(err)
	}
	records := map[string]ap.R1{}
	for _, entry := range entries {
		rec, err := store.Load(entry.Key)
		if err != nil {
			t.Fatal(err)
		}
		records[entry.Key] = rec
	}
	return records
}

func deliverCard(t *testing.T, e *Engine, principal string, id int) {
	t.Helper()
	for _, cmd := range []ap.Command{
		ap.AssistDone{Unavailable: "test"}, ap.BurstStart{}, ap.BurstDone{PartMsgIDs: []int64{1}},
		ap.CardStart{Handle: "abcdefghijkl", ChalHash: ap.ChallengeHash("0123456789abcdef")}, ap.CardDone{Handle: "abcdefghijkl", MsgID: 2},
	} {
		e.mu.Lock()
		key := ap.RecordKey(principal, st.ID(id))
		before, err := e.load(key)
		if err == nil {
			_, _, err = e.commitLocked(key, before, cmd, e.now(), ap.Inputs{})
		}
		e.mu.Unlock()
		if err != nil {
			t.Fatal(err)
		}
	}
}

func TestAdminResolveRefusesAmbiguousRequestID(t *testing.T) {
	e, _, store, _ := engineFixture(t)
	for _, principal := range []string{st.PrincipalA, st.PrincipalB} {
		if _, err := e.Submit(context.Background(), principal, st.JobDraft(st.ID(1), ap.CoordinatorExecutor, e.config.Clock.Wall(), st.Write("true", 60))); err != nil {
			t.Fatal(err)
		}
		deliverCard(t, e, principal, 1)
	}
	submitJob(t, e, 2)
	before := storeRecords(t, store)

	_, err := e.ResolveAdmin(st.ID(1))
	var coded *ap.CodeError
	if !errors.As(err, &coded) || coded.Code != ap.CodeInvalidRequest || coded.Msg != "ambiguous id — use the handle from /pending" {
		t.Fatalf("shared request_id resolved: %v", err)
	}
	if after := storeRecords(t, store); !reflect.DeepEqual(after, before) {
		t.Fatal("ambiguous resolution changed a record")
	}

	keyA := ap.RecordKey(st.PrincipalA, st.ID(1))
	handleA := ap.RecordHandle(keyA)
	if handle, err := e.ResolveAdmin(handleA); err != nil || handle != handleA {
		t.Fatalf("handle %q %v", handle, err)
	}
	if handle, err := e.ResolveAdmin(st.ID(2)); err != nil || handle != ap.RecordHandle(ap.RecordKey(st.PrincipalA, st.ID(2))) {
		t.Fatalf("unique request_id %q %v", handle, err)
	}
	for _, id := range []string{st.ID(3), "abcdefghijklmnop", "not-an-id", ""} {
		if _, err := e.ResolveAdmin(id); err == nil {
			t.Fatalf("%q resolved", id)
		}
	}

	if answer, err := e.Renotify(handleA); err != nil || answer.Reason != "" {
		t.Fatalf("renotify by handle: %+v %v", answer, err)
	}
	after := storeRecords(t, store)
	if got := after[keyA].Header.RenotifyGen; got != 1 || !after[keyA].Payload.CardEntries[0].Retired {
		t.Fatalf("handle renotify gen=%d entries=%+v", got, after[keyA].Payload.CardEntries)
	}
	keyB := ap.RecordKey(st.PrincipalB, st.ID(1))
	if !reflect.DeepEqual(after[keyB], before[keyB]) {
		t.Fatal("renotify by handle touched the other principal's record")
	}
}

func TestAdminRenotifyAuthorizesOneResendPerBurst(t *testing.T) {
	e, _, store, _ := engineFixture(t)
	submitJob(t, e, 1)
	command(t, e, 1, ap.AssistDone{Unavailable: "test"})
	command(t, e, 1, ap.BurstStart{})
	key := ap.RecordKey(st.PrincipalA, st.ID(1))
	handle := ap.RecordHandle(key)
	if _, err := e.Renotify(handle); err == nil || !strings.Contains(err.Error(), "in_progress") {
		t.Fatalf("renotify during this epoch's send: %v", err)
	}

	// A restart makes the burst uncertain; Renotify is its only resend.
	recovered, err := New(e.config)
	if err != nil {
		t.Fatal(err)
	}
	if answer, err := recovered.Renotify(handle); err != nil || answer.Reason != "" {
		t.Fatalf("renotify uncertain: %+v %v", answer, err)
	}
	if answer, err := recovered.Renotify(handle); err != nil || answer.Reason != "already_pending" {
		t.Fatalf("second renotify before the burst: %+v %v", answer, err)
	}
	if rec := storeRecords(t, store)[key]; rec.Header.RenotifyGen != 1 {
		t.Fatalf("renotify_gen %d after two commands", rec.Header.RenotifyGen)
	}

	for gen := 1; gen < ap.MaxBursts; gen++ {
		command(t, recovered, 1, ap.BurstStart{})
		command(t, recovered, 1, ap.BurstDone{PartMsgIDs: []int64{int64(gen)}})
		if gen < ap.MaxBursts-1 {
			if answer, err := recovered.Renotify(handle); err != nil || answer.Reason != "" {
				t.Fatalf("renotify %d: %+v %v", gen, answer, err)
			}
		}
	}
	if _, err := recovered.Renotify(handle); err == nil || !strings.Contains(err.Error(), ap.ReasonNotificationLimit) {
		t.Fatalf("full burst set accepted renotify: %v", err)
	}
}

func TestAdminRenotifyCommitsClockFirst(t *testing.T) {
	e, clock, store, _ := engineFixture(t)
	submitJob(t, e, 1)
	deliverCard(t, e, st.PrincipalA, 1)
	clock.Advance(2 * time.Hour)
	key := ap.RecordKey(st.PrincipalA, st.ID(1))
	if _, err := e.Renotify(ap.RecordHandle(key)); err == nil || !strings.Contains(err.Error(), "not_pending") {
		t.Fatalf("expired record renotified: %v", err)
	}
	rec := storeRecords(t, store)[key]
	if rec.Header.Decision == nil || rec.Header.Decision.Status != ap.ApprovalExpired || rec.Header.RenotifyGen != 0 {
		t.Fatalf("Clock not committed before the refusal: %+v", rec.Header)
	}
}

func TestAdminResolutionUnavailableAfterStop(t *testing.T) {
	e, _, _, _ := engineFixture(t)
	submitJob(t, e, 1)
	e.Close()
	handle := ap.RecordHandle(ap.RecordKey(st.PrincipalA, st.ID(1)))
	if _, err := e.ResolveAdmin(handle); !isCode(err, ap.CodeLifecycleUnavailable) {
		t.Fatalf("resolve after stop: %v", err)
	}
	if _, err := e.Renotify(handle); !isCode(err, ap.CodeLifecycleUnavailable) {
		t.Fatalf("renotify after stop: %v", err)
	}
}

func isCode(err error, code ap.Code) bool {
	var coded *ap.CodeError
	return errors.As(err, &coded) && coded.Code == code
}
