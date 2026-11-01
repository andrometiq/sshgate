//go:build linux

package main

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"reflect"
	"sync"
	"testing"
	"time"

	"github.com/karthikeyan5/sshgate/internal/elapsed/elapsedtest"
	"github.com/karthikeyan5/sshgate/pkg/signerkit/lifecycle"
	ap "github.com/karthikeyan5/sshgate/src/approvalplan"
	st "github.com/karthikeyan5/sshgate/src/approvalplan/statetest"
)

// Clock restarts run the lifecycle over the real file store with a fake
// clock; each generation is a clean stop and a fresh acquisition, which is
// all a wall-clock step while the signer is down can observe.

type clockFreezer struct{}

func (clockFreezer) Freeze(_ context.Context, d ap.ApprovalDraft, principal, _ string, now time.Time) (ap.ApprovalPlanV1, error) {
	return st.Freeze(d, principal, now, time.Hour), nil
}

type clockSnapshots struct{}

func (clockSnapshots) BuildSnapshot(_ context.Context, p ap.ApprovalPlanV1) ([]byte, string, error) {
	return []byte(`{"segments":[]}`), p.Rationale, nil
}

type clockMinter struct{}

func (clockMinter) Mint(_ context.Context, p ap.ApprovalPlanV1, _ time.Time) ([]string, error) {
	signatures := make([]string, len(p.CommandJob.Steps))
	for i := range signatures {
		signatures[i] = "signature"
	}
	return signatures, nil
}

type clockAudit struct{}

func (clockAudit) WriteApproval(context.Context, ap.AuditMetadata) error { return nil }

// clockCards delivers every card and remembers its latest challenge.
type clockCards struct {
	mu    sync.Mutex
	cards map[string]lifecycle.Notification // by record handle
	next  int64
}

func (c *clockCards) Burst(ctx context.Context, fn func(lifecycle.BurstSession) error) error {
	return fn(c)
}
func (c *clockCards) SendParts(context.Context, lifecycle.Notification) ([]int64, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.next++
	return []int64{c.next}, nil
}
func (c *clockCards) SendCard(_ context.Context, n lifecycle.Notification) (int64, error) {
	return c.remember(n), nil
}
func (c *clockCards) EditCard(_ context.Context, _ int64, n lifecycle.Notification) (lifecycle.EditOutcome, error) {
	c.remember(n)
	return lifecycle.EditConfirmed, nil
}
func (c *clockCards) EditStatus(context.Context, int64, lifecycle.StatusDisplay) error { return nil }
func (c *clockCards) MarkIncomplete(context.Context, int64) error                      { return nil }

func (c *clockCards) remember(n lifecycle.Notification) int64 {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.next++
	if c.cards == nil {
		c.cards = map[string]lifecycle.Notification{}
	}
	c.cards[n.PartsHandle] = n
	return c.next
}

func (c *clockCards) card(partsHandle string) (lifecycle.Notification, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	n, ok := c.cards[partsHandle]
	return n, ok
}

type clockSigner struct {
	t      *testing.T
	root   string
	clock  *elapsedtest.Fake
	cards  *clockCards
	engine *lifecycle.Engine
	store  *lifecycle.FileStore
	done   chan error
}

func newClockSigner(t *testing.T, wall time.Time) *clockSigner {
	root := filepath.Join(t.TempDir(), "approvals")
	if err := os.Mkdir(root, 0o700); err != nil {
		t.Fatal(err)
	}
	s := &clockSigner{t: t, root: root, clock: elapsedtest.NewFake(wall), cards: &clockCards{}}
	t.Cleanup(s.stop)
	return s
}

func (s *clockSigner) start() {
	s.t.Helper()
	store := s.acquire()
	engine, err := lifecycle.New(lifecycle.Config{Store: store, Clock: s.clock, Freezer: clockFreezer{}, SnapshotBuilder: clockSnapshots{},
		Minter: clockMinter{}, AuditWriter: clockAudit{}, Notifier: s.cards, AssistTimeout: 5 * time.Second})
	if err != nil {
		store.Close()
		s.t.Fatal(err)
	}
	s.engine, s.store, s.done = engine, store, make(chan error, 1)
	go func() { s.done <- engine.Run(context.Background()) }()
}

func (s *clockSigner) acquire() *lifecycle.FileStore {
	s.t.Helper()
	store, err := lifecycle.AcquireFileStore(s.root, uint32(os.Geteuid()))
	if err == nil {
		if err = store.Reopen(); err != nil {
			store.Close()
		}
	}
	if err != nil {
		s.t.Fatal(err)
	}
	return store
}

func (s *clockSigner) stop() {
	if s.engine == nil {
		return
	}
	s.engine.Close()
	<-s.done
	s.store.Close()
	s.engine = nil
}

func (s *clockSigner) restart() { s.stop(); s.start() }

func (s *clockSigner) key(n int) string { return ap.RecordKey(st.PrincipalA, st.ID(n)) }

func (s *clockSigner) raw(n int) []byte {
	s.t.Helper()
	data, err := os.ReadFile(filepath.Join(s.root, s.key(n)))
	if err != nil {
		s.t.Fatal(err)
	}
	return data
}

func (s *clockSigner) snapshot() map[string][]byte {
	s.t.Helper()
	entries, err := os.ReadDir(s.root)
	if err != nil {
		s.t.Fatal(err)
	}
	files := map[string][]byte{}
	for _, entry := range entries {
		if data, err := os.ReadFile(filepath.Join(s.root, entry.Name())); err == nil {
			files[entry.Name()] = data
		}
	}
	return files
}

func (s *clockSigner) load(n int) ap.R1 {
	s.t.Helper()
	rec, err := ap.DecodeR1(s.raw(n))
	if err != nil {
		s.t.Fatal(err)
	}
	return rec
}

func (s *clockSigner) submit(n int, ttl int) ap.Summary {
	s.t.Helper()
	sum, err := s.engine.Submit(context.Background(), st.PrincipalA, st.JobDraft(st.ID(n), ap.CoordinatorExecutor, s.clock.Wall(), st.Write("true", ttl)))
	if err != nil {
		s.t.Fatal(err)
	}
	return sum
}

func (s *clockSigner) wait(what string, ready func() bool) {
	s.t.Helper()
	eventually(s.t, 10*time.Second, what, ready)
}

// settle lets assist time out and waits for the delivered revision-1 card.
func (s *clockSigner) settle(n int) lifecycle.Notification {
	s.t.Helper()
	s.clock.Advance(5 * time.Second)
	partsHandle := ap.CardHandleFor(s.key(n), 0)
	var card lifecycle.Notification
	s.wait("the revision-1 card", func() bool {
		var ok bool
		card, ok = s.cards.card(partsHandle)
		if !ok || card.Revision != 1 {
			return false
		}
		rec := s.load(n)
		last := rec.Payload.CardEntries[len(rec.Payload.CardEntries)-1]
		return last.Handle == card.Handle && (last.Outcome == ap.OutcomeSent || last.Confirmed)
	})
	return card
}

// vote taps Approve on the card and waits until the decision is audited.
func (s *clockSigner) vote(n int, card lifecycle.Notification) {
	s.t.Helper()
	msg := *s.load(n).Payload.CardEntries[0].MsgID
	answer, err := s.engine.Vote(ap.CastVote{Operator: st.Operator, Decision: ap.VoteApprove, Authn: "telegram", Card: &ap.CardTap{Handle: card.Handle, Challenge: card.Challenge, MsgID: msg}})
	if err != nil || answer.Noise {
		s.t.Fatalf("approve %d: %+v %v", n, answer, err)
	}
	s.wait("the audited decision", func() bool { return !ap.Unflushed(s.load(n)) })
}

func (s *clockSigner) approve(n int) { s.vote(n, s.settle(n)) }

func (s *clockSigner) claim(n int, sum ap.Summary) ap.Answer {
	s.t.Helper()
	answer, err := s.engine.Claim(context.Background(), st.PrincipalA, st.ID(n), ap.Claim{Token: st.Token(st.ID(n)), PlanHash: sum.PlanHash})
	if err != nil {
		s.t.Fatalf("claim %d: %v", n, err)
	}
	return answer
}

// The clock 1 h behind after a restart: nothing is written or contradicted,
// commands are accepted at once, and future decisions fail closed at Claim.
func TestRestartClockBehind(t *testing.T) {
	s := newClockSigner(t, time.Date(2026, 10, 15, 14, 0, 0, 0, time.UTC))
	s.start()
	if n := s.engine.FutureDatedAtStartup(); n != 0 {
		t.Fatalf("empty store reported %d future-dated records", n)
	}
	s.submit(1, 60)
	decided, claimed := s.submit(2, 60), s.submit(3, 60)
	s.approve(2)
	s.approve(3)
	if answer := s.claim(3, claimed); answer.Claim != ap.ClaimSignatures {
		t.Fatalf("first claim %+v", answer)
	}
	// Let the claim's status edit and audit flush land before the stop.
	s.wait("the claimed record to settle", func() bool {
		rec := s.load(3)
		return !ap.Unflushed(rec) && len(rec.Payload.StatusEdits) == 2
	})
	s.stop()
	before := s.snapshot()

	s.clock.StepWall(-time.Hour)
	s.start()
	// Records 2 (unclaimed) and 3 (bytes held) have open windows; pending
	// record 1's future created_at is not counted (SA-1 rule 3).
	if n := s.engine.FutureDatedAtStartup(); n != 2 {
		t.Fatalf("future-dated records reported at Startup: %d, want 2", n)
	}
	time.Sleep(200 * time.Millisecond)
	if after := s.snapshot(); len(after) != len(before) {
		t.Fatal("startup wrote a record")
	} else {
		for name, data := range before {
			if !bytes.Equal(after[name], data) {
				t.Fatalf("startup rewrote %s:\nbefore %s\nafter  %s", name, data, after[name])
			}
		}
	}
	s.submit(4, 60) // accepted at once
	if answer := s.claim(2, decided); answer.Claim != ap.ClaimMaterializationError || answer.Reason != ap.MintReasonClockSkew {
		t.Fatalf("first claim of a future decision: %+v", answer)
	}
	if rec := s.load(3); rec.Payload.Signatures == nil {
		t.Fatal("claimed record lost its bytes before the repeat claim")
	}
	if answer := s.claim(3, claimed); answer.Claim != ap.ClaimExpired {
		t.Fatalf("repeat claim of a future decision: %+v", answer)
	}
	if rec := s.load(3); rec.Payload.Signatures != nil {
		t.Fatal("repeat claim did not erase the bytes in its commit")
	}
}

// The clock 1 h ahead: Clock commits every due fact before anything is
// served, and a corrected clock after another restart shows the same facts.
func TestRestartClockAhead(t *testing.T) {
	s := newClockSigner(t, time.Date(2026, 10, 15, 14, 0, 0, 0, time.UTC))
	s.start()
	s.submit(1, 60)
	s.approve(1) // its 60 s window closes
	claimed := s.submit(2, 60)
	s.approve(2)
	if answer := s.claim(2, claimed); answer.Claim != ap.ClaimSignatures {
		t.Fatalf("claim %+v", answer)
	}
	s.submit(3, 60) // pending with assist preparing: expires and becomes unavailable
	s.stop()
	s.clock.StepWall(time.Hour + time.Minute)
	store := s.acquire()
	engine, err := lifecycle.New(lifecycle.Config{Store: store, Clock: s.clock, Freezer: clockFreezer{}, SnapshotBuilder: clockSnapshots{}, Minter: clockMinter{}, AuditWriter: clockAudit{}})
	if err != nil {
		t.Fatal(err)
	}
	// New has returned and Run has not started: nothing has been served.
	unclaimed, erased, pending := s.load(1), s.load(2), s.load(3)
	engine.Close()
	store.Close()
	if unclaimed.Header.Mint == nil || unclaimed.Header.Mint.Reason != ap.MintReasonWindowClosed {
		t.Fatalf("unclaimed record: %+v", unclaimed.Header.Mint)
	}
	if erased.Payload.Signatures != nil {
		t.Fatal("claimed record kept its bytes past the window")
	}
	if pending.Header.Decision == nil || pending.Header.Decision.Status != ap.ApprovalExpired || pending.Header.Assist == nil || pending.Header.Assist.State != ap.AssistUnavailable {
		t.Fatalf("pending record: %+v", pending.Header)
	}

	s.clock.StepWall(-time.Hour - time.Minute)
	s.start()
	time.Sleep(200 * time.Millisecond)
	// The flusher may advance audited_through; no committed fact may change.
	for n, before := range []ap.R1{unclaimed, erased, pending} {
		after := s.load(n + 1)
		if !reflect.DeepEqual(after.Header.Decision, before.Header.Decision) || !reflect.DeepEqual(after.Header.Mint, before.Header.Mint) ||
			!reflect.DeepEqual(after.Header.Assist, before.Header.Assist) || !reflect.DeepEqual(after.Payload.Signatures, before.Payload.Signatures) {
			t.Fatalf("corrected clock changed record %d:\nbefore %+v\nafter  %+v", n+1, before.Header, after.Header)
		}
	}
}

// S1 against the file store: a record created on a fast clock and approved
// after the correction keeps its window open across a restart.
func TestRestartAfterFastClockCorrectionKeepsWindow(t *testing.T) {
	s := newClockSigner(t, time.Date(2026, 10, 15, 14, 0, 0, 0, time.UTC))
	s.start()
	sum := s.submit(1, 60)
	card := s.settle(1)
	s.clock.StepWall(-time.Hour) // corrected to 13:00:05
	s.clock.Advance(10*time.Minute - 5*time.Second)
	s.vote(1, card) // 13:10
	s.clock.Advance(30 * time.Second)
	s.stop()
	approved := s.raw(1)
	s.start() // 13:10:30
	time.Sleep(200 * time.Millisecond)
	rec := s.load(1)
	if !bytes.Equal(s.raw(1), approved) || rec.Header.Mint != nil {
		t.Fatalf("restart wrote window_closed or an erase: %+v", rec.Header.Mint)
	}
	s.clock.Advance(10 * time.Second) // 13:10:40
	if answer := s.claim(1, sum); answer.Claim != ap.ClaimSignatures {
		t.Fatalf("claim inside the window: %+v", answer)
	}
}
