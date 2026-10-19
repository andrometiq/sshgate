//go:build linux

package lifecycle

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
	"unsafe"

	"github.com/karthikeyan5/sshgate/internal/securestate"
	ap "github.com/karthikeyan5/sshgate/src/approvalplan"
	st "github.com/karthikeyan5/sshgate/src/approvalplan/statetest"
)

func fileRecordFixture(t *testing.T) (string, ap.R1) {
	t.Helper()
	d := st.JobDraft(st.ID(1), ap.CoordinatorExecutor, st.T0, st.Write("touch /tmp/example", 60))
	rec, answer := ap.Apply(nil, st.SubmitOf(d, st.PrincipalA, st.T0, time.Hour), ap.Now{Wall: st.T0}, ap.Inputs{Epoch: st.Epoch(1), Settings: ap.LocalSettings})
	if answer.Code != "" {
		t.Fatal(answer)
	}
	return ap.RecordKey(st.PrincipalA, st.ID(1)), rec
}

func TestFileStoreUncertainCommit(t *testing.T) {
	for _, landed := range []bool{false, true} {
		t.Run(map[bool]string{false: "before", true: "after"}[landed], func(t *testing.T) {
			s, err := OpenFileStore(filepath.Join(t.TempDir(), "approvals"), uint32(os.Getuid()))
			if err != nil {
				t.Fatal(err)
			}
			defer s.Close()
			key, rec := fileRecordFixture(t)
			if err := s.Commit(key, rec); err != nil {
				t.Fatal(err)
			}
			rec.Header.RationaleRedacted = "replacement"
			fault := func() error { return securestate.ErrCommitUncertain }
			if landed {
				s.afterStoreUpdate = fault
			} else {
				s.beforeStoreUpdate = fault
			}
			requireUncertain := func(err error) {
				t.Helper()
				var code *ap.CodeError
				if !errors.As(err, &code) || code.Code != ap.CodeStorageUncertain {
					t.Errorf("expected storage_uncertain, got %v", err)
				}
			}
			requireUncertain(s.Commit(key, rec))
			var group sync.WaitGroup
			for i := 0; i < 8; i++ {
				group.Add(1)
				go func() {
					defer group.Done()
					_, err := s.Load(key)
					requireUncertain(err)
					_, err = s.List()
					requireUncertain(err)
					requireUncertain(s.Commit(key, rec))
					requireUncertain(s.Remove(key))
				}()
			}
			group.Wait()
			s.beforeStoreUpdate, s.afterStoreUpdate = nil, nil
			if err := s.Reopen(); err != nil {
				t.Fatal(err)
			}
			got, err := s.Load(key)
			if err != nil {
				t.Fatal(err)
			}
			if (got.Header.RationaleRedacted == "replacement") != landed {
				t.Fatal("wrong recovered prefix")
			}
		})
	}
}

func TestFileStoreReadersDoNotWaitForDisk(t *testing.T) {
	e, _, s, _ := fileEngineFixture(t)
	key, rec := fileRecordFixture(t)
	steps := make([]st.StepSpec, 6)
	for i := range steps {
		steps[i] = st.Write(strings.Repeat("<", ap.MaxStepBytes), 60)
	}
	draft := st.JobDraft(st.ID(1), ap.CoordinatorExecutor, st.T0, steps...)
	var answer ap.Answer
	rec, answer = ap.Apply(nil, st.SubmitOf(draft, st.PrincipalA, st.T0, time.Hour), ap.Now{Wall: st.T0}, ap.Inputs{Epoch: st.Epoch(1), Settings: ap.LocalSettings})
	if answer.Code != "" {
		t.Fatal(answer)
	}
	rec.Header.Outbox = nil
	for i := 1; i <= ap.MaxRequiredApprovals; i++ {
		rec.Header.Outbox = append(rec.Header.Outbox, ap.OutboxEvent{Seq: uint64(i), Kind: ap.EventVote, Operator: strings.Repeat("o", ap.MaxOperatorIDBytes), Decision: ap.VoteApprove, Detail: strings.Repeat("d", ap.MaxDetailBytes)})
	}
	rec.Header.OutboxSeq = uint64(len(rec.Header.Outbox))
	rec.Header.RequiredApprovals = ap.MaxRequiredApprovals
	for i := 0; i < ap.MaxRequiredApprovals+ap.VoteSlack; i++ {
		rec.Header.Votes = append(rec.Header.Votes, ap.Vote{Operator: fmt.Sprintf("%03d", i) + strings.Repeat("x", ap.MaxOperatorIDBytes-3), Decision: ap.VoteApprove, TS: st.T0, Authn: "telegram"})
	}
	rec.Payload.ReviewSnapshot = []byte(`{"padding":""}`)
	data, err := ap.EncodeR1(rec)
	if err != nil {
		t.Fatal(err)
	}
	padding := (512 << 10) - len(data)
	if padding < 0 || padding+len(rec.Payload.ReviewSnapshot) > ap.ReviewSnapshotMax {
		t.Fatal("invalid large fixture padding", padding)
	}
	rec.Payload.ReviewSnapshot = []byte(`{"padding":"` + strings.Repeat("x", padding) + `"}`)
	data, err = ap.EncodeR1(rec)
	if err != nil || len(data) != 512<<10 {
		t.Fatal("512-KiB fixture", len(data), err)
	}
	if err := s.Commit(key, rec); err != nil {
		t.Fatal(err)
	}
	e = restartFileEngine(t, e, s)
	old, err := e.Get(st.PrincipalA, st.ID(1))
	if err != nil {
		t.Fatal(err)
	}
	// Hold a public mutation inside securestate's transaction, with Engine.mu held.
	field := reflect.ValueOf(s.disk).Elem().FieldByName("beforeTransactionSync")
	seam := (*func() error)(unsafe.Pointer(field.UnsafeAddr()))
	entered, release, done := make(chan struct{}), make(chan struct{}), make(chan error, 1)
	var transactions atomic.Int32
	*seam = func() error { transactions.Add(1); close(entered); <-release; return nil }
	var once sync.Once
	defer once.Do(func() { close(release) })
	go func() {
		_, err := e.AdminCancel(old.RecordHandle, ap.AdminCancel{PlanHash: old.PlanHash, Admin: st.Admin})
		done <- err
	}()
	receiveNotify(t, entered)
	baseline := transactions.Load()
	if baseline != 1 {
		t.Fatal("writer never entered transaction", baseline)
	}
	var group sync.WaitGroup
	for range 8 {
		group.Add(1)
		go func() {
			defer group.Done()
			got, err := e.Get(st.PrincipalA, st.ID(1))
			if err != nil || !reflect.DeepEqual(got, old) {
				t.Errorf("Get during commit: %+v %v", got, err)
			}
			list, err := e.List(st.PrincipalA)
			if err != nil || !reflect.DeepEqual(list, []ap.Summary{old}) {
				t.Errorf("List during commit: %+v %v", list, err)
			}
			wait, err := e.WaitMany(context.Background(), st.PrincipalA, []string{st.ID(1)}, 0)
			if err != nil || !wait.WaitElapsed || !reflect.DeepEqual(wait.Summaries, []ap.Summary{old}) {
				t.Errorf("Wait during commit: %+v %v", wait, err)
			}
		}()
	}
	readers := make(chan struct{})
	go func() { group.Wait(); close(readers) }()
	select {
	case <-readers:
	case <-time.After(5 * time.Second):
		// Release before failing so a mutex regression cannot strand cleanup.
		once.Do(func() { close(release) })
		receiveNotify(t, done)
		receiveNotify(t, readers)
		t.Fatal("cached readers waited for mutation/securestate lock")
	}
	waiting, _ := startWait(t, e, st.ID(1))
	canceled, cancel := startWait(t, e, st.ID(1))
	cancel()
	if got := receiveWait(t, canceled); !errors.Is(got.err, context.Canceled) {
		t.Fatal("held cancellation", got)
	}
	if transactions.Load() != baseline {
		t.Error("reads opened disk transactions")
	}
	once.Do(func() { close(release) })
	if err := receiveNotify(t, done); err != nil {
		t.Fatal(err)
	}
	*seam = nil
	got, err := e.Get(st.PrincipalA, st.ID(1))
	if err != nil || got.ApprovalStatus != ap.ApprovalCanceled {
		t.Fatalf("new view: %+v %v", got, err)
	}
	list, err := e.List(st.PrincipalA)
	if err != nil || !reflect.DeepEqual(list, []ap.Summary{got}) {
		t.Fatal("new List view", list, err)
	}
	result, err := e.WaitMany(context.Background(), st.PrincipalA, []string{st.ID(1)}, 0)
	if err != nil || !reflect.DeepEqual(result.Summaries, list) {
		t.Fatal("new Wait view", result, err)
	}
	wake := receiveWait(t, waiting)
	if wake.err != nil || wake.result.WaitElapsed || !reflect.DeepEqual(wake.result.Summaries, list) {
		t.Fatal("lost commit wakeup", wake)
	}
	if transactions.Load() != baseline {
		t.Error("reads opened transactions after writer released lock")
	}
}

func TestFileStoreUncertainRemove(t *testing.T) {
	for _, landed := range []bool{false, true} {
		t.Run(map[bool]string{false: "before", true: "after"}[landed], func(t *testing.T) {
			s, err := OpenFileStore(filepath.Join(t.TempDir(), "approvals"), uint32(os.Getuid()))
			if err != nil {
				t.Fatal(err)
			}
			defer s.Close()
			key, rec := fileRecordFixture(t)
			if err := s.Commit(key, rec); err != nil {
				t.Fatal(err)
			}
			fault := func() error { return securestate.ErrCommitUncertain }
			if landed {
				s.afterStoreUpdate = fault
			} else {
				s.beforeStoreUpdate = fault
			}
			checkCode(t, s.Remove(key), ap.CodeStorageUncertain)
			assertFileStorePoisoned(t, s)
			s.afterStoreUpdate, s.beforeStoreUpdate = nil, nil
			if err := s.Reopen(); err != nil {
				t.Fatal(err)
			}
			_, err = s.Load(key)
			if landed && !errors.Is(err, ErrNotFound) || !landed && err != nil {
				t.Fatalf("wrong remove prefix: %v", err)
			}
		})
	}
}

// Pause after FileStore has poisoned, before the mutation owner sees its error.
type heldPoisonStore struct {
	*FileStore
	returned chan struct{}
	release  chan struct{}
}

func (s *heldPoisonStore) Commit(key string, record ap.R1) error {
	err := s.FileStore.Commit(key, record)
	if err != nil {
		close(s.returned)
		<-s.release
	}
	return err
}

func TestFileStorePoisonPublishedBeforeMutationReturns(t *testing.T) {
	for _, landed := range []bool{false, true} {
		t.Run(fmt.Sprint(landed), func(t *testing.T) {
			original, _, store, _ := fileEngineFixture(t)
			sum := submitJob(t, original, 1)
			original.Close()
			held := &heldPoisonStore{FileStore: store, returned: make(chan struct{}), release: make(chan struct{})}
			config := original.config
			config.Store = held
			e, err := New(config)
			if err != nil {
				t.Fatal(err)
			}
			defer e.Close()
			waiting, _ := startWait(t, e, st.ID(1))
			fault := func() error { return securestate.ErrCommitUncertain }
			if landed {
				store.afterStoreUpdate = fault
			} else {
				store.beforeStoreUpdate = fault
			}
			var once sync.Once
			defer once.Do(func() { close(held.release) })
			done := make(chan error, 1)
			go func() {
				_, err := e.AdminCancel(sum.RecordHandle, ap.AdminCancel{PlanHash: sum.PlanHash, Admin: st.Admin})
				done <- err
			}()
			receiveNotify(t, held.returned)
			readDone := make(chan struct{})
			go func() {
				defer close(readDone)
				var group sync.WaitGroup
				for range 8 {
					group.Add(1)
					go func() {
						defer group.Done()
						_, err := e.Get(st.PrincipalA, st.ID(1))
						checkCode(t, err, ap.CodeStorageUncertain)
						_, err = e.List(st.PrincipalA)
						checkCode(t, err, ap.CodeStorageUncertain)
						_, err = e.List(st.PrincipalB)
						checkCode(t, err, ap.CodeStorageUncertain)
						_, err = e.WaitMany(context.Background(), st.PrincipalA, []string{st.ID(1)}, 0)
						checkCode(t, err, ap.CodeStorageUncertain)
						checkCode(t, e.Availability(), ap.CodeStorageUncertain)
					}()
				}
				group.Wait()
			}()
			receiveNotify(t, readDone)
			checkCode(t, receiveWait(t, waiting).err, ap.CodeStorageUncertain)
			if e.effectContext.Err() == nil {
				t.Error("poison did not cancel effects immediately")
			}
			once.Do(func() { close(held.release) })
			checkCode(t, receiveNotify(t, done), ap.CodeStorageUncertain)
			e.Close()
			store.beforeStoreUpdate, store.afterStoreUpdate = nil, nil
			next := restartFileEngine(t, e, store)
			checkCode(t, e.Availability(), ap.CodeStorageUncertain)
			_, err = e.List(st.PrincipalB)
			checkCode(t, err, ap.CodeStorageUncertain)
			got, err := next.Get(st.PrincipalA, st.ID(1))
			if err != nil || (got.ApprovalStatus == ap.ApprovalCanceled) != landed {
				t.Fatal("recovered generation", got, err)
			}
		})
	}
}

func TestFileStoreGrantPublicationIsAtomic(t *testing.T) {
	e, clock, store, _ := fileEngineFixture(t)
	submitGrant(t, e, 1, st.PrincipalA)
	voteApprove(t, e, 1)
	submitGrant(t, e, 2, st.PrincipalA)
	vote := readyCard(t, e, 2, true)
	old, err := e.List(st.PrincipalA)
	if err != nil {
		t.Fatal(err)
	}
	entered, release := make(chan struct{}), make(chan struct{})
	field := reflect.ValueOf(store.disk).Elem().FieldByName("beforeTransactionSync")
	seam := (*func() error)(unsafe.Pointer(field.UnsafeAddr()))
	*seam = func() error { close(entered); <-release; return nil }
	var once sync.Once
	defer once.Do(func() { close(release) })
	done := make(chan error, 1)
	go func() { _, err := e.Vote(vote); done <- err }()
	receiveNotify(t, entered)
	waiting, _ := startWait(t, e, st.ID(1)) // The superseded record itself is not written.
	got, err := e.List(st.PrincipalA)
	if err != nil || !reflect.DeepEqual(got, old) {
		t.Fatal("uncommitted grant view", got, err)
	}
	stop, readDone := make(chan struct{}), make(chan struct{})
	go func() {
		defer close(readDone)
		for {
			select {
			case <-stop:
				return
			default:
			}
			list, err := e.List(st.PrincipalA)
			if err != nil {
				t.Error(err)
				return
			}
			byID := make(map[string]ap.Summary)
			for _, sum := range list {
				byID[sum.RequestID] = sum
			}
			first, second := byID[st.ID(1)], byID[st.ID(2)]
			if second.ApprovalStatus == ap.ApprovalApproved {
				if first.Class == ap.ClassLive || second.Class != ap.ClassLive {
					t.Error("split grant publication", list)
					return
				}
			} else if first.Class != ap.ClassLive {
				t.Error("early grant removal", list)
				return
			}
		}
	}()
	once.Do(func() { close(release) })
	if err := receiveNotify(t, done); err != nil {
		t.Fatal(err)
	}
	*seam = nil
	close(stop)
	receiveNotify(t, readDone)
	wake := receiveWait(t, waiting)
	if wake.err != nil || wake.result.WaitElapsed || wake.result.Summaries[0].Class == ap.ClassLive {
		t.Fatal("superseded grant wake", wake)
	}
	got, err = e.List(st.PrincipalA)
	if err != nil {
		t.Fatal(err)
	}
	for _, sum := range got {
		if (sum.Class == ap.ClassLive) != (sum.RequestID == st.ID(2)) {
			t.Fatal("committed grant membership", got)
		}
	}
	waiting, _ = startWait(t, e, st.ID(2))
	clock.Advance(2 * time.Hour)
	// Wall time alone must not publish expiry.
	sum, err := e.Get(st.PrincipalA, st.ID(2))
	if err != nil || sum.Class != ap.ClassLive {
		t.Fatal("reader expired grant", sum, err)
	}
	if err := e.Reconcile(); err != nil {
		t.Fatal(err)
	}
	wake = receiveWait(t, waiting)
	if wake.err != nil || wake.result.WaitElapsed || wake.result.Summaries[0].Class == ap.ClassLive {
		t.Fatal("latched expiry not published", wake)
	}
}
