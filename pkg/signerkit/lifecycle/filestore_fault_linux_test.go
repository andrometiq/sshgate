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
	// Reuse securestate's private transaction seam without adding a production API.
	field := reflect.ValueOf(s.disk).Elem().FieldByName("beforeTransactionSync")
	seam := (*func() error)(unsafe.Pointer(field.UnsafeAddr()))
	var transactions atomic.Int32
	*seam = func() error { transactions.Add(1); return nil }
	defer func() { *seam = nil }()
	entered, release, done := make(chan struct{}), make(chan struct{}), make(chan error, 1)
	var once sync.Once
	defer once.Do(func() { close(release) })
	go func() {
		done <- s.disk.Update(func(tx *securestate.Transaction) error {
			if _, err := tx.WriteCanonicalJSON(key, rec, ap.R1Max); err != nil {
				return err
			}
			close(entered)
			<-release
			return nil
		})
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
			if _, err := e.Get(st.PrincipalA, st.ID(1)); err != nil {
				t.Error(err)
			}
			if _, err := e.List(st.PrincipalA); err != nil {
				t.Error(err)
			}
			if _, err := e.WaitMany(context.Background(), st.PrincipalA, []string{st.ID(1)}, 0); err != nil {
				t.Error(err)
			}
		}()
	}
	readers := make(chan struct{})
	go func() { group.Wait(); close(readers) }()
	select {
	case <-readers:
	case <-time.After(5 * time.Second):
		t.Error("cached readers waited for securestate lock")
	}
	if transactions.Load() != baseline {
		t.Error("reads opened disk transactions")
	}
	once.Do(func() { close(release) })
	if err := receiveNotify(t, done); err != nil {
		t.Fatal(err)
	}
	receiveNotify(t, readers)
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
