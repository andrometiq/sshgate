//go:build linux

package lifecycle

import (
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

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
	s, err := OpenFileStore(filepath.Join(t.TempDir(), "approvals"), uint32(os.Getuid()))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	key, rec := fileRecordFixture(t)
	if err := s.Commit(key, rec); err != nil {
		t.Fatal(err)
	}
	entered, release, done := make(chan struct{}), make(chan struct{}), make(chan error, 1)
	s.beforeStoreUpdate = func() error { close(entered); <-release; return nil }
	go func() { done <- s.Commit(key, rec) }()
	<-entered
	var group sync.WaitGroup
	for i := 0; i < 8; i++ {
		group.Add(1)
		go func() {
			defer group.Done()
			if _, err := s.Load(key); err != nil {
				t.Error(err)
			}
			if _, err := s.List(); err != nil {
				t.Error(err)
			}
		}()
	}
	readers := make(chan struct{})
	go func() { group.Wait(); close(readers) }()
	select {
	case <-readers:
	case <-time.After(5 * time.Second):
		t.Error("readers waited for disk transaction")
	}
	close(release)
	if err := <-done; err != nil {
		t.Fatal(err)
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
