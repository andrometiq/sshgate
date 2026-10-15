package lifecycle_test

import (
	"bytes"
	"errors"
	"fmt"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/karthikeyan5/sshgate/internal/elapsed/elapsedtest"
	"github.com/karthikeyan5/sshgate/pkg/signerkit/lifecycle"
	ap "github.com/karthikeyan5/sshgate/src/approvalplan"
	st "github.com/karthikeyan5/sshgate/src/approvalplan/statetest"
	"go.uber.org/goleak"
)

func TestMain(m *testing.M) { goleak.VerifyTestMain(m) }

func record(t *testing.T, id int) (string, ap.R1) {
	t.Helper()
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	requestID, err := ap.NewRequestID(bytes.NewReader([]byte(fmt.Sprintf("%016d", id))))
	if err != nil {
		t.Fatal(err)
	}
	draft := st.GrantDraft(requestID, "target", time.Hour, now, "touch /tmp/example")
	submit := st.SubmitOf(draft, "local-uid:1000", now, time.Hour)
	submit.ReviewSnapshot = bytes.Clone(submit.ReviewSnapshot)
	rec, answer := ap.Apply(nil, submit, ap.Now{Wall: now}, ap.Inputs{Epoch: st.Epoch(1)})
	if !answer.Changed || answer.Code != "" {
		t.Fatalf("submit: %+v", answer)
	}
	return ap.RecordKey(rec.Header.Principal, rec.Header.RequestID), rec
}

func TestMemStoreRoundTrip(t *testing.T) {
	var store lifecycle.MemStore
	entries, err := store.List()
	if err != nil || len(entries) != 0 {
		t.Fatalf("empty list: %v %v", entries, err)
	}
	key, rec := record(t, 1)
	if _, err := store.Load(key); !errors.Is(err, lifecycle.ErrNotFound) {
		t.Fatal(err)
	}
	if err := store.Remove(key); err != nil {
		t.Fatal(err)
	}
	if err := store.Commit(key, rec); err != nil {
		t.Fatal(err)
	}
	got, err := store.Load(key)
	if err != nil || !reflect.DeepEqual(got, rec) {
		t.Fatalf("round trip: %v", err)
	}
	encoded, err := ap.EncodeR1(rec)
	if err != nil {
		t.Fatal(err)
	}
	entries, err = store.List()
	if err != nil || !reflect.DeepEqual(entries, []lifecycle.StoreEntry{{Key: key, EncodedSize: int64(len(encoded))}}) {
		t.Fatalf("list: %+v %v", entries, err)
	}
	entries[0].Key = "changed"
	again, _ := store.List()
	if again[0].Key != key {
		t.Fatal("List aliases store")
	}
	rec.Header.RationaleRedacted = "replacement"
	if err := store.Commit(key, rec); err != nil {
		t.Fatal(err)
	}
	got, _ = store.Load(key)
	if got.Header.RationaleRedacted != "replacement" {
		t.Fatal("replacement missing")
	}
	if err := store.Remove(key); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Load(key); !errors.Is(err, lifecycle.ErrNotFound) {
		t.Fatal(err)
	}
	entries, _ = store.List()
	if len(entries) != 0 {
		t.Fatal("removed entry remains listed")
	}
}

func TestMemStoreIsolation(t *testing.T) {
	var store lifecycle.MemStore
	key, rec := record(t, 1)
	original, _ := ap.EncodeR1(rec)
	if err := store.Commit(key, rec); err != nil {
		t.Fatal(err)
	}
	mutate := func(r *ap.R1) {
		r.Header.Outbox[0].Kind = "changed"
		r.Payload.Plan.StandingGrant.Commands[0] = "changed"
		r.Payload.ReviewSnapshot[0] = '!'
	}
	mutate(&rec)
	got, err := store.Load(key)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := ap.EncodeR1(got)
	if err != nil || !bytes.Equal(encoded, original) {
		t.Fatalf("Commit retained caller memory: %v", err)
	}
	mutate(&got)
	got, err = store.Load(key)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err = ap.EncodeR1(got)
	if err != nil || !bytes.Equal(encoded, original) {
		t.Fatalf("Load exposed store memory: %v", err)
	}
}

func TestMemStoreRejectsInvalidReplacement(t *testing.T) {
	key, rec := record(t, 1)
	for _, field := range []string{"version", "snapshot", "size", "key"} {
		t.Run(field, func(t *testing.T) {
			var store lifecycle.MemStore
			if err := store.Commit(key, rec); err != nil {
				t.Fatal(err)
			}
			bad, _ := store.Load(key)
			target := key
			switch field {
			case "version":
				bad.Header.Version++
			case "snapshot":
				bad.Payload.ReviewSnapshot = []byte(`null`)
			case "size":
				bad.Header.RationaleRedacted = strings.Repeat("x", ap.R1Max+1)
			case "key":
				target, _ = record(t, 2)
			}
			if err := store.Commit(target, bad); err == nil {
				t.Fatal("invalid commit accepted")
			}
			got, err := store.Load(key)
			if err != nil || !reflect.DeepEqual(got, rec) {
				t.Fatal("failed commit changed record")
			}
			entries, _ := store.List()
			if len(entries) != 1 {
				t.Fatal("failed commit created record")
			}
		})
	}
}

func TestMemStoreRejectsInvalidKeys(t *testing.T) {
	var store lifecycle.MemStore
	_, rec := record(t, 1)
	for _, key := range []string{"", "../record", "r-" + strings.Repeat("!", 52)} {
		if err := store.Commit(key, rec); err == nil {
			t.Fatal("commit accepted invalid key")
		}
		if _, err := store.Load(key); err == nil || errors.Is(err, lifecycle.ErrNotFound) {
			t.Fatal("load hid invalid key")
		}
		if err := store.Remove(key); err == nil {
			t.Fatal("remove accepted invalid key")
		}
	}
}

func TestMemStoreConcurrentSnapshots(t *testing.T) {
	var store lifecycle.MemStore
	var group sync.WaitGroup
	for i := 0; i < 16; i++ {
		key, rec := record(t, i)
		group.Add(1)
		go func() {
			defer group.Done()
			for j := 0; j < 20; j++ {
				if err := store.Commit(key, rec); err != nil {
					t.Error(err)
					return
				}
				got, err := store.Load(key)
				if err != nil || !reflect.DeepEqual(got, rec) {
					t.Errorf("torn record: %v", err)
					return
				}
				entries, err := store.List()
				if err != nil {
					t.Error(err)
					return
				}
				for k := 1; k < len(entries); k++ {
					if entries[k-1].Key >= entries[k].Key {
						t.Error("unsorted or duplicate list")
					}
				}
				if err := store.Remove(key); err != nil {
					t.Error(err)
					return
				}
			}
		}()
	}
	group.Wait()
}

func TestNoDirectTimeReads(t *testing.T) {
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	var sources []string
	for _, file := range files {
		if !strings.HasSuffix(file, "_test.go") {
			sources = append(sources, file)
		}
	}
	if len(sources) < 4 {
		t.Fatalf("expected at least four source files, got %d", len(sources))
	}
	elapsedtest.AssertNoDirectTimeReads(t, sources, "reconcile.go:newReconcileTicker", "flush.go:newClaimFlushTimer", "notify.go:newEditRetryTimer")
}
