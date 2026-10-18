package lifecycle

import (
	"errors"
	"fmt"
	"testing"
	"time"

	ap "github.com/karthikeyan5/sshgate/src/approvalplan"
	st "github.com/karthikeyan5/sshgate/src/approvalplan/statetest"
)

type admissionCountingStore struct {
	Store
	loads, lists int
}

func (s *admissionCountingStore) Load(key string) (ap.R1, error) {
	s.loads++
	return s.Store.Load(key)
}
func (s *admissionCountingStore) List() ([]StoreEntry, error) {
	s.lists++
	return s.Store.List()
}

func TestPayloadPressureStoreWorkIndependentOfShedHistory(t *testing.T) {
	for _, history := range []int{0, 8192} {
		for _, pressure := range []string{"full", "bytes"} {
			t.Run(fmt.Sprintf("%s/history=%d", pressure, history), func(t *testing.T) {
				e, _, store, _ := engineFixture(t)
				submitJob(t, e, 1)
				cancelAdmissionRecord(t, e, 1)
				full, err := store.Load(ap.RecordKey(st.PrincipalA, st.ID(1)))
				if err != nil {
					t.Fatal(err)
				}
				// Seed older, already-shed history through the real store codec.
				// Startup must rebuild the pressure indexes from these records.
				for id := 2; id <= history+1; id++ {
					rec := ap.Shed(full)
					rec.Header.RequestID = st.ID(id)
					decision := *rec.Header.Decision
					decision.DecidedAt = decision.DecidedAt.Add(-time.Second)
					rec.Header.Decision = &decision
					if err := store.Commit(ap.RecordKey(st.PrincipalA, st.ID(id)), rec); err != nil {
						t.Fatal(err)
					}
				}
				counted := &admissionCountingStore{Store: store}
				config := e.config
				config.Store = counted
				if pressure == "full" {
					config.Caps.FullRecords = 1
				} else {
					config.Caps.PayloadBytes = int64(ap.R1Reservation(full))
				}
				recovered, err := New(config)
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { recovered.Close() })
				for id := history + 2; id < history+6; id++ {
					counted.loads, counted.lists = 0, 0
					submitJob(t, recovered, id)
					if counted.loads != 2 || counted.lists != 0 {
						t.Fatalf("pressured Submit: Load=%d List=%d; want 2 and 0", counted.loads, counted.lists)
					}
					if recovered.projections.total.full != 1 {
						t.Fatal("payload pressure did not reclaim one full record")
					}
					cancelAdmissionRecord(t, recovered, id)
				}
			})
		}
	}
}

func TestAdmissionReclamationIndexRestoresSkippedAndFailedCandidates(t *testing.T) {
	e, _, store, _ := engineFixture(t)
	e.config.Caps.FullRecords = 1
	sum := submitJob(t, e, 1)
	command(t, e, 1, ap.AssistDone{Unavailable: "test unavailable"})
	command(t, e, 1, ap.AdminCancel{PlanHash: sum.PlanHash, Admin: st.Admin})
	for range 2 {
		_, err := admissionSubmit(e, 2, st.PrincipalA)
		checkCode(t, err, ap.CodeQueueFull)
	}
	flushRecord(t, e, 1)
	store.fail = true
	if _, err := admissionSubmit(e, 2, st.PrincipalA); err == nil {
		t.Fatal("failed Shed admitted request")
	}
	store.fail = false
	submitJob(t, e, 2)
	rec, err := store.Load(ap.RecordKey(st.PrincipalA, st.ID(1)))
	if err != nil || rec.Payload != nil {
		t.Fatal("candidate lost after refusal or failed commit", err)
	}
}

func TestAdmissionReclamationDecisionTieAndCountPressure(t *testing.T) {
	e, clock, store, _ := engineFixture(t)
	e.config.Caps.FullRecords = 2
	e.config.Caps.RecordsTotal = 2
	for _, id := range []int{2, 1} {
		submitJob(t, e, id)
		cancelAdmissionRecord(t, e, id)
	}
	first, second := 1, 2
	if ap.RecordKey(st.PrincipalA, st.ID(second)) < ap.RecordKey(st.PrincipalA, st.ID(first)) {
		first, second = second, first
	}
	// Both pressures hold. The replay floor refuses deletion, but shedding
	// must still reclaim the first key among equal decision timestamps.
	_, err := admissionSubmit(e, 3, st.PrincipalA)
	checkCode(t, err, ap.CodeQueueFull)
	old, _ := store.Load(ap.RecordKey(st.PrincipalA, st.ID(first)))
	other, _ := store.Load(ap.RecordKey(st.PrincipalA, st.ID(second)))
	if old.Payload != nil || other.Payload == nil {
		t.Fatal("decision tie did not use record key order")
	}
	clock.Advance(25 * time.Hour)
	submitJob(t, e, 3)
	if _, err := store.Load(ap.RecordKey(st.PrincipalA, st.ID(first))); !errors.Is(err, ErrNotFound) {
		t.Fatal("count pressure did not delete oldest shed record", err)
	}
	if _, ok := e.projections.deleteCandidates.positions[ap.RecordKey(st.PrincipalA, st.ID(first))]; ok {
		t.Fatal("removed record remains a reclamation candidate")
	}
}
