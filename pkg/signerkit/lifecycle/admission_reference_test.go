package lifecycle

import (
	"cmp"
	"fmt"
	"maps"
	"math/rand"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	ap "github.com/karthikeyan5/sshgate/src/approvalplan"
	st "github.com/karthikeyan5/sshgate/src/approvalplan/statetest"
)

// Full-scan admission copied from 983b602~2, before A6P. Keep selection
// independent of the production heaps; Apply and commit semantics are shared.
func referenceAdmission(e *Engine, candidate ap.R1, now ap.Now) error {
	principal := candidate.Header.Principal
	if e.liveFull(principal) {
		// X5: the tick may not yet have committed a just-ended window.
		for _, key := range e.dueKeys(now) {
			rec, err := e.load(key)
			if err != nil {
				return err
			}
			if rec == nil {
				return keyError()
			}
			after, answer, err := e.commitLocked(key, rec, ap.Tick{}, now, ap.Inputs{})
			if err != nil {
				return err
			}
			if err := answerError(answer); err != nil {
				return err
			}
			e.projections.schedule(key, after, now, e.epoch, e.config.Settings)
		}
	}
	if e.liveFull(principal) {
		return &ap.CodeError{Code: ap.CodeQueueFull}
	}
	reservation := int64(ap.R1Reservation(candidate))
	caps := e.config.Caps
	payloadFull := func() bool {
		return e.projections.total.full >= caps.FullRecords || reservation > caps.PayloadBytes-e.projections.total.reserved
	}
	countFull := func() bool { return e.projections.total.records >= caps.RecordsTotal }
	if !payloadFull() && !countFull() {
		return nil
	}
	// Ages and pressure order use the committed decision, never creation time.
	type decidedRecord struct {
		key string
		at  time.Time
	}
	var candidates []decidedRecord
	for key := range e.projections.records {
		rec, err := e.load(key)
		if err != nil {
			return err
		}
		if rec == nil {
			return keyError()
		}
		if rec.Header.Decision != nil {
			candidates = append(candidates, decidedRecord{key, rec.Header.Decision.DecidedAt})
		}
	}
	slices.SortFunc(candidates, func(a, b decidedRecord) int {
		if order := a.at.Compare(b.at); order != 0 {
			return order
		}
		return strings.Compare(a.key, b.key)
	})
	for _, candidate := range candidates {
		if !payloadFull() && !countFull() {
			return nil
		}
		rec, err := e.load(candidate.key)
		if err != nil {
			return err
		}
		if rec == nil {
			return keyError()
		}
		if payloadFull() {
			after, answer, err := e.commitLocked(candidate.key, rec, ap.ShedRecord{Pressure: true}, now, ap.Inputs{})
			if err != nil {
				return err
			}
			if err := answerError(answer); err != nil {
				return err
			}
			rec = &after
		}
		if countFull() {
			_, answer, err := e.commitLocked(candidate.key, rec, ap.Delete{Pressure: true}, now, ap.Inputs{})
			if err != nil {
				return err
			}
			if err := answerError(answer); err != nil {
				return err
			}
		}
	}
	if payloadFull() || countFull() {
		return &ap.CodeError{Code: ap.CodeQueueFull}
	}
	return nil
}

type admissionMutation struct {
	Operation, Key string
	Bytes          []byte
}

type admissionTraceStore struct {
	MemStore
	mutations []admissionMutation
	fault     string
	landed    bool
}

func (s *admissionTraceStore) Commit(key string, record ap.R1) error {
	data, err := ap.EncodeR1(record)
	if err != nil {
		return err
	}
	s.mutations = append(s.mutations, admissionMutation{"shed", key, data})
	if s.fault == "shed" {
		return (&uncertainStore{Store: &s.MemStore, landed: s.landed}).Commit(key, record)
	}
	return s.MemStore.Commit(key, record)
}
func (s *admissionTraceStore) Remove(key string) error {
	s.mutations = append(s.mutations, admissionMutation{Operation: "delete", Key: key})
	if s.fault == "delete" {
		return (&uncertainStore{Store: &s.MemStore, landed: s.landed}).Remove(key)
	}
	return s.MemStore.Remove(key)
}

// Check both queue membership and the position/heap invariants against disk,
// rather than accepting two equally stale or malformed indexes as equivalent.
func checkAdmissionIndexes(t *testing.T, e *Engine, store *admissionTraceStore) {
	t.Helper()
	expected := newProjections()
	entries, err := store.List()
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		rec, err := store.Load(entry.Key)
		if err != nil {
			t.Fatal(err)
		}
		expected.update(entry.Key, nil, rec, e.now(), e.epoch, e.config.Settings)
	}
	if !reflect.DeepEqual(e.projections.records, expected.records) || e.projections.total != expected.total ||
		!reflect.DeepEqual(e.projections.principals, expected.principals) ||
		!reflect.DeepEqual(e.projections.unflushed, expected.unflushed) {
		t.Fatal("record projections/accounting differ from committed records")
	}
	for _, pair := range [][2]*reclamationQueue{
		{&e.projections.shedCandidates, &expected.shedCandidates},
		{&e.projections.deleteCandidates, &expected.deleteCandidates},
	} {
		got, want := pair[0], pair[1]
		if got.Len() != want.Len() || len(got.positions) != got.Len() {
			t.Fatal("candidate count mismatch")
		}
		for i, candidate := range got.candidates {
			position, ok := got.positions[candidate.key]
			expectedPosition, exists := want.positions[candidate.key]
			if !ok || position != i || !exists || candidate != want.candidates[expectedPosition] {
				t.Fatal("candidate membership/position mismatch", candidate)
			}
			if i > 0 && got.Less(i, (i-1)/2) {
				t.Fatal("invalid heap order")
			}
		}
	}
}

type admissionLimits struct {
	full, records, payloadSlots int
}

type admissionRecordSpec struct {
	age             time.Duration
	shed, protected bool
}

func TestAdmissionMatchesFullScanReference(t *testing.T) {
	run := func(t *testing.T, specs []admissionRecordSpec, limits admissionLimits, fault string, landed bool, want []admissionMutation) {
		t.Helper()
		fixture, clock, base, _ := engineFixture(t)
		t.Cleanup(func() { fixture.Close() })
		records := make([]ap.R1, len(specs))
		order := make([]int, len(specs))
		for i := range order {
			order[i] = i
		}
		slices.SortFunc(order, func(a, b int) int { return cmp.Compare(specs[b].age, specs[a].age) })
		var candidate ap.R1
		for _, i := range order {
			spec := specs[i]
			clock.Advance(st.T0.Add(48*time.Hour - spec.age).Sub(clock.Wall()))
			id := i + 10
			submitJob(t, fixture, id)
			var err error
			candidate, err = base.Load(ap.RecordKey(st.PrincipalA, st.ID(id)))
			if err != nil {
				t.Fatal(err)
			}
			command(t, fixture, id, ap.AssistDone{Unavailable: "test unavailable"})
			rec := command(t, fixture, id, ap.AdminCancel{PlanHash: candidate.Header.PlanHash, Admin: st.Admin})
			if !spec.protected {
				flushRecord(t, fixture, id)
				rec, err = base.Load(ap.RecordKey(st.PrincipalA, st.ID(id)))
				if err != nil {
					t.Fatal(err)
				}
			}
			if spec.shed {
				rec = ap.Shed(rec)
			}
			records[i] = rec
		}
		clock.Advance(st.T0.Add(48 * time.Hour).Sub(clock.Wall()))
		var engines [2]*Engine
		var stores [2]*admissionTraceStore
		for side := range engines {
			store := &admissionTraceStore{}
			for _, rec := range records {
				if err := store.MemStore.Commit(ap.RecordKey(st.PrincipalA, rec.Header.RequestID), rec); err != nil {
					t.Fatal(err)
				}
			}
			config := fixture.config
			config.Store = store
			config.Caps = Caps{FullRecords: limits.full, RecordsTotal: limits.records, PayloadBytes: int64(limits.payloadSlots) * int64(ap.R1Reservation(candidate))}
			engine, err := New(config)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { engine.Close() })
			store.mutations = nil
			store.fault, store.landed = fault, landed
			engines[side], stores[side] = engine, store
		}
		admit := func(side int) error {
			engine := engines[side]
			engine.mu.Lock()
			defer engine.mu.Unlock()
			if side == 0 {
				return referenceAdmission(engine, candidate, engine.now())
			}
			return engine.admitLocked(candidate, engine.now())
		}
		compare := func() {
			t.Helper()
			if !reflect.DeepEqual(stores[0].mutations, stores[1].mutations) {
				t.Fatal("victim order or mutation bytes differ")
			}
			if !reflect.DeepEqual(stores[0].records, stores[1].records) {
				t.Fatal("committed bytes differ")
			}
		}
		before := maps.Clone(stores[1].records)
		referenceErr, indexedErr := admit(0), admit(1)
		if fmt.Sprint(referenceErr) != fmt.Sprint(indexedErr) {
			t.Fatalf("outcomes differ: %v / %v", referenceErr, indexedErr)
		}
		compare()
		if want != nil {
			got := slices.Clone(stores[1].mutations)
			for i := range got {
				got[i].Bytes = nil
			}
			if !reflect.DeepEqual(got, want) {
				t.Fatalf("targeted victims: got %+v want %+v", got, want)
			}
		}
		if fault != "" {
			checkCode(t, indexedErr, ap.CodeStorageUncertain)
			if reflect.DeepEqual(before, stores[1].records) == landed {
				t.Fatal("fault did not preserve the requested landed/unlanded disk prefix")
			}
			for _, engine := range engines {
				checkCode(t, engine.Availability(), ap.CodeStorageUncertain)
			}
		} else {
			for side, engine := range engines {
				checkAdmissionIndexes(t, engine, stores[side])
			}
		}
		// Replace the generation even for successful/refused admissions. Startup
		// must derive the same charges and candidates from the landed disk prefix.
		for side, engine := range engines {
			engine.Close()
			config := engine.config
			stores[side].fault = ""
			stores[side].mutations = nil
			replacement, err := New(config)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { replacement.Close() })
			if replacement.epoch == engine.epoch {
				t.Fatal("Startup reused epoch")
			}
			engines[side] = replacement
			checkAdmissionIndexes(t, replacement, stores[side])
		}
		compare()
		referenceErr, indexedErr = admit(0), admit(1)
		if fmt.Sprint(referenceErr) != fmt.Sprint(indexedErr) {
			t.Fatalf("post-Startup outcomes differ: %v / %v", referenceErr, indexedErr)
		}
		compare()
		for side, engine := range engines {
			checkAdmissionIndexes(t, engine, stores[side])
		}
	}
	key := func(i int) string { return ap.RecordKey(st.PrincipalA, st.ID(i+10)) }
	t.Run("count-clears-before-payload", func(t *testing.T) {
		run(t, []admissionRecordSpec{{48 * time.Hour, true, false}, {47 * time.Hour, true, false}, {46 * time.Hour, false, false}, {45 * time.Hour, false, false}},
			admissionLimits{records: 4, full: 1}, "", false,
			[]admissionMutation{{Operation: "delete", Key: key(0)}, {Operation: "shed", Key: key(2)}, {Operation: "shed", Key: key(3)}})
	})
	t.Run("multiple-protected", func(t *testing.T) {
		run(t, []admissionRecordSpec{{48 * time.Hour, false, true}, {47 * time.Hour, false, true}, {46 * time.Hour, false, false}},
			admissionLimits{full: 3}, "", false, []admissionMutation{{Operation: "shed", Key: key(2)}})
	})
	for _, fault := range []string{"shed", "delete"} {
		for _, landed := range []bool{false, true} {
			t.Run(fmt.Sprintf("uncertain-%s/landed=%t", fault, landed), func(t *testing.T) {
				specs := []admissionRecordSpec{{48 * time.Hour, false, false}, {47 * time.Hour, false, false}}
				limits := admissionLimits{full: 2}
				if fault == "delete" {
					specs[0].shed = true
					limits = admissionLimits{records: 2}
				}
				run(t, specs, limits, fault, landed, []admissionMutation{{Operation: fault, Key: key(0)}})
			})
		}
	}
	for seed := int64(0); seed < 100; seed++ {
		t.Run(fmt.Sprintf("random-%d", seed), func(t *testing.T) {
			random := rand.New(rand.NewSource(seed))
			specs := make([]admissionRecordSpec, 1+random.Intn(24))
			for i := range specs {
				specs[i] = admissionRecordSpec{age: time.Duration(random.Intn(49)) * time.Hour, protected: random.Intn(3) == 0}
				specs[i].shed = !specs[i].protected && random.Intn(3) == 0
			}
			limits := admissionLimits{records: 1 + random.Intn(len(specs)+1), full: 1 + random.Intn(len(specs)+1),
				payloadSlots: 1 + random.Intn(len(specs)+1)}
			run(t, specs, limits, "", false, nil)
		})
	}
}
