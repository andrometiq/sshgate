package lifecycletest

import (
	"context"
	"errors"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	ap "github.com/karthikeyan5/sshgate/src/approvalplan"
	st "github.com/karthikeyan5/sshgate/src/approvalplan/statetest"
)

func flushRecovery(t *testing.T, factory StoreFactory) {
	const records = 300
	f := newFixture(t, factory)
	for id := 1; id <= records; id++ {
		d := st.JobDraft(st.ID(id), ap.CoordinatorExecutor, st.T0, st.Write("true", 60))
		cmd := st.SubmitOf(d, st.PrincipalA, st.T0, time.Hour)
		cmd.AssistDeadline = st.T0.Add(time.Duration(records+1-id) * time.Millisecond)
		rec, answer := ap.Apply(nil, cmd, ap.Now{Wall: st.T0}, ap.Inputs{Epoch: st.Epoch(1), Settings: ap.LocalSettings})
		if answer.Code != "" {
			t.Fatalf("seed: %+v", answer)
		}
		if err := f.store.Commit(ap.RecordKey(st.PrincipalA, d.RequestID), rec); err != nil {
			t.Fatal(err)
		}
	}
	var mu sync.Mutex
	var writes []string
	failed := false
	f.config.AuditWriter = auditFunc(func(_ context.Context, event ap.AuditMetadata) error {
		mu.Lock()
		defer mu.Unlock()
		if !failed {
			failed = true
			return errors.New("sink unavailable")
		}
		writes = append(writes, event.RequestID)
		return nil
	})
	f.open()
	f.run()
	// The injected clock stays fixed so no record becomes due. The synctest
	// clock drives only the runner's timers, waiting for each pass to finish.
	synctest.Wait() // Startup's first sink write fails.
	for flushed := 0; flushed < records; flushed += ap.FlushBatch {
		time.Sleep(time.Second)
		synctest.Wait()
	}
	entries, err := f.store.List()
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		rec, err := f.store.Load(entry.Key)
		if err != nil {
			t.Fatal(err)
		}
		if ap.Unflushed(rec) {
			t.Fatalf("record %s remains unflushed", entry.Key)
		}
	}
	mu.Lock()
	defer mu.Unlock()
	if len(writes) != records {
		t.Fatalf("sink writes=%d, want %d", len(writes), records)
	}
	for i, id := range writes {
		if id != st.ID(records-i) {
			t.Fatalf("flush order %d: %s", i, id)
		}
	}
}
