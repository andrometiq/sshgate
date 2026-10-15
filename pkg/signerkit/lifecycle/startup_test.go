package lifecycle

import (
	"errors"
	"reflect"
	"testing"
	"time"

	ap "github.com/karthikeyan5/sshgate/src/approvalplan"
	st "github.com/karthikeyan5/sshgate/src/approvalplan/statetest"
)

func TestStartupRebuildsProjectionsAndEpoch(t *testing.T) {
	e, _, store, _ := engineFixture(t)
	submitJob(t, e, 1)
	readyCard(t, e, 1, true)
	submitGrant(t, e, 2, st.PrincipalA)
	approve(t, e, 2)
	sum := submitJob(t, e, 3)
	command(t, e, 3, ap.AdminCancel{PlanHash: sum.PlanHash, Admin: st.Admin})
	flushRecord(t, e, 3)
	command(t, e, 3, ap.ShedRecord{Pressure: true})
	old := e.projections
	restarted, err := New(e.config)
	if err != nil {
		t.Fatal(err)
	}
	if restarted.epoch == e.epoch || len(restarted.projections.grants) != 0 || len(restarted.projections.newest) != 0 {
		t.Fatal("restart retained grant authority")
	}
	got := restarted.projections
	if !reflect.DeepEqual(got.cards, old.cards) || !reflect.DeepEqual(got.handles, old.handles) || !reflect.DeepEqual(got.requestIDs, old.requestIDs) || !reflect.DeepEqual(got.unflushed, old.unflushed) || !reflect.DeepEqual(got.due, old.due) {
		t.Fatal("indexes not rebuilt")
	}
	if got.total.records != old.total.records || got.total.full != old.total.full || got.total.reserved != old.total.reserved || got.total.live != old.total.live-1 {
		t.Fatal("counters not rebuilt")
	}
	if got.principals[st.PrincipalA] != got.total {
		t.Fatal("principal counters not rebuilt")
	}
	for key := range got.records {
		rec, _ := store.Load(key)
		want := ap.Next(rec, restarted.now(), restarted.epoch, restarted.config.Settings, false)
		if !reflect.DeepEqual(got.work[key], want) {
			t.Fatal("startup did not run Next")
		}
	}
}

func TestStartupClockAndNotificationRecovery(t *testing.T) {
	e, clock, store, _ := engineFixture(t)
	submitJob(t, e, 1)
	submitJob(t, e, 2)
	command(t, e, 2, ap.BurstStart{})
	clock.Advance(5 * time.Second)
	restarted, err := New(e.config)
	if err != nil {
		t.Fatal(err)
	}
	for id := 1; id <= 2; id++ {
		key := ap.RecordKey(st.PrincipalA, st.ID(id))
		rec, _ := store.Load(key)
		if rec.Header.Assist == nil {
			t.Fatal("startup skipped Clock")
		}
		kind := restarted.projections.work[key].Notify.Kind
		if id == 1 && kind != ap.NotifyBurst || id == 2 && kind != ap.NotifyNone {
			t.Fatal("recovery would duplicate uncertain burst or omit unsent burst")
		}
	}
	clock.Advance(2 * time.Hour)
	store.fail = true
	if recovered, err := New(e.config); err == nil || recovered != nil {
		t.Fatal("startup served despite failed Clock commit")
	}
	store.fail = false
	restarted, err = New(e.config)
	if err != nil {
		t.Fatal(err)
	}
	got, err := restarted.Get(st.PrincipalA, st.ID(1))
	if err != nil || got.ApprovalStatus != ap.ApprovalExpired {
		t.Fatal("restart expiry missing")
	}
}

type startupStore struct {
	Store
	entries          []StoreEntry
	listErr, loadErr error
}

func (s startupStore) List() ([]StoreEntry, error) { return s.entries, s.listErr }
func (s startupStore) Load(key string) (ap.R1, error) {
	if s.loadErr != nil {
		return ap.R1{}, s.loadErr
	}
	return s.Store.Load(key)
}
func TestStartupQuarantineAndFailures(t *testing.T) {
	e, _, store, _ := engineFixture(t)
	submitJob(t, e, 1)
	entries, _ := store.List()
	quarantined := StoreEntry{Key: ap.RecordKey(st.PrincipalA, st.ID(2)), EncodedSize: 1234, Quarantined: true}
	config := e.config
	config.Store = startupStore{Store: store, entries: append(entries, quarantined)}
	recovered, err := New(config)
	if err != nil {
		t.Fatal(err)
	}
	if recovered.projections.total.reserved != e.projections.total.reserved+1234 || recovered.projections.total.records != 2 || recovered.projections.total.full != 2 || recovered.projections.total.live != 2 || len(recovered.projections.quarantined) != 1 || len(recovered.projections.handles) != 1 {
		t.Fatal("quarantine budget or isolation lost")
	}
	for _, bad := range []startupStore{
		{Store: store, listErr: errors.New("list failed")},
		{Store: store, entries: entries, loadErr: errors.New("load failed")},
		{Store: store, entries: []StoreEntry{{Key: quarantined.Key}}},
		{Store: store, entries: append(entries, entries[0])},
	} {
		config.Store = bad
		if recovered, err := New(config); err == nil || recovered != nil {
			t.Fatal("startup hid incomplete store")
		}
	}
}
