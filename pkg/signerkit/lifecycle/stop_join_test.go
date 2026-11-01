package lifecycle

import (
	"reflect"
	"testing"
	"testing/synctest"
	"time"

	ap "github.com/karthikeyan5/sshgate/src/approvalplan"
	st "github.com/karthikeyan5/sshgate/src/approvalplan/statetest"
)

// The owner stop joins a notify actor even when its transport call ignores
// cancellation: Close returns only after the call does, and nothing commits
// after the latch, so a restart sees the same uncertain burst.
func TestNotifyOwnerStopJoinsBlockedActor(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		e, _, store, _ := engineFixture(t)
		submitJob(t, e, 1)
		command(t, e, 1, ap.AssistDone{Unavailable: "test"})
		entered, release := make(chan struct{}), make(chan struct{})
		n := &testNotifier{parts: func(Notification) ([]int64, error) {
			close(entered)
			<-release // a transport that never sees the stop
			return []int64{1}, nil
		}}
		runNotifier(t, e, n)
		<-entered
		key := ap.RecordKey(st.PrincipalA, st.ID(1))
		latched, err := store.Load(key)
		if err != nil {
			t.Fatal(err)
		}
		start := time.Now()
		time.AfterFunc(2*time.Second, func() { close(release) })
		if err := e.Close(); err != nil {
			t.Fatal(err)
		}
		if took := time.Since(start); took < 2*time.Second {
			t.Fatalf("Close returned after %v, before the blocked call", took)
		}
		after, err := store.Load(key)
		if err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(after, latched) {
			t.Fatal("a commit followed the stop latch")
		}
		recovered, err := New(e.config)
		if err != nil {
			t.Fatal(err)
		}
		defer recovered.Close()
		if sum := recovered.view(key, after, recovered.now()); sum.NotificationStatus != ap.NotificationUncertain {
			t.Fatalf("after restart: %s", sum.NotificationStatus)
		}
	})
}
