package lifecycletest

import (
	"context"
	lc "github.com/karthikeyan5/sshgate/pkg/signerkit/lifecycle"
	"sync"
)

type notifier struct {
	mu    sync.Mutex
	calls map[string]int
	card  lc.Notification
	hook  func(context.Context, string) error
}

func (n *notifier) call(ctx context.Context, kind string) error {
	n.mu.Lock()
	if n.calls == nil {
		n.calls = map[string]int{}
	}
	n.calls[kind]++
	n.mu.Unlock()
	if n.hook != nil {
		return n.hook(ctx, kind)
	}
	return nil
}
func (n *notifier) count(kind string) int                                           { n.mu.Lock(); defer n.mu.Unlock(); return n.calls[kind] }
func (n *notifier) latest() lc.Notification                                         { n.mu.Lock(); defer n.mu.Unlock(); return n.card }
func (n *notifier) Burst(ctx context.Context, fn func(lc.BurstSession) error) error { return fn(n) }
func (n *notifier) SendParts(ctx context.Context, _ lc.Notification) ([]int64, error) {
	return []int64{1, 2, 3}, n.call(ctx, "parts")
}
func (n *notifier) SendCard(ctx context.Context, card lc.Notification) (int64, error) {
	n.mu.Lock()
	n.card = card
	n.mu.Unlock()
	return 4, n.call(ctx, "card")
}
func (n *notifier) EditCard(ctx context.Context, _ int64, card lc.Notification) (lc.EditOutcome, error) {
	n.mu.Lock()
	n.card = card
	n.mu.Unlock()
	if err := n.call(ctx, "edit"); err != nil {
		return lc.EditPossible, err
	}
	return lc.EditConfirmed, nil
}
func (n *notifier) EditStatus(ctx context.Context, _ int64, _ lc.StatusDisplay) error {
	return n.call(ctx, "status")
}
func (n *notifier) MarkIncomplete(ctx context.Context, _ int64) error {
	return n.call(ctx, "incomplete")
}
