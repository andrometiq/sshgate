package lifecycletest

import (
	"context"
	"sync"
	"testing"

	lc "github.com/karthikeyan5/sshgate/pkg/signerkit/lifecycle"
	ap "github.com/karthikeyan5/sshgate/src/approvalplan"
)

// RecoveryTrace exposes the same crash cuts used by the store conformance suite.
func RecoveryTrace(t *testing.T) []ap.R1 { return recoveryTrace(t) }

// Notifier reuses the suite's recording transport for supervisor tests.
type Notifier struct{ notifier }

func NewNotifier(hook func(context.Context, string) error) *Notifier {
	return &Notifier{notifier: notifier{hook: hook}}
}
func (n *Notifier) Count(kind string) int { return n.count(kind) }

// These adapters share the conformance suite's effect implementations.
type AssessorFunc = assessorFunc
type AssistBuilder = assistBuilder
type AuditFunc = auditFunc
type MintFunc = mintFunc

// FaultStore injects one uncertain acknowledgement, with or without durability.
// It deliberately remains usable afterwards: the owner must latch its own stop.
type FaultStore struct {
	lc.Store
	mu            sync.Mutex
	armed, landed bool
	writes        int
}

func (s *FaultStore) Arm(landed bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.armed, s.landed = true, landed
}
func (s *FaultStore) Writes() int { s.mu.Lock(); defer s.mu.Unlock(); return s.writes }
func (s *FaultStore) write(fn func() error) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.writes++
	if !s.armed {
		return fn()
	}
	s.armed = false
	if s.landed {
		if err := fn(); err != nil {
			return err
		}
	}
	return &ap.CodeError{Code: ap.CodeStorageUncertain}
}
func (s *FaultStore) Commit(key string, rec ap.R1) error {
	return s.write(func() error { return s.Store.Commit(key, rec) })
}
func (s *FaultStore) Remove(key string) error {
	return s.write(func() error { return s.Store.Remove(key) })
}
