package assist

import (
	"context"
	"time"

	"github.com/karthikeyan5/sshgate/src/approvalplan"
)

// Assessor must honor cancellation: Run and Pool.Close join every provider call.
// Run stamps InputDigest and validates the result, so an Assessor need not.
type Assessor interface {
	Assess(context.Context, Input) (approvalplan.AssistResult, error)
}

type Timers struct {
	After func(time.Duration) <-chan time.Time
	Now   func() time.Time
}

func (t Timers) defaults() Timers {
	if t.After == nil {
		t.After = time.After
	}
	if t.Now == nil {
		t.Now = time.Now
	}
	return t
}

type Snapshot struct {
	State  approvalplan.AssistState
	Result *approvalplan.AssistResult
	Reason string
}

func unavailable(reason string) Snapshot {
	return Snapshot{State: approvalplan.AssistUnavailable, Reason: reason}
}

// Run uses the freeze-time absolute deadline, cancels and joins on every path,
// and drops late results even when completion and the timer race.
func Run(ctx context.Context, a Assessor, in Input, deadline time.Time, t Timers) Snapshot {
	t = t.defaults()
	if !t.Now().Before(deadline) {
		return unavailable(ReasonDeadline)
	}
	if ctx.Err() != nil {
		return unavailable(ReasonCanceled)
	}
	if a == nil {
		return unavailable(ReasonFailed)
	}
	in = in.clone()
	providerCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	completed := make(chan Snapshot, 1)
	go func() {
		snapshot := unavailable(ReasonFailed)
		defer func() {
			if recover() != nil {
				snapshot = unavailable(ReasonFailed)
			}
			completed <- snapshot
		}()
		result, err := a.Assess(providerCtx, in)
		if err == nil {
			snapshot = accept(result, in)
		}
	}()
	select {
	case snapshot := <-completed:
		if !t.Now().Before(deadline) {
			return unavailable(ReasonDeadline)
		}
		if ctx.Err() != nil {
			return unavailable(ReasonCanceled)
		}
		return snapshot
	case <-t.After(deadline.Sub(t.Now())):
		cancel()
		<-completed
		return unavailable(ReasonDeadline)
	case <-ctx.Done():
		cancel()
		<-completed
		return unavailable(ReasonCanceled)
	}
}

// accept binds result to in and applies the content contract: one effect per
// command (K5), and not_assessed only as the forced legacy alignment (E36).
func accept(result approvalplan.AssistResult, in Input) Snapshot {
	if result.Alignment == approvalplan.AlignmentNotAssessed || len(result.Effects) != len(in.Commands) {
		return unavailable(ReasonFailed)
	}
	if in.legacy {
		result.Alignment = approvalplan.AlignmentNotAssessed
	}
	result.InputDigest = in.Digest()
	if approvalplan.ValidateAssist(result) != nil {
		return unavailable(ReasonFailed)
	}
	return Snapshot{State: approvalplan.AssistReady, Result: &result}
}
