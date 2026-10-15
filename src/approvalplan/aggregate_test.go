package approvalplan

import (
	"math/rand/v2"
	"slices"
	"testing"
)

var allStatuses = []StepStatus{
	StepSucceeded, StepFailed, StepSkipped, StepNotRun,
	StepFailedNotStarted, StepExpiredUnexecuted, StepStaleTarget, StepIndeterminate,
}

func TestStatusPartition(t *testing.T) {
	executed := map[StepStatus]bool{StepSucceeded: true, StepFailed: true, StepIndeterminate: true}
	for _, s := range allStatuses {
		if !s.Valid() {
			t.Errorf("%s is not valid", s)
		}
		if s.Executed() != executed[s] {
			t.Errorf("%s: Executed() = %v", s, s.Executed())
		}
	}
	if StepStatus("ok").Valid() || StepStatus("").Executed() {
		t.Error("an unknown status is valid or executed")
	}
}

func TestAggregateJobClassAndPartial(t *testing.T) {
	S, F, K, N := StepSucceeded, StepFailed, StepSkipped, StepNotRun
	FNS, EU, ST, IND := StepFailedNotStarted, StepExpiredUnexecuted, StepStaleTarget, StepIndeterminate
	cases := []struct {
		steps    []StepStatus
		class    JobClass
		executed []int
		partial  bool
	}{
		{[]StepStatus{F, IND}, ClassIndeterminate, []int{1, 2}, false},
		{[]StepStatus{F, IND, N}, ClassIndeterminate, []int{1, 2}, true},
		{[]StepStatus{IND}, ClassIndeterminate, []int{1}, false},
		{[]StepStatus{F, EU, N}, ClassExpiredUnexecuted, []int{1}, true},
		{[]StepStatus{F, S}, ClassFailed, []int{1, 2}, false},
		{[]StepStatus{S, FNS, N}, ClassFailedNotStarted, []int{1}, true},
		{[]StepStatus{S, S}, ClassSucceeded, []int{1, 2}, false},
		{[]StepStatus{F, K, K}, ClassFailed, []int{1}, true},
		{[]StepStatus{FNS, N}, ClassFailedNotStarted, []int{}, false},
		{[]StepStatus{EU}, ClassExpiredUnexecuted, []int{}, false},
		{[]StepStatus{S, ST, N}, ClassStaleTarget, []int{1}, true},
		{[]StepStatus{S, N}, ClassSucceeded, []int{1}, true},
		{[]StepStatus{N, N}, ClassSucceeded, []int{}, false},
		{[]StepStatus{S, F, S, IND, N, N}, ClassIndeterminate, []int{1, 2, 3, 4}, true},
	}
	for _, c := range cases {
		if got := AggregateJobClass(c.steps); got != c.class {
			t.Errorf("AggregateJobClass(%v) = %s, want %s", c.steps, got, c.class)
		}
		if got := ExecutedOrdinals(c.steps); !slices.Equal(got, c.executed) || got == nil {
			t.Errorf("ExecutedOrdinals(%v) = %v, want %v", c.steps, got, c.executed)
		}
		if got := Partial(c.steps); got != c.partial {
			t.Errorf("Partial(%v) = %v, want %v", c.steps, got, c.partial)
		}
	}
	if b := mustCanon(t, ExecutedOrdinals(nil)); string(b) != "[]" {
		t.Errorf("no executed steps encode as %s, want []", b)
	}
}

func TestAggregateProperties(t *testing.T) {
	rng := rand.New(rand.NewPCG(1, 2))
	for range 20000 {
		steps := make([]StepStatus, 1+rng.IntN(MaxSteps))
		for i := range steps {
			steps[i] = allStatuses[rng.IntN(len(allStatuses))]
		}
		executed := ExecutedOrdinals(steps)
		if !slices.IsSorted(executed) {
			t.Fatalf("%v: ordinals %v not ascending", steps, executed)
		}
		for _, o := range executed {
			if !steps[o-1].Executed() {
				t.Fatalf("%v: ordinal %d is not an executed status", steps, o)
			}
		}
		if want := len(executed) > 0 && len(executed) < len(steps); Partial(steps) != want {
			t.Fatalf("%v: Partial = %v, want %v", steps, Partial(steps), want)
		}
		class := AggregateJobClass(steps)
		if !class.Valid() {
			t.Fatalf("%v: class %q", steps, class)
		}
		firstAbort := slices.IndexFunc(steps, StepStatus.Abort)
		switch {
		case firstAbort >= 0 && class != JobClass(steps[firstAbort]):
			t.Fatalf("%v: class %s, want the abort status", steps, class)
		case firstAbort < 0 && slices.Contains(steps, StepFailed) && class != ClassFailed:
			t.Fatalf("%v: class %s, want failed", steps, class)
		}
	}
}
