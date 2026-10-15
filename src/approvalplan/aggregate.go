package approvalplan

// AggregateJobClass is E29's job class over a job's full step list: the abort
// step's status if there is one (a well-formed list has at most one, the last
// step attempted), otherwise failed if any step failed, otherwise succeeded.
// Uncertainty and unexecuted approved work therefore win over an earlier known
// failure. Every coordinator and the signer's report check use it.
func AggregateJobClass(steps []StepStatus) JobClass {
	failed := false
	for _, s := range steps {
		if s.Abort() {
			return JobClass(s)
		}
		failed = failed || s == StepFailed
	}
	if failed {
		return ClassFailed
	}
	return ClassSucceeded
}

// ExecutedOrdinals returns the 1-based ordinals of the steps that ran or may
// have run, ascending. It is never nil, so an empty set encodes as [].
func ExecutedOrdinals(steps []StepStatus) []int {
	out := []int{}
	for i, s := range steps {
		if s.Executed() {
			out = append(out, i+1)
		}
	}
	return out
}

// Partial reports whether some step executed and some step did not (E29).
func Partial(steps []StepStatus) bool {
	executed, notExecuted := false, false
	for _, s := range steps {
		if s.Executed() {
			executed = true
		} else {
			notExecuted = true
		}
	}
	return executed && notExecuted
}
