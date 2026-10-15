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

// WellFormedSteps reports whether a full step list has E29's shape (E25): a
// prefix of succeeded and failed steps, then either one abort status followed
// only by not_run, or, when the prefix ends in failed, only skipped steps.
// Every report and stored final report has this shape.
func WellFormedSteps(steps []StepStatus) bool {
	i := 0
	for i < len(steps) && (steps[i] == StepSucceeded || steps[i] == StepFailed) {
		i++
	}
	if i == len(steps) {
		return true
	}
	var tail StepStatus
	switch {
	case steps[i].Abort():
		tail, i = StepNotRun, i+1
	case steps[i] == StepSkipped && i > 0 && steps[i-1] == StepFailed:
		tail = StepSkipped
	default:
		return false
	}
	for ; i < len(steps); i++ {
		if steps[i] != tail {
			return false
		}
	}
	return true
}
