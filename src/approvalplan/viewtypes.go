package approvalplan

import "time"

// ApprovalStatus is the approval view (SA-6.1): the decision slot, or pending.
type ApprovalStatus string

const (
	ApprovalPending  ApprovalStatus = "pending"
	ApprovalApproved ApprovalStatus = "approved"
	ApprovalDenied   ApprovalStatus = "denied"
	ApprovalCanceled ApprovalStatus = "canceled"
	ApprovalExpired  ApprovalStatus = "expired"
	ApprovalError    ApprovalStatus = "error"
)

// Valid reports whether s is one of the six statuses.
func (s ApprovalStatus) Valid() bool {
	switch s {
	case ApprovalPending, ApprovalApproved, ApprovalDenied, ApprovalCanceled, ApprovalExpired, ApprovalError:
		return true
	}
	return false
}

// ExecutionStatus is the execution view (SA-6.2).
type ExecutionStatus string

const (
	ExecutionNotApplicable    ExecutionStatus = "not_applicable"
	ExecutionNone             ExecutionStatus = "none"
	ExecutionNotExecutable    ExecutionStatus = "not_executable"
	ExecutionExpiredUnclaimed ExecutionStatus = "expired_unclaimed"
	ExecutionExecuting        ExecutionStatus = "executing"
	ExecutionUnreported       ExecutionStatus = "unreported"
	ExecutionFinal            ExecutionStatus = "final"
)

// Valid reports whether s is one of the execution statuses.
func (s ExecutionStatus) Valid() bool {
	switch s {
	case ExecutionNotApplicable, ExecutionNone, ExecutionNotExecutable, ExecutionExpiredUnclaimed,
		ExecutionExecuting, ExecutionUnreported, ExecutionFinal:
		return true
	}
	return false
}

// NotificationStatus is the notification view (SA-6.3).
type NotificationStatus string

const (
	NotificationNotApplicable NotificationStatus = "not_applicable"
	NotificationNotStarted    NotificationStatus = "not_started"
	NotificationSending       NotificationStatus = "sending"
	NotificationSent          NotificationStatus = "sent"
	NotificationUncertain     NotificationStatus = "uncertain"
	NotificationError         NotificationStatus = "error"
)

// Valid reports whether s is one of the notification statuses.
func (s NotificationStatus) Valid() bool {
	switch s {
	case NotificationNotApplicable, NotificationNotStarted, NotificationSending, NotificationSent,
		NotificationUncertain, NotificationError:
		return true
	}
	return false
}

// AssistState is the assist view (SA-6.1) and the state an assist binding
// records. not_applicable is a grant decision's binding (E23).
type AssistState string

const (
	AssistPreparing     AssistState = "preparing"
	AssistReady         AssistState = "ready"
	AssistUnavailable   AssistState = "unavailable"
	AssistNotApplicable AssistState = "not_applicable"
)

// Valid reports whether s is one of the assist states.
func (s AssistState) Valid() bool {
	switch s {
	case AssistPreparing, AssistReady, AssistUnavailable, AssistNotApplicable:
		return true
	}
	return false
}

// StepStatus is one step's execution status (E29).
type StepStatus string

const (
	StepSucceeded         StepStatus = "succeeded"
	StepFailed            StepStatus = "failed"
	StepSkipped           StepStatus = "skipped"
	StepNotRun            StepStatus = "not_run"
	StepFailedNotStarted  StepStatus = "failed_not_started"
	StepExpiredUnexecuted StepStatus = "expired_unexecuted"
	StepStaleTarget       StepStatus = "stale_target"
	StepIndeterminate     StepStatus = "indeterminate"
)

// Valid reports whether s is one of the eight step statuses.
func (s StepStatus) Valid() bool {
	switch s {
	case StepSucceeded, StepFailed, StepSkipped, StepNotRun:
		return true
	}
	return s.Abort()
}

// Abort reports whether s ends a run: every later step is not_run (E29).
func (s StepStatus) Abort() bool {
	switch s {
	case StepFailedNotStarted, StepExpiredUnexecuted, StepStaleTarget, StepIndeterminate:
		return true
	}
	return false
}

// Executed reports whether a step with status s ran or may have run (E29's
// partition): succeeded, failed and indeterminate. Every other valid status
// was established as not run.
func (s StepStatus) Executed() bool {
	return s == StepSucceeded || s == StepFailed || s == StepIndeterminate
}

// JobClass is a job's step-derived class (E29): an abort status, or failed, or
// succeeded.
type JobClass string

const (
	ClassSucceeded         JobClass = "succeeded"
	ClassFailed            JobClass = "failed"
	ClassFailedNotStarted  JobClass = "failed_not_started"
	ClassExpiredUnexecuted JobClass = "expired_unexecuted"
	ClassStaleTarget       JobClass = "stale_target"
	ClassIndeterminate     JobClass = "indeterminate"
)

// Valid reports whether c is one of the six classes.
func (c JobClass) Valid() bool {
	switch c {
	case ClassSucceeded, ClassFailed, ClassFailedNotStarted, ClassExpiredUnexecuted, ClassStaleTarget, ClassIndeterminate:
		return true
	}
	return false
}

// RecordClass is a record's retention class (SA-6.5).
type RecordClass string

const (
	ClassLive           RecordClass = "live"
	ClassAwaitingReport RecordClass = "awaiting_report"
	ClassSettled        RecordClass = "settled"
)

// Summary is what Get, Wait and List return for one record. It never carries
// signature material or the claim-token hash (E25).
type Summary struct {
	RequestID           string             `json:"request_id"`
	RecordHandle        string             `json:"record_handle"`
	Kind                Kind               `json:"kind"`
	PlanHash            string             `json:"plan_hash"`
	Coordinator         Coordinator        `json:"coordinator,omitempty"`
	CreatedAt           time.Time          `json:"created_at"`
	RequestExpiresAt    time.Time          `json:"request_expires_at"`
	SyncClaimDeadline   *time.Time         `json:"sync_claim_deadline,omitempty"`
	ApprovalStatus      ApprovalStatus     `json:"approval_status"`
	TerminalReason      string             `json:"terminal_reason,omitempty"`
	DecidedAt           *time.Time         `json:"decided_at,omitempty"`
	AssistState         AssistState        `json:"assist_state"`
	AssistRevision      int                `json:"assist_revision"`
	ExecutionStatus     ExecutionStatus    `json:"execution_status"`
	ExecutionClass      JobClass           `json:"execution_class,omitempty"`
	ExecutedOrdinals    []int              `json:"executed_ordinals,omitempty"`
	Partial             bool               `json:"partial,omitempty"`
	NotExecutableReason string             `json:"not_executable_reason,omitempty"`
	NotificationStatus  NotificationStatus `json:"notification_status"`
	Class               RecordClass        `json:"class"`
	Pruned              bool               `json:"pruned,omitempty"`
	GrantID             string             `json:"grant_id,omitempty"`
	GrantExpiresAt      *time.Time         `json:"grant_expires_at,omitempty"`
}
