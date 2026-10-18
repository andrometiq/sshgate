package executorwire

import (
	"github.com/karthikeyan5/sshgate/src/approvalplan"
)

// Job carries only execution facts. Approval status is joined from the signer
// by the MCP; neither a draft nor a claim token belongs in this view.
type Job struct {
	RequestID        string                    `json:"request_id"`
	ExecutionStatus  approvalplan.JobState     `json:"execution_status"`
	Executing        int                       `json:"executing,omitempty"`
	Steps            []approvalplan.StepStatus `json:"steps"`
	Class            approvalplan.JobClass     `json:"class,omitempty"`
	ExecutedOrdinals []int                     `json:"executed_ordinals"`
	Partial          bool                      `json:"partial,omitempty"`
	Outcome          *approvalplan.JobOutcome  `json:"outcome,omitempty"`
	Results          []approvalplan.StepResult `json:"results,omitempty"`
	ResultStatus     string                    `json:"result_status,omitempty"`
	Hint             string                    `json:"hint,omitempty"`
}

func FromSummary(summary approvalplan.JobSummary) Job {
	if summary.Outcome != nil {
		outcome := *summary.Outcome
		summary.Outcome = &outcome
	}
	return Job{RequestID: summary.RequestID, ExecutionStatus: summary.State, Executing: summary.Executing,
		Steps: append([]approvalplan.StepStatus{}, summary.Steps...), Class: summary.Class,
		ExecutedOrdinals: append([]int{}, summary.ExecutedOrdinals...), Partial: summary.Partial, Outcome: summary.Outcome}
}

type Item struct {
	RequestID string     `json:"request_id"`
	Job       *Job       `json:"job,omitempty"`
	Error     *WireError `json:"error,omitempty"`
}
type Response struct {
	ProtoVersion       int                             `json:"proto_version"`
	Kind               string                          `json:"kind"`
	OK                 bool                            `json:"ok"`
	Job                *Job                            `json:"job,omitempty"`
	Items              []Item                          `json:"items,omitempty"`
	NextCursor         string                          `json:"next_cursor,omitempty"`
	NotificationStatus approvalplan.NotificationStatus `json:"notification_status,omitempty"`
	Error              *WireError                      `json:"error,omitempty"`
}

func (j Job) Validate() error {
	if !approvalplan.ValidRequestID(j.RequestID) || len(j.Steps) > approvalplan.MaxSteps || len(j.Results) > len(j.Steps) {
		return invalid("invalid job shape")
	}
	switch j.ExecutionStatus {
	case approvalplan.JobSubmitted, approvalplan.JobAcknowledged, approvalplan.JobApproved, approvalplan.JobExecuting, approvalplan.JobFinal:
	default:
		return invalid("unknown execution status")
	}
	if (j.ExecutionStatus == approvalplan.JobExecuting) != (j.Executing > 0) || j.Executing > approvalplan.MaxSteps || j.Executing < 0 || j.Executing > 0 && j.Executing != len(j.Steps)+1 {
		return invalid("invalid executing ordinal")
	}
	for _, s := range j.Steps {
		if !s.Valid() {
			return invalid("unknown step status")
		}
	}
	if o := j.Outcome; o != nil {
		switch o.Kind {
		case approvalplan.OutcomeDenied, approvalplan.OutcomeCanceled, approvalplan.OutcomeExpired, approvalplan.OutcomeApprovalLost:
			if o.Code != "" || o.Class != "" {
				return invalid("invalid outcome fields")
			}
		case approvalplan.OutcomeJobError:
			if o.Class != "" || o.Code != "" && (!o.Code.Valid() || o.Code.Retryable()) {
				return invalid("invalid outcome error")
			}
		case approvalplan.OutcomeAdopted:
			if !o.Class.Valid() || o.Code != "" {
				return invalid("invalid adopted outcome")
			}
		default:
			return invalid("unknown job outcome")
		}
	}
	expected := approvalplan.ExecutedOrdinals(j.Steps)
	if len(expected) != len(j.ExecutedOrdinals) || j.Partial != (j.ExecutionStatus == approvalplan.JobFinal && approvalplan.Partial(j.Steps)) {
		return invalid("inconsistent execution facts")
	}
	for i, n := range expected {
		if j.ExecutedOrdinals[i] != n {
			return invalid("inconsistent executed ordinals")
		}
	}
	if j.Class != "" && !j.Class.Valid() {
		return invalid("unknown job class")
	}
	if j.ExecutionStatus != approvalplan.JobFinal && (j.Class != "" || j.Outcome != nil || j.ResultStatus != "") {
		return invalid("terminal facts on nonfinal job")
	}
	switch j.ResultStatus {
	case "":
		if j.Hint != "" {
			return invalid("unexpected result hint")
		}
	case "result_withheld":
		if j.Hint != "await this id alone" || len(j.Results) != 0 {
			return invalid("invalid withheld result")
		}
	case "result_expired", "result_evicted":
		if j.Hint != "" || len(j.Results) != 0 {
			return invalid("removed result carries bodies")
		}
	default:
		return invalid("unknown result status")
	}
	total := 0
	for i, r := range j.Results {
		if r.Status != j.Steps[i] || r.StdoutBytes < 0 || r.StderrBytes < 0 || !approvalplan.ValidSHA256Hex(r.StdoutSHA256) || !approvalplan.ValidSHA256Hex(r.StderrSHA256) {
			return invalid("invalid step result")
		}
		if len(r.Stdout) > approvalplan.MaxStreamOutputBytes || len(r.Stderr) > approvalplan.MaxStreamOutputBytes {
			return tooLarge()
		}
		total += len(r.Stdout) + len(r.Stderr)
	}
	if total > approvalplan.MaxJobOutputBytes {
		return tooLarge()
	}
	return nil
}
func (r Response) Validate() error {
	if r.NotificationStatus != "" && (!r.OK || r.Kind != KindSubmit || !r.NotificationStatus.Valid()) {
		return invalid("invalid submit notification")
	}
	if r.ProtoVersion != Proto {
		return invalid("unsupported executor protocol")
	}
	switch r.Kind {
	case KindSubmit, KindGet, KindAwait, KindList:
	default:
		return invalid("unknown executor kind")
	}
	if !r.OK {
		if r.Error == nil || r.Job != nil || len(r.Items) != 0 || r.NextCursor != "" {
			return invalid("invalid refusal shape")
		}
		return r.Error.Validate()
	}
	if r.Error != nil {
		return invalid("success carries error")
	}
	if r.Kind == KindSubmit || r.Kind == KindGet {
		if r.Job == nil || len(r.Items) != 0 || r.NextCursor != "" {
			return invalid("invalid job response")
		}
		return r.Job.Validate()
	}
	if r.Job != nil || len(r.Items) > approvalplan.AwaitMaxIDs || r.Kind != KindList && r.NextCursor != "" {
		return invalid("invalid items response")
	}
	if r.Kind == KindList {
		if err := validateRequest(ListRequest{ProtoVersion: Proto, Kind: KindList, Limit: 100, Cursor: r.NextCursor}); err != nil {
			return err
		}
	}
	seen := map[string]bool{}
	for _, item := range r.Items {
		if !approvalplan.ValidRequestID(item.RequestID) || seen[item.RequestID] || (item.Job == nil) == (item.Error == nil) {
			return invalid("invalid response item")
		}
		seen[item.RequestID] = true
		if item.Job != nil {
			if item.RequestID != item.Job.RequestID {
				return invalid("item request ID mismatch")
			}
			if err := item.Job.Validate(); err != nil {
				return err
			}
		} else if err := item.Error.Validate(); err != nil {
			return err
		}
	}
	return nil
}
func MarshalResponse(response Response) ([]byte, error) {
	if err := response.Validate(); err != nil {
		return nil, err
	}
	return marshal(response, MaxResponseBytes)
}
func DecodeResponse(kind string, frame []byte) (Response, error) {
	var response Response
	if len(frame) > MaxResponseBytes {
		return response, tooLarge()
	}
	if err := decode(frame, &response); err != nil {
		return Response{}, err
	}
	if response.Kind != kind {
		return Response{}, invalid("response kind mismatch")
	}
	if err := response.Validate(); err != nil {
		return Response{}, err
	}
	if !response.OK {
		return response, response.Error
	}
	return response, nil
}
