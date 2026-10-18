//go:build linux

package executor

import (
	"strings"
	"time"

	ap "github.com/karthikeyan5/sshgate/src/approvalplan"
)

// R2FinalCharge reserves every still-empty post-final slot at its encoded bound.
func R2FinalCharge(job ap.R2) (int64, error) {
	if ap.JobView(job, "").State != ap.JobFinal {
		return 0, ErrReportAuthLost
	}
	if job.ReportResult == nil {
		job.ReportResult = &ap.ReportResult{State: ap.ReportRefused, Code: ap.CodeSubmitWindowClosed}
	}
	if job.FirstDeliveredAt == nil {
		at := time.Date(9999, 12, 31, 23, 59, 59, 999999999, time.UTC)
		job.FirstDeliveredAt = &at
	}
	if job.BodiesRemoved == nil {
		job.BodiesRemoved = &ap.BodiesRemoved{Cause: strings.Repeat("x", ap.MaxReasonTokenBytes)}
	}
	// These are sizing placeholders, not a record to commit.
	body, err := ap.Canonical(job)
	return int64(len(body)), err
}
