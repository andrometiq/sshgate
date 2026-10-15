package approvalplan

// Class is the record's retention class (SA-6.5), read from slots: live while
// pending, while an approved record's signature window is open (the mint slot
// empty or still holding bytes) with no final report, or while it is a live
// grant; awaiting_report while claimed and unreported before last_end +
// report horizon; settled otherwise. grantLive is the grant projection's
// verdict on this record.
func Class(rec R1, now Now, s Settings, grantLive bool) RecordClass {
	h := rec.Header
	d := h.Decision
	switch {
	case d == nil:
		return ClassLive
	case d.Status != ApprovalApproved:
		return ClassSettled
	case h.Kind == KindStandingGrant:
		if grantLive && h.RevokedAt == nil {
			return ClassLive
		}
		return ClassSettled
	case h.FinalReport != nil || !h.Kind.ExecutionApplicable():
		return ClassSettled
	case h.Mint == nil || bytesHeld(rec):
		return ClassLive
	case h.ClaimCount > 0 && !pastHorizon(rec, now.norm(), s):
		return ClassAwaitingReport
	}
	return ClassSettled
}
