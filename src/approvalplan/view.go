package approvalplan

import "time"

// View is the summary Get, Wait and List return (SA-6). It is pure: it never
// writes, reads time only from committed slots, and uses now only for the
// provisional report horizon. grantLive is the grant projection's verdict on
// this record (SA-6.4).
func View(rec R1, now Now, epoch string, s Settings, grantLive bool) Summary {
	now = now.norm()
	h := rec.Header
	assist, rev, _ := assistView(h)
	sum := Summary{
		RequestID: h.RequestID, RecordHandle: RecordHandle(RecordKeyOf(h, s.Hosted)), Kind: h.Kind,
		PlanHash: h.PlanHash, Coordinator: h.Coordinator, CreatedAt: h.CreatedAt, RequestExpiresAt: h.RequestExpiresAt,
		ApprovalStatus: ApprovalPending, AssistState: assist, AssistRevision: rev,
		NotificationStatus: notificationView(rec, epoch, s), Class: Class(rec, now, s, grantLive), Pruned: h.Shed,
	}
	if h.Coordinator == CoordinatorInProcessSync {
		t := SyncClaimDeadline(h)
		sum.SyncClaimDeadline = &t
	}
	if d := h.Decision; d != nil {
		at := d.DecidedAt
		sum.ApprovalStatus, sum.TerminalReason, sum.DecidedAt = d.Status, d.TerminalReason, &at
		if h.Kind == KindStandingGrant && d.Status == ApprovalApproved {
			exp := GrantExpiresAt(h)
			sum.GrantID, sum.GrantExpiresAt = h.RequestID, &exp
		}
	}
	status, final, reason := executionView(rec, now, s)
	sum.ExecutionStatus, sum.NotExecutableReason = status, reason
	if final != nil {
		sum.ExecutionClass, sum.Partial = final.Class, final.Partial
		sum.ExecutedOrdinals = append([]int(nil), final.ExecutedOrdinals...)
	}
	return sum
}

// RecordKeyOf is the record key a header is stored under: the local file
// name, or the hosted (client_id, sub_principal, request_id) key.
func RecordKeyOf(h R1Header, hosted bool) string {
	if hosted {
		return HostedRecordKey(h.Principal, h.SubPrincipal, h.RequestID)
	}
	return RecordKey(h.Principal, h.RequestID)
}

// executionView is SA-6.2, read from slots only.
func executionView(rec R1, now Now, s Settings) (ExecutionStatus, *FinalReport, string) {
	h := rec.Header
	if !h.Kind.ExecutionApplicable() {
		return ExecutionNotApplicable, nil, ""
	}
	if h.Decision == nil || h.Decision.Status != ApprovalApproved {
		return ExecutionNone, nil, ""
	}
	m := h.Mint
	switch {
	case m != nil && m.State == MintError && m.Reason != MintReasonWindowClosed:
		return ExecutionNotExecutable, nil, m.Reason
	case h.FinalReport != nil:
		return ExecutionFinal, h.FinalReport, ""
	case m != nil && m.State == MintError:
		return ExecutionExpiredUnclaimed, nil, ""
	case h.ClaimCount > 0:
		if pastHorizon(rec, now, s) {
			return ExecutionUnreported, nil, ""
		}
		return ExecutionExecuting, nil, ""
	}
	return ExecutionNone, nil, ""
}

func pastHorizon(rec R1, now Now, s Settings) bool {
	last, ok := LastEnd(rec)
	return ok && !now.Wall.Before(last.Add(s.ReportHorizon))
}

// notificationView is SA-6.3: it reads the bursts and the unretired send
// entries only, never an edit entry.
func notificationView(rec R1, epoch string, s Settings) NotificationStatus {
	h, p := rec.Header, rec.Payload
	if p == nil || !notifies(h, s) {
		return NotificationNotApplicable
	}
	if h.Decision != nil && h.Decision.Status == ApprovalError {
		return NotificationError
	}
	if h.Decision == nil {
		switch {
		case len(p.Bursts) == 0:
			return NotificationNotStarted
		case resendDue(rec) || cardDue(rec):
			return NotificationSending
		}
	}
	if ep, ok := unsettledSend(rec); ok {
		if ep == epoch {
			return NotificationSending
		}
		return NotificationUncertain
	}
	if e := latestUnretiredSend(p); e != nil && e.Outcome != "" {
		return outcomeStatus(e.Outcome)
	}
	for i := len(p.Bursts) - 1; i >= 0; i-- {
		if o := p.Bursts[i].Outcome; o != "" {
			return outcomeStatus(o)
		}
	}
	return NotificationNotStarted
}

// unsettledSend finds a send with no outcome that still counts: the latest
// burst under the current renotify_gen, or the latest unretired send entry.
// A burst under an older gen was superseded by a Renotify and needs no driver.
func unsettledSend(rec R1) (string, bool) {
	p := rec.Payload
	if b := lastBurst(p); b != nil && b.Outcome == "" && b.Gen == rec.Header.RenotifyGen {
		return b.Epoch, true
	}
	if e := latestUnretiredSend(p); e != nil && e.Outcome == "" {
		return e.Epoch, true
	}
	return "", false
}

func outcomeStatus(o string) NotificationStatus {
	if o == OutcomeSent {
		return NotificationSent
	}
	return NotificationError
}

// GrantExpiresAt is decided_at + duration_seconds (E9).
func GrantExpiresAt(h R1Header) time.Time {
	return h.Decision.DecidedAt.Add(time.Duration(h.DurationSeconds) * time.Second)
}
