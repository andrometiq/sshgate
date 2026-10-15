package statetest

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	ap "github.com/karthikeyan5/sshgate/src/approvalplan"
)

func enc(v any) string {
	b, err := json.Marshal(v)
	if err != nil {
		return "<unencodable: " + err.Error() + ">"
	}
	return string(b)
}

// CheckRecord holds every R1 record to A1a's codec: it validates and encodes
// (within R1Max, ShedMax or its own R1Reservation), and its bytes decode back
// to the same bytes. DecodeR1's own checks are EncodeR1's, so the harness
// runs them once.
func CheckRecord(rec ap.R1) error {
	if d := rec.Header.Decision; d != nil && d.Status == ap.ApprovalApproved && !strings.HasPrefix(d.DecidedBy, ap.GrantDecidedPrefix) {
		if len(strings.Split(d.DecidedBy, ",")) != rec.Header.RequiredApprovals {
			return errors.New("approved vote attribution does not name exactly required_approvals operators")
		}
	}
	b, err := ap.EncodeR1(rec)
	if err != nil {
		return fmt.Errorf("record does not encode: %w", err)
	}
	var back ap.R1
	if err := json.Unmarshal(b, &back); err != nil {
		return fmt.Errorf("record does not decode: %w", err)
	}
	if again, err := ap.Canonical(back); err != nil || !bytes.Equal(again, b) {
		return errors.New("record does not round-trip byte-exactly")
	}
	return nil
}

// CheckTransition checks one commit of an R1 record (SA-11): the codec (so
// the record stays within its own R1Reservation), the frozen header,
// write-once slots and set-entry fields, append-only sets, monotone counters,
// no stamp beyond the wall clock at the commit, and Clock facts only at or
// after their deadline.
// before is nil for a new record.
func CheckTransition(before *ap.R1, after ap.R1, now ap.Now) error {
	if err := CheckRecord(after); err != nil {
		return err
	}
	wall := now.Wall
	if before == nil {
		if !after.Header.CreatedAt.Equal(wall) {
			return errors.New("created_at is not the commit's wall clock")
		}
		return checkClockFacts(nil, after, wall)
	}
	b, a := before.Header, after.Header
	frozenB, frozenA := b, a
	for _, h := range []*ap.R1Header{&frozenB, &frozenA} {
		h.Assist, h.Decision, h.Mint, h.FinalReport, h.RevokedAt, h.Votes = nil, nil, nil, nil, nil, nil
		h.ClaimCount, h.RenotifyGen, h.OutboxSeq, h.AuditedThrough, h.NoiseDropped, h.Outbox, h.Shed = 0, 0, 0, 0, 0, nil, false
	}
	if enc(frozenB) != enc(frozenA) {
		return errors.New("an immutable header field changed")
	}
	for name, pair := range map[string][2]any{
		"assist": {b.Assist, a.Assist}, "decision": {b.Decision, a.Decision}, "mint": {b.Mint, a.Mint},
		"final_report": {b.FinalReport, a.FinalReport}, "revoked_at": {b.RevokedAt, a.RevokedAt},
	} {
		if enc(pair[0]) != "null" && enc(pair[0]) != enc(pair[1]) {
			return fmt.Errorf("write-once slot %s was overwritten", name)
		}
	}
	if len(a.Votes) < len(b.Votes) || !slices.EqualFunc(a.Votes[:len(b.Votes)], b.Votes, func(x, y ap.Vote) bool { return enc(x) == enc(y) }) {
		return errors.New("the vote set is not append-only")
	}
	if a.ClaimCount < b.ClaimCount || a.RenotifyGen < b.RenotifyGen || a.OutboxSeq < b.OutboxSeq ||
		a.AuditedThrough < b.AuditedThrough || a.NoiseDropped < b.NoiseDropped || (b.Shed && !a.Shed) {
		return errors.New("a monotone counter decreased or a shed record regrew")
	}
	if err := checkPayload(*before, after); err != nil {
		return err
	}
	if err := checkStamps(*before, after, wall); err != nil {
		return err
	}
	return checkClockFacts(before, after, wall)
}

func checkPayload(before, after ap.R1) error {
	pb, pa := before.Payload, after.Payload
	if pb == nil || pa == nil {
		if pb == nil && pa != nil {
			return errors.New("a shed record regained a payload")
		}
		return nil
	}
	if enc(pb.Plan) != enc(pa.Plan) || !bytes.Equal(pb.ReviewSnapshot, pa.ReviewSnapshot) {
		return errors.New("the plan or review snapshot changed")
	}
	if pb.AssistResult != nil && enc(pb.AssistResult) != enc(pa.AssistResult) {
		return errors.New("the assist result was overwritten")
	}
	if len(pb.Signatures) > 0 && len(pa.Signatures) > 0 && !slices.Equal(pb.Signatures, pa.Signatures) {
		return errors.New("held signature bytes changed")
	}
	if len(pb.Signatures) == 0 && len(pa.Signatures) > 0 && before.Header.Mint != nil {
		return errors.New("signature bytes reappeared after the Erase")
	}
	if !prefixWithFills(pb.CardEntries, pa.CardEntries, cardFill) {
		return fmt.Errorf("card entries are not append-only with write-once fields: %s -> %s", enc(pb.CardEntries), enc(pa.CardEntries))
	}
	if !prefixWithFills(pb.Bursts, pa.Bursts, burstFill) {
		return fmt.Errorf("bursts are not append-only with write-once fields: %s -> %s", enc(pb.Bursts), enc(pa.Bursts))
	}
	if len(pa.StatusEdits) < len(pb.StatusEdits) || !slices.Equal(pa.StatusEdits[:len(pb.StatusEdits)], pb.StatusEdits) {
		return errors.New("status edits are not append-only")
	}
	return nil
}

// prefixWithFills: before is a prefix of after, each entry changed only by
// filling write-once fields.
func prefixWithFills[T any](before, after []T, fill func(b, a T) bool) bool {
	if len(after) < len(before) {
		return false
	}
	for i := range before {
		if !fill(before[i], after[i]) {
			return false
		}
	}
	return true
}

func cardFill(b, a ap.CardEntry) bool {
	if b.MsgID != nil && (a.MsgID == nil || *a.MsgID != *b.MsgID) || b.Outcome != "" && a.Outcome != b.Outcome ||
		b.Confirmed && !a.Confirmed || b.Retired && !a.Retired {
		return false
	}
	b.MsgID, b.Outcome, b.Confirmed, b.Retired = a.MsgID, a.Outcome, a.Confirmed, a.Retired
	return enc(b) == enc(a)
}

func burstFill(b, a ap.Burst) bool {
	if b.Outcome != "" && (a.Outcome != b.Outcome || !slices.Equal(a.PartMsgIDs, b.PartMsgIDs)) {
		return false
	}
	b.Outcome, b.PartMsgIDs = a.Outcome, a.PartMsgIDs
	return enc(b) == enc(a)
}

// checkStamps: every stamp this commit wrote is at most its wall clock.
func checkStamps(before, after ap.R1, wall time.Time) error {
	b, a := before.Header, after.Header
	late := func(t time.Time) bool { return t.After(wall) }
	for _, v := range a.Votes[len(b.Votes):] {
		if late(v.TS) {
			return errors.New("a vote ts is after the commit's wall clock")
		}
		if !v.TS.Before(a.RequestExpiresAt) {
			return errors.New("a vote was stored at or after request_expires_at (E67)")
		}
	}
	if b.Decision == nil && a.Decision != nil && late(a.Decision.DecidedAt) {
		return errors.New("decided_at is after the commit's wall clock")
	}
	if b.RevokedAt == nil && a.RevokedAt != nil && late(*a.RevokedAt) {
		return errors.New("revoked_at is after the commit's wall clock")
	}
	if before.Payload != nil && after.Payload != nil {
		for _, burst := range after.Payload.Bursts[len(before.Payload.Bursts):] {
			if late(burst.StartedAt) {
				return errors.New("a burst's started_at is after the commit's wall clock")
			}
		}
	}
	return nil
}

// checkClockFacts: a time fact appears only once its deadline is at or
// before the commit's wall clock (SA-11 time property 2).
func checkClockFacts(before *ap.R1, after ap.R1, wall time.Time) error {
	var b ap.R1Header
	if before != nil {
		b = before.Header
	}
	a := after.Header
	if b.Assist == nil && a.Assist != nil && a.Assist.Reason == ap.AssistDeadlineReason && wall.Before(a.AssistDeadline) {
		return errors.New("Clock wrote the assist deadline's snapshot before the deadline")
	}
	if b.Decision == nil && a.Decision != nil && a.Decision.DecidedBy == ap.DecidedByClock && wall.Before(a.RequestExpiresAt) {
		return errors.New("Clock expired a request before request_expires_at")
	}
	if b.Mint == nil && a.Mint != nil && a.Mint.Reason == ap.MintReasonWindowClosed {
		if end, ok := ap.ClaimEnd(after); !ok || wall.Before(end) {
			return errors.New("Clock closed a claim window before claim_end")
		}
	}
	return nil
}

// CheckRecordAnswer checks what an answer may release: signature bytes leave
// only with a Claim on a record holding exactly that set, and never while
// decided_at is more than ReleaseSkew ahead of the wall clock (SA-1 rule 3.2).
func CheckRecordAnswer(after ap.R1, ans ap.Answer, now ap.Now) error {
	if len(ans.Signatures) == 0 {
		return nil
	}
	if ans.Claim != ap.ClaimSignatures || after.Payload == nil || !slices.Equal(ans.Signatures, after.Payload.Signatures) {
		return errors.New("signatures left without being the record's held set")
	}
	if after.Header.Decision.DecidedAt.After(now.Wall.Add(ap.ReleaseSkew)) {
		return errors.New("signatures left while decided_at is more than 5 s ahead of the wall clock")
	}
	return nil
}

// CheckJobTransition checks one commit of an executor job record: the codec,
// the immutable header, write-once slots and step entries (bodies may only be
// removed), the token only dropped, and final_at set exactly by the commit
// that makes the job final, at its wall clock, and never changed.
func CheckJobTransition(before *ap.R2, after ap.R2, now ap.Now, epoch string) error {
	b, err := ap.EncodeR2(after)
	if err != nil {
		return fmt.Errorf("job does not encode: %w", err)
	}
	if back, err := ap.DecodeR2(b); err != nil || enc(back) != enc(after) {
		return errors.New("job does not round-trip")
	}
	final := ap.JobView(after, epoch).State == ap.JobFinal
	if final != (after.FinalAt != nil) {
		return errors.New("final_at is set exactly when the job is final")
	}
	if before == nil {
		return nil
	}
	x, y := *before, after
	if x.RequestID != y.RequestID || x.InputHash != y.InputHash || enc(x.Draft) != enc(y.Draft) ||
		x.DraftHash != y.DraftHash || !x.CreatedAt.Equal(y.CreatedAt) || x.Reservation != y.Reservation {
		return errors.New("an immutable job field changed")
	}
	if x.ClaimToken != y.ClaimToken && y.ClaimToken != "" {
		return errors.New("the claim token changed")
	}
	for name, pair := range map[string][2]any{
		"signer_ack": {nilIfEmpty(x.SignerAck), nilIfEmpty(y.SignerAck)}, "outcome": {x.Outcome, y.Outcome},
		"report_result": {x.ReportResult, y.ReportResult}, "first_delivered_at": {x.FirstDeliveredAt, y.FirstDeliveredAt},
		"bodies_removed": {x.BodiesRemoved, y.BodiesRemoved}, "final_at": {x.FinalAt, y.FinalAt},
	} {
		if enc(pair[0]) != "null" && enc(pair[0]) != enc(pair[1]) {
			return fmt.Errorf("write-once job slot %s was overwritten", name)
		}
	}
	if x.FinalAt == nil && y.FinalAt != nil && !y.FinalAt.Equal(now.Wall) {
		return errors.New("final_at is not the finalizing commit's wall clock")
	}
	for i := range x.Steps {
		sx, sy := x.Steps[i], y.Steps[i]
		if sx.Marker != nil && enc(sx.Marker) != enc(sy.Marker) {
			return errors.New("a step marker was overwritten")
		}
		if sx.Result != nil {
			rx, ry := *sx.Result, *sy.Result
			if y.BodiesRemoved != nil {
				rx.Stdout, rx.Stderr = nil, nil
			}
			if enc(rx) != enc(ry) {
				return errors.New("a step result was overwritten")
			}
		}
	}
	return nil
}

func nilIfEmpty(s string) any {
	if s == "" {
		return nil
	}
	return s
}
