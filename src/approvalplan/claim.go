package approvalplan

import (
	"crypto/subtle"
	"slices"
	"strings"
)

// Claim is the only command that returns signature material (E25). Token is
// the coordinator's raw claim token; the record holds only its hash.
type Claim struct {
	Token    [32]byte
	PlanHash string
}

// Report is the one final execution report (E25, E38).
type Report struct {
	Token    [32]byte
	PlanHash string
	Body     FinalReport
}

func tokenMatches(h R1Header, token [32]byte, planHash string) bool {
	return h.Kind.ExecutionApplicable() && h.ClaimTokenHash != "" &&
		subtle.ConstantTimeCompare([]byte(ClaimTokenHash(token)), []byte(h.ClaimTokenHash)) == 1 &&
		planHash == h.PlanHash
}

// decisionAudited reports whether the outbox has been flushed through the
// decision: the decision event is no longer waiting in it.
func decisionAudited(h R1Header) bool {
	return h.Decision != nil && !slices.ContainsFunc(h.Outbox, func(e OutboxEvent) bool { return e.Kind == EventDecision })
}

// claim is the Claim answer, a total function of the record after Clock
// (SA-4 Claim), in SA-4's precedence: the two expired rows ahead of the flush
// gate, then not_ready, the terminal decisions, a final report, a mint error,
// a repeat Claim, and the first Claim, which mints inside this commit.
func (c *change) claim(cl Claim, in Inputs) Answer {
	h := &c.rec.Header
	if !tokenMatches(*h, cl.Token, cl.PlanHash) {
		ans := c.noise(EventInvalidClaim, "", "", "token_or_plan")
		ans.Code = CodeInvalidClaim
		return ans
	}
	m := h.Mint
	switch {
	case m != nil && m.State == MintError && m.Reason == MintReasonWindowClosed,
		m != nil && m.State == MintSignatures && !bytesHeld(c.rec):
		return Answer{Claim: ClaimExpired}
	case h.Decision == nil || !decisionAudited(*h):
		return Answer{Claim: ClaimNotReady}
	case h.Decision.Status != ApprovalApproved:
		return Answer{Claim: ClaimStatus(h.Decision.Status)}
	case h.FinalReport != nil:
		return Answer{Claim: ClaimExecutionReported, Class: h.FinalReport.Class}
	case m != nil && m.State == MintError:
		return Answer{Claim: ClaimMaterializationError, Reason: m.Reason}
	case m != nil:
		return c.repeatClaim()
	}
	return c.firstClaim(in)
}

func (c *change) repeatClaim() Answer {
	h := &c.rec.Header
	if h.Decision.DecidedAt.After(c.now.Wall.Add(ReleaseSkew)) {
		c.erase()
		return Answer{Claim: ClaimExpired}
	}
	h.ClaimCount++
	c.changed = true
	return c.signaturesAnswer()
}

func (c *change) firstClaim(in Inputs) Answer {
	h := &c.rec.Header
	p := c.rec.Payload
	if p == nil {
		return Answer{Claim: ClaimExpired}
	}
	if err := p.Plan.Validate(); err != nil {
		return Answer{Code: CodeRecordCorrupt, Reason: "stored plan fails E71 or its schema; nothing is minted"}
	}
	if h.Decision.DecidedAt.After(c.now.Wall.Add(ReleaseSkew)) {
		return c.mintError(MintReasonClockSkew)
	}
	if grantDecided(*h) {
		g := in.Grant
		if g == nil {
			return Answer{MintRequired: true}
		}
		id := strings.TrimPrefix(h.Decision.DecidedBy, GrantDecidedPrefix)
		if !g.Live || g.Record.Header.RequestID != id || !GrantLive(g.Record, c.now, c.epoch, true) || !GrantCovers(g.Record, c.rec) {
			return c.mintError(MintReasonGrantNotLive)
		}
	}
	if t := p.Plan.Transfer; t != nil {
		if in.XferDigests == nil {
			return Answer{MintRequired: true}
		}
		if in.XferDigests.Source != t.Source.KeyEntryDigest || in.XferDigests.Destination != t.Destination.KeyEntryDigest {
			return c.mintError(MintReasonStaleTransferKey)
		}
	}
	switch {
	case in.MintFailed:
		return c.mintError(MintReasonSigningFailed)
	case in.Minted == nil:
		return Answer{MintRequired: true}
	case len(in.Minted) != len(signedLegs(p.Plan)):
		return Answer{Code: CodeInvalidRequest, Reason: "minted: one signature per signed leg is required"}
	}
	p.Signatures = slices.Clone(in.Minted)
	h.Mint = &MintSlot{State: MintSignatures, Digest: SignatureSetDigest(p.Signatures)}
	h.ClaimCount = 1
	c.emit(OutboxEvent{Kind: EventMint, Detail: MintSignatures})
	return c.signaturesAnswer()
}

func (c *change) mintError(reason string) Answer {
	c.rec.Header.Mint = &MintSlot{State: MintError, Reason: reason}
	c.emit(OutboxEvent{Kind: EventMint, Detail: reason})
	return Answer{Claim: ClaimMaterializationError, Reason: reason}
}

func (c *change) signaturesAnswer() Answer {
	return Answer{
		Claim: ClaimSignatures, Signatures: slices.Clone(c.rec.Payload.Signatures),
		DecidedAt: c.rec.Header.Decision.DecidedAt, Windows: StepWindows(c.rec),
	}
}

// SignatureSetDigest is the mint slot's digest of a minted set:
// SHA-256("sshgate-v2-signature-set-v1\0" ‖ canonical(set)).
func SignatureSetDigest(set []string) string {
	return hashHex("sshgate-v2-signature-set-v1\x00", mustCanonical(set))
}

// ReportDigest is a final report's body digest: SHA-256(
// "sshgate-approval-report-v1\0" ‖ canonical(report without body_digest)).
// An exact duplicate report has the same digest.
func ReportDigest(r FinalReport) string {
	r.BodyDigest = ""
	b, err := Canonical(r)
	if err != nil {
		return ""
	}
	return hashHex("sshgate-approval-report-v1\x00", b)
}

// report is the report-acceptance rule (SA-4 Report): accepted whenever the
// header exists, shed or past the horizon, when the token and plan_hash
// match, the decision is approved, the final slot is empty, the steps are one
// per ordinal in E29's shape, the class, executed_ordinals and partial equal
// the values derived from them, and an executed mask has a claim behind it.
// An exact duplicate is acked; anything else is invalid_report.
func (c *change) report(r Report) Answer {
	h := &c.rec.Header
	reject := func(reason string) Answer {
		ans := c.noise(EventInvalidReport, "", "", reason)
		ans.Code = CodeInvalidReport
		return ans
	}
	if !tokenMatches(*h, r.Token, r.PlanHash) {
		return reject("token_or_plan")
	}
	if h.Decision == nil || h.Decision.Status != ApprovalApproved {
		return reject("not_approved")
	}
	body := r.Body
	body.BodyDigest = ReportDigest(body)
	if h.FinalReport != nil {
		if h.FinalReport.BodyDigest == body.BodyDigest {
			return Answer{}
		}
		return reject("already_reported")
	}
	if body.validate(h.StepCount) != nil {
		return reject("malformed")
	}
	if len(body.ExecutedOrdinals) > 0 && h.ClaimCount == 0 {
		return reject("executed_without_claim")
	}
	h.FinalReport = &body
	c.emit(OutboxEvent{Kind: EventFinalReport, Detail: string(body.Class)})
	if bytesHeld(c.rec) {
		c.erase()
	}
	return Answer{}
}
