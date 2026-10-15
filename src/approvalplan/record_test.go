package approvalplan

import (
	"bytes"
	"encoding/json"
	"fmt"
	"math"
	"math/rand/v2"
	"strings"
	"testing"
	"time"
)

var (
	epochA   = strings.Repeat("e", EpochLen)
	digestA  = sha256Hex("a")
	reviewOK = json.RawMessage(`{"segments":[]}`)
)

// frozenR1 is the record a freeze of plan commits, before any later write.
func frozenR1(t testing.TB, plan ApprovalPlanV1, n int, rationaleRedacted string, review json.RawMessage) R1 {
	t.Helper()
	planHash, err := PlanHash(plan)
	if err != nil {
		t.Fatal(err)
	}
	h := R1Header{
		Version: R1Version, Principal: plan.RequesterPrincipal, SubPrincipal: plan.RequesterSub,
		RequestID: plan.RequestID, Kind: plan.Kind, DraftHash: sha256Hex("draft"), PlanHash: planHash,
		RationaleOrigin: OriginAgent, RationaleRedacted: rationaleRedacted,
		ClaimTokenHash: plan.ExecutorClaimTokenHash, Coordinator: plan.Coordinator, RequiredApprovals: n,
		CreatedAt: plan.SubmittedAt, RequestExpiresAt: plan.RequestExpiresAt, AssistDeadline: plan.SubmittedAt.Add(5 * time.Second),
		SubmitNotAfter: plan.SubmitNotAfter, StepTTLs: stepTTLs(plan),
	}
	h.StepCount = len(h.StepTTLs)
	if g := plan.StandingGrant; g != nil {
		h.GrantAlias, h.DurationSeconds, h.GrantHostFP = g.Alias, g.DurationSeconds, g.TrustedHostFingerprint
	}
	return R1{Header: h, Payload: &R1Payload{Plan: plan, ReviewSnapshot: review}}
}

// maxAssist is a valid AssistResult as close to MaxAssistBytes as escaped
// text gets it: a full summary of '<', then effects of '<', the last one cut
// to fit.
func maxAssist() AssistResult {
	a := AssistResult{
		Alignment: AlignmentMismatch, Summary: strings.Repeat("<", MaxAssistSummaryBytes),
		Model: strings.Repeat("m", MaxAssistModelBytes), PromptVersion: strings.Repeat("p", MaxAssistPromptVersion),
		InputDigest: digestA, GeneratedAt: t0.Add(999999999),
	}
	size := func() int { b, _ := json.Marshal(a); return len(b) }
	for len(a.Effects) < MaxAssistEffects {
		a.Effects = append(a.Effects, strings.Repeat("<", MaxAssistEffectBytes))
		for size() > MaxAssistBytes {
			last := &a.Effects[len(a.Effects)-1]
			if *last = (*last)[1:]; *last == "" {
				a.Effects = a.Effects[:len(a.Effects)-1]
				return a
			}
		}
	}
	return a
}

// grown is frozen moved to every set and slot bound a valid record can
// reach, built with valid values so EncodeR1 accepts it. It is independent of
// grownR1, which R1Reservation measures.
func grown(t testing.TB, frozen R1) R1 {
	t.Helper()
	rec := frozen
	payload := *frozen.Payload
	rec.Payload = &payload
	h := &rec.Header
	n := h.RequiredApprovals
	voteCap := VoteCap(rec)
	ts := t0.Add(999999999)
	ops := make([]string, voteCap)
	for i := range ops {
		ops[i] = fmt.Sprintf("%0128d", i)
		h.Votes = append(h.Votes, Vote{Operator: ops[i], Decision: VoteApprove, TS: ts, Authn: strings.Repeat("w", MaxAuthnBytes)})
	}
	assist := maxAssist()
	payload.AssistResult = &assist
	h.Assist = &AssistSlot{State: AssistReady, GeneratedAt: assist.GeneratedAt, Digest: AssistDigest(assist)}
	bound := AssistBound{State: AssistReady, Revision: 1, Digest: h.Assist.Digest}
	h.Decision = &Decision{
		Status: ApprovalApproved, DecidedAt: ts, DecidedBy: strings.Join(ops[:n], ","),
		TerminalReason: strings.Repeat("r", MaxReasonTokenBytes), Epoch: epochA, AssistBound: bound,
	}
	if rec.Header.Kind.ExecutionApplicable() {
		h.Mint = &MintSlot{State: MintSignatures, Digest: digestA}
		for _, leg := range signedLegs(payload.Plan) {
			payload.Signatures = append(payload.Signatures, strings.Repeat("A", maxSignatureLen(leg.command, leg.host)))
		}
		// Every step executed, the last one indeterminate: the longest
		// report E29's shape admits.
		h.FinalReport = &FinalReport{Class: ClassIndeterminate, ResultDigest: digestA, BodyDigest: digestA}
		exit, out, trunc := math.MinInt32, int64(math.MaxInt64), true
		for i := 1; i <= h.StepCount; i++ {
			status := StepFailed
			if i == h.StepCount {
				status = StepIndeterminate
			}
			h.FinalReport.Steps = append(h.FinalReport.Steps, StepReport{Ordinal: i, Status: status, ExitCode: &exit, StdoutBytes: &out, StderrBytes: &out, Truncated: &trunc})
			h.FinalReport.ExecutedOrdinals = append(h.FinalReport.ExecutedOrdinals, i)
		}
	} else {
		revoked := ts
		h.RevokedAt = &revoked
	}
	h.ClaimCount, h.RenotifyGen, h.NoiseDropped = math.MaxInt64, MaxBursts+1, math.MaxUint64
	total := OutboxMax(rec) + NoiseFold
	h.OutboxSeq = math.MaxUint64
	h.AuditedThrough = h.OutboxSeq - uint64(total)
	for i := range total {
		e := OutboxEvent{
			Seq: h.AuditedThrough + uint64(i) + 1, Kind: strings.Repeat("k", MaxEventKindBytes), Replay: true,
			Decision: strings.Repeat("d", MaxDecisionBytes), Detail: strings.Repeat("x", MaxDetailBytes), Assist: &bound,
			NoiseDropped: math.MaxUint64,
		}
		e.Operator = ops[i%voteCap]
		if i == voteCap+NoiseFold {
			e.DecidedBy = h.Decision.DecidedBy
		}
		h.Outbox = append(h.Outbox, e)
	}
	msgID := int64(math.MaxInt64)
	for range MaxCardEntries {
		payload.CardEntries = append(payload.CardEntries, CardEntry{
			Handle: strings.Repeat("q", CardHandleLen), Rev: 1, ChalHash: digestA,
			Actions: []string{ActionApprove, ActionDeny}, Kind: CardReplacement, Epoch: epochA, MsgID: &msgID,
			Outcome: OutcomeError, Confirmed: true, Retired: true,
		})
	}
	parts := make([]int64, MaxBurstParts)
	for i := range parts {
		parts[i] = math.MaxInt64
	}
	for range MaxBursts {
		payload.Bursts = append(payload.Bursts, Burst{Epoch: epochA, Gen: MaxBursts + 1, StartedAt: ts, PartMsgIDs: parts, Outcome: OutcomeError})
	}
	for range MaxStatusEdits {
		payload.StatusEdits = append(payload.StatusEdits, StatusEdit{State: strings.Repeat("s", MaxStatusStateBytes)})
	}
	return rec
}

// reviewOfSize is a canonical JSON object of exactly n bytes, mostly '<',
// which encodes to six bytes each.
func reviewOfSize(n int) json.RawMessage {
	esc := `\` + "u003c"
	body := strings.Repeat(esc, (n-8)/len(esc))
	body += strings.Repeat("a", n-8-len(body))
	return json.RawMessage(`{"s":"` + body + `"}`)
}

func hostedWorst(plan ApprovalPlanV1) ApprovalPlanV1 {
	plan.RequesterPrincipal = strings.Repeat("c", MaxPrincipalBytes)
	plan.RequesterSub = "local-uid:4294967295"
	return plan
}

// worstR1s are the frozen worst cases, one per payload shape.
func worstR1s(t testing.TB) map[string]R1 {
	t.Helper()
	review := reviewOfSize(ReviewSnapshotMax)
	redacted := strings.Repeat("<", MaxRationaleRedactedBytes)
	out := map[string]R1{
		"command_job": frozenR1(t, hostedWorst(freeze(worstDraft(), "x", "")), MaxRequiredApprovals, redacted, review),
	}
	grant := *fixtures()[6].draft
	g := *grant.StandingGrant
	g.Alias = strings.Repeat("g", MaxAliasBytes)
	g.TrustedHostFingerprint = "SHA256:" + strings.Repeat("<", MaxFingerprintBytes-7)
	g.Commands = nil
	for range MaxTotalBytes / MaxStepBytes {
		g.Commands = append(g.Commands, strings.Repeat("<", MaxStepBytes))
	}
	grant.StandingGrant = &g
	grant.Rationale = strings.Repeat("<", MaxRationaleBytes)
	out["standing_grant"] = frozenR1(t, hostedWorst(freeze(grant, "x", "")), MaxRequiredApprovals, redacted, review)
	tr := freeze(*fixtures()[8].draft, "x", "")
	transfer := *tr.Transfer
	wire := strings.Repeat("A", MaxTransferLegBytes-len("SSHGATE_XFER_RECV "))
	transfer.SendCommand, transfer.RecvCommand = "SSHGATE_XFER_SEND "+wire, "SSHGATE_XFER_RECV "+wire
	transfer.SendCommandSHA256, transfer.RecvCommandSHA256 = sha256Hex(transfer.SendCommand), sha256Hex(transfer.RecvCommand)
	transfer.Source.Path = "/" + strings.Repeat("<", MaxTransferPathBytes-1)
	transfer.Destination.Path = transfer.Source.Path
	tr.Transfer = &transfer
	tr.Rationale = strings.Repeat("<", MaxRationaleBytes)
	out["transfer"] = frozenR1(t, hostedWorst(tr), MaxRequiredApprovals, redacted, review)
	return out
}

func TestR1WorstCaseWithinBound(t *testing.T) {
	for name, frozen := range worstR1s(t) {
		if _, err := EncodeR1(frozen); err != nil {
			t.Fatalf("%s: frozen record: %v", name, err)
		}
		reservation := R1Reservation(frozen)
		t.Logf("%s: R1Reservation %d bytes (R1Max %d)", name, reservation, R1Max)
		if reservation*6/5 > R1Max {
			t.Errorf("%s: reservation %d leaves under 20%% margin to R1Max %d", name, reservation, R1Max)
		}
		g := grown(t, frozen)
		b, err := EncodeR1(g)
		if err != nil {
			t.Fatalf("%s: grown record: %v", name, err)
		}
		if len(b) > reservation {
			t.Errorf("%s: grown record encodes to %d bytes, above its reservation %d", name, len(b), reservation)
		}
		if got := R1Reservation(g); got != reservation {
			t.Errorf("%s: R1Reservation changed from %d at freeze to %d grown", name, reservation, got)
		}
		back, err := DecodeR1(b)
		if err != nil {
			t.Fatalf("%s: decode: %v", name, err)
		}
		if !bytes.Equal(mustCanon(t, back), b) {
			t.Fatalf("%s: round trip changed the bytes", name)
		}
	}
}

func TestR1ReservationCoversEveryFixture(t *testing.T) {
	for _, f := range fixtures() {
		if f.plan.Kind == KindRegisterTransferKey {
			continue
		}
		frozen := frozenR1(t, f.plan, 1, "x", reviewOK)
		reservation := R1Reservation(frozen)
		b, err := EncodeR1(grown(t, frozen))
		if err != nil {
			t.Fatalf("%s: %v", f.name, err)
		}
		if len(b) > reservation || reservation > R1Max {
			t.Errorf("%s: grown %d, reservation %d, R1Max %d", f.name, len(b), reservation, R1Max)
		}
	}
}

// TestR1ReservationSmallRecordBudget records the reservation of a one-step,
// 200-byte write with a 500-byte reason and checks that 256 of them, the
// local live cap, reserve at most half the payload budget (SA-9).
func TestR1ReservationSmallRecordBudget(t *testing.T) {
	d := jobDraft(idOne, strings.Repeat("r", MaxRationaleBytes), CoordinatorExecutor,
		step(1, RouteSignedWrite, strings.Repeat("w", 200), 60, route("web-1", fpA)))
	frozen := frozenR1(t, freeze(d, "local-uid:1000", ""), 1, strings.Repeat("r", MaxRationaleBytes), reviewOfSize(4096))
	r := R1Reservation(frozen)
	t.Logf("small record reserves %d bytes; %d live records reserve %d of %d", r, LocalLiveTotal, r*LocalLiveTotal, LocalPayloadBudget)
	if r*LocalLiveTotal > LocalPayloadBudget/2 {
		t.Fatalf("%d small live records reserve %d bytes, over half of LocalPayloadBudget %d", LocalLiveTotal, r*LocalLiveTotal, LocalPayloadBudget)
	}
}

func TestShedMaxCoversWorstShedRecord(t *testing.T) {
	for name, frozen := range worstR1s(t) {
		g := grown(t, frozen)
		shed := Shed(g)
		h := &shed.Header
		report := OutboxEvent{Seq: h.OutboxSeq - 1, Kind: strings.Repeat("k", MaxEventKindBytes), Operator: strings.Repeat("o", MaxOperatorIDBytes), Decision: strings.Repeat("d", MaxDecisionBytes),
			Detail: strings.Repeat("x", MaxDetailBytes), Assist: h.Decision.AssistBound.ptr(), NoiseDropped: math.MaxUint64}
		noise := report
		noise.Seq, noise.Replay, noise.Operator = h.OutboxSeq, true, strings.Repeat("o", MaxOperatorIDBytes)
		h.Outbox = []OutboxEvent{report, noise}
		h.AuditedThrough = h.OutboxSeq - 2
		b, err := EncodeR1(shed)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		t.Logf("%s: worst shed record %d bytes (ShedMax %d)", name, len(b), ShedMax)
		if len(b)*6/5 > ShedMax {
			t.Errorf("%s: worst shed record %d bytes leaves under 20%% margin to ShedMax %d", name, len(b), ShedMax)
		}
	}
}

func (a AssistBound) ptr() *AssistBound { return &a }

func TestShedKeepsTheHeader(t *testing.T) {
	frozen := frozenR1(t, fixtures()[0].plan, 1, "Restart nginx [hidden]", reviewOK)
	full := grown(t, frozen)
	full.Header.Outbox, full.Header.AuditedThrough = nil, full.Header.OutboxSeq
	shed := Shed(full)
	if shed.Payload != nil || !shed.Header.Shed {
		t.Fatal("Shed left the payload")
	}
	want := full.Header
	want.Shed = true
	if !bytes.Equal(mustCanon(t, shed.Header), mustCanon(t, want)) {
		t.Fatal("Shed changed a header field")
	}
	if full.Payload == nil {
		t.Fatal("Shed mutated its argument")
	}
	b, err := EncodeR1(shed)
	if err != nil {
		t.Fatal(err)
	}
	back, err := DecodeR1(b)
	if err != nil {
		t.Fatal(err)
	}
	if back.Header.RationaleRedacted != full.Header.RationaleRedacted ||
		!bytes.Equal(mustCanon(t, back.Header.Decision.AssistBound), mustCanon(t, full.Header.Decision.AssistBound)) {
		t.Fatal("shed lost the audit binding")
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(b, &fields); err != nil {
		t.Fatal(err)
	}
	if len(fields) != 1 || fields["header"] == nil {
		t.Fatalf("a shed record holds more than its header: %v", keys(fields))
	}
}

func keys(m map[string]json.RawMessage) []string {
	var out []string
	for k := range m {
		out = append(out, k)
	}
	return out
}

func TestRequiredApprovalsBounds(t *testing.T) {
	for _, n := range []int{0, -1, MaxRequiredApprovals + 1} {
		rec := frozenR1(t, fixtures()[0].plan, n, "x", reviewOK)
		if _, err := EncodeR1(rec); codeOf(err) != CodeInvalidRequest || fieldOf(err) != "required_approvals" {
			t.Errorf("required_approvals %d: EncodeR1 = %v", n, err)
		}
	}
	ok := frozenR1(t, fixtures()[0].plan, MaxRequiredApprovals, "x", reviewOK)
	b, err := EncodeR1(ok)
	if err != nil {
		t.Fatal(err)
	}
	bad := bytes.Replace(b, []byte(`"required_approvals":256`), []byte(`"required_approvals":257`), 1)
	if _, err := DecodeR1(bad); codeOf(err) != CodeRecordCorrupt {
		t.Errorf("DecodeR1 of 257 approvals = %v", err)
	}
}

func TestDecodeR1Refusals(t *testing.T) {
	frozen := frozenR1(t, fixtures()[1].plan, 1, "x", reviewOK)
	good, err := EncodeR1(frozen)
	if err != nil {
		t.Fatal(err)
	}
	mutate := func(f func(*R1)) []byte {
		rec := frozen
		p := *frozen.Payload
		rec.Payload = &p
		rec.Header.Votes = append([]Vote{}, frozen.Header.Votes...)
		f(&rec)
		b, err := json.Marshal(rec)
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	vote := Vote{Operator: "op", Decision: VoteApprove, TS: t0, Authn: "telegram"}
	cases := map[string][]byte{
		"whitespace":        append([]byte(" "), good...),
		"unknown field":     bytes.Replace(good, []byte(`"version":1,`), []byte(`"version":1,"extra":1,`), 1),
		"oversized":         append(append([]byte{}, good...), make([]byte, R1Max)...),
		"payload missing":   mutate(func(r *R1) { r.Payload = nil }),
		"shed with payload": mutate(func(r *R1) { r.Header.Shed = true }),
		"plan hash":         mutate(func(r *R1) { r.Header.PlanHash = digestA }),
		"tampered plan":     mutate(func(r *R1) { r.Payload.Plan.Rationale = "something else" }),
		"principal":         mutate(func(r *R1) { r.Header.Principal = "local-uid:1001" }),
		"duplicate vote":    mutate(func(r *R1) { r.Header.Votes = []Vote{vote, vote} }),
		"vote cap": mutate(func(r *R1) {
			for i := range VoteCap(*r) + 1 {
				r.Header.Votes = append(r.Header.Votes, Vote{Operator: fmt.Sprintf("op%d", i), Decision: VoteDeny, TS: t0, Authn: "telegram"})
			}
		}),
		"outbox order": mutate(func(r *R1) {
			r.Header.OutboxSeq = 2
			r.Header.Outbox = []OutboxEvent{{Seq: 2, Kind: "vote"}, {Seq: 1, Kind: "vote"}}
		}),
		"outbox past seq": mutate(func(r *R1) { r.Header.Outbox = []OutboxEvent{{Seq: 1, Kind: "vote"}} }),
		"decided_by over bound": mutate(func(r *R1) {
			r.Header.OutboxSeq = 1
			r.Header.Outbox = []OutboxEvent{{Seq: 1, Kind: "decision", DecidedBy: strings.Repeat("o", 200)}}
		}),
		"two decided_by": mutate(func(r *R1) {
			r.Header.OutboxSeq = 2
			r.Header.Outbox = []OutboxEvent{{Seq: 1, Kind: "decision", DecidedBy: "op"}, {Seq: 2, Kind: "decision", DecidedBy: "op"}}
		}),
		"signatures without mint": mutate(func(r *R1) { r.Payload.Signatures = []string{"SSHGATE_SIG:x:y"} }),
		"pending decision": mutate(func(r *R1) {
			r.Header.Decision = &Decision{Status: ApprovalPending, DecidedAt: t0, DecidedBy: "clock", Epoch: epochA, AssistBound: AssistBound{State: AssistPreparing}}
		}),
		"mint reason":         mutate(func(r *R1) { r.Header.Mint = &MintSlot{State: MintError, Reason: "oops"} }),
		"review not object":   mutate(func(r *R1) { r.Payload.ReviewSnapshot = json.RawMessage(`"x"`) }),
		"assist without slot": mutate(func(r *R1) { a := maxAssist(); r.Payload.AssistResult = &a }),
		"renotify gen":        mutate(func(r *R1) { r.Header.RenotifyGen = MaxBursts + 2 }),
		"step ttl":            mutate(func(r *R1) { r.Header.StepTTLs[1] = 30 }),
		"register kind":       mutate(func(r *R1) { r.Header.Kind = KindRegisterTransferKey }),
	}
	for name, b := range cases {
		if _, err := DecodeR1(b); codeOf(err) != CodeRecordCorrupt {
			t.Errorf("%s: DecodeR1 = %v, want record_corrupt", name, err)
		}
	}
	if _, err := DecodeR1(good); err != nil {
		t.Fatalf("the unmutated record: %v", err)
	}
}

func TestRecordKeys(t *testing.T) {
	a, b := RecordKey("local-uid:1000", idOne), RecordKey("local-uid:1001", idOne)
	if a == b || RecordHandle(a) == RecordHandle(b) {
		t.Fatal("two principals with one request ID share a key or handle")
	}
	for _, k := range []string{a, b, JobKey(idOne), HostedRecordKey("client", "", idOne)} {
		if len(k) != 54 || !allBytes(k[2:], isLowerBase32Byte) || k[1] != '-' {
			t.Errorf("key %q is not a 2-char prefix and 52 lowercase base32 characters", k)
		}
		if !ValidRecordHandle(RecordHandle(k)) {
			t.Errorf("handle of %q is malformed", k)
		}
	}
	if HostedRecordKey("c", "local-uid:1", idOne) == HostedRecordKey("c", "", idOne) {
		t.Fatal("hosted sub_principal does not separate keys")
	}
	if HostedRecordKey("c", "", idOne) == RecordKey("c", idOne) {
		t.Fatal("hosted and local keys share a space")
	}
	if EventKey(a, 7) != a+":7" {
		t.Fatal("EventKey")
	}
}

func TestOutboxMax(t *testing.T) {
	rec := frozenR1(t, fixtures()[0].plan, 1, "x", reviewOK)
	if got, want := OutboxMax(rec), 1+VoteSlack+123; got != want {
		t.Fatalf("OutboxMax = %d, want %d", got, want)
	}
}

// worstR2 is the largest job record: the worst draft, every step's result at
// its bounds, every slot filled, and 8 MiB of bodies of invalid UTF-8 and '<'
// spread over all 64 bodies.
func worstJob(t testing.TB) R2 {
	t.Helper()
	d := worstDraft()
	draftHash, err := DraftHash(d)
	if err != nil {
		t.Fatal(err)
	}
	pattern := []byte{0xff, '<', 0xfe, '>', 0xc3, '&', 0x00, 0x80}
	body := bytes.Repeat(pattern, MaxJobOutputBytes/64/len(pattern))
	exit, final := 255, t0.Add(time.Hour)
	job := R2{
		Version: R2Version, RequestID: d.RequestID, InputHash: digestA, Draft: d, DraftHash: draftHash, CreatedAt: t0,
		Reservation: int64(R2Reservation(d, MaxJobOutputBytes)), ClaimToken: digestA, SignerAck: digestA,
		Outcome: &JobOutcome{Kind: OutcomeJobError, Code: CodeRequestUnrenderable}, ReportResult: &ReportResult{State: ReportRefused, Code: CodeRequestUnrenderable},
		FirstDeliveredAt: &final, FinalAt: &final,
	}
	bodyDigest := sha256Hex(string(body))
	for i := 1; i <= len(d.CommandJob.Steps); i++ {
		job.Steps = append(job.Steps, JobStep{
			Ordinal: i, Marker: &Marker{Epoch: epochA, At: t0.Add(999999999)},
			Result: &StepResult{
				Status: StepFailed, ExitCode: &exit, StdoutBytes: math.MaxInt64, StderrBytes: math.MaxInt64, Truncated: true,
				StdoutSHA256: bodyDigest, StderrSHA256: bodyDigest, Stdout: body, Stderr: body,
				Annotation: strings.Repeat("n", MaxAnnotationBytes),
			},
		})
	}
	return job
}

func TestR2WorstCaseWithinBound(t *testing.T) {
	job := worstJob(t)
	nonBody := job
	nonBody.Steps = nil
	for _, s := range job.Steps {
		r := *s.Result
		r.Stdout, r.Stderr = nil, nil
		s.Result = &r
		nonBody.Steps = append(nonBody.Steps, s)
	}
	nb := len(mustCanon(t, nonBody))
	t.Logf("worst non-body R2 %d bytes (R2NonBodyMax %d); R2Max %d", nb, R2NonBodyMax, R2Max)
	if nb*6/5 > R2NonBodyMax {
		t.Errorf("non-body part %d leaves under 20%% margin to R2NonBodyMax %d", nb, R2NonBodyMax)
	}
	b, err := EncodeR2(job)
	if err != nil {
		t.Fatal(err)
	}
	if len(b) > R2Max {
		t.Fatalf("worst job %d bytes exceeds R2Max %d", len(b), R2Max)
	}
	if r := R2Reservation(job.Draft, MaxJobOutputBytes); r < len(b) || r > R2Max {
		t.Fatalf("R2Reservation %d is below the encoded job %d or above R2Max %d", r, len(b), R2Max)
	}
	if old := 4*((MaxJobOutputBytes+2)/3) + 64<<10; len(b) <= old {
		t.Fatalf("r5.1's bound %d holds this job (%d bytes); the derivation regressed", old, len(b))
	}
	back, err := DecodeR2(b)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(mustCanon(t, back), b) || !bytes.Equal(back.Steps[3].Result.Stdout, job.Steps[3].Result.Stdout) {
		t.Fatal("a job with invalid UTF-8 bodies does not round-trip byte-exactly")
	}
}

func TestR2Refusals(t *testing.T) {
	base := func() R2 {
		d := *fixtures()[0].draft
		h, _ := DraftHash(d)
		return R2{Version: R2Version, RequestID: d.RequestID, InputHash: digestA, Draft: d, DraftHash: h, CreatedAt: t0,
			Reservation: int64(R2Reservation(d, PermittedOutputBytes(d))), ClaimToken: digestA, Steps: []JobStep{{Ordinal: 1}}}
	}
	if _, err := EncodeR2(base()); err != nil {
		t.Fatalf("base job: %v", err)
	}
	big := bytes.Repeat([]byte("x"), MaxStreamOutputBytes+1)
	cases := map[string]func(*R2){
		"draft hash":  func(j *R2) { j.DraftHash = digestA },
		"request id":  func(j *R2) { j.RequestID = idTwo },
		"step count":  func(j *R2) { j.Steps = append(j.Steps, JobStep{Ordinal: 2}) },
		"ordinal":     func(j *R2) { j.Steps[0].Ordinal = 2 },
		"grant draft": func(j *R2) { j.Draft = *fixtures()[6].draft; j.RequestID = j.Draft.RequestID },
		"body over cap": func(j *R2) {
			j.Steps[0].Result = retained(big, nil)
		},
		"unknown status": func(j *R2) {
			j.Steps[0].Result = &StepResult{Status: "ok", StdoutSHA256: digestA, StderrSHA256: digestA}
		},
		"outcome code":         func(j *R2) { j.Outcome = &JobOutcome{Kind: OutcomeDenied, Code: CodeBusy} },
		"adopted class":        func(j *R2) { j.Outcome = &JobOutcome{Kind: OutcomeAdopted} },
		"refused code":         func(j *R2) { j.ReportResult = &ReportResult{State: ReportRefused} },
		"reservation":          func(j *R2) { j.Reservation = 0 },
		"one-byte reservation": func(j *R2) { j.Reservation = 1 },
		"reservation below the draft's worst case": func(j *R2) {
			j.Reservation = int64(R2Reservation(j.Draft, PermittedOutputBytes(j.Draft))) - 1
		},
		"marker": func(j *R2) { j.Steps[0].Marker = &Marker{Epoch: "x", At: t0} },
	}
	for name, f := range cases {
		j := base()
		f(&j)
		if _, err := EncodeR2(j); err == nil {
			t.Errorf("%s: EncodeR2 accepted it", name)
		}
		b, _ := json.Marshal(j)
		if _, err := DecodeR2(b); codeOf(err) != CodeRecordCorrupt {
			t.Errorf("%s: DecodeR2 = %v, want record_corrupt", name, err)
		}
	}
	if _, err := DecodeR2(make([]byte, R2Max+1)); codeOf(err) != CodeRecordCorrupt {
		t.Error("an oversized R2 file was not refused")
	}
}

func TestR2ReservationScalesWithOutput(t *testing.T) {
	d := *fixtures()[0].draft
	none, full := R2Reservation(d, 0), R2Reservation(d, MaxJobOutputBytes)
	if full-none != 4*((MaxJobOutputBytes+2)/3) {
		t.Fatalf("8 MiB of output reserves %d bytes more, want its base64 length", full-none)
	}
	if R2Reservation(d, -1) != full || R2Reservation(d, MaxJobOutputBytes+1) != full {
		t.Fatal("an out-of-range output cap must reserve the maximum")
	}
}

func TestFinalReportMatchesItsSteps(t *testing.T) {
	encode := func(f func(*FinalReport)) error {
		rec := stateR1(t)
		fr := *rec.Header.FinalReport
		fr.Steps = append([]StepReport{}, fr.Steps...)
		f(&fr)
		rec.Header.FinalReport = &fr
		_, err := EncodeR1(rec)
		return err
	}
	if err := encode(func(*FinalReport) {}); err != nil {
		t.Fatal(err)
	}
	many := make([]int, 100000)
	for i := range many {
		many[i] = 1
	}
	refused := map[string]func(*FinalReport){
		"100000 copies of ordinal 1": func(f *FinalReport) { f.ExecutedOrdinals = many },
		"duplicate ordinal":          func(f *FinalReport) { f.ExecutedOrdinals = []int{1, 1} },
		"missing ordinal":            func(f *FinalReport) { f.ExecutedOrdinals = nil },
		"wrong class":                func(f *FinalReport) { f.Class = ClassFailed },
		"wrong partial":              func(f *FinalReport) { f.Partial = true },
		"not_run with an exit code": func(f *FinalReport) {
			exit := 0
			f.Steps[0] = StepReport{Ordinal: 1, Status: StepNotRun, ExitCode: &exit}
			f.Class, f.ExecutedOrdinals = ClassSucceeded, nil
		},
		"skipped first": func(f *FinalReport) {
			f.Steps[0] = StepReport{Ordinal: 1, Status: StepSkipped}
			f.Class, f.ExecutedOrdinals = ClassSucceeded, nil
		},
	}
	for name, f := range refused {
		if err := encode(f); fieldOf(err) == "" || codeOf(err) != CodeInvalidRequest {
			t.Errorf("%s: EncodeR1 = %v", name, err)
		}
	}
	// The same record arriving as bytes is quarantined.
	good, err := EncodeR1(stateR1(t))
	if err != nil {
		t.Fatal(err)
	}
	bad := bytes.Replace(good, []byte(`"executed_ordinals":[1]`), []byte(`"executed_ordinals":[1,1,1,1]`), 1)
	if _, err := DecodeR1(bad); codeOf(err) != CodeRecordCorrupt {
		t.Fatalf("DecodeR1 with a repeated mask = %v", err)
	}
}

func TestShedLimitsAtTheCodec(t *testing.T) {
	rec := Shed(stateR1(t))
	h := &rec.Header
	h.Outbox = []OutboxEvent{{Seq: 7, Kind: "report"}, {Seq: 8, Kind: "invalid_report", Replay: true}, {Seq: 9, Kind: "invalid_report", Replay: true}}
	h.AuditedThrough = 6
	if _, err := EncodeR1(rec); fieldOf(err) != "outbox" {
		t.Fatalf("a shed record with three unflushed events: %v", err)
	}
	if err := checkR1Size(rec, ShedMax+1); err == nil {
		t.Fatal("a shed record over ShedMax passed the codec")
	}
	full := stateR1(t)
	if err := checkR1Size(full, R1Reservation(full)+1); err == nil {
		t.Fatal("a full record over its reservation passed the codec")
	}
	if err := checkR1Size(full, R1Max+1); err == nil {
		t.Fatal("a record over R1Max passed the codec")
	}
}

// TestR1ReservationCoversVariedFields varies every event and set field the
// validators admit independently (present at its bound or absent), and
// checks that each such record still encodes, which the codec allows only
// within its reservation.
func TestR1ReservationCoversVariedFields(t *testing.T) {
	rng := rand.New(rand.NewPCG(7, 11))
	frozens := []R1{frozenR1(t, fixtures()[0].plan, 1, "x", reviewOK), frozenR1(t, fixtures()[8].plan, 3, "x", reviewOK)}
	for name, f := range worstR1s(t) {
		if name == "command_job" {
			frozens = append(frozens, f)
		}
	}
	for _, frozen := range frozens {
		reservation := R1Reservation(frozen)
		for range 40 {
			g := grown(t, frozen)
			h := &g.Header
			for i := range h.Outbox {
				e := &h.Outbox[i]
				pick := func() bool { return rng.IntN(2) == 0 }
				if pick() {
					e.Operator = ""
				}
				if pick() {
					e.Decision = ""
				}
				if pick() {
					e.Detail = ""
				}
				if pick() {
					e.Assist = nil
				}
				e.Replay = pick()
				if pick() {
					e.NoiseDropped = 0
				}
			}
			if rng.IntN(3) == 0 {
				h.Outbox = h.Outbox[:rng.IntN(len(h.Outbox))]
			}
			p := g.Payload
			p.CardEntries = p.CardEntries[:rng.IntN(len(p.CardEntries)+1)]
			p.Bursts = p.Bursts[:rng.IntN(len(p.Bursts)+1)]
			h.Votes = h.Votes[:rng.IntN(len(h.Votes)+1)]
			b, err := EncodeR1(g)
			if err != nil {
				t.Fatalf("%s: a varied valid record does not encode: %v", frozen.Header.Kind, err)
			}
			if len(b) > reservation {
				t.Fatalf("%s: %d bytes over reservation %d", frozen.Header.Kind, len(b), reservation)
			}
		}
	}
}

func TestR2RefusesTransientCodesAsSettlement(t *testing.T) {
	base := func() R2 {
		d := *fixtures()[0].draft
		h, _ := DraftHash(d)
		final := t0.Add(time.Minute)
		return R2{Version: R2Version, RequestID: d.RequestID, InputHash: digestA, Draft: d, DraftHash: h, CreatedAt: t0,
			Reservation: int64(R2Reservation(d, PermittedOutputBytes(d))), FinalAt: &final, Steps: []JobStep{{Ordinal: 1}}}
	}
	for _, c := range AllCodes {
		for context, set := range map[string]func(*R2){
			"report_result": func(j *R2) { j.ReportResult = &ReportResult{State: ReportRefused, Code: c} },
			"outcome":       func(j *R2) { j.Outcome = &JobOutcome{Kind: OutcomeJobError, Code: c} },
		} {
			j := base()
			set(&j)
			_, err := EncodeR2(j)
			if c.Retryable() != (err != nil) {
				t.Errorf("%s with %s (retryable=%v): EncodeR2 = %v", context, c, c.Retryable(), err)
			}
		}
	}
	j := base()
	j.Outcome = &JobOutcome{Kind: OutcomeJobError}
	if _, err := EncodeR2(j); err != nil {
		t.Fatalf("an error outcome without a code: %v", err)
	}
}

// retained is a result whose stored bodies agree with their counts and
// digests.
func retained(stdout, stderr []byte) *StepResult {
	return &StepResult{
		Status: StepSucceeded, StdoutBytes: int64(len(stdout)), StderrBytes: int64(len(stderr)),
		StdoutSHA256: sha256Hex(string(stdout)), StderrSHA256: sha256Hex(string(stderr)), Stdout: stdout, Stderr: stderr,
	}
}

// smallCapJob is a one-step job whose draft caps each stream at capBytes.
func smallCapJob(t *testing.T, capBytes int64) R2 {
	t.Helper()
	d := *fixtures()[0].draft
	job := *d.CommandJob
	job.MaxOutputBytes = capBytes
	d.CommandJob = &job
	h, err := DraftHash(d)
	if err != nil {
		t.Fatal(err)
	}
	return R2{Version: R2Version, RequestID: d.RequestID, InputHash: digestA, Draft: d, DraftHash: h, CreatedAt: t0,
		Reservation: int64(R2Reservation(d, PermittedOutputBytes(d))), Steps: []JobStep{{Ordinal: 1}}}
}

// expectR2Refused checks a job is refused by EncodeR2 and, as bytes, by
// DecodeR2.
func expectR2Refused(t *testing.T, name string, j R2) {
	t.Helper()
	if _, err := EncodeR2(j); err == nil {
		t.Errorf("%s: EncodeR2 accepted it", name)
	}
	b, err := json.Marshal(j)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := DecodeR2(b); codeOf(err) != CodeRecordCorrupt {
		t.Errorf("%s: DecodeR2 = %v, want record_corrupt", name, err)
	}
}

func TestR2OutputWithinTheDraftAndReservation(t *testing.T) {
	j := smallCapJob(t, 1)
	if got := PermittedOutputBytes(j.Draft); got != 2 {
		t.Fatalf("PermittedOutputBytes = %d, want 2 (one step, two streams of 1 byte)", got)
	}
	j.Steps[0].Result = retained([]byte("a"), []byte("b"))
	b, err := EncodeR2(j)
	if err != nil {
		t.Fatalf("output within a 1-byte cap: %v", err)
	}
	if _, err := DecodeR2(b); err != nil {
		t.Fatal(err)
	}
	if int64(len(b)) > j.Reservation {
		t.Fatalf("encoded %d bytes over the reservation %d", len(b), j.Reservation)
	}

	over := smallCapJob(t, 1)
	over.Steps[0].Result = retained([]byte("ab"), nil)
	expectR2Refused(t, "2-byte body under a 1-byte cap", over)

	mib := smallCapJob(t, 1)
	mib.Reservation = int64(R2Reservation(mib.Draft, 2))
	mib.Steps[0].Result = retained(bytes.Repeat([]byte("x"), MaxStreamOutputBytes), nil)
	expectR2Refused(t, "1 MiB of stdout under a 1-byte cap", mib)

	under := smallCapJob(t, 1)
	under.Reservation = 1
	expectR2Refused(t, "1-byte reservation", under)

}

// TestR2FullStreamFitsTheDraftFloor fills one stream to its cap with the
// worst-escaping byte and checks the record stays within the reservation the
// draft's floor demands, which the codec enforces on both sides.
func TestR2FullStreamFitsTheDraftFloor(t *testing.T) {
	j := smallCapJob(t, MaxStreamOutputBytes)
	j.Steps[0].Result = retained(bytes.Repeat([]byte("<"), MaxStreamOutputBytes), bytes.Repeat([]byte{0xff}, MaxStreamOutputBytes))
	b, err := EncodeR2(j)
	if err != nil {
		t.Fatal(err)
	}
	if floor := int64(R2Reservation(j.Draft, PermittedOutputBytes(j.Draft))); int64(len(b)) > floor {
		t.Fatalf("%d bytes over the draft floor %d", len(b), floor)
	}
	if _, err := DecodeR2(b); err != nil {
		t.Fatal(err)
	}
}

func TestR2RemovedBodiesAreGone(t *testing.T) {
	j := smallCapJob(t, MaxStreamOutputBytes)
	j.Steps[0].Result = retained([]byte("secret\n"), []byte("warn\n"))
	if _, err := EncodeR2(j); err != nil {
		t.Fatal(err)
	}
	removed := j
	removed.BodiesRemoved = &BodiesRemoved{Cause: "retention"}
	expectR2Refused(t, "bodies_removed with bodies present", removed)

	unstorable := j
	r := *j.Steps[0].Result
	r.BodiesUnstorable = true
	unstorable.Steps = []JobStep{{Ordinal: 1, Result: &r}}
	expectR2Refused(t, "bodies_unstorable with bodies present", unstorable)

	// Removing the bodies keeps the digests and counts of what was there.
	for name, mk := range map[string]func() R2{
		"removed": func() R2 {
			k := removed
			r := *j.Steps[0].Result
			r.Stdout, r.Stderr = nil, nil
			k.Steps = []JobStep{{Ordinal: 1, Result: &r}}
			return k
		},
		"unstorable": func() R2 {
			k := j
			r := *j.Steps[0].Result
			r.Stdout, r.Stderr, r.BodiesUnstorable = nil, nil, true
			k.Steps = []JobStep{{Ordinal: 1, Result: &r}}
			return k
		},
	} {
		b, err := EncodeR2(mk())
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if _, err := DecodeR2(b); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
	}
}

func TestR2RetainedBodiesMatchTheirMetadata(t *testing.T) {
	mutate := func(f func(*StepResult)) R2 {
		j := smallCapJob(t, MaxStreamOutputBytes)
		r := retained([]byte("ok <\xff>\n"), nil)
		f(r)
		j.Steps[0].Result = r
		return j
	}
	if _, err := EncodeR2(mutate(func(*StepResult) {})); err != nil {
		t.Fatal(err)
	}
	cases := map[string]func(*StepResult){
		"body changed":           func(r *StepResult) { r.Stdout = []byte("ok >\xff<\n") },
		"stdout digest":          func(r *StepResult) { r.StdoutSHA256 = digestA },
		"stderr digest":          func(r *StepResult) { r.StderrSHA256 = digestA },
		"count without truncate": func(r *StepResult) { r.StdoutBytes = 12 },
		"truncated short count":  func(r *StepResult) { r.Truncated, r.StdoutBytes = true, 3 },
	}
	for name, f := range cases {
		expectR2Refused(t, name, mutate(f))
	}
	if _, err := EncodeR2(mutate(func(r *StepResult) { r.Truncated, r.StdoutBytes = true, 1<<20 })); err != nil {
		t.Fatalf("a truncated stream that produced more than it kept: %v", err)
	}
}
