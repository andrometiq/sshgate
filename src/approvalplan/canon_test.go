package approvalplan

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/karthikeyan5/sshgate/internal/elapsed/elapsedtest"
)

var update = flag.Bool("update", false, "rewrite the goldens in testdata/")

// golden compares got with testdata/name. Goldens freeze stored identities:
// a change needs a version bump, never a regenerated golden alone.
func golden(t *testing.T, name string, got []byte) {
	t.Helper()
	path := filepath.Join("testdata", name)
	if *update {
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, got, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("golden %s: %v", name, err)
	}
	if !bytes.Equal(got, want) {
		t.Errorf("golden %s differs\n got: %.400s\nwant: %.400s", name, got, want)
	}
}

func TestGoldenDraftsAndPlans(t *testing.T) {
	var lines []string
	for _, f := range fixtures() {
		if f.draft != nil {
			b := mustCanon(t, *f.draft)
			golden(t, "drafts/"+f.name+".json", b)
			h, err := DraftHash(*f.draft)
			if err != nil {
				t.Fatal(err)
			}
			if h != hashHex("sshgate-approval-draft-v1\x00", b) {
				t.Fatalf("%s: DraftHash is not the hash of the canonical bytes", f.name)
			}
			lines = append(lines, fmt.Sprintf("%s draft_hash %s", f.name, h))
		}
		b := mustCanon(t, f.plan)
		golden(t, "plans/"+f.name+".json", b)
		h, err := PlanHash(f.plan)
		if err != nil {
			t.Fatal(err)
		}
		lines = append(lines, fmt.Sprintf("%s plan_hash %s", f.name, h))
		var back ApprovalPlanV1
		if err := decodeCanonical(b, &back); err != nil || back.Validate() != nil {
			t.Fatalf("%s: plan does not decode strictly: %v", f.name, err)
		}
	}
	web := route("web-1", fpA)
	lines = append(lines,
		"route_digest web-1 "+web.Digest(),
		"record_key "+RecordKey("local-uid:1000", idOne),
		"record_handle "+RecordHandle(RecordKey("local-uid:1000", idOne)),
		"hosted_record_key "+HostedRecordKey("machine-client", "local-uid:1000", idOne),
		"hosted_record_handle "+RecordHandle(HostedRecordKey("machine-client", "local-uid:1000", idOne)),
		"job_key "+JobKey(idOne),
		"event_key "+EventKey(RecordKey("local-uid:1000", idOne), 42),
		"claim_token_hash "+ClaimTokenHash(tokenA),
		"challenge_hash "+ChallengeHash("0123456789abcdef"),
		"session_binding "+SessionBinding("session-id"),
		"legacy_hosted_plan_hash "+LegacyHostedPlanHash("r_abc", "machine-client", []byte(`["ls"]`), t0, 2),
		"challenge_mac_input "+hex.EncodeToString(ChallengeMACInput(ChallengeBinding{
			Plane: PlaneV2, RecordKey: HostedRecordKey("machine-client", "", idOne), PlanHash: digestA, Operator: "alice",
			SessionBinding: SessionBinding("session-id"), AssistRevision: 1, AssistDigest: digestA,
			AllowedActions: []string{ActionApprove, ActionDeny}, ExpiresAt: t0.Unix(), Nonce: make([]byte, 16),
		})),
		"assist_digest "+AssistDigest(okAssist()),
		"unavailable_assist_digest "+UnavailableAssistDigest(AssistDeadlineReason, t0.Add(5*time.Second)),
	)
	input, err := InputHash(struct {
		RequestID      string    `json:"request_id"`
		SubmitNotAfter time.Time `json:"submit_not_after"`
	}{idOne, t0.Add(SubmitWindowMax)})
	if err != nil {
		t.Fatal(err)
	}
	lines = append(lines, "input_hash "+input)
	zero := bytes.NewReader(make([]byte, 64))
	id, _ := NewRequestID(zero)
	handle, _ := NewCardHandle(zero)
	chal, _ := NewChallenge(zero)
	epoch, _ := NewEpoch(zero)
	lines = append(lines, "zero_request_id "+id, "zero_card_handle "+handle, "zero_challenge "+chal, "zero_epoch "+epoch)
	golden(t, "hashes.txt", []byte(strings.Join(lines, "\n")+"\n"))
}

func TestGoldenCodesAndMarkers(t *testing.T) {
	var codes []string
	for _, c := range AllCodes {
		codes = append(codes, fmt.Sprintf("%s retryable=%v", c, c.Retryable()))
	}
	golden(t, "codes.txt", []byte(strings.Join(codes, "\n")+"\n"))
	markers := []string{
		HiddenMarker(0, nil),
		HiddenMarker(12, nil),
		HiddenMarker(40, []string{"aws-access-token"}),
		HiddenMarker(4096, []string{"pem-block", "generic-api-key", "pem-block"}),
	}
	golden(t, "hidden_markers.txt", []byte(strings.Join(markers, "\n")+"\n"))
}

// stateR1 is the write fixture's record approved, claimed and reported, with
// two events still unflushed.
func stateR1(t *testing.T) R1 {
	rec := frozenR1(t, fixtures()[0].plan, 1, "Restart nginx after the config change", reviewOK)
	h := &rec.Header
	a := okAssist()
	rec.Payload.AssistResult = &a
	h.Assist = &AssistSlot{State: AssistReady, GeneratedAt: a.GeneratedAt, Digest: AssistDigest(a)}
	bound := AssistBound{State: AssistReady, Revision: 1, Digest: h.Assist.Digest}
	decided := t0.Add(40 * time.Second)
	h.Votes = []Vote{{Operator: "telegram:42", Decision: VoteApprove, TS: decided, Authn: "telegram"}}
	h.Decision = &Decision{Status: ApprovalApproved, DecidedAt: decided, DecidedBy: "telegram:42", Epoch: epochA, AssistBound: bound}
	h.Mint = &MintSlot{State: MintSignatures, Digest: digestA}
	h.ClaimCount = 1
	exit, out, errb, trunc := 0, int64(12), int64(0), false
	h.FinalReport = &FinalReport{
		Class: ClassSucceeded, ExecutedOrdinals: []int{1}, ResultDigest: digestA, BodyDigest: digestA,
		Steps: []StepReport{{Ordinal: 1, Status: StepSucceeded, ExitCode: &exit, StdoutBytes: &out, StderrBytes: &errb, Truncated: &trunc}},
	}
	msg := int64(1001)
	rec.Payload.CardEntries = []CardEntry{{Handle: "abcdefghijkl", Rev: 1, ChalHash: ChallengeHash("0123456789abcdef"), Actions: []string{ActionApprove, ActionDeny}, Kind: CardFirst, Epoch: epochA, MsgID: &msg, Outcome: OutcomeSent}}
	rec.Payload.Bursts = []Burst{{Epoch: epochA, StartedAt: t0.Add(time.Second), PartMsgIDs: []int64{1000}, Outcome: OutcomeSent}}
	rec.Payload.StatusEdits = []StatusEdit{{State: "approved"}}
	h.OutboxSeq, h.AuditedThrough = 9, 7
	h.Outbox = []OutboxEvent{
		{Seq: 8, Kind: "minted"},
		{Seq: 9, Kind: "report", Detail: "succeeded"},
	}
	return rec
}

func TestGoldenRecords(t *testing.T) {
	rec := stateR1(t)
	b, err := EncodeR1(rec)
	if err != nil {
		t.Fatal(err)
	}
	golden(t, "r1-write.json", b)
	shedRec := Shed(rec)
	shedRec.Header.Outbox, shedRec.Header.AuditedThrough = nil, shedRec.Header.OutboxSeq
	sb, err := EncodeR1(shedRec)
	if err != nil {
		t.Fatal(err)
	}
	golden(t, "r1-write-shed.json", sb)

	d := *fixtures()[0].draft
	dh, _ := DraftHash(d)
	exit, final, stdout := 0, t0.Add(time.Minute), []byte("ok <\xff>\n")
	job := R2{
		Version: R2Version, RequestID: d.RequestID, InputHash: digestA, Draft: d, DraftHash: dh, CreatedAt: t0,
		Reservation: int64(R2Reservation(d, MaxJobOutputBytes)), SignerAck: digestA,
		ReportResult: &ReportResult{State: ReportAcked}, FinalAt: &final,
		Steps: []JobStep{{Ordinal: 1, Marker: &Marker{Epoch: epochA, At: t0.Add(45 * time.Second)}, Result: &StepResult{
			Status: StepSucceeded, ExitCode: &exit, StdoutBytes: int64(len(stdout)), StdoutSHA256: sha256Hex(string(stdout)),
			StderrSHA256: sha256Hex(""), Stdout: stdout,
		}}},
	}
	jb, err := EncodeR2(job)
	if err != nil {
		t.Fatal(err)
	}
	golden(t, "r2-write.json", jb)
	for name, raw := range map[string][]byte{"r1": b, "r1-shed": sb} {
		if _, err := DecodeR1(raw); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
	if _, err := DecodeR2(jb); err != nil {
		t.Error(err)
	}
	lines := []string{
		fmt.Sprintf("R1Max %d", R1Max), fmt.Sprintf("ShedMax %d", ShedMax), fmt.Sprintf("R2NonBodyMax %d", R2NonBodyMax),
		fmt.Sprintf("R2BodyOverhead %d", R2BodyOverhead), fmt.Sprintf("R2Max %d", R2Max), fmt.Sprintf("MaxDraftBytes %d", MaxDraftBytes),
		fmt.Sprintf("LocalPayloadBudget %d", LocalPayloadBudget), fmt.Sprintf("ReviewSnapshotMax %d", ReviewSnapshotMax),
		fmt.Sprintf("OutboxMax(N=1) %d", OutboxMax(rec)),
		fmt.Sprintf("R1Reservation(r1-write) %d", R1Reservation(rec)),
		fmt.Sprintf("R2Reservation(write, 8 MiB) %d", R2Reservation(d, MaxJobOutputBytes)),
	}
	golden(t, "bounds.txt", []byte(strings.Join(lines, "\n")+"\n"))
}

func TestCanonicalMatchesSecurestate(t *testing.T) {
	// securestate stores and demands exactly json.Marshal's bytes.
	v := map[string]string{"cmd": "<a>&\u2028"}
	got, err := Canonical(v)
	if err != nil {
		t.Fatal(err)
	}
	want, _ := json.Marshal(v)
	if !bytes.Equal(got, want) || !bytes.Contains(got, []byte(`\`+"u003c")) {
		t.Fatalf("Canonical = %s", got)
	}
	if _, err := Canonical(func() {}); err == nil {
		t.Fatal("Canonical of an unencodable value succeeded")
	}
}

func TestClaimTokenHashIsTheSpecDigest(t *testing.T) {
	var token [32]byte
	for i := range token {
		token[i] = byte(i)
	}
	want := hashHex("sshgate-executor-claim-v1", token[:])
	if ClaimTokenHash(token) != want || !ValidSHA256Hex(want) {
		t.Fatal("ClaimTokenHash")
	}
}

// TestNoDirectTimeReads holds approvalplan to taking time as arguments: its
// pure core judges deadlines only on the (wall, elapsed) pair it is given.
func TestNoDirectTimeReads(t *testing.T) {
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	var src []string
	for _, f := range files {
		if !strings.HasSuffix(f, "_test.go") {
			src = append(src, f)
		}
	}
	elapsedtest.AssertNoDirectTimeReads(t, src)
}

func TestCheckCanonicalJSON(t *testing.T) {
	esc := `\u`
	accepted := []string{
		`{}`, `{"a":{"b":[1,-2,0,"x` + esc + `003c",true,false,null,{}]},"c":[]}`,
		`{"segments":[{"text":"caf` + "é" + `","spans":[{"start":0,"rules":["a","b"]}]}]}`,
	}
	for _, s := range accepted {
		if err := checkCanonicalJSON([]byte(s)); err != nil {
			t.Errorf("%s: %v", s, err)
		}
	}
	refused := map[string]string{
		"top duplicate":      `{"a":1,"a":2}`,
		"nested duplicate":   `{"a":{"k":1,"k":2}}`,
		"duplicate in array": `{"a":[{"k":1,"k":1}]}`,
		"alternate escape":   `{"a":["` + esc + `0061"]}`,
		"raw html":           `{"a":{"b":"<"}}`,
		"invalid utf-8":      "{\"a\":[\"\xff\"]}",
		"invalid utf-8 key":  "{\"\xff\":1}",
		"whitespace":         `{"a": 1}`,
		"float":              `{"a":1.0}`,
		"exponent":           `{"a":1e2}`,
		"negative zero":      `{"a":-0}`,
		"leading zero":       `{"a":01}`,
		"trailing data":      `{"a":1}{}`,
		"escaped slash":      `{"a":"` + "\\" + `/"}`,
		"truncated":          `{"a":[1,2}`,
	}
	for name, s := range refused {
		if err := checkCanonicalJSON([]byte(s)); err == nil {
			t.Errorf("%s: %s accepted", name, s)
		}
	}
}

func TestReviewSnapshotIsCanonicalAtEveryDepth(t *testing.T) {
	esc := `\u`
	for _, review := range []string{
		`{"reason":"a","reason":"b"}`,
		`{"s":"` + esc + `0061"}`,
		"{\"segments\":[{\"text\":\"\xff\"}]}",
		`{"segments":[{"spans":[{"rules":["a"],"rules":["b"]}]}]}`,
	} {
		rec := frozenR1(t, fixtures()[0].plan, 1, "x", json.RawMessage(review))
		if _, err := EncodeR1(rec); fieldOf(err) != "payload.review_snapshot" {
			t.Errorf("%q: EncodeR1 = %v", review, err)
		}
		rec.Payload.ReviewSnapshot = reviewOK
		good, err := EncodeR1(rec)
		if err != nil {
			t.Fatal(err)
		}
		bad := bytes.Replace(good, []byte(reviewOK), []byte(review), 1)
		if _, err := DecodeR1(bad); codeOf(err) != CodeRecordCorrupt {
			t.Errorf("%q: DecodeR1 = %v", review, err)
		}
	}
}
