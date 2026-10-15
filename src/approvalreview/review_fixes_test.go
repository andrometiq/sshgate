package approvalreview

import (
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/karthikeyan5/sshgate/src/approvalplan"
	"github.com/karthikeyan5/sshgate/src/redact"
)

func isTooLarge(err error) bool {
	var ce *approvalplan.CodeError
	return errors.As(err, &ce) && ce.Code == approvalplan.CodeRequestTooLarge
}

func TestLegacySpanBoundaryAndSalt(t *testing.T) {
	for _, n := range []int{(64 << 10) - 1, 64 << 10, (64 << 10) + 1} {
		t.Run(fmt.Sprint(n), func(t *testing.T) {
			req := legacyBase()
			req.Commands = []LegacyCommand{{Server: "web", Command: strings.Repeat(" ", n-len("PASSWORD=hunter2secret")) + "PASSWORD=hunter2secret"}}
			salt := testSalt()
			snap, err := BuildLegacySnapshot(req, &salt, testRules)
			if salt != ([32]byte{}) {
				t.Fatal("salt survived")
			}
			if n > redact.MaxSpanInput {
				if !IsUnrenderable(err) {
					t.Fatalf("over-limit: %v", err)
				}
				return
			}
			if err != nil {
				if !IsUnrenderable(err) && !isTooLarge(err) {
					t.Fatal(err)
				}
				return
			}
			raw, e := snap.Encode()
			if e != nil {
				t.Fatal(e)
			}
			v, e := BuildView(snap, Assist{State: approvalplan.AssistPreparing})
			if e != nil {
				t.Fatal(e)
			}
			for _, text := range []string{string(raw), string(viewJSON(t, v))} {
				if strings.Contains(text, "hunter2secret") || strings.Contains(text, "SSHGATE_REDACTED") {
					t.Fatal("secret or marker escaped")
				}
			}
			if !strings.HasPrefix(renderDisplay(snap.Steps[0].Command), strings.Repeat(" ", n-len("PASSWORD=hunter2secret"))+"PASSWORD=") {
				t.Fatal("unmatched prefix lost")
			}
		})
	}
	for i, setup := range []func(*LegacyRequest){
		func(r *LegacyRequest) {},
		func(r *LegacyRequest) {
			r.Commands = []LegacyCommand{{Command: "true", Reveal: true, Reason: strings.Repeat("x", 65537)}}
		},
		func(r *LegacyRequest) {
			r.Commands = []LegacyCommand{{Command: "true", Server: strings.Repeat("x", 65537)}}
		},
	} {
		req := legacyBase()
		setup(&req)
		salt := testSalt()
		_, err := BuildLegacySnapshot(req, &salt, testRules)
		if err == nil || salt != ([32]byte{}) {
			t.Fatal("invalid legacy request accepted or salt survived")
		}
		if i > 0 && !IsUnrenderable(err) {
			t.Fatalf("unprovable legacy text: %v", err)
		}
	}
	if _, err := BuildLegacySnapshot(legacyBase(), nil, testRules); err == nil {
		t.Fatal("nil salt accepted")
	}
}

func TestBuildMetadataRedactionAndTokens(t *testing.T) {
	for _, field := range []string{"basename", "staged", "running"} {
		p := loadPlan(t, "update")
		td := p.CommandJob.Steps[0].TrustedDisplay
		value := "PASSWORD=hunter2secret next=forged"
		switch field {
		case "basename":
			td.StagedBasename = value
		case "staged":
			td.StagedVersion = value
		case "running":
			td.RunningVersion = value
		}
		s := mustSnapshot(t, p)
		r := render(t, s, readyAssist())
		for _, text := range r.texts() {
			if strings.Contains(text, "hunter2secret") || strings.Contains(text, "SSHGATE_REDACTED") {
				t.Fatal("metadata leaked")
			}
		}
		notes := strings.Join(r.view.Items[0].Notes, "\n")
		if !strings.Contains(notes, `\x20next=forged`) || !strings.Contains(notes, approvalplan.GlyphHiddenOpen) {
			t.Fatal("metadata did not use tokenized segments")
		}
	}
}

func TestDecodeRejectsInvalidContent(t *testing.T) {
	for name, mutate := range map[string]func(*ReviewSnapshot){
		"short hash":   func(s *ReviewSnapshot) { s.PlanHash = "a" },
		"bad hash":     func(s *ReviewSnapshot) { s.Steps[0].Command.SHA256 = strings.Repeat("z", 64) },
		"kind":         func(s *ReviewSnapshot) { s.Kind = "unknown" },
		"route":        func(s *ReviewSnapshot) { s.Steps[0].Route = "unknown" },
		"two payloads": func(s *ReviewSnapshot) { s.Grant = &Grant{} },
		"no payload":   func(s *ReviewSnapshot) { s.Steps = nil },
		"visible fully hidden value": func(s *ReviewSnapshot) {
			s.Reason = Display{Bytes: 1, HiddenBytes: 1, FullyHidden: true, Segments: []Segment{{Hidden: 1}, {Text: "x"}}}
		},
		"wrong payload": func(s *ReviewSnapshot) { s.Kind = approvalplan.KindTransfer },
		"hidden sum":    func(s *ReviewSnapshot) { s.Reason.HiddenBytes = 1 },
		"negative":      func(s *ReviewSnapshot) { s.Reason.Bytes = -1 },
		"mixed segment": func(s *ReviewSnapshot) { s.Reason.Segments[0].Hidden = 1 },
		"empty segment": func(s *ReviewSnapshot) { s.Reason.Segments = []Segment{{}} },
		"fully hidden":  func(s *ReviewSnapshot) { s.Reason.FullyHidden = true },
	} {
		t.Run(name, func(t *testing.T) {
			s := mustSnapshot(t, loadPlan(t, "write"))
			mutate(&s)
			b, err := approvalplan.Canonical(s)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := DecodeSnapshot(b); err == nil {
				t.Fatal("invalid content accepted")
			}
		})
	}
	if planPrefix(View{PlanHash: "a"}) != "a" {
		t.Fatal("short prefix")
	}
}

func TestDecisionCardOmissionBudget(t *testing.T) {
	v, err := BuildView(mustSnapshot(t, loadPlan(t, "write")), readyAssist())
	if err != nil {
		t.Fatal(err)
	}
	// Leave one byte after the fixed ready card; the required notice cannot fit.
	base := v
	base.Assist.State = string(approvalplan.AssistPreparing)
	head := strings.Join(assistHead(v.Assist), "\n")
	prep, _ := DecisionCard(base, testHandle, 1)
	fixed := len(prep) - len(strings.Join(assistHead(base.Assist), "\n")) + len(head)
	v.Requester += strings.Repeat("a", PartBytes-2-fixed)
	if _, err := DecisionCard(v, testHandle, 1); !isTooLarge(err) {
		t.Fatalf("omission overflow: %v", err)
	}
}

func TestReviewByteBoundBelowMessageBound(t *testing.T) {
	v := View{RequestID: "x", PlanHash: strings.Repeat("a", 64)}
	// 35 nearly full parts fit the message count but exceed 128 KiB.
	for range 35 {
		v.Items = append(v.Items, Item{Heading: strings.Repeat("x", 3700)})
	}
	if _, err := PackParts(v, testHandle); !isTooLarge(err) {
		t.Fatalf("byte overflow: %v", err)
	}
}

func TestLabelsAndV2NotAssessed(t *testing.T) {
	r := render(t, mustSnapshot(t, loadPlan(t, "write")), readyAssist())
	it := r.view.Items[0]
	if len(it.Notes) < 2 || it.Notes[0] != LabelRoute || !strings.Contains(it.Notes[1], "web") {
		t.Fatal("route label not above route")
	}
	p := loadPlan(t, "transfer")
	p.Transfer.Source.Path = "/PASSWORD=hunter2secret"
	tr := render(t, mustSnapshot(t, p), readyAssist())
	text := strings.Join(tr.parts, "\n")
	if strings.Count(text, "fingerprint ("+LabelPathSupplied+")") != 2 {
		t.Fatal("fingerprint provenance missing")
	}
	if strings.Contains(tr.view.Items[1].TextLabel, "command") || !strings.Contains(tr.view.Items[1].TextLabel, "Display-redacted value") {
		t.Fatal("path has command label")
	}
	a := readyAssist()
	a.Result.Alignment = approvalplan.AlignmentNotAssessed
	v, err := BuildView(mustSnapshot(t, loadPlan(t, "write")), a)
	if err != nil || v.Assist.Alignment != "not assessed" {
		t.Fatalf("v2 alignment: %q %v", v.Assist.Alignment, err)
	}
}

func maxRoutes(p *approvalplan.ApprovalPlanV1) {
	for i := range p.CommandJob.Steps {
		s := &p.CommandJob.Steps[i]
		s.Target.ServerAlias = strings.Repeat("a", approvalplan.MaxAliasBytes)
		s.Target.ResolvedUser = strings.Repeat("u", approvalplan.MaxUserBytes)
		s.Target.ResolvedHost = strings.Repeat("h", approvalplan.MaxHostBytes)
		s.Target.ResolvedPort = 65535
		s.RegistryEntryDigest = s.Target.Digest()
	}
}

func TestPackingSweep(t *testing.T) {
	largestPlain, densestSecret := 0, 0
	plainCase, secretCase := "", ""
	for _, atom := range []string{"\x01", "é", "passwd=abcd ", "PASSWORD=Xq7vB2mK ", "<", "a"} {
		for steps := 1; steps <= 32; steps++ {
			maxSize := min(4096, 24576/steps)
			for _, size := range []int{maxSize / 2, maxSize - 1, maxSize} {
				cmd := strings.Repeat(atom, size/len(atom)) + strings.Repeat(" ", size%len(atom))
				specs := make([]stepSpec, steps)
				for i := range specs {
					specs[i] = signed(cmd)
				}
				p := withSteps(t, specs...)
				maxRoutes(&p)
				salt := testSalt()
				s, err := BuildSnapshot(p, &salt, testRules)
				if err != nil {
					if !isTooLarge(err) {
						t.Fatalf("atom=%q steps=%d bytes=%d: %v", atom, steps, size, err)
					}
					continue
				}
				r := render(t, s, readyAssist())
				checkTelegramShape(t, r)
				total := len(r.ready)
				for _, part := range r.parts {
					total += len(part)
				}
				if s.Steps[0].Command.HiddenBytes == 0 {
					if total > largestPlain {
						largestPlain = total
						plainCase = fmt.Sprintf("atom=%q steps=%d bytes_per_step=%d parts=%d", atom, steps, size, len(r.parts))
					}
				} else {
					if total > densestSecret {
						densestSecret = total
						secretCase = fmt.Sprintf("atom=%q steps=%d bytes_per_step=%d parts=%d", atom, steps, size, len(r.parts))
					}
				}
			}
		}
	}
	t.Logf("sweep envelope: largest hidden-span-free accepted review=%d bytes (%s); largest dense-secret accepted review=%d bytes (%s)", largestPlain, plainCase, densestSecret, secretCase)
}

func TestRequiredPackingProbes(t *testing.T) {
	for _, c := range []struct {
		steps, size int
		atom        string
	}{{8, 3072, "\x01"}, {10, 2457, "\x01"}, {20, 1228, "\x01"}, {25, 983, "\x01"}, {24, 1000, "é"}, {32, 768, "a"}, {32, 768, "<"}} {
		t.Run(fmt.Sprintf("%d_%d_%x", c.steps, c.size, c.atom), func(t *testing.T) {
			specs := make([]stepSpec, c.steps)
			for i := range specs {
				specs[i] = signed(strings.Repeat(c.atom, c.size/len(c.atom)))
			}
			p := withSteps(t, specs...)
			maxRoutes(&p)
			r := render(t, mustSnapshot(t, p), readyAssist())
			checkTelegramShape(t, r)
			total := len(r.ready)
			for _, part := range r.parts {
				total += len(part)
			}
			t.Logf("parts=%d total_bytes=%d", len(r.parts), total)
		})
	}
}

func TestLegacySaltNeverLeavesSuccessfulBuild(t *testing.T) {
	req := legacyBase()
	req.Commands = []LegacyCommand{{Server: "web", Command: "PASSWORD=hunter2secret ./run", Reveal: true, Reason: "use PASSWORD=hunter2secret"}}
	salt := testSalt()
	original := salt
	snap, err := BuildLegacySnapshot(req, &salt, testRules)
	if err != nil {
		t.Fatal(err)
	}
	if salt != ([32]byte{}) {
		t.Fatal("legacy salt survived successful build")
	}
	for _, text := range render(t, snap, readyAssist()).texts() {
		for _, needle := range []string{string(original[:]), hex.EncodeToString(original[:]), base64.StdEncoding.EncodeToString(original[:]), base64.RawURLEncoding.EncodeToString(original[:]), "hunter2secret", "SSHGATE_REDACTED"} {
			if strings.Contains(text, needle) {
				t.Fatal("legacy secret, salt or marker reached a surface")
			}
		}
	}
}

func TestGreedyPackingPreservesEveryDisplay(t *testing.T) {
	v := View{RequestID: "x", PlanHash: strings.Repeat("a", 64)}
	var want strings.Builder
	for i, size := range []int{1, 3500, 200, 7000, 12, 3300} {
		text := strings.Repeat(`\x01`, size/4) + strings.Repeat("z", size%4)
		text += approvalplan.HiddenMarker(8, []string{"test-rule"})
		v.Items = append(v.Items, Item{Heading: fmt.Sprintf("item-%d", i), TextLabel: "Display", Text: text, Ref: fmt.Sprintf("item-%d", i), SHA256: strings.Repeat("b", 64)})
		want.WriteString(text)
	}
	parts, err := PackParts(v, testHandle)
	if err != nil {
		t.Fatal(err)
	}
	var got strings.Builder
	for _, part := range parts {
		for _, line := range strings.Split(part, "\n") {
			if strings.HasPrefix(line, QuotePrefix) {
				got.WriteString(strings.TrimPrefix(line, QuotePrefix))
			}
		}
	}
	if got.String() != want.String() {
		t.Fatal("packing lost, reordered or duplicated display bytes")
	}
}

func TestSummaryScopesHiddenByteCounts(t *testing.T) {
	p := loadPlan(t, "update")
	p.CommandJob.Steps[0].TrustedDisplay.StagedVersion = "PASSWORD=hunter2secret"
	v, err := BuildView(mustSnapshot(t, p), readyAssist())
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(v.Summary, "no command bytes hidden") {
		t.Fatal("command count claims to cover metadata")
	}
	req := legacyBase()
	req.Register = loadPlan(t, "register-key").RegisterTransferKey
	v, err = BuildView(mustLegacy(t, req), readyAssist())
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(v.Summary, "bytes hidden") {
		t.Fatal("key registration makes an unsupported byte-count claim")
	}
	req.Register = nil
	req.Transfer = &LegacyTransfer{SourcePath: "/source", DestPath: "/dest", DestFingerprint: "PASSWORD=hunter2secret"}
	v, err = BuildView(mustLegacy(t, req), readyAssist())
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(v.Summary, "no path bytes hidden") {
		t.Fatal("path count claims to cover fingerprints")
	}
}
