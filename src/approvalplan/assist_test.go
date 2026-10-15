package approvalplan

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

var timeZone = time.FixedZone("IST", 5*3600+1800)

func okAssist() AssistResult {
	return AssistResult{
		Alignment: AlignmentAligned, Summary: "Restarts nginx to load the new config.",
		Effects: []string{"Restarts the nginx service"}, Concerns: []Concern{{Severity: SeverityCaution, Text: "Brief downtime"}},
		Model: "gpt-x", PromptVersion: "assist-v1", InputDigest: digestA, GeneratedAt: t0,
	}
}

func TestValidateAssist(t *testing.T) {
	if err := ValidateAssist(okAssist()); err != nil {
		t.Fatal(err)
	}
	max := maxAssist()
	if err := ValidateAssist(max); err != nil {
		t.Fatalf("the largest valid result: %v", err)
	}
	if b, _ := json.Marshal(max); len(b) > MaxAssistBytes || len(b) < MaxAssistBytes-MaxAssistEffectBytes*6 {
		t.Fatalf("maxAssist encodes to %d bytes", len(b))
	}
	notAssessed := okAssist()
	notAssessed.Alignment = AlignmentNotAssessed
	if err := ValidateAssist(notAssessed); err != nil {
		t.Fatal(err)
	}
	refused := map[string]func(*AssistResult){
		"alignment":        func(a *AssistResult) { a.Alignment = "confident" },
		"empty summary":    func(a *AssistResult) { a.Summary = "" },
		"summary 401":      func(a *AssistResult) { a.Summary = strings.Repeat("s", 401) },
		"summary newline":  func(a *AssistResult) { a.Summary = "a\nb" },
		"summary bidi":     func(a *AssistResult) { a.Summary = "a\u202eb" },
		"summary utf8":     func(a *AssistResult) { a.Summary = "a\xffb" },
		"effect 241":       func(a *AssistResult) { a.Effects = []string{strings.Repeat("e", 241)} },
		"empty effect":     func(a *AssistResult) { a.Effects = []string{""} },
		"too many effects": func(a *AssistResult) { a.Effects = make([]string, MaxAssistEffects+1) },
		"nine concerns":    func(a *AssistResult) { a.Concerns = make([]Concern, 9) },
		"severity":         func(a *AssistResult) { a.Concerns = []Concern{{Severity: "critical", Text: "x"}} },
		"concern 241": func(a *AssistResult) {
			a.Concerns = []Concern{{Severity: SeverityHigh, Text: strings.Repeat("c", 241)}}
		},
		"concern control": func(a *AssistResult) { a.Concerns = []Concern{{Severity: SeverityHigh, Text: "x\x07"}} },
		"model":           func(a *AssistResult) { a.Model = "" },
		"model space":     func(a *AssistResult) { a.Model = "gpt x" },
		"prompt version":  func(a *AssistResult) { a.PromptVersion = "" },
		"input digest":    func(a *AssistResult) { a.InputDigest = "abc" },
		"generated at":    func(a *AssistResult) { a.GeneratedAt = a.GeneratedAt.In(timeZone) },
		"over 8 KiB": func(a *AssistResult) {
			*a = maxAssist()
			a.Concerns = append(a.Concerns, Concern{Severity: SeverityHigh, Text: strings.Repeat("<", 200)})
		},
	}
	for name, f := range refused {
		a := okAssist()
		f(&a)
		if err := ValidateAssist(a); codeOf(err) != CodeInvalidRequest {
			t.Errorf("%s: ValidateAssist = %v", name, err)
		}
	}
}

func TestAssistDigests(t *testing.T) {
	a := okAssist()
	b := a
	b.Summary += "."
	if AssistDigest(a) == AssistDigest(b) || !ValidSHA256Hex(AssistDigest(a)) {
		t.Fatal("AssistDigest does not separate results")
	}
	d1 := UnavailableAssistDigest(AssistDeadlineReason, t0)
	if d1 != UnavailableAssistDigest(AssistDeadlineReason, t0.In(timeZone)) {
		t.Fatal("the unavailable digest depends on the zone")
	}
	if d1 == UnavailableAssistDigest("assist busy", t0) || d1 == UnavailableAssistDigest(AssistDeadlineReason, t0.Add(1)) {
		t.Fatal("the unavailable digest ignores its inputs")
	}
}
