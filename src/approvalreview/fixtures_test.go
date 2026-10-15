package approvalreview

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/karthikeyan5/sshgate/src/approvalplan"
	"github.com/karthikeyan5/sshgate/src/redact"
	redactrules "github.com/karthikeyan5/sshgate/src/redact/rules"
)

var update = flag.Bool("update", false, "rewrite the goldens and the shared fixture")

var (
	t0         = time.Date(2026, 10, 15, 9, 30, 0, 0, time.UTC)
	testRules  = redactrules.Combined()
	testHandle = "k7m2q3x4c5v6"
)

// testSalt is a fixed salt with no zero byte, so a leak is recognisable.
func testSalt() [32]byte {
	var s [32]byte
	for i := range s {
		s[i] = byte(0xa0 + i)
	}
	return s
}

// loadPlan reads one of approvalplan's frozen plan goldens.
func loadPlan(t testing.TB, name string) approvalplan.ApprovalPlanV1 {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("..", "approvalplan", "testdata", "plans", name+".json"))
	if err != nil {
		t.Fatal(err)
	}
	var p approvalplan.ApprovalPlanV1
	if err := json.Unmarshal(b, &p); err != nil {
		t.Fatal(err)
	}
	if err := p.Validate(); err != nil {
		t.Fatalf("%s: %v", name, err)
	}
	return p
}

type stepSpec struct {
	route   approvalplan.Route
	command string
}

func signed(cmd string) stepSpec { return stepSpec{approvalplan.RouteSignedWrite, cmd} }

// withSteps replaces the write plan's steps, keeping its target.
func withSteps(t testing.TB, specs ...stepSpec) approvalplan.ApprovalPlanV1 {
	t.Helper()
	p := loadPlan(t, "write")
	target := p.CommandJob.Steps[0].Target
	job := *p.CommandJob
	job.Steps = nil
	for i, s := range specs {
		ttl := 0
		if s.route.Signed() {
			ttl = approvalplan.MaxStepTTL(s.route, s.command)
		}
		job.Steps = append(job.Steps, approvalplan.Step{
			Ordinal: i + 1, Route: s.route, Target: target, RegistryEntryDigest: target.Digest(),
			ExactCommand: s.command, CommandSHA256: sha256Hex(s.command), SignatureTTLSeconds: ttl,
		})
	}
	p.CommandJob = &job
	if err := p.Validate(); err != nil {
		t.Fatal(err)
	}
	return p
}

func withReason(t testing.TB, p approvalplan.ApprovalPlanV1, reason string) approvalplan.ApprovalPlanV1 {
	t.Helper()
	p.Rationale = reason
	if err := p.Validate(); err != nil {
		t.Fatal(err)
	}
	return p
}

func sha256Hex(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

// pemKey is a synthetic private-key block, assembled so this file holds no
// literal key header.
func pemKey() string {
	kind := "OPENSSH " + "PRIVATE KEY"
	body := strings.Repeat("b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAAB\n", 6)
	return "-----BEGIN " + kind + "-----\n" + body + "-----END " + kind + "-----\n"
}

func mustSnapshot(t testing.TB, p approvalplan.ApprovalPlanV1) ReviewSnapshot {
	t.Helper()
	salt := testSalt()
	s, err := BuildSnapshot(p, &salt, testRules)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func mustLegacy(t testing.TB, req LegacyRequest) ReviewSnapshot {
	t.Helper()
	s, err := BuildLegacySnapshot(req, saltPointer(), testRules)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func readyAssist() Assist {
	return Assist{State: approvalplan.AssistReady, Result: &approvalplan.AssistResult{
		Alignment: approvalplan.AlignmentAligned,
		Summary:   "Restarts the service named in the reason.",
		Effects:   []string{"Restarts nginx; open connections drop."},
		Concerns: []approvalplan.Concern{
			{Severity: approvalplan.SeverityInfo, Text: "Brief downtime."},
			{Severity: approvalplan.SeverityHigh, Text: "No config test before the restart."},
		},
		Model: "test-model", PromptVersion: "assist-v1", InputDigest: strings.Repeat("ab", 32), GeneratedAt: t0,
	}}
}

// rendered is every surface output for one snapshot.
type rendered struct {
	parts       []string
	preparing   string
	ready       string
	view        View
	viewJSON    []byte
	snapshotRaw []byte
}

func render(t testing.TB, s ReviewSnapshot, assist Assist) rendered {
	t.Helper()
	raw, err := s.Encode()
	if err != nil {
		t.Fatal(err)
	}
	stored, err := DecodeSnapshot(raw)
	if err != nil {
		t.Fatal(err)
	}
	preparing, err := BuildView(stored, Assist{State: approvalplan.AssistPreparing})
	if err != nil {
		t.Fatal(err)
	}
	parts, err := PackParts(preparing, testHandle)
	if err != nil {
		t.Fatal(err)
	}
	card, err := DecisionCard(preparing, testHandle, len(parts))
	if err != nil {
		t.Fatal(err)
	}
	view, err := BuildView(stored, assist)
	if err != nil {
		t.Fatal(err)
	}
	ready, err := DecisionCard(view, testHandle, len(parts))
	if err != nil {
		t.Fatal(err)
	}
	for _, text := range append(append([]string{string(raw), string(viewJSON(t, view)), card, ready}, parts...), preparing.Reason) {
		if strings.Contains(text, "SSHGATE_REDACTED") {
			t.Fatal("redactor marker reached a surface")
		}
	}
	return rendered{parts: parts, preparing: card, ready: ready, view: view, viewJSON: viewJSON(t, view), snapshotRaw: raw}
}

func viewJSON(t testing.TB, v View) []byte {
	t.Helper()
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	if err := enc.Encode(v); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

// texts is every rendered string, for whole-output assertions.
func (r rendered) texts() []string {
	return append(append([]string(nil), r.parts...), r.preparing, r.ready, string(r.viewJSON), string(r.snapshotRaw))
}

func (r rendered) golden() string {
	var b strings.Builder
	fmt.Fprintf(&b, "=== buttons: %s | %s\n", r.view.ApproveLabel, r.view.DenyLabel)
	for i, p := range r.parts {
		fmt.Fprintf(&b, "=== part %d/%d (%d bytes)\n%s\n", i+1, len(r.parts), len(p), p)
	}
	fmt.Fprintf(&b, "=== decision card, preparing (%d bytes)\n%s\n", len(r.preparing), r.preparing)
	fmt.Fprintf(&b, "=== decision card, ready (%d bytes)\n%s\n", len(r.ready), r.ready)
	fmt.Fprintf(&b, "=== hosted view, ready\n%s", r.viewJSON)
	return b.String()
}

func checkGolden(t *testing.T, name, got string) {
	t.Helper()
	path := filepath.Join("testdata", "golden", name+".txt")
	if *update {
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(got), 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("%v (run with -update to create it)", err)
	}
	if string(want) != got {
		t.Errorf("%s: output differs from %s (run with -update after review)\n--- got ---\n%s", name, path, got)
	}
}

// forceSpans makes RedactSpans answer ok=false for the test's duration.
func forceSpans(t *testing.T, fn func(string, [32]byte, []redact.Rule) (redact.SpanResult, bool)) {
	t.Helper()
	old := redactSpans
	redactSpans = fn
	t.Cleanup(func() { redactSpans = old })
}

func saltPointer() *[32]byte { s := testSalt(); return &s }
