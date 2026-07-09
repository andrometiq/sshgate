package classify

import (
	"fmt"
	"strings"
)

// Reason names the FIRST write-causing trigger for a KindWrite result. The
// zero value accompanies KindRead / KindUnknown. It carries no secret beyond
// the command text the agent already submitted — it is a friendlier-denial
// aid, NOT a security boundary.
type Reason struct {
	// Trigger is the class of the first write cause:
	// "substitution" | "redirect" | "sudo" | "env-var" | "unknown-head" | "rule".
	Trigger string
	// Segment is the 1-based offending segment index; 0 for whole-command
	// triggers (substitution / redirect).
	Segment int
	// SegText is the offending segment text (trimmed); "" for whole-command
	// triggers.
	SegText string
	// Head is the offending head / env key; "" otherwise.
	Head string
}

// String renders a one-line, agent-facing reason. For whole-command triggers
// (Segment==0) the `segment N` prefix is omitted.
func (r Reason) String() string {
	switch r.Trigger {
	case "substitution":
		return "command/process substitution ($(...) or backticks) is opaque and always needs approval"
	case "redirect":
		return "writes to a file (redirect >). If you meant a read, drop the redirect or send it to /dev/null / a pipe"
	case "sudo":
		return "sudo always requires approval"
	case "env-var":
		return fmt.Sprintf("%senv prefix `%s` can smuggle execution", r.segPrefix(), r.Head)
	case "unknown-head":
		return fmt.Sprintf("%s`%s` is not a recognized read utility", r.segPrefix(), r.Head)
	case "rule":
		return fmt.Sprintf("%sthe `%s` form is a write (a write flag/subcommand, not a recognized read)", r.segPrefix(), r.Head)
	default:
		return ""
	}
}

// segPrefix renders the “segment N `<seg>`: “ prefix for per-segment
// triggers, or "" for a whole-command trigger.
func (r Reason) segPrefix() string {
	if r.Segment == 0 {
		return ""
	}
	return fmt.Sprintf("segment %d `%s`: ", r.Segment, r.SegText)
}

// Explain returns the same Kind as Classify PLUS the first write reason. It is
// ADDITIVE and MCP-only: the gate's security decision stays on Classify, which
// is untouched. Explain mirrors Classify's top-level walk and reuses the SAME
// per-rule logic (readAllowlist) for the read/write decision, so there is no
// second copy of the per-command rules — only the top-level walk is duplicated.
//
// INVARIANT (property-tested by TestExplain_MatchesClassify): for every input,
// Explain(cmd).Kind == Classify(cmd). Because Explain reuses hasWritingRedirect
// and the patched splitSegments, the §5.1/§5.2 structural fixes flow through
// automatically.
func Explain(cmd string) (Kind, Reason) {
	if !hasPrintable(cmd) {
		return KindUnknown, Reason{}
	}
	if containsSubstitution(cmd) {
		return KindWrite, Reason{Trigger: "substitution"}
	}
	if hasWritingRedirect(cmd) {
		return KindWrite, Reason{Trigger: "redirect"}
	}
	segs := splitSegments(cmd)
	if len(segs) == 0 {
		return KindUnknown, Reason{}
	}
	sawRead := false
	for idx, seg := range segs {
		k, why := classifySegmentExplain(seg)
		switch k {
		case KindWrite:
			why.Segment = idx + 1
			why.SegText = seg
			return KindWrite, why
		case KindRead:
			sawRead = true
		}
	}
	if sawRead {
		return KindRead, Reason{}
	}
	return KindUnknown, Reason{}
}

// classifySegmentExplain mirrors classifySegment (classifier.go) and returns
// the SAME Kind plus the trigger for a write. It calls the same
// readAllowlist[head] rule for the read/write decision, so no per-rule logic is
// duplicated. The Segment/SegText fields are filled in by the caller.
func classifySegmentExplain(seg string) (Kind, Reason) {
	tokens := tokenize(seg)
	if len(tokens) == 0 {
		return KindUnknown, Reason{}
	}
	i := 0
	for i < len(tokens) && isAssignment(tokens[i]) {
		key := tokens[i][:strings.IndexByte(tokens[i], '=')]
		if dangerousEnvVars[key] {
			return KindWrite, Reason{Trigger: "env-var", Head: key}
		}
		i++
	}
	if i >= len(tokens) {
		return KindUnknown, Reason{}
	}
	head := tokens[i]
	args := tokens[i+1:]

	if head == "sudo" {
		return KindWrite, Reason{Trigger: "sudo", Head: "sudo"}
	}

	rule, ok := readAllowlist[head]
	if !ok {
		return KindWrite, Reason{Trigger: "unknown-head", Head: head}
	}
	if rule == nil {
		return KindRead, Reason{}
	}
	if rule(args) == KindWrite {
		return KindWrite, Reason{Trigger: "rule", Head: head}
	}
	return KindRead, Reason{}
}
