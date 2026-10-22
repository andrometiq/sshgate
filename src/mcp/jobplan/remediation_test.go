package jobplan

import "testing"

func TestReadJailRemediationMatchesOutcome(t *testing.T) {
	for _, kind := range []StepKind{UnsignedRead, SignedWrite, SignedReveal} {
		for _, suffix := range []string{"", ": the jail failed after the read may have started"} {
			outcome := StepOutcome(kind, false, PhasedResult{ExitCode: 77, Stderr: []byte("gate: read jail unavailable" + suffix)})
			message, ok := ReadJailRemediation(outcome.Annotation)
			if !ok || message != outcome.Message || outcome.Retryable || outcome.VerdictClass != "read_jail_unavailable" {
				t.Fatal(outcome, message, ok)
			}
		}
	}
	for _, text := range []string{"", "gate refused (signature)", "read jail unavailable", ReadJailSigned + " appended"} {
		if _, ok := ReadJailRemediation(text); ok {
			t.Fatal("accepted non-exact annotation", text)
		}
	}
}
