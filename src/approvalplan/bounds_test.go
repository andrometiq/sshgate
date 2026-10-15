package approvalplan

import (
	"testing"
	"time"
)

func TestCheckSubmitWindow(t *testing.T) {
	cases := []struct {
		name      string
		notAfter  time.Time
		allowance time.Duration
		want      Code
	}{
		{"now", t0, LocalSkew, ""},
		{"one hour ahead", t0.Add(SubmitWindowMax), LocalSkew, ""},
		{"local allowance", t0.Add(SubmitWindowMax + LocalSkew), LocalSkew, ""},
		{"past local allowance", t0.Add(SubmitWindowMax + LocalSkew + time.Second), LocalSkew, CodeSubmitWindowAhead},
		{"hosted allowance", t0.Add(SubmitWindowMax + HostedSkew), HostedSkew, ""},
		{"past hosted allowance", t0.Add(SubmitWindowMax + HostedSkew + 1), HostedSkew, CodeSubmitWindowAhead},
		{"closed", t0.Add(-time.Nanosecond), LocalSkew, CodeSubmitWindowClosed},
	}
	for _, c := range cases {
		if err := CheckSubmitWindow(t0, c.notAfter, c.allowance); codeOf(err) != c.want {
			t.Errorf("%s: %v, want %q", c.name, err, c.want)
		}
	}
	if !CodeSubmitWindowAhead.Retryable() || CodeSubmitWindowClosed.Retryable() {
		t.Fatal("submit_window_ahead is transient and submit_window_closed definitive (SA-1 rule 3.5)")
	}
}

func TestVoteCap(t *testing.T) {
	rec := R1{Header: R1Header{RequiredApprovals: MaxRequiredApprovals}}
	if got := VoteCap(rec); got != 320 {
		t.Fatalf("VoteCap at N=256 = %d, want 320", got)
	}
}

func TestBoundsMatchThePlan(t *testing.T) {
	if MaxSteps != 32 || MaxStepBytes != 4096 || MaxTotalBytes != 24576 {
		t.Fatal("K19 bounds")
	}
	if ValidityMin != 5*time.Minute || ValidityDefault != 24*time.Hour || ValidityMax != 7*24*time.Hour {
		t.Fatal("K12 validity bounds")
	}
	if SyncClaimWindow != 310*time.Second || AwaitMaxWait != 55*time.Second || AwaitMaxIDs != 100 {
		t.Fatal("sync and await bounds")
	}
	if R2Max != 4*((MaxJobOutputBytes+2)/3)+R2BodyOverhead+R2NonBodyMax {
		t.Fatal("R2Max derivation")
	}
}
