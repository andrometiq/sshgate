package classify

import (
	"path/filepath"
	"testing"

	"github.com/karthikeyan5/sshgate/internal/redteam"
)

// TestExplain_MatchesClassify is the MANDATORY drift guard for the duplicated
// top-level walk in Explain. It asserts Explain(cmd).Kind == Classify(cmd) for
// EVERY row in classifier-corpus.txt + fp-corpus.txt + every internal/redteam
// corpus command. The gate's decision path stays on Classify; this proves the
// additive Explain never diverges from it.
func TestExplain_MatchesClassify(t *testing.T) {
	t.Parallel()

	var cmds []string
	for _, p := range []string{
		filepath.Join("..", "..", "tests", "testdata", "classifier-corpus.txt"),
		filepath.Join("..", "..", "tests", "testdata", "fp-corpus.txt"),
	} {
		for _, row := range loadCorpus(t, p) {
			cmds = append(cmds, row.cmd)
		}
	}
	// Every internal/redteam corpus command (placeholder canary/secret paths —
	// only the command text matters for classification).
	for _, atk := range redteam.Corpus("/canary", "/secret") {
		cmds = append(cmds, atk.Cmd)
	}

	for _, cmd := range cmds {
		wantKind := Classify(cmd)
		gotKind, _ := Explain(cmd)
		if gotKind != wantKind {
			t.Errorf("Explain(%q).Kind = %s; Classify = %s (drift)", cmd, gotKind, wantKind)
		}
	}
}

// TestExplain_Triggers pins the rendered reason for each trigger class so the
// friendlier-denial text stays correct.
func TestExplain_Triggers(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name        string
		cmd         string
		wantKind    Kind
		wantTrigger string
		wantSeg     int
	}{
		{"substitution", "grep \"$(hostname)\" /etc/hosts", KindWrite, "substitution", 0},
		{"redirect", "echo x > /tmp/y", KindWrite, "redirect", 0},
		{"sudo", "sudo systemctl restart nginx", KindWrite, "sudo", 1},
		{"env-var", "LD_PRELOAD=/tmp/x cat /etc/hosts", KindWrite, "env-var", 1},
		{"unknown-head", "frobnicate /etc/hosts", KindWrite, "unknown-head", 1},
		{"rule write", "git commit -m x", KindWrite, "rule", 1},
		{"rule write later segment", "ls && rm x", KindWrite, "unknown-head", 2},
		{"read no reason", "cat /etc/hosts", KindRead, "", 0},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			k, r := Explain(tc.cmd)
			if k != tc.wantKind {
				t.Fatalf("Explain(%q).Kind = %s; want %s", tc.cmd, k, tc.wantKind)
			}
			if r.Trigger != tc.wantTrigger {
				t.Errorf("Explain(%q).Trigger = %q; want %q", tc.cmd, r.Trigger, tc.wantTrigger)
			}
			if r.Segment != tc.wantSeg {
				t.Errorf("Explain(%q).Segment = %d; want %d", tc.cmd, r.Segment, tc.wantSeg)
			}
			if tc.wantKind == KindWrite && r.String() == "" {
				t.Errorf("Explain(%q) write result rendered an empty reason", tc.cmd)
			}
		})
	}
}
