package classify

import (
	"bufio"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// corpusPath points at the canonical spec-sourced classifier corpus.
// The file is shared across packages, so it lives under tests/testdata/
// rather than this package's own testdata/.
var corpusPath = filepath.Join("..", "..", "tests", "testdata", "classifier-corpus.txt")

func TestClassify_Corpus(t *testing.T) {
	t.Parallel()

	rows := loadCorpus(t, corpusPath)
	if len(rows) == 0 {
		t.Fatalf("loadCorpus(%q) returned 0 rows; corpus must be non-empty", corpusPath)
	}

	for _, row := range rows {
		row := row // capture for parallel subtest
		t.Run(row.cmd, func(t *testing.T) {
			t.Parallel()
			got := Classify(row.cmd)
			if got != row.want {
				t.Errorf("Classify(%q) = %s; want %s", row.cmd, got, row.want)
			}
		})
	}
}

func TestClassify_EdgeCases(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		cmd  string
		want Kind
	}{
		{"empty string", "", KindUnknown},
		{"whitespace only", "   \t  ", KindUnknown},
		{"null bytes only", "\x00\x00", KindUnknown},
		{"very long unknown command", "frobnicate " + strings.Repeat("x", 10_000), KindWrite},

		// v1.1 Task B: pipe/chain segment classification edge cases.
		{"empty segments via double semicolon", "ls ;; cat /etc/hosts", KindRead},
		{"trailing pipe is whitespace-eaten", "ls |", KindRead},
		{"leading semicolon", "; ls -la", KindRead},
		{"nested command substitution", "echo $(echo $(ls))", KindWrite},
		{"backtick substitution", "echo `whoami`", KindWrite},
		{"process substitution input", "diff <(ls /a) <(ls /b)", KindWrite},
		{"process substitution output", "tee >(cat) < /dev/null", KindWrite},
		{"mixed read pipe + write chain", "cat /tmp/x | tee /tmp/y && rm /tmp/z", KindWrite},
		{"whitespace-tolerant pipe", "cat /tmp/x|grep foo", KindRead},
		{"redirect inside chain still write", "ls && echo hi > /tmp/x", KindWrite},

		// Mi3/Mi4 regression coverage.
		{"git stash bare", "git stash", KindWrite},
		{"git stash push -m", "git stash push -m wip", KindWrite},
		{"git stash list", "git stash list", KindRead},
		{"git stash show w/ ref", "git stash show stash@{0}", KindRead},
		{"git config --set is write", "git config --set foo bar", KindWrite},
		{"git config --get is read", "git config --get foo", KindRead},
		{"wget bare URL is write", "wget https://example.com/file.tar", KindWrite},
		{"wget -O- is read", "wget -O- https://example.com", KindRead},
		{"wget -O file is write", "wget -O /tmp/x https://example.com", KindWrite},
		{"wget --output-document=- is read", "wget --output-document=- https://example.com", KindRead},
		{"curl -o /tmp/x is write", "curl -o /tmp/x https://example.com", KindWrite},
		{"curl -o - is read", "curl -o - https://example.com", KindRead},
		{"curl -O remote-name is write", "curl -O https://example.com/file.tar", KindWrite},

		// 2026-05-19 audit MAJOR follow-ups.
		// M1: env wrapper recursion.
		{"env bare", "env", KindRead},
		{"env only assignments", "env LANG=C TZ=UTC", KindRead},
		{"env wrap read", "env FOO=bar cat /etc/hosts", KindRead},
		{"env wrap write", "env rm /tmp/x", KindWrite},
		{"env -i wrap", "env -i cat /etc/hosts", KindWrite},
		{"env LD_PRELOAD wrap", "env LD_PRELOAD=/tmp/x cat /etc/hosts", KindWrite},
		{"env -- read", "env -- cat /etc/hosts", KindRead},
		{"env -- write", "env -- rm /tmp/x", KindWrite},
		{"env nested env", "env FOO=bar env BAR=baz cat /etc/hosts", KindRead},
		{"env nested env write", "env FOO=bar env BAR=baz rm /tmp/x", KindWrite},

		// M2: journalctl mutating flags.
		{"journalctl --rotate is write", "journalctl --rotate", KindWrite},
		{"journalctl --rot abbrev", "journalctl --rot", KindWrite},
		{"journalctl --vacuum-size= write", "journalctl --vacuum-size=10M", KindWrite},
		{"journalctl --vacu abbrev", "journalctl --vacu=10M", KindWrite},
		{"journalctl --flush is write", "journalctl --flush", KindWrite},
		{"journalctl read still works", "journalctl -u nginx", KindRead},
		{"journalctl --no-pager read", "journalctl --no-pager -u nginx", KindRead},

		// M3: git -c injection.
		{"git -c core.pager is write", "git -c core.pager='sh -c id' log", KindWrite},
		{"git -c alias is write", "git -c alias.x='!id' x", KindWrite},
		{"git --config-env is write", "git --config-env=KEY=ENV log", KindWrite},
		{"plain git log still read", "git log --oneline", KindRead},

		// M4: GNU long-option abbreviation for sed --in-place.
		{"sed --in-pl is write", "sed --in-pl 's/x/y/' /etc/hosts", KindWrite},
		{"sed --in-p is write", "sed --in-p 's/x/y/' /etc/hosts", KindWrite},
		{"sed --in is write", "sed --in 's/x/y/' /etc/hosts", KindWrite},
		{"sed --in-place=.bak write", "sed --in-place=.bak 's/x/y/' /etc/hosts", KindWrite},

		// M5: curl -K config bypass.
		{"curl -K is write", "curl -K /tmp/cfg https://example.com", KindWrite},
		{"curl --config is write", "curl --config /tmp/cfg https://example.com", KindWrite},
		{"curl --config= is write", "curl --config=/tmp/cfg https://example.com", KindWrite},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := Classify(tc.cmd)
			if got != tc.want {
				t.Errorf("Classify(%q) = %s; want %s", tc.cmd, got, tc.want)
			}
		})
	}
}

// residualByDesign is the EXACT set of read-intent fp-corpus rows that the
// classifier legitimately routes to WRITE (Appendix B of W2-CLASSIFIER-SPEC-v2):
// package-manager queries, openssl, cloud CLIs beyond kubectl, and the one
// command-substitution row. Each is a fail-closed unknown-head / opaque default,
// individually justified — none is a W2 false positive to fix. It pins the
// residual set so TestClassify_FPCorpus part (c) can prove no REAL FP was
// relabeled into the residual and no undocumented residual crept in.
var residualByDesign = []string{
	"apt list --installed",
	"dpkg -l",
	"rpm -qa",
	"pip list",
	"npm ls",
	"openssl x509 -noout -text -in /etc/ssl/cert.pem",
	"openssl s_client -connect example.com:443",
	"helm list",
	"aws s3 ls",
	"gcloud compute instances list",
	"az vm list",
	"terraform plan",
	`grep "$(hostname)" /etc/hosts`,
}

// TestClassify_FPCorpus IS the W2 false-positive measurement instrument. It
// loads the 161-row read-intent corpus and:
//
//	(a) per-row correctness — Classify(row)==row.want for all 161. Catches both
//	    a regression (a READ row going WRITE) and gaming (a residual WRITE
//	    relabeled READ without a real classifier fix).
//	(b) the FP-rate gate — read-intent commands still routed to WRITE must be
//	    <= 10%. The exact fraction is t.Logf'd EVERY run (before = 96/161 =
//	    59.6% on the pristine classifier; after = 13/161 = 8.1%).
//	(c) anti-gaming — the WRITE-labeled set must equal residualByDesign exactly,
//	    so nobody can hide a real FP in the residual or add an undocumented one.
func TestClassify_FPCorpus(t *testing.T) {
	t.Parallel()

	fpPath := filepath.Join("..", "..", "tests", "testdata", "fp-corpus.txt")
	rows := loadCorpus(t, fpPath)
	if len(rows) == 0 {
		t.Fatalf("loadCorpus(%q) returned 0 rows; fp-corpus must be non-empty", fpPath)
	}

	// (a) Per-row correctness.
	// (b) is measured from the ACTUAL classification (Classify(row)==KindWrite),
	// per §1.3 — NOT from the row label — so the logged rate genuinely moves
	// 59.6% (pristine) -> 8.1% (fixed) and the gate FAILS if a future change
	// regresses a read-intent row back to WRITE. Counting the label instead
	// would pin the rate to a constant 8.1% and defeat the measurement.
	writes := 0
	for _, r := range rows {
		got := Classify(r.cmd)
		if got != r.want {
			t.Errorf("Classify(%q) = %s; want %s", r.cmd, got, r.want)
		}
		if got == KindWrite {
			writes++
		}
	}

	// (b) FP-rate gate. Always log the measured fraction (release-note figure).
	rate := float64(writes) / float64(len(rows))
	t.Logf("fp-corpus: %d/%d = %.1f%% residual WRITE (gate <= 10%%)", writes, len(rows), rate*100)
	if rate > 0.10 {
		t.Errorf("residual WRITE rate %.1f%% exceeds the 10%% ceiling (%d/%d)", rate*100, writes, len(rows))
	}

	// (c) Anti-gaming: the WRITE-labeled set must equal residualByDesign exactly.
	got := map[string]bool{}
	for _, r := range rows {
		if r.want == KindWrite {
			got[r.cmd] = true
		}
	}
	for _, cmd := range residualByDesign {
		if !got[cmd] {
			t.Errorf("residual row missing from fixture: %q", cmd)
		}
	}
	if len(got) != len(residualByDesign) {
		t.Errorf("fixture has %d WRITE rows; residual set has %d — an undocumented residual crept in",
			len(got), len(residualByDesign))
	}
}

func TestKind_String(t *testing.T) {
	t.Parallel()

	cases := []struct {
		k    Kind
		want string
	}{
		{KindUnknown, "unknown"},
		{KindRead, "read"},
		{KindWrite, "write"},
		{Kind(99), "unknown"},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.want, func(t *testing.T) {
			t.Parallel()
			got := tc.k.String()
			if got != tc.want {
				t.Errorf("Kind(%d).String() = %q; want %q", int(tc.k), got, tc.want)
			}
		})
	}
}

// --- helpers ---

type corpusRow struct {
	want Kind
	cmd  string
}

func loadCorpus(t *testing.T, path string) []corpusRow {
	t.Helper()

	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("open corpus %q: %v", path, err)
	}
	t.Cleanup(func() { _ = f.Close() })

	var rows []corpusRow
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	lineno := 0
	for sc.Scan() {
		lineno++
		line := sc.Text()
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		// Each row: <EXPECTED>\t<cmd>. We split on the FIRST tab so the
		// command itself can contain whatever it wants.
		tab := strings.IndexByte(line, '\t')
		if tab < 0 {
			t.Fatalf("corpus %s:%d: missing tab separator in %q", path, lineno, line)
		}
		label := strings.TrimSpace(line[:tab])
		cmd := line[tab+1:]
		var want Kind
		switch label {
		case "READ":
			want = KindRead
		case "WRITE":
			want = KindWrite
		default:
			t.Fatalf("corpus %s:%d: unknown label %q (want READ or WRITE)", path, lineno, label)
		}
		rows = append(rows, corpusRow{want: want, cmd: cmd})
	}
	if err := sc.Err(); err != nil {
		t.Fatalf("scan corpus %q: %v", path, err)
	}
	return rows
}
