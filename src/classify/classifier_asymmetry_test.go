package classify

import "testing"

// TestClassify_LowPriorityAsymmetryPins locks the CURRENT behavior of several
// edge cases the 2026-06-14 testability audit flagged as low-priority. These
// are NOT security bypasses (the two real read-only-gate bypasses are pinned
// in classifier_bypass_test.go). Some rows pin a deliberately over-conservative
// false-positive (a read command classified WRITE): that is the fail-safe
// direction, and pinning it documents the behavior + guards against a
// "cleanup" that silently widens the read surface. Each row notes whether it
// is correct-by-design or an accepted over-conservative FP.
func TestClassify_LowPriorityAsymmetryPins(t *testing.T) {
	cases := []struct {
		name string
		cmd  string
		want Kind
		// note explains why this is the expected (and acceptable) result.
		note string
	}{
		// --- Trailing-only operators: the operator separates segments, the
		// trailing empty segment is dropped, so only the read head survives. ---
		{
			name: "trailing semicolon", cmd: "ls;", want: KindRead,
			note: "splitSegments drops the empty post-';' segment; head 'ls' is read",
		},
		{
			name: "trailing logical-and", cmd: "ls &&", want: KindRead,
			note: "'&&' with nothing after -> single read segment 'ls'",
		},
		{
			name: "trailing semicolon w/ space", cmd: "ls ; ", want: KindRead,
			note: "trailing whitespace+';' still leaves only the read segment",
		},
		{
			name: "trailing pipe-or", cmd: "ls ||", want: KindRead,
			note: "'||' trailing -> only the read segment 'ls' remains",
		},

		// --- Single '&' background operator. A lone '&' is a top-level
		// separator (background), handled like ';'. So 'ls &' is just the
		// read 'ls'; 'ls & rm x' splits into read + a write segment -> WRITE. ---
		{
			name: "single ampersand background read", cmd: "ls &", want: KindRead,
			note: "lone '&' backgrounds 'ls'; trailing empty segment dropped -> read",
		},
		{
			name: "single ampersand then write", cmd: "ls & rm x", want: KindWrite,
			note: "'&' splits to ['ls','rm x']; the 'rm' segment is an unknown/write head",
		},
		{
			name: "single ampersand background then read", cmd: "ls & cat /etc/hosts", want: KindRead,
			note: "both segments are read heads -> read (no write segment)",
		},

		// --- 'git -C DIR <sub>': OVER-CONSERVATIVE FALSE POSITIVE. firstNonFlag
		// skips the '-C' flag but NOT its operand DIR, so it returns DIR (a
		// path) instead of the real subcommand 'status'. DIR is not a read
		// subcommand, so gitRule falls through to WRITE. This is a read command
		// misclassified WRITE — the safe direction. Pinned to document it; do
		// NOT "fix" toward READ without re-reviewing the flag-operand handling. ---
		{
			name: "git -C dir status (FP -> write)", cmd: "git -C /repo status", want: KindWrite,
			note: "OVER-CONSERVATIVE FP: '-C /repo' operand swallows the subcommand slot; safe direction",
		},
		{
			name: "git -C dir log (FP -> write)", cmd: "git -C /srv/app log --oneline", want: KindWrite,
			note: "same FP as above for 'log'; pinned as accepted over-conservatism",
		},
		{
			name: "plain git status still read", cmd: "git status", want: KindRead,
			note: "non-regression: without -C, 'status' is correctly read",
		},

		// --- 'ls 2>&1': the target-aware hasWritingRedirect (§5, W2-3d) carves
		// out fd-dup/close (2>&1) and the sink devices as NON-writing, so a
		// stderr->stdout dup now correctly classifies READ. The B1 splitSegments
		// fix keeps the `&` of `2>&1` from splitting the segment. A real-path
		// target (2>/tmp/x, >&file) still forces WRITE. ---
		{
			name: "stderr redirect 2>&1 (now read)", cmd: "ls 2>&1", want: KindRead,
			note: "2>&1 is an fd dup, not a file write; carved out by hasWritingRedirect + B1 split fix",
		},
		{
			name: "stdout+stderr redirect (now read)", cmd: "cat /etc/hosts 2>&1", want: KindRead,
			note: "read head 'cat' with a non-writing fd-dup redirect -> read",
		},

		// --- curl '-XPOST' (no space) and '-X post' (lowercase): both must be
		// WRITE. The combined '-XPOST' form is parsed via the a[2:] branch, and
		// the lowercase method is upper-cased before comparison. ---
		{
			name: "curl -XPOST combined", cmd: "curl -XPOST https://example.com", want: KindWrite,
			note: "combined short flag '-XPOST' -> method POST -> write",
		},
		{
			name: "curl -X post lowercase", cmd: "curl -X post https://example.com", want: KindWrite,
			note: "method is upper-cased before match; 'post' -> POST -> write",
		},
		{
			name: "curl -XPUT combined", cmd: "curl -XPUT https://example.com", want: KindWrite,
			note: "combined '-XPUT' -> write",
		},
		{
			name: "curl -X delete lowercase", cmd: "curl -X delete https://example.com", want: KindWrite,
			note: "lowercase 'delete' upper-cased -> DELETE -> write",
		},
		{
			name: "curl -X get stays read", cmd: "curl -X get https://example.com", want: KindRead,
			note: "non-regression: GET is not a write method -> read",
		},

		// --- 'find -execdir': writes/executes per-directory, same as -exec.
		// findRule lists -execdir explicitly -> WRITE. ---
		{
			name: "find -execdir", cmd: "find /tmp -execdir rm {} ;", want: KindWrite,
			note: "-execdir runs a command per directory -> write",
		},
		{
			name: "find -execdir touch", cmd: "find . -name '*.tmp' -execdir touch {} +", want: KindWrite,
			note: "-execdir variant -> write regardless of the wrapped command",
		},
		{
			name: "plain find still read", cmd: "find /tmp -name '*.log'", want: KindRead,
			note: "non-regression: a find with no exec/write primitive is read",
		},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			if got := Classify(tc.cmd); got != tc.want {
				t.Errorf("Classify(%q) = %s; want %s (%s)", tc.cmd, got, tc.want, tc.note)
			}
		})
	}
}
