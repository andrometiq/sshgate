package main

import (
	"bufio"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/karthikeyan5/sshgate/src/classify"
)

// TestGateClassifyUnchanged documents the W2-4 invariant: the GATE binary's
// security decision path stays on classify.Classify (main.go:164), byte for
// byte, and the additive Explain (#26) is MCP-only — it never reaches the gate.
// This golden asserts classify.Classify over the full classifier-corpus.txt
// still matches every expected label. It is trivially true today (Classify is
// untouched); it exists so a future refactor that merges the Classify/Explain
// paths or drifts the gate's classification fails loudly here.
func TestGateClassifyUnchanged(t *testing.T) {
	path := filepath.Join("..", "..", "..", "..", "tests", "testdata", "classifier-corpus.txt")
	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("open corpus %q: %v", path, err)
	}
	defer f.Close()

	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	lineno := 0
	rows := 0
	for sc.Scan() {
		lineno++
		line := sc.Text()
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		tab := strings.IndexByte(line, '\t')
		if tab < 0 {
			t.Fatalf("corpus %s:%d: missing tab separator in %q", path, lineno, line)
		}
		var want classify.Kind
		switch strings.TrimSpace(line[:tab]) {
		case "READ":
			want = classify.KindRead
		case "WRITE":
			want = classify.KindWrite
		default:
			t.Fatalf("corpus %s:%d: unknown label", path, lineno)
		}
		cmd := line[tab+1:]
		if got := classify.Classify(cmd); got != want {
			t.Errorf("classify.Classify(%q) = %s; want %s (gate decision drift)", cmd, got, want)
		}
		rows++
	}
	if err := sc.Err(); err != nil {
		t.Fatalf("scan corpus %q: %v", path, err)
	}
	if rows == 0 {
		t.Fatalf("corpus %q had 0 rows", path)
	}
}
