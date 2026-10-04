package gate_test

import (
	"bufio"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/karthikeyan5/sshgate/src/gate"
)

// readRecords reads every JSON-Lines record from path and decodes them
// into a slice of maps for flexible assertions.
func readRecords(t *testing.T, path string) []map[string]any {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("open audit log: %v", err)
	}
	defer f.Close()
	var recs []map[string]any
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 1<<20)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		var m map[string]any
		if err := json.Unmarshal([]byte(line), &m); err != nil {
			t.Fatalf("bad json line %q: %v", line, err)
		}
		recs = append(recs, m)
	}
	if err := sc.Err(); err != nil {
		t.Fatalf("scan: %v", err)
	}
	return recs
}

// TestParseAuditLevel covers the level parser and its fail-to-default
// behaviour for unknown / empty input.
func TestParseAuditLevel(t *testing.T) {
	cases := map[string]gate.AuditLevel{
		"off":      gate.AuditOff,
		"writes":   gate.AuditWrites,
		"all":      gate.AuditAll,
		"all+meta": gate.AuditAllMeta,
		"all+full": gate.AuditAllFull,
		// whitespace / case tolerance
		" all+meta\n": gate.AuditAllMeta,
		"ALL":         gate.AuditAll,
	}
	for in, want := range cases {
		if got := gate.ParseAuditLevel(in); got != want {
			t.Errorf("ParseAuditLevel(%q) = %v, want %v", in, got, want)
		}
	}
	// Unknown / empty -> default all+meta (fail to the safe default).
	for _, bad := range []string{"", "bogus", "verbose", "none"} {
		if got := gate.ParseAuditLevel(bad); got != gate.AuditAllMeta {
			t.Errorf("ParseAuditLevel(%q) = %v, want default AuditAllMeta", bad, got)
		}
	}
}

// TestLoadAuditLevel covers reading the level from the gate dir's
// audit-level file, defaulting to all+meta when absent/unreadable.
func TestLoadAuditLevel(t *testing.T) {
	t.Run("absent file -> default all+meta", func(t *testing.T) {
		dir := t.TempDir()
		if got := gate.LoadAuditLevel(dir); got != gate.AuditAllMeta {
			t.Errorf("level = %v, want default AuditAllMeta", got)
		}
	})
	t.Run("file present -> parsed", func(t *testing.T) {
		dir := t.TempDir()
		if err := os.WriteFile(filepath.Join(dir, "audit-level"), []byte("writes\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		if got := gate.LoadAuditLevel(dir); got != gate.AuditWrites {
			t.Errorf("level = %v, want AuditWrites", got)
		}
	})
	t.Run("garbage file -> default all+meta", func(t *testing.T) {
		dir := t.TempDir()
		if err := os.WriteFile(filepath.Join(dir, "audit-level"), []byte("garbage"), 0o600); err != nil {
			t.Fatal(err)
		}
		if got := gate.LoadAuditLevel(dir); got != gate.AuditAllMeta {
			t.Errorf("level = %v, want default AuditAllMeta", got)
		}
	})
}

// makeRecord is a small helper to build a representative AuditRecord.
func makeRecord(cmd, class, status string, exit int, meta *gate.AuditMeta) gate.AuditRecord {
	return gate.AuditRecord{
		TS:             time.Now().UTC().Unix(),
		Command:        cmd,
		Classification: class,
		ApprovalStatus: status,
		ExitCode:       exit,
		Meta:           meta,
	}
}

// TestAuditLogLevels is the core leveling matrix: each level emits the
// right records.
func TestAuditLogLevels(t *testing.T) {
	meta := &gate.AuditMeta{StdoutBytes: 10, StderrBytes: 0, Lines: 1, DurationMS: 5}

	t.Run("off emits nothing", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, "audit.log")
		al := gate.NewAuditLogger(gate.AuditOff, path)
		al.Record(makeRecord("ls", "read", "unsigned", 0, meta))
		al.Record(makeRecord("rm x", "write", "signed", 0, meta))
		al.Record(makeRecord("rm x", "write", "denied", 77, nil))
		if _, err := os.Stat(path); !os.IsNotExist(err) {
			t.Errorf("off level must not create the log file (err=%v)", err)
		}
	})

	t.Run("writes emits writes + rejections only", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, "audit.log")
		al := gate.NewAuditLogger(gate.AuditWrites, path)
		al.Record(makeRecord("ls", "read", "unsigned", 0, meta))  // dropped
		al.Record(makeRecord("rm x", "write", "signed", 0, meta)) // kept
		al.Record(makeRecord("rm x", "write", "denied", 77, nil)) // kept (rejection)
		recs := readRecords(t, path)
		if len(recs) != 2 {
			t.Fatalf("got %d records, want 2 (writes + rejection)", len(recs))
		}
		for _, r := range recs {
			if r["classification"] == "read" {
				t.Errorf("writes level leaked a read record: %v", r)
			}
		}
	})

	t.Run("all emits reads + writes + rejections", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, "audit.log")
		al := gate.NewAuditLogger(gate.AuditAll, path)
		al.Record(makeRecord("ls", "read", "unsigned", 0, meta))
		al.Record(makeRecord("rm x", "write", "signed", 0, meta))
		al.Record(makeRecord("rm x", "write", "denied", 77, nil))
		recs := readRecords(t, path)
		if len(recs) != 3 {
			t.Fatalf("got %d records, want 3", len(recs))
		}
	})

	t.Run("all+meta includes metadata but NO raw output", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, "audit.log")
		al := gate.NewAuditLogger(gate.AuditAllMeta, path)
		r := makeRecord("ls", "read", "unsigned", 0, meta)
		r.Stdout = "raw output that must NOT appear"
		r.Stderr = "raw stderr that must NOT appear"
		al.Record(r)
		recs := readRecords(t, path)
		if len(recs) != 1 {
			t.Fatalf("got %d records, want 1", len(recs))
		}
		got := recs[0]
		if _, ok := got["stdout"]; ok {
			t.Errorf("all+meta must NOT serialise raw stdout: %v", got)
		}
		if _, ok := got["stderr"]; ok {
			t.Errorf("all+meta must NOT serialise raw stderr: %v", got)
		}
		// Metadata must be present.
		m, ok := got["meta"].(map[string]any)
		if !ok {
			t.Fatalf("all+meta must include meta object: %v", got)
		}
		if m["stdout_bytes"].(float64) != 10 {
			t.Errorf("meta.stdout_bytes = %v, want 10", m["stdout_bytes"])
		}
		if m["lines"].(float64) != 1 {
			t.Errorf("meta.lines = %v, want 1", m["lines"])
		}
		// Sanity: the raw output strings do not appear anywhere in the
		// serialised line.
		raw := mustReadFile(t, path)
		if strings.Contains(raw, "raw output that must NOT appear") {
			t.Errorf("all+meta leaked raw stdout into the log: %s", raw)
		}
	})

	t.Run("all+full includes raw output", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, "audit.log")
		al := gate.NewAuditLogger(gate.AuditAllFull, path)
		r := makeRecord("cat secret", "read", "signed", 0, meta)
		r.Stdout = "SECRET-VALUE-123"
		al.Record(r)
		raw := mustReadFile(t, path)
		if !strings.Contains(raw, "SECRET-VALUE-123") {
			t.Errorf("all+full must include raw output: %s", raw)
		}
	})
}

// TestAuditLogAppendOnly proves records accumulate across separate
// loggers pointed at the same path (each invocation opens, appends,
// closes — statelessness).
func TestAuditLogAppendOnly(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.log")
	meta := &gate.AuditMeta{StdoutBytes: 1, Lines: 0, DurationMS: 1}
	for i := 0; i < 3; i++ {
		al := gate.NewAuditLogger(gate.AuditAllMeta, path)
		al.Record(makeRecord("ls", "read", "unsigned", 0, meta))
	}
	recs := readRecords(t, path)
	if len(recs) != 3 {
		t.Fatalf("append-only across invocations: got %d, want 3", len(recs))
	}
}

// TestAuditLogFileMode pins the on-disk mode of the gate-side audit log
// at 0600 (owner-only). The log carries command text always, and raw
// output at all+full, so it must never be group- or world-readable.
func TestAuditLogFileMode(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.log")
	al := gate.NewAuditLogger(gate.AuditAllMeta, path)
	al.Record(makeRecord("ls", "read", "unsigned", 0, &gate.AuditMeta{StdoutBytes: 1}))
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if got := info.Mode().Perm(); got != 0o600 {
		t.Errorf("audit log mode = %#o; want 0600 (owner-only)", got)
	}
}

// TestAuditLogFailOpen proves a logging failure (unwritable path) does
// NOT panic or otherwise propagate as a blocking error — the caller
// continues. We point the path at a location that cannot be created (a
// file used as a directory component) and assert Record does not panic
// and the gate-side caller sees no fatal error.
func TestAuditLogFailOpen(t *testing.T) {
	dir := t.TempDir()
	// Create a regular file, then ask the logger to write to a path that
	// treats that file as a directory: open will fail (ENOTDIR).
	blocker := filepath.Join(dir, "blocker")
	if err := os.WriteFile(blocker, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	badPath := filepath.Join(blocker, "audit.log")
	al := gate.NewAuditLogger(gate.AuditAllMeta, badPath)
	// Must not panic; Record swallows the error (fail-open). The audit is
	// a side effect, never a gate.
	al.Record(makeRecord("ls", "read", "unsigned", 0, &gate.AuditMeta{}))
	// Nothing to assert beyond "did not panic / block"; reaching here is
	// the pass condition.
}

func mustReadFile(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return string(b)
}

// TestAuditRungOmitEmpty pins the additive rung field: absent from records that
// ran no read child (so their shape is unchanged), present when a read set it.
func TestAuditRungOmitEmpty(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.log")
	l := gate.NewAuditLogger(gate.AuditAllMeta, path)
	l.Record(makeRecord("deny", "write", "denied", 77, nil))
	read := makeRecord("cat /etc/hostname", "read", "unsigned", 0, &gate.AuditMeta{})
	read.Rung = "full"
	l.Record(read)
	recs := readRecords(t, path)
	if len(recs) != 2 {
		t.Fatalf("got %d records, want 2", len(recs))
	}
	if _, ok := recs[0]["rung"]; ok {
		t.Errorf("record without a rung serialised one: %v", recs[0])
	}
	if recs[1]["rung"] != "full" {
		t.Errorf("rung = %v, want full", recs[1]["rung"])
	}
}

func TestAuditCleanupErrorKeepsExitStatus(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.log")
	logger := gate.NewAuditLogger(gate.AuditAllMeta, path)
	logger.Record(gate.AuditRecord{Classification: "read", ApprovalStatus: "unsigned", ExitCode: 23, CleanupError: "descendant cleanup exceeded deadline"})
	records := readRecords(t, path)
	if len(records) != 1 || records[0]["exit_code"] != float64(23) || records[0]["cleanup_error"] != "descendant cleanup exceeded deadline" {
		t.Fatalf("cleanup audit: %#v", records)
	}
}
