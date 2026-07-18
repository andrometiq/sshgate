package signer_test

import (
	"bufio"
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/karthikeyan5/sshgate/pkg/signerkit"
)

func TestAuditLog_WriteAndReopenParses(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "approvals.log")

	log, err := signerkit.OpenAuditLog(path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	ev1 := signerkit.AuditEvent{
		TS:        time.Now().UTC(),
		RequestID: "r_1",
		Status:    "approved",
		Commands:  []string{"systemctl restart nginx"},
		Servers:   []string{"prod-db"},
	}
	ev2 := signerkit.AuditEvent{
		TS:        time.Now().UTC(),
		RequestID: "r_2",
		Status:    "denied",
		Commands:  []string{"rm -rf /"},
		Servers:   []string{"prod-db"},
	}
	if err := log.Write(ev1); err != nil {
		t.Fatalf("Write ev1: %v", err)
	}
	if err := log.Write(ev2); err != nil {
		t.Fatalf("Write ev2: %v", err)
	}
	if err := log.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	// Reopen + parse
	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer f.Close()
	var got []signerkit.AuditEvent
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		var ev signerkit.AuditEvent
		if err := json.Unmarshal(sc.Bytes(), &ev); err != nil {
			t.Fatalf("parse %q: %v", sc.Text(), err)
		}
		got = append(got, ev)
	}
	if err := sc.Err(); err != nil {
		t.Fatalf("scan: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("got %d events; want 2", len(got))
	}
	if got[0].RequestID != "r_1" || got[1].RequestID != "r_2" {
		t.Errorf("got request IDs %v; want [r_1 r_2]", []string{got[0].RequestID, got[1].RequestID})
	}
	if got[0].Status != "approved" || got[1].Status != "denied" {
		t.Errorf("statuses = %v / %v; want approved / denied", got[0].Status, got[1].Status)
	}
}

// TestAuditEvent_AuthModeOnDisk pins F4-B4: the signer's authoritative audit
// log carries a first-class auth_mode alongside approved_by, so the HOW
// (human tap vs grant auto-sign) is recorded independently of the WHO. A
// grant auto-sign event reads auth_mode="grant:<id>" with approved_by the
// same "grant:<id>"; a human-tap event reads auth_mode="human" with the
// approver's name. An empty auth_mode (denied/read) OMITS the key (omitempty).
func TestAuditEvent_AuthModeOnDisk(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "approvals.log")
	log, err := signerkit.OpenAuditLog(path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	grant := signerkit.AuditEvent{
		TS:         time.Now().UTC(),
		RequestID:  "r_grant",
		Status:     "approved",
		Commands:   []string{"systemctl restart nginx"},
		Servers:    []string{"prod"},
		ApprovedBy: "grant:g_abc",
		AuthMode:   "grant:g_abc",
	}
	human := signerkit.AuditEvent{
		TS:         time.Now().UTC(),
		RequestID:  "r_human",
		Status:     "approved",
		Commands:   []string{"rm /tmp/x"},
		Servers:    []string{"prod"},
		ApprovedBy: "karthi",
		AuthMode:   "human",
	}
	denied := signerkit.AuditEvent{
		TS:        time.Now().UTC(),
		RequestID: "r_denied",
		Status:    "denied",
		Commands:  []string{"rm -rf /"},
		Servers:   []string{"prod"},
		// No ApprovedBy / AuthMode — the key must be omitted.
	}
	for _, ev := range []signerkit.AuditEvent{grant, human, denied} {
		if err := log.Write(ev); err != nil {
			t.Fatalf("Write: %v", err)
		}
	}
	if err := log.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer f.Close()
	var raw []map[string]any
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		var m map[string]any
		if err := json.Unmarshal(sc.Bytes(), &m); err != nil {
			t.Fatalf("parse %q: %v", sc.Text(), err)
		}
		raw = append(raw, m)
	}
	if len(raw) != 3 {
		t.Fatalf("got %d events; want 3", len(raw))
	}
	// Grant row: auth_mode carries the grant id AND approved_by is the same.
	if raw[0]["auth_mode"] != "grant:g_abc" {
		t.Errorf("grant auth_mode = %v; want grant:g_abc", raw[0]["auth_mode"])
	}
	if raw[0]["approved_by"] != "grant:g_abc" {
		t.Errorf("grant approved_by = %v; want grant:g_abc", raw[0]["approved_by"])
	}
	// Human row: auth_mode "human", approved_by the approver name.
	if raw[1]["auth_mode"] != "human" {
		t.Errorf("human auth_mode = %v; want human", raw[1]["auth_mode"])
	}
	if raw[1]["approved_by"] != "karthi" {
		t.Errorf("human approved_by = %v; want karthi", raw[1]["approved_by"])
	}
	// Denied row: auth_mode omitted (omitempty).
	if v, ok := raw[2]["auth_mode"]; ok {
		t.Errorf("denied event has auth_mode = %v; want the key OMITTED", v)
	}
}

func TestAuditLog_FileMode(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "approvals.log")
	log, err := signerkit.OpenAuditLog(path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer log.Close()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	// The signer audit log carries command text, so it is created 0600
	// (owner-only). A tighter umask cannot make it more permissive, so an
	// exact match is safe here.
	if got := info.Mode().Perm(); got != 0o600 {
		t.Errorf("audit log mode = %#o; want 0600 (owner-only)", got)
	}
}

func TestAuditLog_ConcurrentWritesDontInterleave(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "approvals.log")
	log, err := signerkit.OpenAuditLog(path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}

	const N = 50
	var wg sync.WaitGroup
	wg.Add(N)
	for i := 0; i < N; i++ {
		i := i
		go func() {
			defer wg.Done()
			ev := signerkit.AuditEvent{
				TS:        time.Now().UTC(),
				RequestID: "r_" + itoaPad(i),
				Status:    "approved",
				Commands:  []string{"echo " + itoaPad(i)},
				Servers:   []string{"s"},
			}
			if err := log.Write(ev); err != nil {
				t.Errorf("write %d: %v", i, err)
			}
		}()
	}
	wg.Wait()
	if err := log.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	// Every line must parse as a complete JSON object. If concurrent
	// writes interleaved, json.Unmarshal will fail on at least one line.
	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	count := 0
	for sc.Scan() {
		var ev signerkit.AuditEvent
		if err := json.Unmarshal(sc.Bytes(), &ev); err != nil {
			t.Fatalf("line %d failed to parse: %v\nline=%q", count, err, sc.Text())
		}
		count++
	}
	if count != N {
		t.Errorf("got %d lines; want %d", count, N)
	}
}

func TestAuditLog_PersistsAcrossClose(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "approvals.log")
	// Three writes through three separate OpenAuditLog/Write/Close
	// cycles emulate a daemon that crashes and is restarted between
	// each event. With fsync-per-write, all three lines must survive.
	for i := 0; i < 3; i++ {
		log, err := signerkit.OpenAuditLog(path)
		if err != nil {
			t.Fatalf("Open[%d]: %v", i, err)
		}
		ev := signerkit.AuditEvent{
			TS:        time.Now().UTC(),
			RequestID: "r_" + itoaPad(i),
			Status:    "approved",
			Commands:  []string{"x"},
			Servers:   []string{"s"},
		}
		if err := log.Write(ev); err != nil {
			t.Fatalf("Write[%d]: %v", i, err)
		}
		if err := log.Close(); err != nil {
			t.Fatalf("Close[%d]: %v", i, err)
		}
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if got := countLines(data); got != 3 {
		t.Errorf("line count = %d; want 3", got)
	}
}

func TestNewMemAuditLog_AcceptsWritesAndCloses(t *testing.T) {
	t.Parallel()
	log, err := signerkit.NewMemAuditLog()
	if err != nil {
		t.Fatalf("NewMemAuditLog: %v", err)
	}
	// Writes must succeed and not block, even with no reader on the
	// other side (the internal drain goroutine reads continuously).
	for i := 0; i < 100; i++ {
		ev := signerkit.AuditEvent{
			TS:        time.Now().UTC(),
			RequestID: "r_" + itoaPad(i),
			Status:    "approved",
			Commands:  []string{"x"},
			Servers:   []string{"s"},
		}
		if err := log.Write(ev); err != nil {
			t.Fatalf("Write[%d]: %v", i, err)
		}
	}
	if err := log.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	// Writing after Close should fail rather than panic.
	err = log.Write(signerkit.AuditEvent{RequestID: "post", Status: "x", Commands: []string{}, Servers: []string{}})
	if err == nil {
		t.Error("Write after Close returned nil; expected an error")
	}
}

// helpers
func itoaPad(i int) string {
	// fixed-width tag so request IDs sort and the test diagnostic is
	// human readable; not load-bearing.
	const digits = "0123456789"
	hi := i / 10
	lo := i % 10
	return string([]byte{digits[hi%10], digits[lo]})
}

func countLines(b []byte) int {
	n := 0
	for _, c := range b {
		if c == '\n' {
			n++
		}
	}
	return n
}
