package registry_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/karthikeyan5/sshgate/src/mcp/registry"
)

func TestNew_MissingFileIsEmpty(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "servers.json")
	s, err := registry.New(path)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if got := len(s.List()); got != 0 {
		t.Fatalf("List() len = %d; want 0", got)
	}
}

func TestLoad_RoundTrip(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "servers.json")
	now := time.Date(2026, 5, 19, 12, 0, 0, 0, time.UTC)
	body, err := json.Marshal(map[string]registry.Entry{
		"prod-db": {Host: "10.0.0.1", Port: 22, User: "operator", AddedAt: now},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, body, 0o600); err != nil {
		t.Fatalf("seed: %v", err)
	}
	s, err := registry.New(path)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	e, ok := s.Get("prod-db")
	if !ok {
		t.Fatal("missing prod-db entry")
	}
	if e.Host != "10.0.0.1" || e.Port != 22 || e.User != "operator" {
		t.Errorf("got %+v", e)
	}
	if !e.AddedAt.Equal(now) {
		t.Errorf("AddedAt: got %v want %v", e.AddedAt, now)
	}
}

// TestFingerprint_PersistsThroughSaveLoad pins that an Entry.Fingerprint
// survives a save (Add) and an independent reload (New). The gate's per-server
// host-key binding depends on this value being durable: if it were dropped on
// persist, the MCP would later supply an empty Host and every signed write
// would fail closed at the gate.
func TestFingerprint_PersistsThroughSaveLoad(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "servers.json")
	s, err := registry.New(path)
	if err != nil {
		t.Fatal(err)
	}
	const fp = "SHA256:persistedHostKeyFingerprintAAAAAAAAAAAAAAAAA"
	if err := s.Add("prod", registry.Entry{
		Host: "10.0.0.1", Port: 22, User: "operator", AddedAt: time.Now().UTC(), Fingerprint: fp,
	}); err != nil {
		t.Fatalf("Add: %v", err)
	}

	// Reload through a fresh Servers so we exercise the on-disk JSON, not the
	// in-memory map.
	s2, err := registry.New(path)
	if err != nil {
		t.Fatalf("reload New: %v", err)
	}
	e, ok := s2.Get("prod")
	if !ok {
		t.Fatal("missing prod after reload")
	}
	if e.Fingerprint != fp {
		t.Errorf("Fingerprint = %q; want %q (must persist through save/load)", e.Fingerprint, fp)
	}
}

func TestAdd_PersistsAtomically(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "servers.json")
	s, err := registry.New(path)
	if err != nil {
		t.Fatal(err)
	}
	added := time.Date(2026, 5, 19, 12, 0, 0, 0, time.UTC)
	if err := s.Add("h1", registry.Entry{Host: "a", Port: 22, User: "u", AddedAt: added}); err != nil {
		t.Fatalf("Add: %v", err)
	}
	// File must exist and be readable as JSON.
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	var got map[string]registry.Entry
	if err := json.Unmarshal(body, &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if got["h1"].Host != "a" {
		t.Errorf("h1.Host = %q; want a", got["h1"].Host)
	}
	// File mode must be 0600.
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Errorf("file mode = %#o; want 0600", perm)
	}
	// Reloading sees the same data.
	s2, err := registry.New(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := s2.Get("h1"); !ok {
		t.Error("h1 missing after reload")
	}
}

func TestAdd_NoTempLeftover(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "servers.json")
	s, err := registry.New(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Add("h1", registry.Entry{Host: "a", Port: 22, User: "u", AddedAt: time.Now()}); err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if e.Name() == filepath.Base(path) {
			continue
		}
		// Any leftover .tmp / sibling is a partial-write failure.
		if strings.Contains(e.Name(), "tmp") || strings.HasPrefix(e.Name(), ".") {
			t.Errorf("unexpected sibling %q after Add", e.Name())
		}
	}
}

func TestRemove(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "servers.json")
	s, err := registry.New(path)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	if err := s.Add("a", registry.Entry{Host: "h", Port: 22, User: "u", AddedAt: now}); err != nil {
		t.Fatal(err)
	}
	if err := s.Add("b", registry.Entry{Host: "h", Port: 22, User: "u", AddedAt: now}); err != nil {
		t.Fatal(err)
	}
	if err := s.Remove("a"); err != nil {
		t.Fatalf("Remove: %v", err)
	}
	if _, ok := s.Get("a"); ok {
		t.Error("a still present after Remove")
	}
	if _, ok := s.Get("b"); !ok {
		t.Error("b removed unexpectedly")
	}
	// Persisted state matches.
	s2, err := registry.New(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := s2.Get("a"); ok {
		t.Error("a present after reload")
	}
	if _, ok := s2.Get("b"); !ok {
		t.Error("b missing after reload")
	}
}

func TestRemove_UnknownAliasError(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "servers.json")
	s, err := registry.New(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Remove("nope"); err == nil {
		t.Error("Remove of unknown alias returned nil; want error")
	}
}

func TestNew_RefusesGroupWritable(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "servers.json")
	if err := os.WriteFile(path, []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o660); err != nil {
		t.Fatal(err)
	}
	if _, err := registry.New(path); err == nil {
		t.Error("New on group-writable file returned nil; want error")
	}
}

func TestNew_RefusesWorldWritable(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "servers.json")
	if err := os.WriteFile(path, []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o606); err != nil {
		t.Fatal(err)
	}
	if _, err := registry.New(path); err == nil {
		t.Error("New on world-writable file returned nil; want error")
	}
}

func TestList_ReturnsCopy(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "servers.json")
	s, err := registry.New(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Add("a", registry.Entry{Host: "h", Port: 22, User: "u", AddedAt: time.Now()}); err != nil {
		t.Fatal(err)
	}
	out := s.List()
	out["mutation"] = registry.Entry{Host: "evil"}
	if _, ok := s.Get("mutation"); ok {
		t.Error("List returned a live map; mutation leaked into Servers")
	}
}

func TestConcurrentAddRemove(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "servers.json")
	s, err := registry.New(path)
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	const N = 8
	for i := 0; i < N; i++ {
		i := i
		wg.Add(1)
		go func() {
			defer wg.Done()
			alias := "a" + strings.Repeat("x", i)
			_ = s.Add(alias, registry.Entry{Host: "h", Port: 22, User: "u", AddedAt: time.Now()})
		}()
	}
	wg.Wait()
}
