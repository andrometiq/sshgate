package registry

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/karthikeyan5/sshgate/src/approvalplan"
)

func currentFixture(t *testing.T) (*Servers, string, Entry) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "servers.json")
	entry := Entry{Host: "host", Port: 22, User: "user", Fingerprint: "SHA256:test", AddedAt: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)}
	writeCurrent(t, path, map[string]Entry{"host": entry})
	servers, err := New(path)
	if err != nil {
		t.Fatal(err)
	}
	return servers, path, entry
}

func writeCurrent(t *testing.T, path string, entries map[string]Entry) {
	t.Helper()
	body, err := json.Marshal(entries)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, body, 0600); err != nil {
		t.Fatal(err)
	}
}

func TestReadCurrentFailuresAndGetCompatibility(t *testing.T) {
	for _, kind := range []string{"malformed", "unreadable", "insecure", "absent", "changed", "empty", "missing alias", "empty wrapper", "null wrapper", "populated wrapper", "null", "read failure"} {
		t.Run(kind, func(t *testing.T) {
			servers, path, old := currentFixture(t)
			_, digest, err := servers.ReadCurrent("host")
			if err != nil {
				t.Fatal(err)
			}
			wantDetail := ""
			switch kind {
			case "malformed":
				err = os.WriteFile(path, []byte("{"), 0600)
			case "unreadable":
				if os.Geteuid() == 0 {
					t.Skip("mode 0000 requires an unprivileged reader")
				}
				err = os.Chmod(path, 0000)
				wantDetail = "registry unreadable"
			case "insecure":
				err = os.Chmod(path, 0620)
			case "absent":
				err = os.Remove(path)
				wantDetail = "alias not found"
			case "changed":
				changed := old
				changed.Host = "new-host"
				writeCurrent(t, path, map[string]Entry{"host": changed})
			case "empty":
				err = os.WriteFile(path, nil, 0600)
				wantDetail = "alias not found"
			case "missing alias":
				writeCurrent(t, path, map[string]Entry{"other": old})
				wantDetail = "alias not found"
			case "empty wrapper":
				err = os.WriteFile(path, []byte(`{"servers":{}}`), 0600)
				wantDetail = "alias not found"
			case "null wrapper":
				err = os.WriteFile(path, []byte(`{"servers":null}`), 0600)
				wantDetail = "alias not found"
			case "populated wrapper":
				err = os.WriteFile(path, []byte(`{"servers":{"node":{"host":"hidden"}}}`), 0600)
			case "null":
				err = os.WriteFile(path, []byte(`null`), 0600)
				wantDetail = "alias not found"
			case "read failure":
				if err = os.Remove(path); err == nil {
					err = os.Mkdir(path, 0700)
				}
				wantDetail = "registry unreadable"
			}
			if err != nil {
				t.Fatal(err)
			}
			snapshot, gotDigest, readErr := servers.ReadCurrent("host")
			if kind == "changed" {
				if readErr != nil || gotDigest == digest || snapshot.ResolvedHost != "new-host" {
					t.Fatalf("changed route: %+v %q %v", snapshot, gotDigest, readErr)
				}
			} else {
				if readErr == nil || snapshot != (approvalplan.RouteSnapshot{}) || gotDigest != "" {
					t.Fatalf("did not fail closed: %+v %q %v", snapshot, gotDigest, readErr)
				}
				if wantDetail != "" && readErr.Error() != wantDetail {
					t.Fatalf("detail = %q, want %q", readErr, wantDetail)
				}
			}
			// The fresh read must never mutate the legacy cache, even on success.
			if servers.data["host"] != old {
				t.Fatal("ReadCurrent mutated cache")
			}
			got, ok := servers.Get("host")
			switch kind {
			case "malformed", "unreadable", "insecure", "populated wrapper", "read failure":
				if !ok || got != old {
					t.Fatalf("Get lost last-known entry: %+v %v", got, ok)
				}
			case "changed":
				if !ok || got.Host != "new-host" {
					t.Fatal("Get did not reload changed entry")
				}
			default:
				if ok {
					t.Fatal("Get retained absent alias")
				}
			}
		})
	}
}

func TestSnapshotFieldsAndDigest(t *testing.T) {
	servers, path, entry := currentFixture(t)
	expected := approvalplan.RouteSnapshot{ServerAlias: "host", ResolvedHost: entry.Host, ResolvedPort: entry.Port, ResolvedUser: entry.User, TrustedHostFingerprint: entry.Fingerprint, ReadOnly: entry.ReadOnly, AddedAt: entry.AddedAt}
	got, digest, err := servers.ReadCurrent("host")
	if err != nil || got != expected || digest != expected.Digest() {
		t.Fatalf("snapshot: %+v %q %v", got, digest, err)
	}
	for _, change := range []func(*Entry){func(e *Entry) { e.Host = "other" }, func(e *Entry) { e.Port++ }, func(e *Entry) { e.User = "other" }, func(e *Entry) { e.Fingerprint = "SHA256:other" }, func(e *Entry) { e.ReadOnly = true }, func(e *Entry) { e.AddedAt = e.AddedAt.Add(time.Second) }} {
		changed := entry
		change(&changed)
		writeCurrent(t, path, map[string]Entry{"host": changed})
		_, changedDigest, err := servers.ReadCurrent("host")
		if err != nil || changedDigest == digest {
			t.Fatalf("route drift missed: %+v %v", changed, err)
		}
	}
	if Snapshot("other", entry).Digest() == digest {
		t.Fatal("alias omitted from digest")
	}
	entry.AddedAt = entry.AddedAt.In(time.FixedZone("offset", 3600))
	if Snapshot("host", entry) != expected {
		t.Fatal("snapshot did not normalize time")
	}
	writeCurrent(t, path, map[string]Entry{"servers": entry})
	if _, _, err := servers.ReadCurrent("servers"); err != nil {
		t.Fatalf("real servers alias refused: %v", err)
	}
}

func TestReadCurrentDescriptorReplacement(t *testing.T) {
	servers, path, entry := currentFixture(t)
	var writer sync.WaitGroup
	writer.Add(1)
	done := make(chan struct{})
	go func() {
		defer writer.Done()
		defer close(done)
		for i := 0; i < 1000; i++ {
			replacement := path + ".next"
			next := entry
			mode := os.FileMode(0600)
			if i%2 == 0 {
				next.Host = "insecure"
				mode = 0620
			}
			body, err := json.Marshal(map[string]Entry{"host": next})
			if err == nil {
				err = os.WriteFile(replacement, body, mode)
			}
			if err == nil {
				err = os.Chmod(replacement, mode)
			}
			if err == nil {
				err = os.Rename(replacement, path)
			}
			if err != nil {
				t.Error(err)
				return
			}
		}
	}()
	defer writer.Wait()
	for {
		snapshot, _, err := servers.ReadCurrent("host")
		if err == nil && snapshot.ResolvedHost != "host" {
			t.Fatalf("accepted insecure replacement: %+v", snapshot)
		}
		select {
		case <-done:
			return
		default:
		}
	}
}

func TestReadCurrentWrapperAlias(t *testing.T) {
	servers, path, _ := currentFixture(t)
	for _, body := range []string{`{"servers":{}}`, `{"servers":null}`, `{"servers":{"node":{"host":"hidden"}}}`} {
		if err := os.WriteFile(path, []byte(body), 0600); err != nil {
			t.Fatal(err)
		}
		if _, _, err := servers.ReadCurrent("servers"); err == nil {
			t.Fatalf("accepted wrapper %s", body)
		}
	}
}
