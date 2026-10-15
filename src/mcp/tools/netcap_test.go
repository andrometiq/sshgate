package tools

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/karthikeyan5/sshgate/src/mcp/registry"
	signpkg "github.com/karthikeyan5/sshgate/src/mcp/sign"
)

const capReply = `{"v":1,"enforcement":"kernel","pinned":true,"net":true,"net_grants":true,"label":"ready","reason":""}`

type capSSH struct {
	mu    sync.Mutex
	calls int
	out   string
	exit  int
	err   error
}

func (s *capSSH) Run(_ context.Context, host, user string, port int, cmd string) ([]byte, []byte, int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if cmd == "SSHGATE_VERSION" || cmd == "" {
		return nil, nil, 0, nil
	}
	if cmd != "SSHGATE_JAIL" || host != "host" || user != "user" || port != 2222 {
		return nil, nil, 0, errors.New("unexpected probe")
	}
	s.calls++
	return []byte(s.out), nil, s.exit, s.err
}

var capEntry = registry.Entry{Host: "host", User: "user", Port: 2222}

func TestCapParse(t *testing.T) {
	cases := []struct {
		name, out string
		exit      int
		err       error
		valid     bool
	}{
		{"kernel", capReply, 0, nil, true},
		{"classifier", strings.Replace(capReply, "kernel", "classifier", 1), 0, nil, true},
		{"unavailable", strings.Replace(capReply, "kernel", "unavailable", 1), 0, nil, true},
		{"newline", capReply + "\n", 0, nil, true},
		{"extra-key", strings.Replace(capReply, `"v":1`, `"future":[],"v":1`, 1), 0, nil, true},
		{"old-gate", capReply, 77, nil, false},
		{"ssh-error", capReply, 0, errors.New("transport"), false},
		{"non-json", "not json", 0, nil, false},
		{"two-lines", capReply + "\n" + capReply, 0, nil, false},
		{"two-values", capReply + capReply, 0, nil, false},
		{"blank-line", capReply + "\n\n", 0, nil, false},
		{"v2", strings.Replace(capReply, `"v":1`, `"v":2`, 1), 0, nil, false},
		{"unknown-enforcement", strings.Replace(capReply, "kernel", "other", 1), 0, nil, false},
	}
	for _, key := range []string{"v", "enforcement", "pinned", "net", "net_grants"} {
		var fields map[string]json.RawMessage
		if err := json.Unmarshal([]byte(capReply), &fields); err != nil {
			t.Fatal(err)
		}
		delete(fields, key)
		missing, _ := json.Marshal(fields)
		cases = append(cases, struct {
			name, out string
			exit      int
			err       error
			valid     bool
		}{"missing-" + key, string(missing), 0, nil, false})
		for _, bad := range []string{"null", "[]"} {
			fields[key] = json.RawMessage(bad)
			body, _ := json.Marshal(fields)
			cases = append(cases, struct {
				name, out string
				exit      int
				err       error
				valid     bool
			}{bad + "-" + key, string(body), 0, nil, false})
		}
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ssh := &capSSH{out: tc.out, exit: tc.exit, err: tc.err}
			r := &Runner{SSH: ssh}
			got := r.fetchCap(context.Background(), "a", capEntry)
			if (got != nil) != tc.valid {
				t.Fatalf("capability=%+v, valid=%v", got, tc.valid)
			}
			if got != nil && (got.V != 1 || !got.Pinned || !got.Net || !got.NetGrants || got.Label != "ready") {
				t.Fatalf("fields lost: %+v", got)
			}
			r.fetchCap(context.Background(), "a", capEntry)
			if ssh.calls != 1 {
				t.Fatalf("cache probe count=%d", ssh.calls)
			}
		})
	}
}

type capSigner struct{ SignClient }

func (capSigner) Sign(context.Context, string, []signpkg.CmdReq) (signpkg.SignResult, error) {
	return signpkg.SignResult{Signed: []signpkg.Signed{{Sig: "signature"}}}, nil
}

type capUpdate struct {
	out  string
	exit int
	err  error
}

func (s capUpdate) RunWithStdin(context.Context, string, string, int, string, io.Reader) ([]byte, []byte, int, error) {
	return []byte(s.out), nil, s.exit, s.err
}

func TestCapCacheInvalidation(t *testing.T) {
	body := []byte("fixture")
	sum := sha256.Sum256(body)
	marker := fmt.Sprintf("SSHGATE_UPDATED sha256=%x size=7 rev=test", sum)
	for _, tc := range []struct {
		name    string
		update  capUpdate
		success bool
	}{
		{"success", capUpdate{out: marker}, true},
		{"denied", capUpdate{exit: 77}, false},
		{"transport", capUpdate{err: errors.New("transport")}, false},
		{"missing-marker", capUpdate{}, false},
		{"wrong-hash", capUpdate{out: "SSHGATE_UPDATED sha256=wrong size=7 rev=test"}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			servers, err := registry.New(filepath.Join(dir, "servers.json"))
			if err != nil {
				t.Fatal(err)
			}
			if err := servers.Add("a", capEntry); err != nil {
				t.Fatal(err)
			}
			staged := filepath.Join(dir, "gate")
			if err := os.WriteFile(staged, body, 0600); err != nil {
				t.Fatal(err)
			}
			ssh := &capSSH{out: capReply}
			r := &Runner{SSH: ssh, SSHStdin: tc.update, Sign: capSigner{}, Servers: servers, StagedGatePath: staged}
			r.fetchCap(context.Background(), "a", capEntry)
			r.fetchCap(context.Background(), "b", capEntry)
			_, err = r.UpdateGate(context.Background(), UpdateGateInput{Alias: "a"})
			if (err == nil) != tc.success {
				t.Fatalf("update error=%v", err)
			}
			ssh.out = strings.Replace(capReply, `"net":true`, `"net":false`, 1)
			got := r.fetchCap(context.Background(), "a", capEntry)
			if got == nil || got.Net == tc.success {
				t.Fatalf("stale capability: %+v", got)
			}
			if !r.fetchCap(context.Background(), "b", capEntry).Net {
				t.Fatal("other alias invalidated")
			}
			want := 2
			if tc.success {
				want = 3
			}
			if ssh.calls != want {
				t.Fatalf("probes=%d want %d", ssh.calls, want)
			}
		})
	}
}
func TestCapCacheConcurrent(t *testing.T) {
	ssh := &capSSH{out: capReply}
	r := &Runner{SSH: ssh}
	var wg sync.WaitGroup
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 30; j++ {
				cap := r.fetchCap(context.Background(), "a", capEntry)
				if cap == nil || !cap.Net {
					t.Error("capability lost")
					return
				}
				cap.Net = false // callers cannot mutate the shared snapshot
				r.invalidateCap("a")
			}
		}()
	}
	wg.Wait()
	if cap := r.fetchCap(context.Background(), "a", capEntry); cap == nil || !cap.Net {
		t.Fatalf("capability=%+v", cap)
	}
}
