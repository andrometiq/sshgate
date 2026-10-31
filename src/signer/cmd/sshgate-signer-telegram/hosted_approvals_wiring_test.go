package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/karthikeyan5/sshgate/pkg/signerkit"
)

type hostedWiringTransport func(*http.Request) (*http.Response, error)

func (f hostedWiringTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestHostedApprovalsWiring(t *testing.T) {
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "token")
	if err := os.WriteFile(keyPath, []byte("test-token"), 0600); err != nil {
		t.Fatal(err)
	}
	bk, err := buildHostedBackend(hostedConfig{BaseURL: "https://signer.example", APIKeyFile: keyPath, ClientID: "test-client"})
	if err != nil {
		t.Fatal(err)
	}
	hosted := bk.(*signerkit.HostedServerBackend)
	calls := 0
	hosted.HTTPClient = &http.Client{Transport: hostedWiringTransport(func(r *http.Request) (*http.Response, error) {
		calls++
		if r.URL.Path != "/v2/approvals" || r.URL.Query().Get("requester_sub") != "local-uid:17" {
			t.Errorf("wrong route %s", r.URL)
		}
		return &http.Response{StatusCode: 200, Header: http.Header{"Content-Type": []string{"application/json"}}, Body: io.NopCloser(strings.NewReader(`{"approval_proto":1,"ok":true}`))}, nil
	})}
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	audit, err := signerkit.OpenAuditLog(filepath.Join(dir, "audit.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	defer audit.Close()
	svc, err := signerkit.New(signerkit.Config{Signer: key, Backend: bk, Audit: audit})
	if err != nil {
		t.Fatal(err)
	}
	defer svc.Close()
	cfg := tomlConfig{}
	cfg.Approvals.AllowedUIDs = []uint32{17}
	cfg.Approvals.JournalRoot = filepath.Join(dir, "approvals")
	runtime, err := attachApprovals(svc, bk, cfg, audit, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(cfg.Approvals.JournalRoot); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("hosted forwarder opened a local approval store: %v", err)
	}
	if !errors.Is(runtime.Status(), signerkit.ErrHostedForwarder) || runtime.Legacy() != nil {
		t.Fatal("hosted runtime not wired", runtime.Status())
	}
	for _, uid := range []uint32{17, 18} {
		conn := &wiringConnection{input: bytes.NewReader([]byte("{\"approval_proto\":1,\"kind\":\"approval_list_v2\",\"limit\":50}\n"))}
		if err := svc.HandleSignRequestWithPeer(context.Background(), conn, &signerkit.PeerCredentials{UID: uid}); err != nil {
			t.Fatal(err)
		}
		if uid == 17 && !strings.Contains(conn.output.String(), `"ok":true`) {
			t.Fatal(conn.output.String())
		}
		if uid == 18 && !strings.Contains(conn.output.String(), `"code":"not_found"`) {
			t.Fatal(conn.output.String())
		}
	}
	if calls != 1 {
		t.Fatalf("calls %d", calls)
	}
}
