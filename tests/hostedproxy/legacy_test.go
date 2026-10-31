package hostedproxy_test

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"

	sk "github.com/karthikeyan5/sshgate/pkg/signerkit"
	"github.com/karthikeyan5/sshgate/src/xfer"
)

func TestHostedV1RecordedParity(t *testing.T) {
	data, err := os.ReadFile("testdata/legacy-a8fc4d5.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixtures []struct {
		Request  string   `json:"request"`
		Response string   `json:"response"`
		HTTP     []string `json:"http"`
	}
	if err = json.Unmarshal(data, &fixtures); err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	var calls []string
	transport := fixtureTransport(func(req *http.Request) (*http.Response, error) {
		var body []byte
		var err error
		if req.Body != nil {
			body, err = io.ReadAll(req.Body)
			if err != nil {
				return nil, err
			}
		}
		mu.Lock()
		calls = append(calls, req.Method+" "+req.URL.RequestURI()+" "+string(body))
		mu.Unlock()
		status := 200
		response := `{"request_id":"r_fixture","status":"denied"}`
		if req.Method == "POST" {
			status = 202
			response = `{"request_id":"r_fixture"}`
		}
		return &http.Response{StatusCode: status, Header: http.Header{"Content-Type": {"application/json"}}, Body: io.NopCloser(strings.NewReader(response)), Request: req}, nil
	})
	root := t.TempDir()
	key := ed25519.NewKeyFromSeed(make([]byte, 32))
	box := xfer.BoxPublicText(&[32]byte{1})
	id := xfer.IDPublicText(key.Public().(ed25519.PublicKey))
	registry, err := sk.LoadXferRegistry(filepath.Join(root, "registry.json"))
	if err != nil {
		t.Fatal(err)
	}
	for _, fp := range []string{"SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", "SHA256:BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"} {
		if err = registry.Register(fp, "test", box, id); err != nil {
			t.Fatal(err)
		}
	}
	audit, err := sk.OpenAuditLog(filepath.Join(root, "audit.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	defer audit.Close()
	backend := &sk.HostedServerBackend{BaseURL: "https://signer.example", APIKey: "test-key", ClientID: "client", HTTPClient: &http.Client{Transport: transport}}
	svc, err := sk.New(sk.Config{Signer: key, Audit: audit, Backend: backend, XferRegistry: registry})
	if err != nil {
		t.Fatal(err)
	}
	defer svc.Close()
	runtime, err := sk.NewApprovalRuntime(sk.ApprovalRuntimeConfig{Forwarder: backend})
	if err != nil {
		t.Fatal(err)
	}
	if err = svc.AttachApprovals(runtime); err != nil {
		t.Fatal(err)
	}
	if runtime.Legacy() != nil {
		t.Fatal("hosted runtime has a legacy store")
	}
	wantKinds := []string{"request_grant", "list_grants", "sign", "transfer", "register_xfer_key"}
	if len(fixtures) != len(wantKinds) {
		t.Fatal("incomplete legacy capture")
	}
	for i, fixture := range fixtures {
		var header struct {
			Kind string `json:"kind"`
		}
		if err = json.Unmarshal([]byte(fixture.Request), &header); err != nil {
			t.Fatal(err)
		}
		if header.Kind != wantKinds[i] {
			t.Fatalf("capture kind %d = %q, want %q", i, header.Kind, wantKinds[i])
		}
		t.Run(header.Kind, func(t *testing.T) {
			mu.Lock()
			calls = []string{}
			mu.Unlock()
			if got := string(directFrame(t, svc, []byte(fixture.Request))); got != fixture.Response {
				t.Fatalf("response = %s want %s", got, fixture.Response)
			}
			mu.Lock()
			got := append([]string{}, calls...)
			mu.Unlock()
			if !reflect.DeepEqual(got, fixture.HTTP) {
				t.Fatalf("HTTP = %q want %q", got, fixture.HTTP)
			}
			if runtime.Legacy() != nil {
				t.Fatal("v1 created a LegacyRequest store")
			}
		})
	}
}

func TestHostedRefusesNet(t *testing.T) {
	calls := 0
	backend := &sk.HostedServerBackend{BaseURL: "https://signer.example", APIKey: "key", ClientID: "client", HTTPClient: &http.Client{Transport: fixtureTransport(func(*http.Request) (*http.Response, error) { calls++; t.Error("Net reached HTTP"); return nil, io.EOF })}}
	channel, err := backend.Request(context.Background(), sk.ApprovalRequest{RequestID: "net", Commands: []sk.CommandReq{{Server: "web", Cmd: "cat /etc/hosts", TTLSec: 60, Net: true}}})
	if err == nil || !strings.HasPrefix(err.Error(), "net_unsupported:") || channel != nil || calls != 0 {
		t.Fatalf("Net: channel %v error %v HTTP %d", channel, err, calls)
	}
	svc, _ := fixtureService(t, backend.HTTPClient.Transport)
	frame := directFrame(t, svc, []byte(`{"kind":"sign","request_id":"net","commands":[{"server":"web","cmd":"cat /etc/hosts","ttl_seconds":60,"net":true,"reason":"inspect network state"}]}`))
	var response struct {
		Status string `json:"status"`
		Error  string `json:"error"`
	}
	if err = json.Unmarshal(frame, &response); err != nil {
		t.Fatal(err)
	}
	if response.Status != "error" || !strings.Contains(response.Error, "net_unsupported:") || calls != 0 {
		t.Fatalf("daemon Net = %s calls %d", frame, calls)
	}
}
