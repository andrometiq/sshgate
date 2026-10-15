package backend_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/karthikeyan5/sshgate/pkg/signerkit"
	"github.com/karthikeyan5/sshgate/src/sigwire"
)

func TestHostedRefusesNet(t *testing.T) {
	var requests atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	backend := &signerkit.HostedServerBackend{
		BaseURL: server.URL, APIKey: "test-key", ClientID: "test-client", HTTPClient: server.Client(),
	}
	for _, commands := range [][]signerkit.CommandReq{
		{{Server: "test", Cmd: "curl https://example.com", TTLSec: 60, Net: true, Reason: "check endpoint"}},
		{
			{Server: "test", Cmd: "ls", TTLSec: 60},
			{Server: "test", Cmd: "curl https://example.com", TTLSec: 60, Net: true, Reason: "check endpoint"},
		},
		{{Server: "test", Cmd: "curl https://example.com", TTLSec: 60, Net: true, Reveal: true, Reason: "inspect response"}},
	} {
		result, err := backend.Request(context.Background(), signerkit.ApprovalRequest{
			RequestID: "net-request", Commands: commands,
		})
		if err == nil || !strings.HasPrefix(err.Error(), sigwire.SignerNetUnsupported) {
			t.Errorf("network request error = %v; want net_unsupported: prefix", err)
		}
		if result != nil {
			t.Error("network refusal returned a result channel")
		}
	}
	if got := requests.Load(); got != 0 {
		t.Errorf("MUTATION-EFFECT hosted-http-net")
		t.Errorf("network requests reached hosted HTTP server %d times; want zero", got)
	}
}
