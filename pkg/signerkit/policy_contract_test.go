package signerkit

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/karthikeyan5/sshgate/src/policy"
	"github.com/karthikeyan5/sshgate/src/policywire"
)

type splitReadWriter struct {
	reader *bytes.Reader
	writer bytes.Buffer
}

func (rw *splitReadWriter) Read(p []byte) (int, error)  { return rw.reader.Read(p) }
func (rw *splitReadWriter) Write(p []byte) (int, error) { return rw.writer.Write(p) }

func TestBaseManifestBackendCapabilityIsOptional(t *testing.T) {
	var ordinary Backend = &StubBackend{}
	if _, ok := ordinary.(BaseManifestApprovalBackend); ok {
		t.Fatal("ordinary Backend unexpectedly implements policy capability")
	}
}

func TestBaseManifestKindCannotReachOrdinaryBackend(t *testing.T) {
	payload, err := policy.MarshalBaseManifest(policy.BaseManifest{
		Schema: policy.SchemaV1, Host: policyTestHost, Epoch: 1, Revision: 1,
		MissAction: policy.MissActionClassifier, Growth: policy.GrowthNone,
	})
	if err != nil {
		t.Fatal(err)
	}
	req, err := policywire.NewRequest(
		"pm_0123456789abcdef0123456789abcdef",
		policyTestHost,
		strings.Repeat("a", 64),
		payload,
		"",
		true,
	)
	if err != nil {
		t.Fatal(err)
	}
	line, err := policywire.MarshalRequestLine(req)
	if err != nil {
		t.Fatal(err)
	}
	mock := NewMockBackend()
	audit, err := NewMemAuditLog()
	if err != nil {
		t.Fatal(err)
	}
	rw := &splitReadWriter{reader: bytes.NewReader(line)}
	d := &Daemon{Backend: mock, Audit: audit}
	if err := d.HandleSignRequest(context.Background(), rw); err != nil {
		t.Fatal(err)
	}
	mock.mu.Lock()
	pending := len(mock.pending)
	mock.mu.Unlock()
	if pending != 0 {
		t.Fatalf("policy kind reached ordinary backend: %d pending requests", pending)
	}
	var response signResponse
	if err := json.Unmarshal(rw.writer.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	if response.Status != "error" || !strings.Contains(response.Error, "unsupported kind") {
		t.Fatalf("response = %#v; want safe unsupported-kind rejection", response)
	}
}
