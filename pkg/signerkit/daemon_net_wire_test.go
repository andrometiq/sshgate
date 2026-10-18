package signerkit

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"os"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/karthikeyan5/sshgate/src/sigwire"
)

// v1SignRequest and v1SignRequestCmd are vendored copies of the daemon's
// socket request shapes at ad7407a, before the net field. Every signer shipped
// so far decodes a sign request into them with DisallowUnknownFields.
type v1SignRequest struct {
	Kind         string             `json:"kind"`
	RequestID    string             `json:"request_id"`
	Commands     []v1SignRequestCmd `json:"commands"`
	ProtoVersion int                `json:"proto_version,omitempty"`
}

type v1SignRequestCmd struct {
	Server string `json:"server"`
	Cmd    string `json:"cmd"`
	TTLSec int64  `json:"ttl_seconds"`
	Host   string `json:"host,omitempty"`
	Reveal bool   `json:"reveal,omitempty"`
	Reason string `json:"reason,omitempty"`
}

// The request lines the MCP client writes without and with network (pinned
// against the client in src/mcp/sign's TestSignRequestWireNoNetGolden).
const (
	clientRequestNoNet = `{"kind":"sign","request_id":"r_net_wire","commands":[` +
		`{"server":"prod","cmd":"uptime","ttl_seconds":60,"host":"SHA256:netWireHostFingerprintAAAAAAAAAAAAAAAAAAAAAA"},` +
		`{"server":"prod","cmd":"cat /etc/app.env","ttl_seconds":120,"host":"SHA256:netWireHostFingerprintAAAAAAAAAAAAAAAAAAAAAA","reveal":true,"reason":"debug the deploy"}` +
		`],"proto_version":1}`
	clientRequestNet = `{"kind":"sign","request_id":"r_net_wire","commands":[` +
		`{"server":"prod","cmd":"uptime","ttl_seconds":60,"host":"SHA256:netWireHostFingerprintAAAAAAAAAAAAAAAAAAAAAA","net":true},` +
		`{"server":"prod","cmd":"cat /etc/app.env","ttl_seconds":120,"host":"SHA256:netWireHostFingerprintAAAAAAAAAAAAAAAAAAAAAA","reveal":true,"reason":"debug the deploy"}` +
		`],"proto_version":1}`
)

// TestOldDaemonStrictDecoder proves a signer built before the net field still
// accepts the new client's request without network, and refuses one with
// network rather than signing it without the grant.
func TestOldDaemonStrictDecoder(t *testing.T) {
	decodeV1 := func(line string) error {
		dec := json.NewDecoder(strings.NewReader(line))
		dec.DisallowUnknownFields()
		var req v1SignRequest
		return dec.Decode(&req)
	}
	if err := decodeV1(clientRequestNoNet); err != nil {
		t.Errorf("old daemon refused the request without network: %v", err)
	}
	err := decodeV1(clientRequestNet)
	if err == nil {
		t.Fatal("old daemon accepted a request with network")
	}
	if !strings.Contains(err.Error(), sigwire.OldStrictDecodeNet) {
		t.Errorf("old daemon error %q does not contain %q", err, sigwire.OldStrictDecodeNet)
	}

	// The current daemon's shape reads both, and keeps the flag.
	var current signRequest
	dec := json.NewDecoder(strings.NewReader(clientRequestNet))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&current); err != nil {
		t.Fatalf("current daemon refused the request with network: %v", err)
	}
	if !current.Commands[0].Net || current.Commands[1].Net {
		t.Errorf("decoded net flags = %v, %v; want true, false", current.Commands[0].Net, current.Commands[1].Net)
	}
}

// countingBackend records whether the daemon asked it for an approval.
type countingBackend struct {
	*MockBackend
	requests atomic.Int32
}

func (b *countingBackend) Request(ctx context.Context, req ApprovalRequest) (<-chan Result, error) {
	b.requests.Add(1)
	return b.MockBackend.Request(ctx, req)
}

func readAuditRows(t *testing.T, path string) []AuditEvent {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read audit: %v", err)
	}
	var rows []AuditEvent
	scanner := bufio.NewScanner(bytes.NewReader(raw))
	for scanner.Scan() {
		var row AuditEvent
		if err := json.Unmarshal(scanner.Bytes(), &row); err != nil {
			t.Fatalf("decode audit row %q: %v", scanner.Text(), err)
		}
		rows = append(rows, row)
	}
	return rows
}
