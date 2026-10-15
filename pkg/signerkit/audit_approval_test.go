//go:build linux

package signerkit

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/karthikeyan5/sshgate/src/approvalplan"
)

func TestApprovalAuditMetadataTrailingEncoding(t *testing.T) {
	metadata := &approvalplan.AuditMetadata{Transition: "submitted"}
	for _, event := range []any{
		AuditEvent{Approval: metadata},
		AuditCall{Approval: metadata},
		AuditVerdict{Approval: metadata},
	} {
		got, err := json.Marshal(event)
		if err != nil {
			t.Fatal(err)
		}
		if !strings.HasSuffix(string(got), `,"approval":{"transition":"submitted"}}`) {
			t.Fatalf("%T: approval metadata missing or not trailing: %s", event, got)
		}
	}
}

func TestApprovalAuditNilPreservesSinkBytes(t *testing.T) {
	now := time.Date(2026, time.July, 20, 1, 2, 3, 0, time.UTC)
	call := AuditCall{Time: now, RequestID: "r_frozen", HostKeyFP: "host", CommandSHA256: "digest"}
	verdict := AuditVerdict{Time: now, RequestID: "r_frozen", CommandSHA256: "digest", Approved: true}
	const sinkBytes = `{"kind":"call","event":{"time":"2026-07-20T01:02:03Z","request_id":"r_frozen","host_key_fp":"host","command_sha256":"digest"}}
{"kind":"verdict","event":{"time":"2026-07-20T01:02:03Z","request_id":"r_frozen","operator":{"ID":"","DisplayName":"","Verified":false,"AuthnMethod":""},"command_sha256":"digest","approved":true}}
`
	const logBytes = `{"ts":"2026-07-20T01:02:03Z","request_id":"r_frozen","status":"call","commands":["sha256:digest"],"servers":["host"]}
{"ts":"2026-07-20T01:02:03Z","request_id":"r_frozen","status":"approved","commands":["digest"],"servers":null}
`
	for _, kind := range []string{"append-only", "durable", "audit-log"} {
		t.Run(kind, func(t *testing.T) {
			var sink AuditSink
			var buffer bytes.Buffer
			path := filepath.Join(t.TempDir(), "audit.jsonl")
			want := sinkBytes
			switch kind {
			case "append-only":
				sink = NewAppendOnlySink(&buffer)
			case "durable":
				path = durableAuditTestPath(t)
				durable := openDurableAuditForTest(t, path)
				t.Cleanup(func() {
					if err := durable.Close(); err != nil {
						t.Error(err)
					}
				})
				if err := durable.PolicyAuditReady(context.Background()); err != nil {
					t.Fatal(err)
				}
				sink = durable
			case "audit-log":
				log, err := OpenAuditLog(path)
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() {
					if err := log.Close(); err != nil {
						t.Error(err)
					}
				})
				sink = log
				want = logBytes
			}
			if err := sink.Call(context.Background(), call); err != nil {
				t.Fatal(err)
			}
			if err := sink.Verdict(context.Background(), verdict); err != nil {
				t.Fatal(err)
			}
			got := buffer.Bytes()
			if kind != "append-only" {
				var err error
				got, err = os.ReadFile(path)
				if err != nil {
					t.Fatal(err)
				}
			}
			if string(got) != want {
				t.Fatalf("audit bytes changed:\n got %s\nwant %s", got, want)
			}
		})
	}
}
