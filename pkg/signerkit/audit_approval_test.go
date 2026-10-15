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

func TestApprovalAuditSinkEncodings(t *testing.T) {
	now := time.Date(2026, time.July, 20, 1, 2, 3, 0, time.UTC)
	const verdictPrefix = `{"time":"2026-07-20T01:02:03Z","request_id":"request","operator":{"ID":"operator","DisplayName":"Reviewer","Verified":true,"AuthnMethod":"totp"},"command_sha256":"digest","approved":true`
	const logPrefix = `{"ts":"2026-07-20T01:02:03Z","request_id":"request","status":"`
	const logVerdictSuffix = `","commands":["digest"],"servers":null,"approved_by":"Reviewer","auth_mode":"totp"`
	cases := []struct {
		name       string
		transition string
		replay     bool
		lifecycle  string
		appendJSON string
		logJSON    string
	}{
		{
			name: "duplicate", transition: "vote_duplicate", replay: true,
			appendJSON: `{"kind":"verdict_inert","event":` + verdictPrefix + `,"approval":{"transition":"vote_duplicate","decision":"approve","replay":true}}}`,
			logJSON:    logPrefix + `approval-vote_duplicate` + logVerdictSuffix + `,"approval":{"transition":"vote_duplicate","decision":"approve","replay":true}}`,
		},
		{
			name: "expired", transition: "vote_refused{expired}", replay: true,
			appendJSON: `{"kind":"verdict_inert","event":` + verdictPrefix + `,"approval":{"transition":"vote_refused{expired}","decision":"approve","replay":true}}}`,
			logJSON:    logPrefix + `approval-vote_refused{expired}` + logVerdictSuffix + `,"approval":{"transition":"vote_refused{expired}","decision":"approve","replay":true}}`,
		},
		{
			name: "replay", transition: "vote_replay", replay: true,
			appendJSON: `{"kind":"verdict_inert","event":` + verdictPrefix + `,"approval":{"transition":"vote_replay","decision":"approve","replay":true}}}`,
			logJSON:    logPrefix + `approval-vote_replay` + logVerdictSuffix + `,"approval":{"transition":"vote_replay","decision":"approve","replay":true}}`,
		},
		{
			name: "metadata_without_replay", transition: "vote_replay",
			appendJSON: `{"kind":"verdict","event":` + verdictPrefix + `,"approval":{"transition":"vote_replay","decision":"approve"}}}`,
			logJSON:    logPrefix + `approved` + logVerdictSuffix + `,"approval":{"transition":"vote_replay","decision":"approve"}}`,
		},
		{
			name:       "ordinary_verdict",
			appendJSON: `{"kind":"verdict","event":` + verdictPrefix + `}}`,
			logJSON:    logPrefix + `approved` + logVerdictSuffix + `}`,
		},
		{
			name: "approval_call", transition: "submitted", lifecycle: "approval-submitted",
			appendJSON: `{"kind":"lifecycle","event":{"time":"2026-07-20T01:02:03Z","request_id":"request","lifecycle":"approval-submitted","approval":{"transition":"submitted"}}}`,
			logJSON:    logPrefix + `approval-submitted","commands":[],"servers":null,"approval":{"transition":"submitted"}}`,
		},
		{
			name: "custody_call", lifecycle: "lock",
			appendJSON: `{"kind":"lifecycle","event":{"time":"2026-07-20T01:02:03Z","lifecycle":"lock","reason":"maintenance","operator":{"ID":"operator","DisplayName":"Reviewer","Verified":true,"AuthnMethod":"totp"}}}`,
			logJSON:    `{"ts":"2026-07-20T01:02:03Z","request_id":"","status":"lock","commands":["custody: lock (maintenance)"],"servers":null,"approved_by":"Reviewer","auth_mode":"totp"}`,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			for _, kind := range []string{"append-only", "audit-log"} {
				t.Run(kind, func(t *testing.T) {
					var buffer bytes.Buffer
					var sink AuditSink = NewAppendOnlySink(&buffer)
					path := filepath.Join(t.TempDir(), "audit.jsonl")
					want := tc.appendJSON + "\n"
					if kind == "audit-log" {
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
						want = tc.logJSON + "\n"
					}
					var metadata *approvalplan.AuditMetadata
					if tc.transition != "" {
						metadata = &approvalplan.AuditMetadata{Transition: tc.transition, Replay: tc.replay}
					}
					operator := Operator{ID: "operator", DisplayName: "Reviewer", Verified: true, AuthnMethod: "totp"}
					var err error
					if tc.lifecycle != "" {
						call := AuditCall{Time: now, Lifecycle: tc.lifecycle, Approval: metadata}
						if metadata != nil {
							call.RequestID = "request"
						} else {
							call.Operator = &operator
							call.Reason = "maintenance"
						}
						err = sink.Call(context.Background(), call)
					} else {
						if metadata != nil {
							metadata.Decision = "approve"
						}
						err = sink.Verdict(context.Background(), AuditVerdict{Time: now, RequestID: "request", Operator: operator, CommandSHA256: "digest", Approved: true, Approval: metadata})
					}
					if err != nil {
						t.Fatal(err)
					}
					got := buffer.Bytes()
					if kind == "audit-log" {
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
		})
	}
}
