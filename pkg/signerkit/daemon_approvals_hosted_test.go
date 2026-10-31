package signerkit

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"path/filepath"
	"strings"
	"testing"
	"testing/synctest"
	"time"

	"github.com/karthikeyan5/sshgate/pkg/signerkit/lifecycle"
	ap "github.com/karthikeyan5/sshgate/src/approvalplan"
	aw "github.com/karthikeyan5/sshgate/src/approvalwire"
)

type forwardFunc func(context.Context, string, any) (HostedApprovalResponse, error)

func (f forwardFunc) RequestApproval(ctx context.Context, sub string, req any) (HostedApprovalResponse, error) {
	return f(ctx, sub, req)
}

func hostedRuntime(t *testing.T, forward ApprovalForwarder) *ApprovalRuntime {
	t.Helper()
	r, err := NewApprovalRuntime(ApprovalRuntimeConfig{Forwarder: forward})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { r.Close() })
	return r
}
func hostedService(t *testing.T, r *ApprovalRuntime, bk Backend) (*Service, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	audit, err := OpenAuditLog(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { audit.Close() })
	key, _ := goldenSignerKey()
	svc, err := New(Config{Signer: key, Backend: bk, Audit: audit})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { svc.Close() })
	if err := svc.AttachApprovals(r); err != nil {
		t.Fatal(err)
	}
	return svc, path
}
func hostedFrame(t *testing.T, svc *Service, peer *PeerCredentials, data []byte) []byte {
	t.Helper()
	conn := &splitReadWriter{reader: bytes.NewReader(append(bytes.Clone(data), '\n'))}
	if err := svc.HandleSignRequestWithPeer(context.Background(), conn, peer); err != nil {
		t.Fatal(err)
	}
	return conn.writer.Bytes()
}

func TestHostedForwarderConfiguration(t *testing.T) {
	f := forwardFunc(func(context.Context, string, any) (HostedApprovalResponse, error) {
		return HostedApprovalResponse{}, nil
	})
	for _, name := range []string{"store", "legacy", "factory", "prepare"} {
		t.Run(name, func(t *testing.T) {
			c := ApprovalRuntimeConfig{Forwarder: f}
			switch name {
			case "store":
				c.Store = &runtimeStore{}
			case "legacy":
				c.Legacy = &lifecycle.LegacyService{}
			case "factory":
				c.NewEngine = func(lifecycle.Store) (*lifecycle.Engine, error) { t.Fatal("engine constructed"); return nil, nil }
			case "prepare":
				c.PrepareLegacy = func(*lifecycle.PreparedLegacyApproval) error { return nil }
			}
			if r, err := NewApprovalRuntime(c); err == nil {
				r.Close()
				t.Fatal("mixed mode accepted")
			}
		})
	}
	if _, err := NewApprovalRuntime(ApprovalRuntimeConfig{}); err == nil {
		t.Fatal("empty configuration accepted")
	}
	r := hostedRuntime(t, f)
	if !errors.Is(r.Status(), ErrHostedForwarder) || r.Legacy() != nil || r.engine != nil {
		t.Fatal("not stateless", r.Status())
	}
	r.Close()
	runtimeCode(t, r.Status(), ap.CodeLifecycleUnavailable)
}

func TestHostedForwarderShutdown(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		entered, canceled, release := make(chan struct{}), make(chan struct{}), make(chan struct{})
		r := hostedRuntime(t, forwardFunc(func(ctx context.Context, _ string, _ any) (HostedApprovalResponse, error) {
			close(entered)
			<-ctx.Done()
			close(canceled)
			<-release
			return HostedApprovalResponse{}, ctx.Err()
		}))
		runctx, cancel := context.WithCancel(context.Background())
		runDone := make(chan error, 1)
		go func() { runDone <- r.Run(runctx) }()
		callDone := make(chan struct{})
		go func() {
			defer close(callDone)
			r.forward(context.Background(), "local-uid:7", approvalRequestFixture(t, "get"))
		}()
		<-entered
		cancel()
		if !errors.Is(<-runDone, context.Canceled) {
			t.Fatal("Run did not return cancellation")
		}
		<-canceled
		closed := make(chan struct{})
		go func() { r.Close(); close(closed) }()
		synctest.Wait()
		select {
		case <-closed:
			t.Fatal("Close did not join call")
		default:
		}
		close(release)
		<-closed
		<-callDone
		_, err := r.forward(context.Background(), "local-uid:7", approvalRequestFixture(t, "get"))
		runtimeCode(t, err, ap.CodeLifecycleUnavailable)
		if err := r.Run(context.Background()); err == nil {
			t.Fatal("Run after close accepted")
		}
	})
}

func TestHostedForwarderLocalGuards(t *testing.T) {
	for _, tc := range []struct {
		name, fixture string
		edit          func([]byte) []byte
		peer          *PeerCredentials
		allowed       []uint32
		code          ap.Code
	}{
		{"no-peer", "get", nil, nil, nil, ap.CodeInvalidRequest},
		{"uid", "get", nil, &PeerCredentials{UID: 7}, []uint32{8}, ap.CodeNotFound},
		{"malformed-get", "get", func(b []byte) []byte {
			return bytes.ReplaceAll(b, []byte("a2_AAAAAAAAAAAAAAAAAAAAAA"), []byte("r_bad"))
		}, &PeerCredentials{UID: 7}, nil, ap.CodeInvalidRequest},
		{"malformed-claim", "claim", func(b []byte) []byte {
			return bytes.ReplaceAll(b, []byte("a2_AAAAAAAAAAAAAAAAAAAAAA"), []byte("bad/id"))
		}, &PeerCredentials{UID: 7}, nil, ap.CodeInvalidRequest},
		{"malformed-report", "report", func(b []byte) []byte { return bytes.ReplaceAll(b, []byte("a2_AAAAAAAAAAAAAAAAAAAAAA"), nil) }, &PeerCredentials{UID: 7}, nil, ap.CodeInvalidRequest},
		{"claim-hash", "submit-write", func(b []byte) []byte {
			var m aw.SubmitRequest
			json.Unmarshal(b, &m)
			m.Draft.ExecutorClaimTokenHash = ""
			out, _ := json.Marshal(m)
			return out
		}, &PeerCredentials{UID: 7}, nil, ap.CodeInvalidRequest},
		{"reserved", "submit-write", func(b []byte) []byte {
			b = bytes.ReplaceAll(b, []byte("systemctl restart nginx"), []byte("SSHGATE_XFER_SEND secret"))
			return bytes.ReplaceAll(b, []byte(fmt.Sprintf("%x", sha256.Sum256([]byte("systemctl restart nginx")))), []byte(fmt.Sprintf("%x", sha256.Sum256([]byte("SSHGATE_XFER_SEND secret")))))
		}, &PeerCredentials{UID: 7}, nil, ap.CodeReservedVerb},
		{"grant", "submit-grant", nil, &PeerCredentials{UID: 7}, nil, ap.CodeInvalidRequest},
		{"transfer", "submit-transfer", nil, &PeerCredentials{UID: 7}, nil, ap.CodeInvalidRequest},
		{"reveal", "submit-write", func(b []byte) []byte { return bytes.ReplaceAll(b, []byte("signed_write"), []byte("signed_reveal")) }, &PeerCredentials{UID: 7}, nil, ap.CodeInvalidRequest},
	} {
		t.Run(tc.name, func(t *testing.T) {
			calls := 0
			h := approvalBackend(func(http.ResponseWriter, *http.Request) { calls++ })
			r := hostedRuntime(t, h)
			r.config.AllowedUIDs = tc.allowed
			svc, path := hostedService(t, r, h)
			data := approvalFixture(t, "local/request-"+tc.fixture+".json")
			if tc.edit != nil {
				data = tc.edit(data)
			}
			frame := hostedFrame(t, svc, tc.peer, data)
			var got aw.Response
			json.Unmarshal(frame, &got)
			if got.Error == nil || got.Error.Code != tc.code || calls != 0 {
				t.Fatalf("frame %s calls %d", frame, calls)
			}
			rows := approvalAuditRows(t, svc, path)
			if len(rows) != 1 || rows[0].Approval == nil || rows[0].Approval.Transition != "refused{"+string(tc.code)+"}" {
				t.Fatalf("audit %+v", rows)
			}
		})
	}
}

func TestHostedForwarderRoutesAndRefusals(t *testing.T) {
	for _, name := range []string{"submit-write", "get", "list-first", "wait", "claim", "report"} {
		for _, code := range []ap.Code{ap.CodeSignerIncompatible, ap.CodeBusy, ap.CodeStorageUncertain, ap.CodeConflict, ap.CodeQueueFull, ap.CodeNotFound} {
			t.Run(name+"/"+string(code), func(t *testing.T) {
				calls := 0
				expected := aw.ErrorResponse(code, string(code))
				h := approvalBackend(func(w http.ResponseWriter, req *http.Request) {
					calls++
					sub := req.URL.Query().Get("requester_sub")
					if req.Method == http.MethodPost {
						var body struct {
							Sub string `json:"requester_sub"`
						}
						json.NewDecoder(req.Body).Decode(&body)
						sub = body.Sub
					}
					if sub != "local-uid:4294967295" {
						t.Errorf("sub %q", sub)
					}
					if code == ap.CodeSignerIncompatible {
						w.WriteHeader(404)
						io.WriteString(w, "not found")
						return
					}
					status := aw.HTTPStatus(code)
					w.Header().Set("Content-Type", "application/json")
					if code == ap.CodeBusy {
						w.Header().Set("Retry-After", "1")
					}
					w.WriteHeader(status)
					data, marshalErr := json.Marshal(expected)
					if marshalErr != nil {
						t.Fatal(marshalErr)
					}
					w.Write(data)
				})
				r := hostedRuntime(t, h)
				svc, path := hostedService(t, r, h)
				frame := hostedFrame(t, svc, &PeerCredentials{UID: 4294967295}, approvalFixture(t, "local/request-"+name+".json"))
				var meta struct {
					Kind string `json:"kind"`
				}
				json.Unmarshal(approvalFixture(t, "local/request-"+name+".json"), &meta)
				want, err := aw.MarshalLocalResponse(meta.Kind, expected)
				if err != nil {
					t.Fatal(err)
				}
				if !bytes.Equal(frame, want) || calls != 1 {
					t.Fatalf("got %s want %s calls %d", frame, want, calls)
				}
				rows := approvalAuditRows(t, svc, path)
				if len(rows) != 1 || rows[0].Approval.Transition != "refused{"+string(code)+"}" || rows[0].Approval.Principal != "local-uid:4294967295" {
					t.Fatalf("audit %+v", rows)
				}
			})
		}
	}
}

func TestHostedForwarderLegacyGrantsAndNet(t *testing.T) {
	calls := 0
	h := approvalBackend(func(http.ResponseWriter, *http.Request) { calls++ })
	r := hostedRuntime(t, h)
	svc, _ := hostedService(t, r, h)
	svc.daemon.grants = map[string]grant{"web": {id: "legacy-grant", alias: "web", scope: "all", expiry: time.Now().Add(time.Hour)}}
	listed := hostedFrame(t, svc, &PeerCredentials{UID: 7}, []byte(`{"kind":"list_grants","request_id":"before"}`))
	if !bytes.Contains(listed, []byte("legacy-grant")) {
		t.Fatal(string(listed))
	}
	for _, data := range []string{
		`{"kind":"revoke_grant","request_id":"test","alias":"web"}`,
		`{"kind":"list_grants","request_id":"test"}`,
	} {
		frame := hostedFrame(t, svc, &PeerCredentials{UID: 7}, []byte(data))
		if strings.Contains(string(frame), `"status":"error"`) {
			t.Fatal(string(frame))
		}
	}
	if len(svc.daemon.grants) != 0 {
		t.Fatal("legacy grant survived revoke")
	}
	// Legacy Net remains on the backend and must fail before any HTTP request.
	_, _, err := svc.daemon.legacyApprove(context.WithValue(context.Background(), approvalCallerKey{}, approvalCaller{runtime: r}), ApprovalRequest{Commands: []CommandReq{{Cmd: "cat /etc/hosts", Net: true}}}, nil)
	if err == nil || !strings.HasPrefix(err.Error(), "net_unsupported:") || calls != 0 {
		t.Fatalf("net err %v calls %d", err, calls)
	}
}

func TestHostedForwarderSuccess(t *testing.T) {
	for _, tc := range []struct{ name, response string }{{"submit-write", "submit-ok"}, {"get", "get-final"}, {"list-first", "list-empty"}, {"wait", "wait-ok"}, {"claim", "claim-signatures"}, {"report", "report-ok"}} {
		t.Run(tc.name, func(t *testing.T) {
			calls := 0
			want := approvalFixture(t, "local/response-"+tc.response+".json")
			h := approvalBackend(func(w http.ResponseWriter, _ *http.Request) {
				calls++
				w.Header().Set("Content-Type", "application/json")
				w.Write(bytes.TrimSpace(want))
			})
			r := hostedRuntime(t, h)
			svc, path := hostedService(t, r, h)
			frame := hostedFrame(t, svc, &PeerCredentials{UID: 7}, approvalFixture(t, "local/request-"+tc.name+".json"))
			if !bytes.Equal(bytes.TrimSpace(frame), bytes.TrimSpace(want)) || calls != 1 {
				t.Fatalf("frame %s calls %d", frame, calls)
			}
			if rows := approvalAuditRows(t, svc, path); len(rows) != 0 {
				t.Fatalf("unexpected audit %+v", rows)
			}
		})
	}
}

func TestHostedForwarderTransportRefusal(t *testing.T) {
	for _, failure := range []error{context.DeadlineExceeded, aw.ErrResponseLost, aw.ErrTransport} {
		t.Run(failure.Error(), func(t *testing.T) {
			calls := 0
			r := hostedRuntime(t, forwardFunc(func(context.Context, string, any) (HostedApprovalResponse, error) {
				calls++
				return HostedApprovalResponse{}, failure
			}))
			svc, path := hostedService(t, r, &StubBackend{})
			frame := hostedFrame(t, svc, &PeerCredentials{UID: 7}, approvalFixture(t, "local/request-get.json"))
			want, _ := aw.MarshalLocalResponse(aw.KindGet, aw.ErrorResponse(ap.CodeLifecycleUnavailable, string(ap.CodeLifecycleUnavailable)))
			if !bytes.Equal(frame, want) || calls != 1 {
				t.Fatalf("frame %s calls %d", frame, calls)
			}
			rows := approvalAuditRows(t, svc, path)
			if len(rows) != 1 || rows[0].Approval.Transition != "refused{lifecycle_unavailable}" {
				t.Fatalf("audit %+v", rows)
			}
		})
	}
}
