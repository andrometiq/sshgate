package signerkit

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	ap "github.com/karthikeyan5/sshgate/src/approvalplan"
	aw "github.com/karthikeyan5/sshgate/src/approvalwire"
)

type approvalRoundTrip func(*http.Request) (*http.Response, error)

func (f approvalRoundTrip) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }
func approvalBackend(handler http.HandlerFunc) *HostedServerBackend {
	return &HostedServerBackend{BaseURL: "https://signer.example", APIKey: "test-token", ClientID: "test-client", HTTPClient: &http.Client{Transport: approvalRoundTrip(func(r *http.Request) (*http.Response, error) {
		if r.Body != nil {
			defer r.Body.Close()
		}
		w := httptest.NewRecorder()
		handler(w, r)
		return w.Result(), nil
	})}}
}
func approvalFixture(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile("../../src/approvalwire/testdata/" + name)
	if err != nil {
		t.Fatal(err)
	}
	return b
}
func approvalRequestFixture(t *testing.T, name string) any {
	t.Helper()
	r, err := aw.DecodeLocalRequest(approvalFixture(t, "local/request-"+name+".json"))
	if err != nil {
		t.Fatal(err)
	}
	return r
}
func TestHostedApprovalRoutes(t *testing.T) {
	for _, tc := range []struct{ name, method, path, query, body, response string }{
		{"submit-write", "POST", "", "", "body-submit.json", "submit-ok"},
		{"get", "GET", "/a2_AAAAAAAAAAAAAAAAAAAAAA", "requester_sub=local-uid%3A1000", "", "get-final"},
		{"list-first", "GET", "", "limit=50&requester_sub=local-uid%3A1000", "", "list-empty"},
		{"wait", "POST", "/wait", "", "body-wait.json", "wait-ok"},
		{"claim", "POST", "/a2_AAAAAAAAAAAAAAAAAAAAAA/claim", "", "body-claim.json", "claim-signatures"},
		{"report", "POST", "/a2_AAAAAAAAAAAAAAAAAAAAAA/report", "", "body-report.json", "report-ok"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			calls := 0
			h := approvalBackend(func(w http.ResponseWriter, r *http.Request) {
				calls++
				if r.GetBody != nil {
					t.Error("replayable request body")
				}
				if r.Method != tc.method || r.URL.Path != aw.HostedRoot+tc.path || r.URL.RawQuery != tc.query {
					t.Errorf("route: %s %s", r.Method, r.URL)
				}
				if r.Header.Get("Authorization") != "Bearer test-token" || r.Header.Get("Accept") != "application/json" {
					t.Error("missing headers")
				}
				deadline, ok := r.Context().Deadline()
				if !ok || time.Until(deadline) > 60*time.Second {
					t.Error("missing bounded deadline")
				}
				b, _ := io.ReadAll(r.Body)
				if tc.body != "" {
					expected := strings.TrimSpace(string(approvalFixture(t, "hosted/"+tc.body)))
					if tc.name == "wait" {
						expected = strings.Replace(expected, `"wait_seconds":30`, `"wait_seconds":55`, 1)
					}
					if string(b) != expected {
						t.Errorf("body mismatch: %s", b)
					}
					if r.Header.Get("Content-Type") != "application/json" {
						t.Error("missing content type")
					}
				} else if len(b) != 0 {
					t.Error("unexpected body")
				}
				w.Header().Set("Content-Type", "application/json")
				w.Write([]byte(strings.TrimSpace(string(approvalFixture(t, "local/response-"+tc.response+".json")))))
			})
			got, err := h.RequestApproval(context.Background(), "local-uid:1000", approvalRequestFixture(t, tc.name))
			if err != nil || !got.Response.OK || calls != 1 {
				t.Fatalf("got %+v, %v, calls %d", got, err, calls)
			}
		})
	}
}
func TestHostedApprovalRefusals(t *testing.T) {
	for _, kind := range aw.Kinds {
		for _, code := range []ap.Code{ap.CodeBusy, ap.CodeStorageUncertain, ap.CodeNotFound, ap.CodeConflict, ap.CodeQueueFull} {
			t.Run(kind+"/"+string(code), func(t *testing.T) {
				names := map[string]string{aw.KindSubmit: "submit-write", aw.KindGet: "get", aw.KindList: "list-first", aw.KindWait: "wait", aw.KindClaim: "claim", aw.KindReport: "report"}
				response := aw.ErrorResponse(code, "request refused")
				status, b, err := aw.MarshalHostedResponse(kind, response)
				if err != nil {
					t.Fatal(err)
				}
				calls := 0
				h := approvalBackend(func(w http.ResponseWriter, r *http.Request) {
					calls++
					w.Header().Set("Content-Type", "application/json")
					w.Header().Set("Retry-After", "1")
					w.WriteHeader(status)
					w.Write(b)
				})
				got, err := h.RequestApproval(context.Background(), "", approvalRequestFixture(t, names[kind]))
				var wire *aw.WireError
				if !errors.As(err, &wire) || wire.Code != code || got.Response.Error == nil || got.Response.Error.Code != code || got.RetryAfter != "1" || calls != 1 {
					t.Fatalf("got %+v, %v, calls %d", got, err, calls)
				}
				if code == ap.CodeBusy && !errors.Is(err, aw.ErrBusy) || code == ap.CodeStorageUncertain && !errors.Is(err, aw.ErrStorageUncertain) {
					t.Fatal("lost typed refusal")
				}
			})
		}
	}
}
func TestHostedApprovalStrictResponses(t *testing.T) {
	for _, tc := range []struct {
		name              string
		status            int
		contentType, body string
		want              error
	}{
		{"old-text", 404, "text/plain", "404 page not found", aw.ErrSignerIncompatible},
		{"old-policy", 404, "application/json", `{"error":"not found"}`, aw.ErrSignerIncompatible},
		{"proxy-busy", 503, "text/plain", "unavailable", aw.ErrTransport},
		{"unknown-field", 200, "application/json", `{"approval_proto":1,"ok":true,"extra":1}`, aw.ErrTransport},
		{"version", 200, "application/json", `{"approval_proto":2,"ok":true}`, aw.ErrTransport},
		{"unknown-code", 503, "application/json", `{"approval_proto":1,"ok":false,"error":{"code":"new_code","message":"refused"}}`, aw.ErrTransport},
		{"duplicate", 200, "application/json", `{"approval_proto":1,"ok":true,"ok":true}`, aw.ErrTransport},
		{"trailing", 200, "application/json", `{"approval_proto":1,"ok":true}{}`, aw.ErrTransport},
		{"wrong-type", 200, "text/plain", `{"approval_proto":1,"ok":true}`, aw.ErrTransport},
		{"wrong-status", 503, "application/json", `{"approval_proto":1,"ok":true}`, nil},
		{"oversized", 200, "application/json", strings.Repeat("x", aw.MaxFrameBytes+1), nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			calls := 0
			h := approvalBackend(func(w http.ResponseWriter, r *http.Request) {
				calls++
				w.Header().Set("Content-Type", tc.contentType)
				w.WriteHeader(tc.status)
				w.Write([]byte(tc.body))
			})
			_, err := h.RequestApproval(context.Background(), "", approvalRequestFixture(t, "report"))
			if err == nil || tc.want != nil && !errors.Is(err, tc.want) || calls != 1 {
				t.Fatalf("got %v calls %d", err, calls)
			}
			if strings.Contains(err.Error(), tc.body) && len(tc.body) > 20 {
				t.Fatal("response leaked into error")
			}
		})
	}
}
func TestHostedApprovalInvalidInputNeverSent(t *testing.T) {
	for _, name := range []string{"get", "claim", "report", "wait", "submit-write", "list-first"} {
		t.Run(name, func(t *testing.T) {
			r := approvalRequestFixture(t, name)
			switch v := r.(type) {
			case aw.GetRequest:
				v.RequestID = "r_bad"
				r = v
			case aw.ClaimRequest:
				v.RequestID = ""
				r = v
			case aw.ReportRequest:
				v.RequestID = "a2_bad%2Fid"
				r = v
			case aw.WaitRequest:
				v.RequestIDs = []string{"bad"}
				r = v
			case aw.SubmitRequest:
				v.Draft.CommandJob.Steps[0].ExactCommand = "SSHGATE_XFER_FORGED"
				v.Draft.CommandJob.Steps[0].CommandSHA256 = fmt.Sprintf("%x", sha256.Sum256([]byte("SSHGATE_XFER_FORGED")))
				r = v
			case aw.ListRequest:
				v.ApprovalProto = 2
				r = v
			}
			h := approvalBackend(func(http.ResponseWriter, *http.Request) { t.Fatal("invalid request sent") })
			_, err := h.RequestApproval(context.Background(), "", r)
			var coded *ap.CodeError
			if name == "submit-write" && (!errors.As(err, &coded) || coded.Code != ap.CodeReservedVerb) {
				t.Fatalf("want reserved_verb, got %v", err)
			}
			if !errors.As(err, &coded) {
				t.Fatalf("want typed refusal, got %v", err)
			}
		})
	}
	h := approvalBackend(func(http.ResponseWriter, *http.Request) { t.Fatal("invalid sub sent") })
	for _, name := range []string{"get", "list-first", "submit-write", "wait", "claim", "report"} {
		if _, err := h.RequestApproval(context.Background(), "forged", approvalRequestFixture(t, name)); err == nil {
			t.Fatal("invalid sub accepted")
		}
	}
	r := approvalRequestFixture(t, "submit-write").(aw.SubmitRequest)
	r.Draft.ExecutorClaimTokenHash = ""
	if _, err := h.RequestApproval(context.Background(), "", r); err == nil {
		t.Fatal("missing claim hash accepted")
	}
}
func TestHostedApprovalTimeoutAndRedirect(t *testing.T) {
	h := approvalBackend(func(http.ResponseWriter, *http.Request) { t.Fatal("unexpected call") })
	h.Timeout = 10 * time.Millisecond
	h.HTTPClient.Transport = approvalRoundTrip(func(r *http.Request) (*http.Response, error) { <-r.Context().Done(); return nil, r.Context().Err() })
	_, err := h.RequestApproval(context.Background(), "", approvalRequestFixture(t, "get"))
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("deadline: %v", err)
	}
	h.Timeout = -1
	if _, err = h.RequestApproval(context.Background(), "", approvalRequestFixture(t, "get")); err == nil {
		t.Fatal("negative timeout accepted")
	}
	calls := 0
	h = approvalBackend(func(w http.ResponseWriter, r *http.Request) {
		calls++
		w.Header().Set("Location", "https://other.example/secret")
		w.WriteHeader(307)
	})
	_, err = h.RequestApproval(context.Background(), "", approvalRequestFixture(t, "get"))
	if !errors.Is(err, aw.ErrTransport) || calls != 1 {
		t.Fatalf("redirect: %v calls %d", err, calls)
	}
	if h.HTTPClient.CheckRedirect != nil {
		t.Fatal("mutated shared client")
	}
}

// Oversized bodies must be rejected without draining the server stream.
type approvalEndlessBody struct {
	read   int
	closed bool
}

func (b *approvalEndlessBody) Read(p []byte) (int, error) {
	if b.read >= 2*aw.MaxFrameBytes {
		return 0, io.EOF
	}
	for i := range p {
		p[i] = 'x'
	}
	b.read += len(p)
	return len(p), nil
}
func (b *approvalEndlessBody) Close() error { b.closed = true; return nil }
func TestHostedApprovalBoundedBody(t *testing.T) {
	b := &approvalEndlessBody{}
	h := approvalBackend(nil)
	h.HTTPClient.Transport = approvalRoundTrip(func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: 200, Header: http.Header{"Content-Type": []string{"application/json"}}, Body: b}, nil
	})
	_, err := h.RequestApproval(context.Background(), "", approvalRequestFixture(t, "get"))
	if err == nil || !strings.Contains(err.Error(), "response exceeds") || b.read != aw.MaxFrameBytes+1 || !b.closed {
		t.Fatalf("err %v bytes %d closed %v", err, b.read, b.closed)
	}
}
func TestHostedApprovalConfiguration(t *testing.T) {
	for _, tc := range []struct {
		name   string
		change func(*HostedServerBackend)
	}{
		{"origin", func(h *HostedServerBackend) { h.BaseURL = "http://untrusted.example" }},
		{"credentials", func(h *HostedServerBackend) { h.APIKey = "" }},
		{"path", func(h *HostedServerBackend) { h.BaseURL += "/extra" }},
		{"negative-timeout", func(h *HostedServerBackend) { h.Timeout = -time.Second }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := approvalBackend(func(http.ResponseWriter, *http.Request) { t.Fatal("invalid configuration sent") })
			tc.change(h)
			if _, err := h.RequestApproval(context.Background(), "", approvalRequestFixture(t, "get")); err == nil {
				t.Fatal("accepted invalid configuration")
			}
		})
	}
}
func TestHostedApprovalTransportErrors(t *testing.T) {
	h := approvalBackend(nil)
	h.HTTPClient.Transport = approvalRoundTrip(func(*http.Request) (*http.Response, error) { return nil, errors.New("private transport details") })
	_, err := h.RequestApproval(context.Background(), "", approvalRequestFixture(t, "claim"))
	if !errors.Is(err, aw.ErrResponseLost) || strings.Contains(err.Error(), "private") {
		t.Fatalf("transport error: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err = h.RequestApproval(ctx, "", approvalRequestFixture(t, "claim"))
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled: %v", err)
	}
}

type approvalBrokenBody struct{ closed bool }

func (*approvalBrokenBody) Read([]byte) (int, error) { return 0, errors.New("private body failure") }
func (b *approvalBrokenBody) Close() error           { b.closed = true; return nil }
func TestHostedApprovalReadFailure(t *testing.T) {
	b := &approvalBrokenBody{}
	h := approvalBackend(nil)
	h.HTTPClient.Transport = approvalRoundTrip(func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: 200, Header: http.Header{"Content-Type": []string{"application/json"}}, Body: b}, nil
	})
	_, err := h.RequestApproval(context.Background(), "", approvalRequestFixture(t, "get"))
	if !errors.Is(err, aw.ErrResponseLost) || !b.closed || strings.Contains(err.Error(), "private") {
		t.Fatalf("read failure: %v closed %v", err, b.closed)
	}
}

func TestHostedApprovalCompatibilityEveryRoute(t *testing.T) {
	for _, name := range []string{"submit-write", "get", "list-first", "wait", "claim", "report"} {
		t.Run(name, func(t *testing.T) {
			for _, body := range []string{"404 page not found\n", `{"error":"not found"}`} {
				calls := 0
				h := approvalBackend(func(w http.ResponseWriter, r *http.Request) {
					calls++
					w.Header().Set("Content-Type", "application/json")
					w.WriteHeader(404)
					io.WriteString(w, body)
				})
				_, err := h.RequestApproval(context.Background(), "", approvalRequestFixture(t, name))
				if !errors.Is(err, aw.ErrSignerIncompatible) || calls != 1 {
					t.Fatalf("compatibility: %v calls %d", err, calls)
				}
			}
		})
	}
}
