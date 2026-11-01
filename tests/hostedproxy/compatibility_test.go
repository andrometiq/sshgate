package hostedproxy_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	sk "github.com/karthikeyan5/sshgate/pkg/signerkit"
	ap "github.com/karthikeyan5/sshgate/src/approvalplan"
	aw "github.com/karthikeyan5/sshgate/src/approvalwire"
	"github.com/karthikeyan5/sshgate/src/mcp/sign"
)

type fixtureTransport func(*http.Request) (*http.Response, error)

func (f fixtureTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

type capturedAnswer struct {
	Method string      `json:"method"`
	Target string      `json:"target"`
	Status int         `json:"status"`
	Header http.Header `json:"header"`
	Body   string      `json:"body"`
}

func wireFixture(t *testing.T, name string) []byte {
	t.Helper()
	b, e := os.ReadFile(filepath.Join("../../src/approvalwire/testdata/local", name+".json"))
	if e != nil {
		t.Fatal(e)
	}
	return b
}
func olderAnswers(t *testing.T) map[string][]capturedAnswer {
	t.Helper()
	b, e := os.ReadFile("testdata/older-a8fc4d5.json")
	if e != nil {
		t.Fatal(e)
	}
	var out map[string][]capturedAnswer
	if e = json.Unmarshal(b, &out); e != nil {
		t.Fatal(e)
	}
	if len(out) != 2 || len(out["policy-absent"]) != 6 || len(out["policy-attached"]) != 6 {
		t.Fatal("capture must contain all six routes with and without the policy plane")
	}
	return out
}

var fixtureKinds = []string{"submit-write", "get", "list-first", "wait", "claim", "report"}

func replayAnswer(t *testing.T, answer capturedAnswer, calls *int) http.RoundTripper {
	return fixtureTransport(func(r *http.Request) (*http.Response, error) {
		*calls++
		want, e := url.Parse(answer.Target)
		if e != nil {
			t.Fatal(e)
		}
		if r.Method != answer.Method || r.URL.Path != want.Path {
			t.Errorf("route = %s %s; want %s %s", r.Method, r.URL.Path, answer.Method, want.Path)
		}
		return &http.Response{StatusCode: answer.Status, Header: answer.Header.Clone(), Body: io.NopCloser(strings.NewReader(answer.Body)), Request: r}, nil
	})
}

type frameBuffer struct {
	io.Reader
	bytes.Buffer
}

func (b *frameBuffer) Read(p []byte) (int, error) { return b.Reader.Read(p) }
func fixtureService(t *testing.T, rt http.RoundTripper) (*sk.Service, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	audit, e := sk.OpenAuditLog(path)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { audit.Close() })
	backend := &sk.HostedServerBackend{BaseURL: "https://signer.example", APIKey: "test-key", ClientID: "client", HTTPClient: &http.Client{Transport: rt}}
	svc, e := sk.New(sk.Config{Signer: ed25519.NewKeyFromSeed(make([]byte, 32)), Backend: backend, Audit: audit})
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { svc.Close() })
	runtime, e := sk.NewApprovalRuntime(sk.ApprovalRuntimeConfig{Forwarder: backend})
	if e != nil {
		t.Fatal(e)
	}
	if e = svc.AttachApprovals(runtime); e != nil {
		t.Fatal(e)
	}
	return svc, path
}
func directFrame(t *testing.T, svc *sk.Service, request []byte) []byte {
	t.Helper()
	conn := &frameBuffer{Reader: bytes.NewReader(append(bytes.TrimSpace(request), '\n'))}
	if e := svc.HandleSignRequestWithPeer(context.Background(), conn, &sk.PeerCredentials{UID: 7}); e != nil {
		t.Fatal(e)
	}
	return conn.Bytes()
}
func assertRefusalAudit(t *testing.T, path string, code ap.Code) {
	t.Helper()
	b, e := os.ReadFile(path)
	if e != nil {
		t.Fatal(e)
	}
	lines := bytes.Split(bytes.TrimSpace(b), []byte{'\n'})
	if len(lines) != 1 {
		t.Fatalf("audit rows = %s", b)
	}
	var event sk.AuditEvent
	if e = json.Unmarshal(lines[0], &event); e != nil {
		t.Fatal(e)
	}
	if event.Approval == nil || event.Approval.Transition != "refused{"+string(code)+"}" || event.Approval.Principal != "local-uid:7" {
		t.Fatalf("audit = %s", b)
	}
}
func TestOlderHostedFixturesFrames(t *testing.T) {
	for mode, answers := range olderAnswers(t) {
		if len(answers) != len(fixtureKinds) {
			t.Fatal("incomplete route capture")
		}
		for i, answer := range answers {
			t.Run(mode+"/"+fixtureKinds[i], func(t *testing.T) {
				calls := 0
				svc, path := fixtureService(t, replayAnswer(t, answer, &calls))
				got := directFrame(t, svc, wireFixture(t, "request-"+fixtureKinds[i]))
				want := wireFixture(t, "response-signer-incompatible")
				if !bytes.Equal(got, want) || calls != 1 {
					t.Fatalf("frame %s want %s calls %d", got, want, calls)
				}
				assertRefusalAudit(t, path, ap.CodeSignerIncompatible)
			})
		}
	}
}
func callFixture(t *testing.T, c *sign.ApprovalClient, kind string) error {
	t.Helper()
	ctx := context.Background()
	data := wireFixture(t, "request-"+kind)
	switch kind {
	case "submit-write":
		var r aw.SubmitRequest
		if err := json.Unmarshal(data, &r); err != nil {
			t.Fatal(err)
		}
		_, e := c.Submit(ctx, r.Draft)
		return e
	case "get":
		var r aw.GetRequest
		if err := json.Unmarshal(data, &r); err != nil {
			t.Fatal(err)
		}
		_, e := c.Get(ctx, r.RequestID)
		return e
	case "list-first":
		var r aw.ListRequest
		if err := json.Unmarshal(data, &r); err != nil {
			t.Fatal(err)
		}
		_, _, e := c.List(ctx, r.Limit, r.Cursor)
		return e
	case "wait":
		var r aw.WaitRequest
		if err := json.Unmarshal(data, &r); err != nil {
			t.Fatal(err)
		}
		_, e := c.Wait(ctx, r.RequestIDs, 0)
		return e
	case "claim":
		var r aw.ClaimRequest
		if err := json.Unmarshal(data, &r); err != nil {
			t.Fatal(err)
		}
		_, e := c.Claim(ctx, r.RequestID, r.PlanHash, [32]byte{1, 2, 3})
		return e
	case "report":
		var r aw.ReportRequest
		if err := json.Unmarshal(data, &r); err != nil {
			t.Fatal(err)
		}
		return c.Report(ctx, r.RequestID, r.PlanHash, [32]byte{1, 2, 3}, r.Report)
	}
	t.Fatal(kind)
	return nil
}
func TestOlderHostedFixturesMCP(t *testing.T) {
	for mode, answers := range olderAnswers(t) {
		for i, answer := range answers {
			t.Run(mode+"/"+fixtureKinds[i], func(t *testing.T) {
				calls := 0
				h := &proxyHarness{t: t, http: &httptest.Server{URL: "https://signer.example"}, transport: &recordingTransport{next: replayAnswer(t, answer, &calls), bodies: make(map[string][][]byte)}}
				p := h.socket(7)
				if err := callFixture(t, p.client, fixtureKinds[i]); !errors.Is(err, aw.ErrSignerIncompatible) {
					t.Fatalf("error = %v", err)
				}
				p.close()
				if calls != 1 {
					t.Fatalf("HTTP calls %d", calls)
				}
				assertRefusalAudit(t, p.audit, ap.CodeSignerIncompatible)
			})
		}
	}
}
func TestHostedTypedRefusalFrames(t *testing.T) {
	for _, code := range []ap.Code{ap.CodeNotFound, ap.CodeConflict, ap.CodeQueueFull, ap.CodeStorageUncertain, ap.CodeBusy} {
		for i, answer := range olderAnswers(t)["policy-absent"] {
			t.Run(string(code)+"/"+fixtureKinds[i], func(t *testing.T) {
				body, e := json.Marshal(aw.ErrorResponse(code, string(code)))
				if e != nil {
					t.Fatal(e)
				}
				answer.Body = string(body)
				answer.Status = aw.HTTPStatus(code)
				answer.Header = http.Header{"Content-Type": {"application/json"}}
				if code == ap.CodeBusy {
					answer.Header.Set("Retry-After", "1")
				}
				calls := 0
				svc, path := fixtureService(t, replayAnswer(t, answer, &calls))
				got := directFrame(t, svc, wireFixture(t, "request-"+fixtureKinds[i]))
				var response aw.Response
				if e = json.Unmarshal(got, &response); e != nil {
					t.Fatal(e)
				}
				if response.Error == nil || response.Error.Code != code || calls != 1 {
					t.Fatalf("frame = %s calls %d", got, calls)
				}
				assertRefusalAudit(t, path, code)
			})
		}
	}
}
func TestHostedTypedNotFoundMCP(t *testing.T) {
	for i, answer := range olderAnswers(t)["policy-absent"] {
		t.Run(fixtureKinds[i], func(t *testing.T) {
			body, e := json.Marshal(aw.ErrorResponse(ap.CodeNotFound, "not_found"))
			if e != nil {
				t.Fatal(e)
			}
			answer.Body = string(body)
			answer.Header = http.Header{"Content-Type": {"application/json"}}
			calls := 0
			h := &proxyHarness{t: t, http: &httptest.Server{URL: "https://signer.example"}, transport: &recordingTransport{next: replayAnswer(t, answer, &calls), bodies: make(map[string][][]byte)}}
			p := h.socket(7)
			err := callFixture(t, p.client, fixtureKinds[i])
			var wire *aw.WireError
			if !errors.As(err, &wire) || wire.Code != ap.CodeNotFound || errors.Is(err, aw.ErrSignerIncompatible) {
				t.Fatalf("error = %v", err)
			}
			p.close()
			if calls != 1 {
				t.Fatalf("HTTP calls %d", calls)
			}
			assertRefusalAudit(t, p.audit, ap.CodeNotFound)
		})
	}
}
