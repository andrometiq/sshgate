package sign

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/karthikeyan5/sshgate/internal/lineframe"
	"github.com/karthikeyan5/sshgate/src/approvalplan"
	"github.com/karthikeyan5/sshgate/src/approvalwire"
)

const (
	approvalIDOne = "a2_AAAAAAAAAAAAAAAAAAAAAA"
	approvalIDTwo = "a2_BBBBBBBBBBBBBBBBBBBBBB"
	approvalPlan  = "64879f7d6b960a01909762d911a32d4582c20010c5641ee90278b644a9e3b525"
)

var approvalToken = [32]byte{1, 2, 3}

// wireGolden reads one of approvalwire's frozen frames, so the client is held
// to the exact bytes the wire package freezes.
func wireGolden(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("..", "..", "approvalwire", "testdata", "local", name))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func writeDraft(t *testing.T) approvalplan.ApprovalDraft {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("..", "..", "approvalplan", "testdata", "drafts", "write.json"))
	if err != nil {
		t.Fatal(err)
	}
	d, err := approvalplan.DecodeDraft(b)
	if err != nil {
		t.Fatal(err)
	}
	return d
}

// fakeDaemon serves each dialed connection with handle on the far end of a
// net.Pipe and records what it saw.
type fakeDaemon struct {
	mu        sync.Mutex
	dials     int
	requests  [][]byte
	deadlines []time.Time
	handle    func(conn net.Conn, request []byte)
}

type deadlineConn struct {
	net.Conn
	daemon *fakeDaemon
}

func (c deadlineConn) SetDeadline(t time.Time) error {
	c.daemon.mu.Lock()
	c.daemon.deadlines = append(c.daemon.deadlines, t)
	c.daemon.mu.Unlock()
	return c.Conn.SetDeadline(t)
}

func installFakeDaemon(t *testing.T, handle func(conn net.Conn, request []byte)) *fakeDaemon {
	t.Helper()
	d := &fakeDaemon{handle: handle}
	var served sync.WaitGroup
	original := dialWithCtx
	dialWithCtx = func(ctx context.Context, path string) (net.Conn, error) {
		client, server := net.Pipe()
		d.mu.Lock()
		d.dials++
		d.mu.Unlock()
		served.Add(1)
		go func() {
			defer served.Done()
			defer server.Close()
			request, err := lineframe.Read(server, approvalwire.MaxFrameBytes)
			if err != nil {
				return
			}
			d.mu.Lock()
			d.requests = append(d.requests, request)
			d.mu.Unlock()
			d.handle(server, request)
		}()
		return deadlineConn{client, d}, nil
	}
	t.Cleanup(func() {
		dialWithCtx = original
		served.Wait()
	})
	return d
}

func reply(frame []byte) func(net.Conn, []byte) {
	return func(conn net.Conn, _ []byte) { _, _ = conn.Write(frame) }
}

func approvalClient() *ApprovalClient {
	return &ApprovalClient{SocketPath: "/run/sshgate/test.sock"}
}

// allApprovalCalls runs each of the six methods once and returns its error.
func allApprovalCalls(t *testing.T, ctx context.Context, c *ApprovalClient) map[string]error {
	_, submitErr := c.Submit(ctx, writeDraft(t))
	_, getErr := c.Get(ctx, approvalIDOne)
	_, _, listErr := c.List(ctx, 50, "")
	_, claimErr := c.Claim(ctx, approvalIDOne, approvalPlan, approvalToken)
	reportErr := c.Report(ctx, approvalIDOne, approvalPlan, approvalToken, approvalReport())
	_, waitErr := c.Wait(ctx, []string{approvalIDOne}, time.Second) // last: its deadline may spend ctx
	return map[string]error{
		approvalwire.KindSubmit: submitErr, approvalwire.KindGet: getErr, approvalwire.KindList: listErr,
		approvalwire.KindWait: waitErr, approvalwire.KindClaim: claimErr, approvalwire.KindReport: reportErr,
	}
}

func approvalReport() approvalwire.Report {
	zero, exit1 := 0, 1
	out, none := int64(120), int64(0)
	truncated := false
	return approvalwire.Report{
		ReportSequence: approvalwire.ReportSequence,
		Steps: []approvalplan.StepReport{
			{Ordinal: 1, Status: approvalplan.StepSucceeded, ExitCode: &zero, StdoutBytes: &out, StderrBytes: &none, Truncated: &truncated},
			{Ordinal: 2, Status: approvalplan.StepFailed, ExitCode: &exit1, StdoutBytes: &none, StderrBytes: &out, Truncated: &truncated},
			{Ordinal: 3, Status: approvalplan.StepSkipped},
		},
		Class: approvalplan.ClassFailed, ExecutedOrdinals: []int{1, 2}, Partial: true,
		ResultDigest: "f6a214f7a5fcda0c2cee9660b7fc29f5649e3c68aad48e20e950137c98913a68",
	}
}

// TestApprovalClientSendsTheFrozenFrames drives every method against a fake
// daemon that checks the request bytes against approvalwire's goldens and
// answers with its golden responses.
func TestApprovalClientSendsTheFrozenFrames(t *testing.T) {
	cases := []struct {
		name, request, response string
		call                    func(c *ApprovalClient) (any, error)
		check                   func(t *testing.T, got any)
	}{
		{"submit", "request-submit-write.json", "response-submit-ok.json",
			func(c *ApprovalClient) (any, error) { return c.Submit(context.Background(), writeDraft(t)) },
			func(t *testing.T, got any) {
				if s := got.(approvalplan.Summary); s.RequestID != approvalIDOne || s.ApprovalStatus != approvalplan.ApprovalPending {
					t.Errorf("summary %+v", s)
				}
			}},
		{"get", "request-get.json", "response-get-shed-grant.json",
			func(c *ApprovalClient) (any, error) { return c.Get(context.Background(), approvalIDOne) },
			func(t *testing.T, got any) {
				if s := got.(approvalplan.Summary); !s.Pruned || s.GrantID != approvalIDOne || s.GrantExpiresAt == nil {
					t.Errorf("summary %+v", s)
				}
			}},
		{"list", "request-list-next.json", "response-list-page.json",
			func(c *ApprovalClient) (any, error) {
				page, cursor, err := c.List(context.Background(), 50, "c2_cursor-1")
				return fmt.Sprintf("%d %s", len(page), cursor), err
			},
			func(t *testing.T, got any) {
				if got != "2 c2_cursor-2" {
					t.Errorf("page %v", got)
				}
			}},
		{"wait", "request-wait.json", "response-wait-ok.json",
			func(c *ApprovalClient) (any, error) {
				return c.Wait(context.Background(), []string{approvalIDOne, approvalIDTwo}, 55*time.Second)
			},
			func(t *testing.T, got any) {
				if s := got.([]approvalplan.Summary); len(s) != 2 || s[1].ApprovalStatus != approvalplan.ApprovalDenied {
					t.Errorf("summaries %+v", s)
				}
			}},
		{"claim", "request-claim.json", "response-claim-signatures.json",
			func(c *ApprovalClient) (any, error) {
				return c.Claim(context.Background(), approvalIDOne, approvalPlan, approvalToken)
			},
			func(t *testing.T, got any) {
				if a := got.(approvalwire.ClaimAnswer); a.Status != approvalplan.ClaimSignatures || len(a.Signatures) != 2 || a.DecidedAt == nil {
					t.Errorf("claim %+v", a)
				}
			}},
		{"report", "request-report.json", "response-report-ok.json",
			func(c *ApprovalClient) (any, error) {
				return nil, c.Report(context.Background(), approvalIDOne, approvalPlan, approvalToken, approvalReport())
			},
			func(*testing.T, any) {}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			want := wireGolden(t, tc.request)
			d := installFakeDaemon(t, reply(wireGolden(t, tc.response)))
			got, err := tc.call(approvalClient())
			if err != nil {
				t.Fatal(err)
			}
			tc.check(t, got)
			if len(d.requests) != 1 || string(d.requests[0]) != string(want) {
				t.Fatalf("request\n%s\nwant\n%s", d.requests, want)
			}
		})
	}
}

func TestApprovalClientDeadlines(t *testing.T) {
	d := installFakeDaemon(t, reply(wireGolden(t, "response-wait-ok.json")))
	c := &ApprovalClient{SocketPath: "/run/sshgate/test.sock", CallTimeout: time.Second}
	start := time.Now()
	if _, err := c.Wait(context.Background(), []string{approvalIDOne, approvalIDTwo}, 55*time.Second); err != nil {
		t.Fatal(err)
	}
	if got := d.deadlines[0].Sub(start); got < 64*time.Second || got > 66*time.Second {
		t.Errorf("wait deadline %v after the call; want wait + %v", got, ApprovalWaitGrace)
	}
	d.handle = reply(wireGolden(t, "response-submit-ok.json"))
	start = time.Now()
	if _, err := (&ApprovalClient{SocketPath: "x"}).Get(context.Background(), approvalIDTwo); err == nil {
		t.Fatal("a mismatched summary was accepted")
	}
	if got := d.deadlines[1].Sub(start); got < DefaultApprovalCallTimeout-time.Second || got > DefaultApprovalCallTimeout+time.Second {
		t.Errorf("default deadline %v; want %v", got, DefaultApprovalCallTimeout)
	}
	if _, err := c.Wait(context.Background(), []string{approvalIDOne}, 1500*time.Millisecond); err == nil {
		t.Error("a fractional wait was sent")
	}
}

// TestApprovalClientResponseLost: the request was written in full but no
// answer came back, by EOF or by the call's deadline. The command may have
// been applied, so the client answers ErrResponseLost, never a definitive
// error and never a retry.
func TestApprovalClientResponseLost(t *testing.T) {
	handlers := map[string]func(net.Conn, []byte){
		"eof after write": func(net.Conn, []byte) {},
		"deadline": func(conn net.Conn, _ []byte) {
			buf := make([]byte, 1)
			_, _ = conn.Read(buf) // blocks until the client gives up and closes
		},
	}
	for name, handle := range handlers {
		t.Run(name, func(t *testing.T) {
			d := installFakeDaemon(t, handle)
			c := &ApprovalClient{SocketPath: "x", CallTimeout: 50 * time.Millisecond}
			// Wait's own deadline is wait + 10 s; the parent bounds it here.
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			for kind, err := range allApprovalCalls(t, ctx, c) {
				if !errors.Is(err, approvalwire.ErrResponseLost) || errors.Is(err, approvalwire.ErrStorageUncertain) {
					t.Errorf("%s: %v; want ErrResponseLost only", kind, err)
				}
			}
			if name == "eof after write" && d.dials != 6 {
				t.Errorf("%d dials for 6 calls: the client retried", d.dials)
			}
		})
	}
	t.Run("parent canceled after write", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		installFakeDaemon(t, func(conn net.Conn, _ []byte) {
			cancel()
			buf := make([]byte, 1)
			_, _ = conn.Read(buf)
		})
		_, err := approvalClient().Get(ctx, approvalIDOne)
		if !errors.Is(err, approvalwire.ErrResponseLost) || !errors.Is(err, context.Canceled) {
			t.Fatalf("%v; want ErrResponseLost and context.Canceled", err)
		}
	})
}

// TestApprovalClientSignerIncompatible: a pre-v2 daemon answers every v2 kind
// with its legacy unsupported-kind error frame (pkg/signerkit/daemon.go:519
// and :762 at 2ffe928), and a current daemon in front of an older hosted
// server answers E69's signer_incompatible frame. Both are the same typed
// error.
func TestApprovalClientSignerIncompatible(t *testing.T) {
	legacy := func(conn net.Conn, request []byte) {
		var kind string
		for _, k := range approvalwire.Kinds {
			if strings.Contains(string(request), `"kind":"`+k+`"`) {
				kind = k
			}
		}
		fmt.Fprintf(conn, `{"request_id":%q,"status":"error","error":"unsupported kind \"%s\"","proto_version":1}`+"\n", kind, kind)
	}
	for name, handle := range map[string]func(net.Conn, []byte){
		"legacy unsupported kind": legacy,
		"signer_incompatible":     reply(wireGolden(t, "response-signer-incompatible.json")),
	} {
		t.Run(name, func(t *testing.T) {
			installFakeDaemon(t, handle)
			for kind, err := range allApprovalCalls(t, context.Background(), approvalClient()) {
				if !errors.Is(err, approvalwire.ErrSignerIncompatible) || errors.Is(err, approvalwire.ErrResponseLost) {
					t.Errorf("%s: %v; want ErrSignerIncompatible", kind, err)
				}
			}
		})
	}
}

func TestApprovalClientTypedRefusals(t *testing.T) {
	refusals := strings.SplitAfter(string(wireGolden(t, "refusals.jsonl")), "\n")
	frame := func(code approvalplan.Code) []byte {
		for _, line := range refusals {
			if strings.Contains(line, `"code":"`+string(code)+`"`) {
				return []byte(line)
			}
		}
		t.Fatalf("no golden for %s", code)
		return nil
	}
	cases := map[approvalplan.Code]error{
		approvalplan.CodeStorageUncertain: approvalwire.ErrStorageUncertain,
		approvalplan.CodeBusy:             approvalwire.ErrBusy,
	}
	all := []error{approvalwire.ErrStorageUncertain, approvalwire.ErrBusy, approvalwire.ErrResponseLost, approvalwire.ErrSignerIncompatible}
	for code, want := range cases {
		d := installFakeDaemon(t, reply(frame(code)))
		for kind, err := range allApprovalCalls(t, context.Background(), approvalClient()) {
			for _, other := range all {
				if errors.Is(err, other) != (other == want) {
					t.Errorf("%s answered %s: %v; errors.Is(%v) wrong", kind, code, err, other)
				}
			}
		}
		if d.dials != 6 {
			t.Errorf("%s: %d dials for 6 calls: the client retried", code, d.dials)
		}
	}
	installFakeDaemon(t, reply(frame(approvalplan.CodeNotFound)))
	_, err := approvalClient().Get(context.Background(), approvalIDOne)
	var we *approvalwire.WireError
	if !errors.As(err, &we) || we.Code != approvalplan.CodeNotFound || errors.Is(err, approvalwire.ErrSignerIncompatible) {
		t.Fatalf("not_found: %v", err)
	}
}

func TestApprovalClientRefusesBeforeDialing(t *testing.T) {
	d := installFakeDaemon(t, reply(nil))
	c := approvalClient()
	ctx := context.Background()
	draft := writeDraft(t)
	draft.ExecutorClaimTokenHash = ""
	errs := []error{}
	_, err := c.Submit(ctx, draft)
	errs = append(errs, err)
	_, err = c.Get(ctx, "r_0123")
	errs = append(errs, err)
	_, _, err = c.List(ctx, 0, "")
	errs = append(errs, err)
	_, err = c.Wait(ctx, nil, time.Second)
	errs = append(errs, err)
	_, err = c.Claim(ctx, approvalIDOne, "nothex", approvalToken)
	errs = append(errs, err)
	bad := approvalReport()
	bad.ReportSequence = 2
	errs = append(errs, c.Report(ctx, approvalIDOne, approvalPlan, approvalToken, bad))
	for i, err := range errs {
		var ce *approvalplan.CodeError
		if !errors.As(err, &ce) {
			t.Errorf("call %d: %v; want a *CodeError", i, err)
		}
	}
	if d.dials != 0 {
		t.Errorf("%d dials for invalid requests", d.dials)
	}
}

func TestApprovalClientCorrelatesAnswers(t *testing.T) {
	installFakeDaemon(t, reply(wireGolden(t, "response-wait-ok.json")))
	if _, err := approvalClient().Wait(context.Background(), []string{approvalIDOne}, 0); err == nil {
		t.Error("wait accepted more summaries than ids")
	}
	if _, err := approvalClient().Wait(context.Background(), []string{approvalIDOne, "a2_CCCCCCCCCCCCCCCCCCCCCC"}, 0); err == nil {
		t.Error("wait accepted a summary for an id not asked for")
	}
	if _, _, err := approvalClient().List(context.Background(), 1, ""); err == nil {
		t.Error("list accepted more summaries than its limit")
	}
	installFakeDaemon(t, reply(wireGolden(t, "response-claim-signatures.json")))
	if _, err := approvalClient().Get(context.Background(), approvalIDOne); err == nil {
		t.Error("get accepted a claim answer")
	}
}

func TestApprovalClientUnreachableSocket(t *testing.T) {
	c := &ApprovalClient{SocketPath: filepath.Join(t.TempDir(), "missing.sock")}
	if _, err := c.Get(context.Background(), approvalIDOne); !errors.Is(err, ErrUnreachable) {
		t.Fatalf("%v; want ErrUnreachable", err)
	}
	if _, err := (&ApprovalClient{}).Get(context.Background(), approvalIDOne); err == nil {
		t.Fatal("an empty SocketPath dialed")
	}
}
