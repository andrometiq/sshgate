package backend_test

import (
	"context"
	"testing"
	"time"

	"github.com/karthikeyan5/sshgate/pkg/signerkit"
)

// TestHostedServerBackend_PollMatrix sweeps the /v1/poll outcomes that
// must all collapse to StatusTimeout from the client's perspective:
//   - 404 (unknown request_id / lost row): non-200 → terminal timeout
//   - server "error" status: terminal, mapped to timeout (no distinct
//     remote-error status in v1)
//   - malformed JSON body on 200: unmarshal failure → timeout
//   - unknown status string: defensive default → timeout
//
// Each runs against the reused fakeServer with a different knob.
func TestHostedServerBackend_PollMatrix(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name    string
		mutate  func(fs *fakeServer)
		wantSts signerkit.ResultStatus
	}{
		{
			name:    "poll_404",
			mutate:  func(fs *fakeServer) { fs.pollHTTPStatus = 404 },
			wantSts: signerkit.StatusTimeout,
		},
		{
			name:    "poll_error_status",
			mutate:  func(fs *fakeServer) { fs.pollAction = "error" },
			wantSts: signerkit.StatusTimeout,
		},
		{
			name:    "poll_malformed_json",
			mutate:  func(fs *fakeServer) { fs.pollMalformed = true },
			wantSts: signerkit.StatusTimeout,
		},
		{
			name:    "poll_unknown_status",
			mutate:  func(fs *fakeServer) { fs.pollRawStatus = "frobnicated" },
			wantSts: signerkit.StatusTimeout,
		},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			fs := &fakeServer{reqID: "r_matrix"}
			tc.mutate(fs)
			hb, _ := newFakeServerBackend(t, fs)
			hb.PollWait = 50 * time.Millisecond
			hb.Timeout = 2 * time.Second

			ch, err := hb.Request(context.Background(), signerkit.ApprovalRequest{
				RequestID: "r1",
				Commands:  []signerkit.CommandReq{{Server: "p", Cmd: "x", TTLSec: 60}},
			})
			if err != nil {
				t.Fatalf("Request: %v", err)
			}
			select {
			case res := <-ch:
				if res.Status != tc.wantSts {
					t.Errorf("status = %v; want %v", res.Status, tc.wantSts)
				}
			case <-time.After(3 * time.Second):
				t.Fatal("Request did not resolve within 3s")
			}
		})
	}
}

// TestHostedServerBackend_ConnectErrorThenApproved asserts the retry
// behaviour: the first /v1/poll connection is dropped (transient connect
// error), the client backs off ~500ms and re-polls, and the second poll
// returns approved. The Result must be StatusApproved with the
// passed-through signature — proving a single transient network blip
// doesn't fail the whole request.
func TestHostedServerBackend_ConnectErrorThenApproved(t *testing.T) {
	t.Parallel()
	fs := &fakeServer{
		reqID:            "r_retry",
		pollAction:       "approved",
		signatureCmd:     "echo hi",
		pollConnErrFirst: true,
	}
	hb, _ := newFakeServerBackend(t, fs)
	hb.PollWait = 100 * time.Millisecond
	hb.Timeout = 5 * time.Second

	start := time.Now()
	ch, err := hb.Request(context.Background(), signerkit.ApprovalRequest{
		RequestID: "r1",
		Commands:  []signerkit.CommandReq{{Server: "prod", Cmd: "echo hi", TTLSec: 60}},
	})
	if err != nil {
		t.Fatalf("Request: %v", err)
	}
	select {
	case res := <-ch:
		if res.Status != signerkit.StatusApproved {
			t.Fatalf("status = %v; want StatusApproved after retry", res.Status)
		}
		if len(res.Signatures) != 1 || res.Signatures[0].Cmd != "echo hi" {
			t.Errorf("Signatures = %+v; want one entry for 'echo hi'", res.Signatures)
		}
	case <-time.After(4 * time.Second):
		t.Fatal("Request did not resolve within 4s (retry path stalled?)")
	}
	// The client backs off 500ms between the dropped poll and the retry,
	// so resolution must take at least ~500ms.
	if elapsed := time.Since(start); elapsed < 400*time.Millisecond {
		t.Errorf("elapsed = %v; want >= ~500ms (one backoff between connect-error and retry)", elapsed)
	}
}

// TestHostedServerBackend_SignEmptyRequestID asserts that a 202 with an
// empty request_id is rejected up-front: Request returns an error and no
// channel (the daemon would answer the MCP with an error rather than
// poll a phantom id).
func TestHostedServerBackend_SignEmptyRequestID(t *testing.T) {
	t.Parallel()
	fs := &fakeServer{reqID: "", signEmptyReqID: true}
	hb, _ := newFakeServerBackend(t, fs)

	ch, err := hb.Request(context.Background(), signerkit.ApprovalRequest{
		RequestID: "r1",
		Commands:  []signerkit.CommandReq{{Server: "p", Cmd: "x", TTLSec: 60}},
	})
	if err == nil {
		t.Fatal("Request returned nil err on empty request_id; want an error")
	}
	if ch != nil {
		t.Error("Request returned a non-nil channel alongside the error; contract is (nil, err)")
	}
}
