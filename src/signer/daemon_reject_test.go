package signer_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/karthikeyan5/sshgate/src/signer/backend"
)

// TestDaemon_RejectsBadRequests is the protocol-validation table. Each
// row drives HandleSignRequest with a single malformed/illegal request
// line and asserts the daemon (a) writes an {status:"error"} response
// and (b) records exactly one audit row with status "error". The daemon
// contract is "every request produces an audit row, and protocol-level
// mischief is visible at status:error" (daemon.md §5.1/§6), so both the
// wire response AND the audit row are checked for every case.
//
// All rows use a MockBackend that is never armed: a correct daemon
// rejects these requests BEFORE ever calling Backend.Request. If a
// regression let one of these illegal requests slip through to the
// backend, the un-armed mock's channel would never resolve and the test
// would hang until the package -timeout fires — a loud failure rather
// than a false green.
func TestDaemon_RejectsBadRequests(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		// req is the raw request line (without trailing newline; the
		// harness appends it).
		req string
		// wantErrSubstr, when non-empty, must appear in the response's
		// error field. Kept loose (substring) so wording tweaks in the
		// daemon don't break the test, while still pinning the daemon to
		// the right rejection reason.
		wantErrSubstr string
	}{
		{
			name:          "kind not sign",
			req:           `{"kind":"verify","request_id":"r1","commands":[{"server":"p","cmd":"ls","ttl_seconds":60}]}`,
			wantErrSubstr: "unsupported kind",
		},
		{
			name:          "missing request_id",
			req:           `{"kind":"sign","commands":[{"server":"p","cmd":"ls","ttl_seconds":60}]}`,
			wantErrSubstr: "missing request_id",
		},
		{
			name:          "empty commands array",
			req:           `{"kind":"sign","request_id":"r1","commands":[]}`,
			wantErrSubstr: "no commands",
		},
		{
			name:          "empty cmd string",
			req:           `{"kind":"sign","request_id":"r1","commands":[{"server":"p","cmd":"","ttl_seconds":60}]}`,
			wantErrSubstr: "cmd is empty",
		},
		{
			name:          "ttl zero",
			req:           `{"kind":"sign","request_id":"r1","commands":[{"server":"p","cmd":"ls","ttl_seconds":0}]}`,
			wantErrSubstr: "ttl_seconds must be > 0",
		},
		{
			name:          "ttl negative",
			req:           `{"kind":"sign","request_id":"r1","commands":[{"server":"p","cmd":"ls","ttl_seconds":-1}]}`,
			wantErrSubstr: "ttl_seconds must be > 0",
		},
		{
			name:          "ttl over max validity",
			req:           `{"kind":"sign","request_id":"r1","commands":[{"server":"p","cmd":"ls","ttl_seconds":301}]}`,
			wantErrSubstr: "exceeds max",
		},
		{
			// Regression: a ttl past the int64-nanosecond overflow point
			// (~9.2e9s). The pre-fix clamp did time.Duration(ttl)*Second,
			// which overflowed NEGATIVE and let this slip past the cap to
			// the un-armed mock — hanging until the package timeout. The
			// fixed clamp compares in int64 seconds, so it rejects here.
			name:          "ttl past int64-nanosecond overflow point",
			req:           `{"kind":"sign","request_id":"r1","commands":[{"server":"p","cmd":"ls","ttl_seconds":9300000000}]}`,
			wantErrSubstr: "exceeds max",
		},
		{
			name:          "ttl at MaxInt64",
			req:           `{"kind":"sign","request_id":"r1","commands":[{"server":"p","cmd":"ls","ttl_seconds":9223372036854775807}]}`,
			wantErrSubstr: "exceeds max",
		},
		{
			name:          "unknown extra json field",
			req:           `{"kind":"sign","request_id":"r1","commands":[{"server":"p","cmd":"ls","ttl_seconds":60}],"bogus":true}`,
			wantErrSubstr: "malformed",
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			mock := backend.NewMockBackend()
			d, _, audit, auditPath := newDaemon(t, mock)
			defer audit.Close()

			conn := &memConn{in: bytes.NewReader([]byte(tc.req + "\n")), out: &bytes.Buffer{}}
			if err := d.HandleSignRequest(context.Background(), conn); err != nil {
				t.Fatalf("HandleSignRequest returned hard error (a written response was expected): %v", err)
			}

			var resp struct {
				Status string `json:"status"`
				Error  string `json:"error"`
			}
			if err := json.Unmarshal(bytes.TrimRight(conn.out.Bytes(), "\n"), &resp); err != nil {
				t.Fatalf("unmarshal response: %v\nraw=%q", err, conn.out.String())
			}
			if resp.Status != "error" {
				t.Errorf("Status = %q; want error", resp.Status)
			}
			if resp.Error == "" {
				t.Errorf("Error field empty; want a rejection reason")
			}
			if tc.wantErrSubstr != "" && !strings.Contains(resp.Error, tc.wantErrSubstr) {
				t.Errorf("Error = %q; want it to contain %q", resp.Error, tc.wantErrSubstr)
			}

			audit.Close()
			got := readAudit(t, auditPath)
			if len(got) != 1 {
				t.Fatalf("audit rows = %d; want exactly 1", len(got))
			}
			if got[0].Status != "error" {
				t.Errorf("audit Status = %q; want error", got[0].Status)
			}
		})
	}
}

// TestDaemon_TTLBoundaryExactMaxAllowed pins the inclusive boundary: a
// ttl exactly equal to MaxSigValidity (300s) is allowed (the daemon
// rejects only ttl > max), so the table's 301-rejection above is a true
// boundary test rather than an off-by-one.
func TestDaemon_TTLBoundaryExactMaxAllowed(t *testing.T) {
	t.Parallel()
	mock := backend.NewMockBackend()
	d, _, audit, _ := newDaemon(t, mock)
	defer audit.Close()
	mock.Approve("r_ttlmax", "karthi")

	req := `{"kind":"sign","request_id":"r_ttlmax","commands":[{"server":"p","cmd":"ls","ttl_seconds":300}]}`
	conn := &memConn{in: bytes.NewReader([]byte(req + "\n")), out: &bytes.Buffer{}}
	if err := d.HandleSignRequest(context.Background(), conn); err != nil {
		t.Fatalf("HandleSignRequest: %v", err)
	}
	var resp struct {
		Status string `json:"status"`
	}
	if err := json.Unmarshal(bytes.TrimRight(conn.out.Bytes(), "\n"), &resp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if resp.Status != "approved" {
		t.Errorf("Status = %q; want approved (ttl == MaxSigValidity is allowed)", resp.Status)
	}
}

// TestDaemon_BackendError covers the path where Backend.Request itself
// returns a hard error (e.g. a hosted backend's submit POST failed). The
// daemon must respond with an "error" status whose reason is prefixed
// "backend:" and record an "error" audit row.
func TestDaemon_BackendError(t *testing.T) {
	t.Parallel()
	bk := errBackend{err: errors.New("submit failed: connection refused")}
	d, _, audit, auditPath := newDaemon(t, bk)
	defer audit.Close()

	req := `{"kind":"sign","request_id":"r_be","commands":[{"server":"p","cmd":"ls","ttl_seconds":60}]}`
	conn := &memConn{in: bytes.NewReader([]byte(req + "\n")), out: &bytes.Buffer{}}
	if err := d.HandleSignRequest(context.Background(), conn); err != nil {
		t.Fatalf("HandleSignRequest: %v", err)
	}

	var resp struct {
		Status string `json:"status"`
		Error  string `json:"error"`
	}
	if err := json.Unmarshal(bytes.TrimRight(conn.out.Bytes(), "\n"), &resp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if resp.Status != "error" {
		t.Errorf("Status = %q; want error", resp.Status)
	}
	if !strings.HasPrefix(resp.Error, "backend:") {
		t.Errorf("Error = %q; want it to start with %q", resp.Error, "backend:")
	}
	if !strings.Contains(resp.Error, "connection refused") {
		t.Errorf("Error = %q; want it to carry the underlying backend error", resp.Error)
	}

	audit.Close()
	got := readAudit(t, auditPath)
	if len(got) != 1 || got[0].Status != "error" {
		t.Errorf("audit = %+v; want one error row", got)
	}
}

// TestDaemon_ReadEOFBeforeBytes covers the hard-read-error contract: a
// peer that connects and immediately drops without sending a single byte
// must surface as a non-nil error from HandleSignRequest, and NO
// response is written (there is no request_id to pin a response to).
func TestDaemon_ReadEOFBeforeBytes(t *testing.T) {
	t.Parallel()
	mock := backend.NewMockBackend()
	d, _, audit, _ := newDaemon(t, mock)
	defer audit.Close()

	// Empty reader => ReadBytes returns (0 bytes, io.EOF) immediately.
	out := &bytes.Buffer{}
	conn := &memConn{in: bytes.NewReader(nil), out: out}
	err := d.HandleSignRequest(context.Background(), conn)
	if err == nil {
		t.Fatal("expected a hard read error for connect-then-drop; got nil")
	}
	if out.Len() != 0 {
		t.Errorf("response written = %q; want none on a pre-bytes read error", out.String())
	}
}

// TestDaemon_EmptyLineMalformed covers an empty request line and a
// whitespace-only request line: both decode to a JSON error and must be
// rejected as "error" (malformed) rather than crashing or hanging. These
// differ from the connect-then-drop case because the newline-terminated
// (even if blank) line means ReadBytes returns no error, so the daemon
// proceeds to JSON-decode and rejects there.
func TestDaemon_EmptyLineMalformed(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		line string
	}{
		{"empty line", "\n"},
		{"whitespace only", "   \t  \n"},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			mock := backend.NewMockBackend()
			d, _, audit, auditPath := newDaemon(t, mock)
			defer audit.Close()

			conn := &memConn{in: bytes.NewReader([]byte(tc.line)), out: &bytes.Buffer{}}
			if err := d.HandleSignRequest(context.Background(), conn); err != nil {
				t.Fatalf("HandleSignRequest returned hard error; want a written malformed response: %v", err)
			}
			var resp struct {
				Status string `json:"status"`
				Error  string `json:"error"`
			}
			if err := json.Unmarshal(bytes.TrimRight(conn.out.Bytes(), "\n"), &resp); err != nil {
				t.Fatalf("unmarshal: %v\nraw=%q", err, conn.out.String())
			}
			if resp.Status != "error" {
				t.Errorf("Status = %q; want error", resp.Status)
			}
			if !strings.Contains(resp.Error, "malformed") {
				t.Errorf("Error = %q; want a malformed-request reason", resp.Error)
			}
			audit.Close()
			got := readAudit(t, auditPath)
			if len(got) != 1 || got[0].Status != "error" {
				t.Errorf("audit = %+v; want one error row", got)
			}
		})
	}
}

// errBackend is a tiny new fake: Request always returns a hard error and
// no channel, exercising the daemon's backend-submit-failure branch. The
// existing MockBackend/StubBackend never return an error from Request, so
// this case needs its own fixture (per the brief's "build only the tiny
// new fakes noted").
type errBackend struct{ err error }

func (b errBackend) Request(_ context.Context, _ backend.ApprovalRequest) (<-chan backend.Result, error) {
	return nil, b.err
}

func (b errBackend) RequestGrant(_ context.Context, _ backend.GrantApprovalRequest) (<-chan backend.Result, error) {
	return nil, b.err
}

func (b errBackend) RequestTransfer(_ context.Context, _ backend.TransferApprovalRequest) (<-chan backend.Result, error) {
	return nil, b.err
}

func (b errBackend) RequestRegisterKey(_ context.Context, _ backend.RegisterApprovalRequest) (<-chan backend.Result, error) {
	return nil, b.err
}
