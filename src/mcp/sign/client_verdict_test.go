package sign

import (
	"context"
	"errors"
	"io"
	"net"
	"os"
	"strings"
	"sync"
	"testing"
	"time"
)

// readResultConn is a net.Conn whose Write always SUCCEEDS (the request goes
// out) and whose Read returns a pre-configured error — io.EOF (peer closed
// after the daemon decided but couldn't deliver) or a net timeout (the
// daemon wedged past the deadline). It is the F1 fixture: a verdict that was
// decided but whose response line never arrived must surface as
// ErrVerdictUnknown (fail-safe: a human may have DENIED), not a generic
// retryable read error.
type readResultConn struct {
	readErr   error
	closed    chan struct{}
	closeOnce sync.Once
}

func newReadResultConn(readErr error) *readResultConn {
	return &readResultConn{readErr: readErr, closed: make(chan struct{})}
}

func (r *readResultConn) Read(b []byte) (int, error) {
	return 0, r.readErr
}
func (r *readResultConn) Write(b []byte) (int, error) { return len(b), nil }
func (r *readResultConn) Close() error {
	r.closeOnce.Do(func() { close(r.closed) })
	return nil
}
func (r *readResultConn) LocalAddr() net.Addr                { return dummyAddr{} }
func (r *readResultConn) RemoteAddr() net.Addr               { return dummyAddr{} }
func (r *readResultConn) SetDeadline(t time.Time) error      { return nil }
func (r *readResultConn) SetReadDeadline(t time.Time) error  { return nil }
func (r *readResultConn) SetWriteDeadline(t time.Time) error { return nil }

// netTimeoutErr is a net.Error reporting Timeout()==true, simulating the
// client's own read deadline firing while the daemon is wedged.
type netTimeoutErr struct{}

func (netTimeoutErr) Error() string   { return "i/o timeout (fake)" }
func (netTimeoutErr) Timeout() bool   { return true }
func (netTimeoutErr) Temporary() bool { return true }

// withFakeDial swaps the dialWithCtx seam to return conn for the duration of
// the test.
func withFakeDial(t *testing.T, conn net.Conn) {
	t.Helper()
	orig := dialWithCtx
	t.Cleanup(func() { dialWithCtx = orig })
	dialWithCtx = func(ctx context.Context, path string) (net.Conn, error) {
		return conn, nil
	}
}

// TestSign_EOFAfterRequestSent_IsVerdictUnknown: a clean EOF on the read
// after the request was fully written means the signer decided but the
// response did not arrive — must be ErrVerdictUnknown, NOT a bare read error.
func TestSign_EOFAfterRequestSent_IsVerdictUnknown(t *testing.T) {
	withFakeDial(t, newReadResultConn(io.EOF))
	c := &Client{SocketPath: "/unused", Timeout: 2 * time.Second}
	_, err := c.Sign(context.Background(), "r1", []CmdReq{{Server: "s", Cmd: "x", TTLSec: 60}})
	if err == nil {
		t.Fatal("err is nil; want ErrVerdictUnknown on EOF after request sent")
	}
	if !errors.Is(err, ErrVerdictUnknown) {
		t.Errorf("err = %v; want errors.Is(ErrVerdictUnknown)", err)
	}
	// Must NOT collapse into a plain transport read error or a wrong sentinel.
	if errors.Is(err, ErrDenied) || errors.Is(err, ErrTimeout) ||
		errors.Is(err, ErrUnreachable) || errors.Is(err, ErrSignerPermission) {
		t.Errorf("verdict-unknown mis-mapped to another sentinel: %v", err)
	}
	if strings.Contains(err.Error(), "read response") {
		t.Errorf("err = %q; should be the verdict-unknown message, not the generic read-response wrap", err.Error())
	}
}

// TestSign_NetTimeoutAfterRequestSent_IsVerdictUnknown: a net timeout on the
// read after the request was sent (the daemon wedged) is also indeterminate.
func TestSign_NetTimeoutAfterRequestSent_IsVerdictUnknown(t *testing.T) {
	withFakeDial(t, newReadResultConn(netTimeoutErr{}))
	c := &Client{SocketPath: "/unused", Timeout: 2 * time.Second}
	_, err := c.Sign(context.Background(), "r1", []CmdReq{{Server: "s", Cmd: "x", TTLSec: 60}})
	if !errors.Is(err, ErrVerdictUnknown) {
		t.Errorf("err = %v; want errors.Is(ErrVerdictUnknown) on net-timeout after request sent", err)
	}
}

// TestSign_DeadlineExceededAfterRequestSent_IsVerdictUnknown: os.ErrDeadlineExceeded
// (what a conn deadline read returns) is treated as indeterminate too.
func TestSign_DeadlineExceededAfterRequestSent_IsVerdictUnknown(t *testing.T) {
	withFakeDial(t, newReadResultConn(os.ErrDeadlineExceeded))
	c := &Client{SocketPath: "/unused", Timeout: 2 * time.Second}
	_, err := c.Sign(context.Background(), "r1", []CmdReq{{Server: "s", Cmd: "x", TTLSec: 60}})
	if !errors.Is(err, ErrVerdictUnknown) {
		t.Errorf("err = %v; want errors.Is(ErrVerdictUnknown) on deadline-exceeded after request sent", err)
	}
}

// TestSign_CtxCancelStillCtxError: when ctx itself is cancelled, the read
// error must surface as the ctx error (unchanged behaviour), NOT
// ErrVerdictUnknown — a caller-cancelled call is not an indeterminate verdict.
func TestSign_CtxCancelStillCtxError(t *testing.T) {
	withFakeDial(t, newReadResultConn(io.EOF))
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // ctx.Err() != nil before the read-error branch runs
	c := &Client{SocketPath: "/unused", Timeout: 2 * time.Second}
	_, err := c.Sign(ctx, "r1", []CmdReq{{Server: "s", Cmd: "x", TTLSec: 60}})
	if err == nil {
		t.Fatal("err is nil; want the ctx error")
	}
	if errors.Is(err, ErrVerdictUnknown) {
		t.Errorf("ctx-cancel mis-mapped to ErrVerdictUnknown: %v", err)
	}
	if !errors.Is(err, context.Canceled) {
		t.Errorf("err = %v; want errors.Is(context.Canceled)", err)
	}
}

// TestSign_PartialMalformedLine_StillReadError: a partial/malformed line
// (bytes with no trailing newline, then a non-EOF read error) is NOT a clean
// verdict-undelivered case — it stays a read error. We model this with a
// read error that is neither EOF nor a timeout.
func TestSign_PartialMalformedLine_StillReadError(t *testing.T) {
	withFakeDial(t, newReadResultConn(errors.New("connection reset by peer")))
	c := &Client{SocketPath: "/unused", Timeout: 2 * time.Second}
	_, err := c.Sign(context.Background(), "r1", []CmdReq{{Server: "s", Cmd: "x", TTLSec: 60}})
	if err == nil {
		t.Fatal("err is nil; want a read error")
	}
	if errors.Is(err, ErrVerdictUnknown) {
		t.Errorf("a non-EOF/non-timeout read error must NOT be verdict-unknown: %v", err)
	}
	if !strings.Contains(err.Error(), "read response") {
		t.Errorf("err = %q; want the generic read-response wrap for a non-indeterminate error", err.Error())
	}
}
