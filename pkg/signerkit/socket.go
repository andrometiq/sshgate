package signerkit

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"sync"
	"syscall"
	"time"

	"github.com/karthikeyan5/sshgate/src/sigwire"
)

// RequestHandler is the per-connection callback the Server invokes once
// per accepted connection. The Daemon implements this against its real
// Backend; tests inject a small echo or fake handler.
//
// Implementations are expected to read one JSON request line and write
// one JSON response line; they may use the conn after Handle returns
// only if they also close it themselves (the Server does not call Close
// on connections the handler has not relinquished — see Listen).
type RequestHandler interface {
	HandleSignRequest(ctx context.Context, conn io.ReadWriter) error
}

// Server binds a Unix-domain socket at Path and dispatches accepted
// connections to Handler. One JSON request per connection; the Server
// itself owns the accept loop and per-connection deadlines, but does
// not interpret the protocol — that's Handler's job.
//
// The socket file is created with mode 0660 (owner + group rw). The
// daemon expects the karthi user to be in the sshgatesigner group on the
// real install so it can dial without being root; tests bind in a
// t.TempDir() and verify the mode bits.
type Server struct {
	Path    string
	Handler RequestHandler

	// HandlerTimeout bounds a single connection's lifetime: request read
	// + approval wait + response write, all under one absolute deadline
	// (see serveOne). Zero means 30s — fine for the stub/mock backends
	// and tests, but TOO SHORT for a human-in-the-loop backend. A caller
	// using one MUST set this larger than the approval window; the cmd
	// wire-up pins it to sigwire.SignerHandlerTimeout (= ApprovalWindow +
	// slack). Otherwise the deadline cuts the approval short and the
	// post-approval response write fails ("approved-undelivered").
	HandlerTimeout time.Duration
}

// Listen binds the socket and serves accept loop until ctx is cancelled.
//
// Behaviour:
//
//   - If Path points to a live socket (a process is listening), Listen
//     refuses to start and returns an error: a second copy of the
//     daemon would silently steal traffic. Detection is by "try-dial":
//     daemon.md §4.5 / §3.5 pattern, lightweight and correct.
//   - If Path points to a stale socket file (or any non-socket file),
//     Listen removes it and proceeds. The flock in cmd/signer is the
//     real singleton enforcement; this cleanup is just so a previous
//     crash doesn't leave the path EADDRINUSE.
//   - Returns nil after a graceful ctx-cancel shutdown.
//   - Returns the underlying error from net.Listen if bind fails for
//     any reason other than the live-socket case.
func (s *Server) Listen(ctx context.Context) error {
	if s.Handler == nil {
		return errors.New("signer.Server: Handler is nil")
	}
	if s.Path == "" {
		return errors.New("signer.Server: Path is empty")
	}

	// Live-process check: if the path exists AND a dial succeeds, a
	// peer is alive; refuse. If the path exists but dial fails, the
	// socket is stale — unlink it and continue.
	if _, err := os.Stat(s.Path); err == nil {
		conn, dialErr := net.DialTimeout("unix", s.Path, 200*time.Millisecond)
		if dialErr == nil {
			conn.Close()
			return fmt.Errorf("socket %s is already in use by a live process", s.Path)
		}
		if rmErr := os.Remove(s.Path); rmErr != nil {
			return fmt.Errorf("remove stale socket %s: %w", s.Path, rmErr)
		}
	}

	ln, err := net.Listen("unix", s.Path)
	if err != nil {
		return fmt.Errorf("listen %s: %w", s.Path, err)
	}
	// Tighten mode to 0660 via Fchmod on the listener's underlying FD
	// rather than os.Chmod on the path. net.Listen creates the socket
	// inode honouring umask (typically 0o022 → mode 0755), which is
	// briefly more permissive than we want before a path-based
	// os.Chmod runs (bind-then-chmod TOCTOU, daemon.md §4.5). Fchmod
	// is atomic relative to the inode and avoids the path-resolution
	// race; we don't go through syscall.Umask because that mutates
	// process-global state and would race with concurrent tests / any
	// other goroutine creating files. The path-based os.Chmod stays
	// as belt-and-braces in case a Linux variant (or future Go
	// runtime) ignores Fchmod on AF_UNIX inodes.
	if err := chmodListenerFD(ln, 0o660); err != nil {
		ln.Close()
		return fmt.Errorf("fchmod socket: %w", err)
	}
	if err := os.Chmod(s.Path, 0o660); err != nil {
		ln.Close()
		return fmt.Errorf("chmod socket: %w", err)
	}

	// Close the listener when ctx is cancelled so Accept returns.
	stopCh := make(chan struct{})
	go func() {
		// Belt-and-braces panic recovery, mirroring serveOne. The
		// watcher goroutine is trivial (one select + Close) so a
		// panic is highly unlikely, but a silent panic here would
		// leave the accept loop wedged on a closed-context listener.
		defer func() {
			if r := recover(); r != nil {
				fmt.Fprintf(os.Stderr, "signer: panic in listener watcher: %v\n", r)
			}
		}()
		select {
		case <-ctx.Done():
		case <-stopCh:
		}
		ln.Close()
	}()
	defer close(stopCh)

	timeout := s.HandlerTimeout
	if timeout == 0 {
		timeout = 30 * time.Second
	}

	// Track in-flight handlers so we can wait for them on shutdown.
	var wg sync.WaitGroup
	for {
		conn, err := ln.Accept()
		if err != nil {
			// Cancellation path: ctx is done and we closed the
			// listener.
			if ctx.Err() != nil {
				wg.Wait()
				// Remove the socket file on clean shutdown so a
				// future start does not have to handle a stale file.
				_ = os.Remove(s.Path)
				return nil
			}
			// Genuine accept error — exit the loop so the daemon can
			// restart cleanly.
			wg.Wait()
			_ = os.Remove(s.Path)
			return fmt.Errorf("accept: %w", err)
		}
		wg.Add(1)
		go s.serveOne(ctx, conn, timeout, &wg)
	}
}

// serveOne handles a single accepted connection with a per-connection
// deadline, recovers panics in the Handler so one buggy request cannot
// kill the daemon, and always closes the connection.
func (s *Server) serveOne(ctx context.Context, conn net.Conn, timeout time.Duration, wg *sync.WaitGroup) {
	defer wg.Done()
	defer conn.Close()

	defer func() {
		if r := recover(); r != nil {
			// daemon.md §4.1: per-handler panic recovery, log, continue.
			fmt.Fprintf(os.Stderr, "signer: panic in handler: %v\n", r)
		}
	}()

	// Split the connection's lifetime into a WAIT budget and a reserved
	// write grace. The initial connection deadline AND connCtx (which the
	// backend waits on) are bounded by the wait budget = timeout -
	// ResponseWriteGrace, so the verdict resolves with the grace still
	// unspent. The daemon then resets the write deadline to now + grace
	// immediately before writing each response (see daemon.go setWriteGrace),
	// guaranteeing a verdict that resolves at the wait deadline still has a
	// fresh, non-racing budget to reach the client (F1: verdict-undelivered).
	// Max connection lifetime stays <= timeout (= SignerHandlerTimeout), so
	// ClientSignTimeout still dominates the race.
	//
	// Guard: if the configured timeout is <= the grace (only possible with a
	// deliberately tiny test/stub HandlerTimeout), fall back to the full
	// timeout as the wait budget rather than a non-positive deadline.
	waitBudget := timeout - sigwire.ResponseWriteGrace
	if waitBudget <= 0 {
		waitBudget = timeout
	}
	if err := conn.SetDeadline(time.Now().Add(waitBudget)); err != nil {
		fmt.Fprintf(os.Stderr, "signer: set deadline: %v\n", err)
		return
	}
	connCtx, cancel := context.WithTimeout(ctx, waitBudget)
	defer cancel()

	if err := s.Handler.HandleSignRequest(connCtx, conn); err != nil {
		// Handler errors are surfaced to operators; the protocol-level
		// response (if any) was the handler's responsibility.
		fmt.Fprintf(os.Stderr, "signer: handler: %v\n", err)
	}
}

// chmodListenerFD applies mode to the inode behind ln by reaching
// the listener's underlying FD via SyscallConn and calling
// syscall.Fchmod. The FD path is atomic relative to the path lookup
// os.Chmod would do, closing the bind-then-chmod TOCTOU window.
//
// We deliberately use SyscallConn rather than UnixListener.File()
// here: File() returns a duplicated os.File whose Fd() forces the
// underlying socket into blocking mode, which breaks the
// ctx-cancel-driven accept-loop shutdown. SyscallConn.Control gives
// us the raw int FD without that side effect.
func chmodListenerFD(ln net.Listener, mode os.FileMode) error {
	ul, ok := ln.(*net.UnixListener)
	if !ok {
		return fmt.Errorf("not a *net.UnixListener: %T", ln)
	}
	rc, err := ul.SyscallConn()
	if err != nil {
		return fmt.Errorf("syscall conn: %w", err)
	}
	var fchmodErr error
	ctrlErr := rc.Control(func(fd uintptr) {
		fchmodErr = syscall.Fchmod(int(fd), uint32(mode))
	})
	if ctrlErr != nil {
		return fmt.Errorf("control: %w", ctrlErr)
	}
	if fchmodErr != nil {
		return fmt.Errorf("fchmod: %w", fchmodErr)
	}
	return nil
}
