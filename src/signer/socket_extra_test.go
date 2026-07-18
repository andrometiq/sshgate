package signer_test

import (
	"bufio"
	"context"
	"io"
	"net"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/karthikeyan5/sshgate/pkg/signerkit"
)

// blockingHandler never reads and never writes; it blocks until its
// context is cancelled (the per-connection deadline) and then returns.
// Used to prove Server.serveOne enforces a per-connection deadline so a
// silent/never-writing peer cannot pin a goroutine forever.
type blockingHandler struct{}

func (blockingHandler) HandleSignRequest(ctx context.Context, _ io.ReadWriter) error {
	<-ctx.Done()
	return ctx.Err()
}

// TestServer_PerConnectionDeadline asserts that a peer which connects and
// then never sends a byte gets its connection torn down once the short
// HandlerTimeout elapses — the daemon must not leak a goroutine per idle
// peer. We assert the SERVER side closes the conn by having the handler
// return on ctx-deadline; the client observes EOF on its read.
func TestServer_PerConnectionDeadline(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	sockPath := filepath.Join(dir, "sock")
	ctx, cancel := context.WithCancel(context.Background())
	srv := &signerkit.Server{
		Path:           sockPath,
		Handler:        blockingHandler{},
		HandlerTimeout: 150 * time.Millisecond,
	}
	done := make(chan error, 1)
	go func() { done <- srv.Listen(ctx) }()
	waitForSocket(t, sockPath, cancel)
	defer func() {
		cancel()
		select {
		case <-done:
		case <-time.After(2 * time.Second):
			t.Error("Listen did not exit within 2s of cancel")
		}
	}()

	conn, err := net.Dial("unix", sockPath)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	// Never write anything. The server's per-connection deadline should
	// fire, the handler returns, serveOne closes the conn, and our read
	// observes EOF. Give it generous headroom over the 150ms timeout.
	conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 1)
	_, readErr := conn.Read(buf)
	if readErr == nil {
		t.Fatal("expected the server to close the idle connection; read returned no error")
	}
	// A client-side read-deadline timeout would be a net.Error with
	// Timeout()==true; a server close is io.EOF. We want the latter
	// (server-driven close), so flag a timeout explicitly.
	if ne, ok := readErr.(net.Error); ok && ne.Timeout() {
		t.Fatalf("read hit the CLIENT deadline (%v); the server did not close the idle conn in time", readErr)
	}
}

// panicOnceHandler panics on the first connection it serves and echoes on
// every subsequent connection. It proves the daemon survives a handler
// panic (recovered in serveOne) and keeps accepting new connections.
type panicOnceHandler struct {
	mu       sync.Mutex
	panicked bool
}

func (h *panicOnceHandler) HandleSignRequest(_ context.Context, conn io.ReadWriter) error {
	h.mu.Lock()
	first := !h.panicked
	h.panicked = true
	h.mu.Unlock()
	if first {
		panic("boom: simulated handler panic")
	}
	br := bufio.NewReader(conn)
	line, err := br.ReadBytes('\n')
	if err != nil {
		return err
	}
	_, err = conn.Write(line)
	return err
}

// TestServer_HandlerPanicRecovered drives a panicking handler on the
// first connection, then a normal request on a second connection. The
// daemon must recover the panic (daemon.md §4.1) and remain able to
// accept and serve the second connection.
func TestServer_HandlerPanicRecovered(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	sockPath := filepath.Join(dir, "sock")
	ctx, cancel := context.WithCancel(context.Background())
	srv := &signerkit.Server{Path: sockPath, Handler: &panicOnceHandler{}}
	done := make(chan error, 1)
	go func() { done <- srv.Listen(ctx) }()
	waitForSocket(t, sockPath, cancel)
	defer func() {
		cancel()
		select {
		case <-done:
		case <-time.After(2 * time.Second):
			t.Error("Listen did not exit within 2s of cancel")
		}
	}()

	// First connection: triggers the panic. The server recovers and
	// closes the conn; we don't assert anything about the response.
	c1, err := net.Dial("unix", sockPath)
	if err != nil {
		t.Fatalf("dial 1: %v", err)
	}
	_, _ = c1.Write([]byte("trigger\n"))
	c1.SetReadDeadline(time.Now().Add(1 * time.Second))
	_, _ = bufio.NewReader(c1).ReadString('\n') // EOF or nothing; ignored
	c1.Close()

	// Second connection: the daemon must still be accepting and serving.
	c2, err := net.Dial("unix", sockPath)
	if err != nil {
		t.Fatalf("dial 2 (daemon should still accept after a recovered panic): %v", err)
	}
	defer c2.Close()
	const msg = "still-alive\n"
	if _, err := c2.Write([]byte(msg)); err != nil {
		t.Fatalf("write 2: %v", err)
	}
	c2.SetReadDeadline(time.Now().Add(2 * time.Second))
	got, err := bufio.NewReader(c2).ReadString('\n')
	if err != nil {
		t.Fatalf("read 2 (daemon wedged after panic?): %v", err)
	}
	if got != msg {
		t.Errorf("echo after panic = %q; want %q", got, msg)
	}
}

// waitForSocket blocks until sockPath exists or a 2s deadline passes
// (calling cancel + t.Fatalf on timeout). Mirrors the wait loop in the
// existing socket_test.go helper.
func waitForSocket(t *testing.T, sockPath string, cancel context.CancelFunc) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for {
		if _, err := os.Stat(sockPath); err == nil {
			return
		}
		if time.Now().After(deadline) {
			cancel()
			t.Fatalf("socket %s did not appear within 2s", sockPath)
		}
		time.Sleep(10 * time.Millisecond)
	}
}
