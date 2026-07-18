package signer_test

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/karthikeyan5/sshgate/pkg/signerkit"
)

// echoHandler reads one line from the connection and writes it back.
// Suitable for testing Server's accept loop and per-connection wiring
// without dragging the real Daemon in.
type echoHandler struct{}

func (echoHandler) HandleSignRequest(_ context.Context, conn io.ReadWriter) error {
	br := bufio.NewReader(conn)
	line, err := br.ReadBytes('\n')
	if err != nil {
		return err
	}
	_, err = conn.Write(line)
	return err
}

func startTestServer(t *testing.T, h signerkit.RequestHandler) (sockPath string, stop func()) {
	t.Helper()
	dir := t.TempDir()
	sockPath = filepath.Join(dir, "sock")
	ctx, cancel := context.WithCancel(context.Background())
	srv := &signerkit.Server{Path: sockPath, Handler: h}
	done := make(chan error, 1)
	go func() {
		done <- srv.Listen(ctx)
	}()
	// Wait for the socket to be ready.
	deadline := time.Now().Add(2 * time.Second)
	for {
		if _, err := os.Stat(sockPath); err == nil {
			break
		}
		if time.Now().After(deadline) {
			cancel()
			t.Fatalf("socket %s did not appear within 2s", sockPath)
		}
		time.Sleep(10 * time.Millisecond)
	}
	return sockPath, func() {
		cancel()
		select {
		case err := <-done:
			// Acceptable: Listen returns nil on graceful cancel, or a
			// net.ErrClosed wrapped error. Either is fine; we just
			// want the goroutine to have exited.
			if err != nil && !errors.Is(err, net.ErrClosed) && !errors.Is(err, context.Canceled) {
				t.Logf("Listen returned: %v", err)
			}
		case <-time.After(2 * time.Second):
			t.Errorf("Listen did not exit within 2s of cancel")
		}
	}
}

func TestSocketServer_BindAndRoundtrip(t *testing.T) {
	t.Parallel()
	path, stop := startTestServer(t, echoHandler{})
	defer stop()

	conn, err := net.Dial("unix", path)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()
	const msg = `{"kind":"sign","request_id":"r"}` + "\n"
	if _, err := conn.Write([]byte(msg)); err != nil {
		t.Fatalf("write: %v", err)
	}
	conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	br := bufio.NewReader(conn)
	got, err := br.ReadString('\n')
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if got != msg {
		t.Errorf("got %q; want %q", got, msg)
	}
}

func TestSocketServer_FileModeIs0660(t *testing.T) {
	t.Parallel()
	path, stop := startTestServer(t, echoHandler{})
	defer stop()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if got := info.Mode().Perm(); got != 0o660 {
		t.Errorf("socket mode = %#o; want 0660", got)
	}
	// Defence-in-depth: under no circumstances should the socket be
	// world-readable or world-writable, even briefly. Server.Listen
	// fchmods the listener's FD before any goroutine can dial; this
	// assertion catches a future regression that drops the Fchmod
	// step and leaves only the (umask-permissive) path-based chmod.
	if mode := info.Mode().Perm(); mode&0o007 != 0 {
		t.Errorf("socket mode = %#o has world bits set; want world bits cleared", mode)
	}
}

func TestSocketServer_ConcurrentClients(t *testing.T) {
	t.Parallel()
	path, stop := startTestServer(t, echoHandler{})
	defer stop()
	const N = 5
	var wg sync.WaitGroup
	wg.Add(N)
	for i := 0; i < N; i++ {
		i := i
		go func() {
			defer wg.Done()
			conn, err := net.Dial("unix", path)
			if err != nil {
				t.Errorf("dial %d: %v", i, err)
				return
			}
			defer conn.Close()
			msg := fmt.Sprintf(`{"i":%d}`, i) + "\n"
			if _, err := conn.Write([]byte(msg)); err != nil {
				t.Errorf("write %d: %v", i, err)
				return
			}
			conn.SetReadDeadline(time.Now().Add(2 * time.Second))
			got, err := bufio.NewReader(conn).ReadString('\n')
			if err != nil {
				t.Errorf("read %d: %v", i, err)
				return
			}
			if got != msg {
				t.Errorf("client %d got %q; want %q", i, got, msg)
			}
		}()
	}
	wg.Wait()
}

func TestSocketServer_CleansStaleSocketFile(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	sockPath := filepath.Join(dir, "sock")
	// Plant a stale file with the socket's name. Listen must remove it
	// and bind successfully.
	if err := os.WriteFile(sockPath, []byte("stale"), 0o660); err != nil {
		t.Fatalf("plant stale: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	srv := &signerkit.Server{Path: sockPath, Handler: echoHandler{}}
	done := make(chan error, 1)
	go func() { done <- srv.Listen(ctx) }()
	deadline := time.Now().Add(2 * time.Second)
	for {
		conn, err := net.Dial("unix", sockPath)
		if err == nil {
			conn.Close()
			break
		}
		if time.Now().After(deadline) {
			cancel()
			t.Fatalf("could not dial socket: %v", err)
		}
		time.Sleep(10 * time.Millisecond)
	}
	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Listen did not exit within 2s of cancel")
	}
}

func TestSocketServer_RefusesIfLiveProcessHoldsSocket(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	sockPath := filepath.Join(dir, "sock")

	// First server holds the socket.
	ctx1, cancel1 := context.WithCancel(context.Background())
	defer cancel1()
	srv1 := &signerkit.Server{Path: sockPath, Handler: echoHandler{}}
	done1 := make(chan error, 1)
	go func() { done1 <- srv1.Listen(ctx1) }()
	deadline := time.Now().Add(2 * time.Second)
	for {
		if _, err := os.Stat(sockPath); err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("first server never bound")
		}
		time.Sleep(10 * time.Millisecond)
	}

	// Second server on same path must refuse.
	srv2 := &signerkit.Server{Path: sockPath, Handler: echoHandler{}}
	err := srv2.Listen(context.Background())
	if err == nil {
		t.Error("second server.Listen returned nil; want refusal")
	}

	cancel1()
	select {
	case <-done1:
	case <-time.After(2 * time.Second):
		t.Fatal("first server did not exit within 2s")
	}
}

func TestSocketServer_CtxCancelStopsAccept(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	sockPath := filepath.Join(dir, "sock")
	ctx, cancel := context.WithCancel(context.Background())
	srv := &signerkit.Server{Path: sockPath, Handler: echoHandler{}}
	done := make(chan error, 1)
	go func() { done <- srv.Listen(ctx) }()
	// Wait for bind
	deadline := time.Now().Add(2 * time.Second)
	for {
		if _, err := os.Stat(sockPath); err == nil {
			break
		}
		if time.Now().After(deadline) {
			cancel()
			t.Fatal("bind never happened")
		}
		time.Sleep(10 * time.Millisecond)
	}
	cancel()
	select {
	case err := <-done:
		if err != nil && !errors.Is(err, net.ErrClosed) && !errors.Is(err, context.Canceled) {
			t.Errorf("Listen err: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Listen did not return within 2s of cancel")
	}
}
