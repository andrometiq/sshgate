package signerkit

import (
	"context"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"testing"
	"time"
)

type peerRecordingHandler struct {
	peer        *PeerCredentials
	legacyCalls int
	peerCalls   int
}

func (h *peerRecordingHandler) HandleSignRequest(_ context.Context, conn io.ReadWriter) error {
	h.legacyCalls++
	_, err := io.WriteString(conn, "legacy\n")
	return err
}

func (h *peerRecordingHandler) HandleSignRequestWithPeer(_ context.Context, conn io.ReadWriter, peer *PeerCredentials) error {
	h.peerCalls++
	h.peer = peer
	_, err := io.WriteString(conn, "peer\n")
	return err
}

// Deliberately implements only RequestHandler.
type legacyPeerTestHandler struct{ calls int }

func (h *legacyPeerTestHandler) HandleSignRequest(_ context.Context, conn io.ReadWriter) error {
	h.calls++
	_, err := io.WriteString(conn, "legacy\n")
	return err
}

func peerTestConnections(t *testing.T) (*net.UnixConn, *net.UnixConn) {
	t.Helper()
	// t.TempDir embeds the test name; Darwin caps socket paths at 103 bytes.
	dir, err := os.MkdirTemp("", "pc")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: filepath.Join(dir, "peer.sock"), Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	client, err := net.DialUnix("unix", nil, listener.Addr().(*net.UnixAddr))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { client.Close() })
	server, err := listener.AcceptUnix()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { server.Close() })
	return server, client
}

func runPeerTestConnection(t *testing.T, server *Server, accepted, client net.Conn) string {
	t.Helper()
	if err := client.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	wg.Add(1)
	go server.serveOne(context.Background(), accepted, 5*time.Second, &wg)
	response, err := io.ReadAll(client)
	wg.Wait()
	if err != nil {
		t.Fatal(err)
	}
	return string(response)
}

func TestSocketPeerCredentials(t *testing.T) {
	for _, name := range []string{"kernel", "injected", "root", "unavailable"} {
		t.Run(name, func(t *testing.T) {
			accepted, client := peerTestConnections(t)
			handler := &peerRecordingHandler{}
			server := &Server{Handler: handler}
			wantUID := uint32(os.Getuid())
			wantPeer := runtime.GOOS == "linux" || runtime.GOOS == "darwin"
			switch name {
			case "injected", "root":
				wantUID = 12345
				if name == "root" {
					wantUID = 0
				}
				wantPeer = true
				server.peerCredentials = func(conn *net.UnixConn) (uint32, error) {
					if conn != accepted {
						t.Error("resolver received a different connection")
					}
					return wantUID, nil
				}
			case "unavailable":
				wantPeer = false
				server.peerCredentials = func(*net.UnixConn) (uint32, error) { return 12345, errors.New("unavailable") }
			}
			if got := runPeerTestConnection(t, server, accepted, client); got != "peer\n" {
				t.Fatalf("response = %q", got)
			}
			if handler.peerCalls != 1 || handler.legacyCalls != 0 {
				t.Fatalf("dispatch = %+v", handler)
			}
			if wantPeer {
				if handler.peer == nil || handler.peer.UID != wantUID {
					t.Fatalf("peer = %+v; want uid %d", handler.peer, wantUID)
				}
			} else if handler.peer != nil {
				t.Fatalf("unverified peer = %+v", handler.peer)
			}
		})
	}
}

func TestSocketPeerCredentialsNonUnix(t *testing.T) {
	accepted, client := net.Pipe()
	defer client.Close()
	handler := &peerRecordingHandler{}
	server := &Server{Handler: handler, peerCredentials: func(*net.UnixConn) (uint32, error) { t.Error("resolver called for non-Unix connection"); return 0, nil }}
	runPeerTestConnection(t, server, accepted, client)
	if handler.peerCalls != 1 || handler.legacyCalls != 0 || handler.peer != nil {
		t.Fatalf("dispatch = %+v", handler)
	}
}

func TestSocketLegacyHandlerSkipsPeerResolution(t *testing.T) {
	accepted, client := peerTestConnections(t)
	handler := &legacyPeerTestHandler{}
	server := &Server{Handler: handler, peerCredentials: func(*net.UnixConn) (uint32, error) {
		t.Error("legacy request resolved peer")
		return 0, errors.New("unavailable")
	}}
	if got := runPeerTestConnection(t, server, accepted, client); got != "legacy\n" {
		t.Fatalf("response = %q", got)
	}
	if handler.calls != 1 {
		t.Fatalf("legacy calls = %d", handler.calls)
	}
}

func TestSocketPeerCredentialsClosedConnection(t *testing.T) {
	accepted, _ := peerTestConnections(t)
	accepted.Close()
	if _, err := socketPeerUID(accepted); err == nil {
		t.Fatal("closed connection has credentials")
	}
}
