package ssh_test

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/karthikeyan5/sshgate/internal/elapsed/elapsedtest"
	sshpkg "github.com/karthikeyan5/sshgate/src/mcp/ssh"
	sshlib "golang.org/x/crypto/ssh"
)

const phasedWire = "SSHGATE_SIG:c2lnbmF0dXJl:cGF5bG9hZA== touch /unique-command"

type phasedServer struct {
	client      *sshpkg.Client
	port        int
	connections atomic.Int32
	execs       atomic.Int32
}

// Hooks run at the actual handshake and channel-open boundaries.
func newPhasedServer(t *testing.T, handshake, session func(), mode string, onExec func()) *phasedServer {
	t.Helper()
	key, _ := generateClientKey(t)
	hostKey, _ := generateClientKey(t)
	hostSignerBytes, err := osReadKey(hostKey)
	if err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	s := &phasedServer{client: &sshpkg.Client{KeyPath: key, KnownHostsPath: filepath.Join(t.TempDir(), "known_hosts"), Timeout: time.Second}, port: listener.Addr().(*net.TCPAddr).Port}
	done := make(chan struct{})
	go func() {
		defer close(done)
		tcp, err := listener.Accept()
		if err != nil {
			return
		}
		defer tcp.Close()
		s.connections.Add(1)
		if handshake != nil {
			handshake()
		}
		cfg := &sshlib.ServerConfig{NoClientAuth: true}
		cfg.AddHostKey(hostSignerBytes)
		conn, channels, requests, err := sshlib.NewServerConn(tcp, cfg)
		if err != nil {
			return
		}
		defer conn.Close()
		go sshlib.DiscardRequests(requests)
		for ch := range channels {
			if session != nil {
				session()
			}
			if mode == "session_reject" {
				_ = ch.Reject(sshlib.Prohibited, "refused")
				continue
			}
			channel, requests, err := ch.Accept()
			if err != nil {
				return
			}
			for req := range requests {
				if req.Type != "exec" {
					_ = req.Reply(false, nil)
					continue
				}
				s.execs.Add(1)
				if onExec != nil && !strings.HasPrefix(mode, "cancel_exit") {
					onExec()
				}
				if mode == "start_io" {
					_ = channel.Close()
					return
				}
				if mode == "reject" {
					_ = req.Reply(false, nil)
					_ = channel.Close()
					break
				}
				_ = req.Reply(true, nil)
				if mode == "cancel" {
					<-requests
					_ = channel.Close()
					return
				}
				if mode == "transport" {
					_ = conn.Close()
					return
				}
				if mode == "missing" {
					_ = channel.Close()
					break
				}
				if mode == "stdin" {
					_, _ = io.Copy(channel, channel)
				} else {
					_, _ = channel.Write([]byte("stdout"))
					_, _ = channel.Stderr().Write([]byte("stderr"))
				}
				status := uint32(0)
				if mode == "exit3" || mode == "cancel_exit3" {
					status = 3
				}
				_, _ = channel.SendRequest("exit-status", false, sshlib.Marshal(struct{ Status uint32 }{status}))
				if strings.HasPrefix(mode, "cancel_exit") {
					// The reply proves Session.wait has consumed the preceding exit status.
					_, _ = channel.SendRequest("completion-barrier", true, nil)
					onExec()
				}
				_ = channel.Close()
				break
			}
		}
	}()
	t.Cleanup(func() { _ = listener.Close(); <-done })
	return s
}

func checkPhasedError(t *testing.T, err error, class, phase, detail string) {
	t.Helper()
	var p *sshpkg.PhasedError
	if !errors.As(err, &p) || p.Class != class || p.Phase != phase || p.Detail != detail {
		t.Fatalf("error = %#v; want %s/%s/%s", err, class, phase, detail)
	}
	for _, secret := range []string{"SSHGATE_SIG:", "c2lnbmF0dXJl", "cGF5bG9hZA==", "touch /unique-command"} {
		if strings.Contains(fmt.Sprintf("%v %#v", err, err), secret) {
			t.Fatal("diagnostic leaked command material")
		}
	}
	if errors.Unwrap(err) != nil {
		t.Fatal("raw error retained")
	}
}

func TestRunPhasedNilGuard(t *testing.T) {
	s := newPhasedServer(t, nil, nil, "ok", nil)
	// Invalid key proves refusal precedes even key loading.
	s.client.KeyPath = filepath.Join(t.TempDir(), "missing")
	_, _, _, err := s.client.RunPhased(context.Background(), "127.0.0.1", "tester", s.port, phasedWire, nil, nil)
	checkPhasedError(t, err, "failed_not_started", "pre_dial", "missing pre-start guard")
	if s.connections.Load() != 0 {
		t.Fatal("nil guard dialed")
	}
}

func TestRunPhasedGuardAfterSetup(t *testing.T) {
	for _, boundary := range []string{"handshake", "session"} {
		for _, movement := range []string{"wall", "elapsed", "neither", "unsigned"} {
			t.Run(boundary+"/"+movement, func(t *testing.T) {
				clock := elapsedtest.NewFake(time.Unix(100, 0))
				wallEnd := clock.Wall().Add(10 * time.Second)
				elapsedEnd := clock.Elapsed() + 10*time.Second
				guard := func() error {
					if !clock.Wall().Add(2*time.Second).Before(wallEnd) || clock.Elapsed()+2*time.Second >= elapsedEnd {
						return errors.New(phasedWire)
					}
					return nil
				}
				if guard() != nil {
					t.Fatal("initial guard failed")
				}
				hook := func() {
					if movement == "wall" {
						clock.StepWall(9 * time.Second)
					}
					if movement == "elapsed" {
						clock.Advance(9 * time.Second)
						clock.StepWall(-9 * time.Second)
					}
				}
				var handshake, session func()
				if boundary == "handshake" {
					handshake = hook
				} else {
					session = hook
				}
				s := newPhasedServer(t, handshake, session, "ok", nil)
				cmd := phasedWire
				if movement == "unsigned" {
					cmd = "echo unsigned"
					guard = nil
				}
				_, _, _, err := s.client.RunPhased(context.Background(), "127.0.0.1", "tester", s.port, cmd, nil, guard)
				if movement == "wall" || movement == "elapsed" {
					checkPhasedError(t, err, "guard_refused", "pre_start", "pre-start guard refused")
					if s.execs.Load() != 0 {
						t.Fatal("expired guard sent exec")
					}
				} else if err != nil || s.execs.Load() != 1 {
					t.Fatalf("control: execs=%d err=%v", s.execs.Load(), err)
				}
			})
		}
	}
}

func TestRunPhasedOutcomes(t *testing.T) {
	for _, mode := range []string{"ok", "exit3", "reject", "start_io", "missing", "session_reject", "stdin", "cancel", "transport"} {
		t.Run(mode, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			var onExec func()
			if mode == "cancel" {
				onExec = cancel
			}
			s := newPhasedServer(t, nil, nil, mode, onExec)
			var input io.Reader
			if mode == "stdin" {
				input = strings.NewReader("binary\x00input")
			}
			out, stderr, exit, err := s.client.RunPhased(ctx, "127.0.0.1", "tester", s.port, phasedWire, input, func() error { return nil })
			switch mode {
			case "reject":
				checkPhasedError(t, err, "failed_not_started", "start", "exec request rejected")
			case "start_io":
				checkPhasedError(t, err, "indeterminate", "start", "start i/o error")
			case "missing":
				checkPhasedError(t, err, "indeterminate", "wait", "channel closed without exit status")
			case "session_reject":
				checkPhasedError(t, err, "failed_not_started", "new_session", "new session failed")
			case "cancel", "transport":
				var p *sshpkg.PhasedError
				if !errors.As(err, &p) || p.Class != "indeterminate" {
					t.Fatalf("cancel: %v", err)
				}
			default:
				wantExit := 0
				if mode == "exit3" {
					wantExit = 3
				}
				if err != nil || exit != wantExit {
					t.Fatalf("exit=%d err=%v", exit, err)
				}
				if mode == "stdin" {
					if string(out) != "binary\x00input" {
						t.Fatalf("stdin echo %q", out)
					}
				} else if string(out) != "stdout" || string(stderr) != "stderr" {
					t.Fatal("output lost")
				}
			}
		})
	}
}

func osReadKey(path string) (sshlib.Signer, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return sshlib.ParsePrivateKey(data)
}

func TestRunPhasedKnownExitWinsCancellation(t *testing.T) {
	for _, mode := range []string{"cancel_exit0", "cancel_exit3"} {
		t.Run(mode, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			s := newPhasedServer(t, nil, nil, mode, cancel)
			_, _, exit, err := s.client.RunPhased(ctx, "127.0.0.1", "tester", s.port, phasedWire, nil, func() error { return nil })
			want := 0
			if mode == "cancel_exit3" {
				want = 3
			}
			if ctx.Err() == nil || err != nil || exit != want {
				t.Fatalf("known exit lost: %d %v (context %v)", exit, err, ctx.Err())
			}
		})
	}
}

func TestRunPhasedPreDispatchFailures(t *testing.T) {
	key, _ := generateClientKey(t)
	c := &sshpkg.Client{KeyPath: key, KnownHostsPath: filepath.Join(t.TempDir(), "known_hosts"), Timeout: time.Second}
	c.KeyPath = filepath.Join(t.TempDir(), "missing")
	_, _, _, err := c.RunPhased(context.Background(), "127.0.0.1", "tester", 1, phasedWire, nil, func() error { return nil })
	checkPhasedError(t, err, "failed_not_started", "pre_dial", "key load failed")
	c.KeyPath = key
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	_ = listener.Close()
	_, _, _, err = c.RunPhased(context.Background(), "127.0.0.1", "tester", port, phasedWire, nil, func() error { return nil })
	checkPhasedError(t, err, "failed_not_started", "dial", "dial failed")
	s := newPhasedServer(t, nil, nil, "ok", nil)
	// A malformed pin fails in the real host-key callback during handshake.
	if err := os.WriteFile(s.client.KnownHostsPath, []byte("invalid pin\n"), 0600); err != nil {
		t.Fatal(err)
	}
	_, _, _, err = s.client.RunPhased(context.Background(), "127.0.0.1", "tester", s.port, phasedWire, nil, func() error { return nil })
	checkPhasedError(t, err, "failed_not_started", "handshake", "handshake failed")
}

func FuzzRunPhasedMissingGuard(f *testing.F) {
	f.Add([]byte("touch /unique-command"))
	f.Add([]byte{0, 255, 10})
	f.Fuzz(func(t *testing.T, command []byte) {
		c := &sshpkg.Client{}
		_, _, _, err := c.RunPhased(context.Background(), "", "", 0, "SSHGATE_SIG:c2lnbmF0dXJl:cGF5bG9hZA== "+string(command), nil, nil)
		checkPhasedError(t, err, "failed_not_started", "pre_dial", "missing pre-start guard")
	})
}

func TestRunPhasedExecutionOutlivesDialTimeout(t *testing.T) {
	key, pub := generateClientKey(t)
	srv := newTestServer(t, pub, func(string) ([]byte, []byte, int) {
		time.Sleep(1200 * time.Millisecond)
		return []byte("completed"), nil, 0
	})
	defer srv.stop()
	c := &sshpkg.Client{KeyPath: key, KnownHostsPath: filepath.Join(t.TempDir(), "known_hosts"), Timeout: time.Second}
	out, _, _, err := c.RunPhased(context.Background(), srv.host, "tester", srv.port, "read", nil, nil)
	if err != nil || string(out) != "completed" {
		t.Fatalf("execution deadline: %q %v", out, err)
	}
}

func FuzzRunPhasedExecRejection(f *testing.F) {
	f.Add([]byte("touch /unique-command"))
	f.Add([]byte{0, 255, 10})
	f.Fuzz(func(t *testing.T, command []byte) {
		s := newPhasedServer(t, nil, nil, "reject", nil)
		cmd := "SSHGATE_SIG:c2lnbmF0dXJl:cGF5bG9hZA== " + string(command)
		_, _, _, err := s.client.RunPhased(context.Background(), "127.0.0.1", "tester", s.port, cmd, nil, func() error { return nil })
		checkPhasedError(t, err, "failed_not_started", "start", "exec request rejected")
		if s.execs.Load() != 1 {
			t.Fatal("rejection was not exercised")
		}
	})
}
