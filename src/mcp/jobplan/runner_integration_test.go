package jobplan

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/karthikeyan5/sshgate/src/approvalplan"
	gatessh "github.com/karthikeyan5/sshgate/src/mcp/ssh"
	sshlib "golang.org/x/crypto/ssh"
)

type runnerServer struct {
	client *gatessh.Client
	port   int
	execs  atomic.Int32
}

// A real SSH peer; hooks move the fake clock at protocol boundaries.
func newRunnerServer(t *testing.T, handshake, session, exec func(), mode string) *runnerServer {
	t.Helper()
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := sshlib.NewSignerFromKey(key)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "key")
	if err = os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), 0600); err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	s := &runnerServer{client: &gatessh.Client{KeyPath: keyPath, KnownHostsPath: filepath.Join(dir, "known_hosts"), Timeout: 5 * time.Second}, port: listener.Addr().(*net.TCPAddr).Port}
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			tcp, err := listener.Accept()
			if err != nil {
				return
			}
			func() {
				defer tcp.Close()
				if handshake != nil {
					handshake()
				}
				cfg := &sshlib.ServerConfig{NoClientAuth: true}
				cfg.AddHostKey(signer)
				conn, channels, requests, err := sshlib.NewServerConn(tcp, cfg)
				if err != nil {
					return
				}
				defer conn.Close()
				go sshlib.DiscardRequests(requests)
				for incoming := range channels {
					if session != nil {
						session()
					}
					channel, requests, err := incoming.Accept()
					if err != nil {
						return
					}
					for request := range requests {
						if request.Type != "exec" {
							_ = request.Reply(false, nil)
							continue
						}
						s.execs.Add(1)
						if exec != nil {
							exec()
						}
						if mode == "reject" {
							_ = request.Reply(false, nil)
							_ = channel.Close()
							break
						}
						if mode == "start_io" {
							_ = conn.Close()
							return
						}
						_ = request.Reply(true, nil)
						if mode == "missing" {
							_ = channel.Close()
							break
						}
						if mode == "transport" {
							_ = conn.Close()
							return
						}
						status := uint32(0)
						if mode == "jail" {
							_, _ = io.WriteString(channel.Stderr(), "gate: read jail unavailable: jail probe failed\n")
							status = 77
						}
						if mode == "output" {
							chunk := strings.Repeat("x", 8192)
							for i := 0; i < 160; i++ {
								_, _ = io.WriteString(channel, chunk)
							}
							_, _ = channel.Stderr().Write([]byte{0xff, 0xfe})
						}
						_, _ = channel.SendRequest("exit-status", false, sshlib.Marshal(struct{ Status uint32 }{status}))
						_ = channel.Close()
						break
					}
				}
			}()
		}
	}()
	t.Cleanup(func() { _ = listener.Close(); <-done })
	return s
}
func connectRunner(r *Runner, s *runnerServer) {
	for i := range r.draft.CommandJob.Steps {
		step := &r.draft.CommandJob.Steps[i]
		step.Target.ResolvedHost = "127.0.0.1"
		step.Target.ResolvedPort = s.port
		step.RegistryEntryDigest = step.Target.Digest()
	}
	target := r.draft.CommandJob.Steps[0].Target
	r.registry = registryFunc(func(string) (approvalplan.RouteSnapshot, string, error) { return target, target.Digest(), nil })
}

func TestRunnerRealSSHGuardAndJournal(t *testing.T) {
	for _, boundary := range []string{"handshake", "session"} {
		for _, clockHalf := range []string{"wall", "elapsed", "unchanged", "unsigned"} {
			t.Run(boundary+"/"+clockHalf, func(t *testing.T) {
				var delayed func()
				ready := make(chan struct{})
				hook := func() { <-ready; delayed() }
				var handshake, session func()
				if boundary == "handshake" {
					handshake = hook
				} else {
					session = hook
				}
				var marked atomic.Bool
				var completed atomic.Bool
				s := newRunnerServer(t, handshake, session, func() {
					if !marked.Load() {
						t.Error("exec before journal marker")
					}
					completed.Store(true)
				}, "success")
				commands := []string{"touch /x", "touch /y"}
				if clockHalf == "unsigned" {
					commands[0] = "cat /x"
				}
				r, clock, dispatch := runnerFixture(t, commands, approvalplan.StopNever, s.client)
				connectRunner(r, s)
				delayed = func() {
					switch clockHalf {
					case "wall":
						clock.StepWall(59 * time.Second)
					case "elapsed":
						clock.Suspend(59 * time.Second)
						clock.StepWall(-59 * time.Second)
					case "unsigned":
						clock.StepWall(time.Hour)
					}
				}
				close(ready)
				j := &journal{beforeHook: func(int) error { marked.Store(true); return nil }, afterHook: func(_ int, result approvalplan.StepResult) error {
					if result.Status == approvalplan.StepSucceeded && !completed.Load() {
						t.Error("journal result before exec")
					}
					return nil
				}}
				got, err := r.Run(context.Background(), dispatch, j)
				if err != nil {
					t.Fatal(err)
				}
				want := []approvalplan.StepStatus{approvalplan.StepExpiredUnexecuted, approvalplan.StepNotRun}
				execs := int32(0)
				if clockHalf == "unchanged" {
					want = []approvalplan.StepStatus{approvalplan.StepSucceeded, approvalplan.StepSucceeded}
					execs = 2
				}
				if clockHalf == "unsigned" {
					want = []approvalplan.StepStatus{approvalplan.StepSucceeded, approvalplan.StepExpiredUnexecuted}
					execs = 1
				}
				assertRun(t, got, want)
				if s.execs.Load() != execs {
					t.Fatalf("execs %d want %d", s.execs.Load(), execs)
				}
			})
		}
	}
}

func TestRunnerRealSSHJailRoutes(t *testing.T) {
	for _, reveal := range []bool{false, true} {
		t.Run(fmt.Sprint(reveal), func(t *testing.T) {
			s := newRunnerServer(t, nil, nil, nil, "jail")
			r, _, dispatch := runnerFixture(t, []string{"cat /x", "touch /y"}, approvalplan.StopNever, s.client)
			if reveal {
				r.draft.CommandJob.Steps = r.draft.CommandJob.Steps[:1]
				step := &r.draft.CommandJob.Steps[0]
				step.Route = approvalplan.RouteSignedReveal
				step.SignatureTTLSeconds = 60
				r.lastSigned = 1
				r.held[1] = approvalplan.Acquire(approvalplan.Now{Wall: r.clock.Wall()}, r.clock.Wall().Add(time.Minute), time.Minute)
				dispatch = []Dispatch{{WireCommand: "SSHGATE_SIG:c2ln:cGF5bG9hZA cat /x"}}
			}
			connectRunner(r, s)
			got, err := r.Run(context.Background(), dispatch, nil)
			if err != nil {
				t.Fatal(err)
			}
			want := []approvalplan.StepStatus{approvalplan.StepFailedNotStarted, approvalplan.StepNotRun}
			if reveal {
				want = []approvalplan.StepStatus{approvalplan.StepFailed}
			}
			assertRun(t, got, want)
			if s.execs.Load() != 1 {
				t.Fatal("dispatch after jail refusal")
			}
		})
	}
}

func TestRunnerRealSSHErrorsCommandFree(t *testing.T) {
	for _, mode := range []string{"reject", "start_io", "missing", "transport"} {
		t.Run(mode, func(t *testing.T) {
			s := newRunnerServer(t, nil, nil, nil, mode)
			r, _, dispatch := runnerFixture(t, []string{"touch /unique-command"}, approvalplan.StopNever, s.client)
			connectRunner(r, s)
			got, err := r.Run(context.Background(), dispatch, nil)
			if err != nil {
				t.Fatal(err)
			}
			status := approvalplan.StepIndeterminate
			if mode == "reject" {
				status = approvalplan.StepFailedNotStarted
			}
			assertRun(t, got, []approvalplan.StepStatus{status})
			text := fmt.Sprintf("%+v", got)
			for _, secret := range []string{"SSHGATE_SIG:", "c2ln", "cGF5bG9hZA", "touch /unique-command"} {
				if strings.Contains(text, secret) {
					t.Fatal("wire command leaked into result")
				}
			}
		})
	}
}

func TestRunnerRealSSHBoundedCapture(t *testing.T) {
	s := newRunnerServer(t, nil, nil, nil, "output")
	r, _, dispatch := runnerFixture(t, []string{"touch /x"}, approvalplan.StopNever, s.client)
	connectRunner(r, s)
	r.budget = &captureBudget{remaining: approvalplan.MaxJobOutputBytes}
	r.draft.CommandJob.MaxOutputBytes = 1024
	got, err := r.Run(context.Background(), dispatch, nil)
	if err != nil {
		t.Fatal(err)
	}
	result := got.Steps[0].Result
	if len(result.Stdout) != 1024 || result.StdoutBytes != 160*8192 || !result.Truncated || result.StderrBytes != 2 || result.StdoutSHA256 != outputDigest(result.Stdout) {
		t.Fatalf("bounded output: %d/%d", len(result.Stdout), result.StdoutBytes)
	}
}
