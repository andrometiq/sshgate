//go:build linux

package executor

import (
	"bufio"
	"context"
	"errors"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/karthikeyan5/sshgate/internal/elapsed/elapsedtest"
	"github.com/karthikeyan5/sshgate/internal/securestate"
	st "github.com/karthikeyan5/sshgate/src/approvalplan/statetest"
	"github.com/karthikeyan5/sshgate/src/executorwire"
	"github.com/karthikeyan5/sshgate/src/mcp/registry"
)

func TestUncertainProcess(t *testing.T) {
	mode := os.Getenv("EXECUTOR_TEST_UNCERTAIN")
	if mode == "" {
		return
	}
	local, err := OpenLocal(os.Getenv("EXECUTOR_TEST_RUNTIME"), os.Getenv("EXECUTOR_TEST_CONFIG"))
	if err != nil {
		t.Fatal(err)
	}
	store, err := local.OpenJobStore()
	if err != nil {
		t.Fatal(err)
	}
	servers, err := registry.New(os.Getenv("EXECUTOR_TEST_REGISTRY"))
	if err != nil {
		t.Fatal(err)
	}
	service, err := NewService(Config{Store: store, Servers: servers, Clock: elapsedtest.NewFake(st.T0)})
	if err != nil {
		t.Fatal(err)
	}
	store.update = func(fn func(*securestate.Transaction) error) error {
		if mode == "landed" {
			if err := store.disk.Update(fn); err != nil {
				return err
			}
		}
		return securestate.ErrCommitUncertain
	}
	if err := service.Serve(context.Background(), local); errors.Is(err, securestate.ErrCommitUncertain) {
		os.Exit(23)
	}
	os.Exit(0)
}

func TestUncertainExitAndRestart(t *testing.T) {
	for _, mode := range []string{"landed", "not-landed"} {
		t.Run(mode, func(t *testing.T) {
			_, _, _, registryPath := submitService(t)
			runtime, config := roots(t)
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestUncertainProcess$", "-test.timeout=30m")
			cmd.Env = append(os.Environ(), "EXECUTOR_TEST_UNCERTAIN="+mode, "EXECUTOR_TEST_RUNTIME="+runtime, "EXECUTOR_TEST_CONFIG="+config, "EXECUTOR_TEST_REGISTRY="+registryPath)
			if err := cmd.Start(); err != nil {
				t.Fatal(err)
			}
			defer func() {
				if cmd.ProcessState == nil {
					cmd.Process.Kill()
					cmd.Wait()
				}
			}()
			socket := filepath.Join(runtime, "sshgate", "executor.sock")
			var conn net.Conn
			for {
				var err error
				conn, err = net.DialTimeout("unix", socket, 100*time.Millisecond)
				if err == nil {
					break
				}
				select {
				case <-ctx.Done():
					t.Fatal("socket did not start")
				case <-time.After(10 * time.Millisecond):
				}
			}
			conn.SetDeadline(time.Now().Add(5 * time.Second))
			frame, _ := executorwire.MarshalRequest(submitRequest(t, 1))
			if _, err := conn.Write(frame); err != nil {
				t.Fatal(err)
			}
			response, err := bufio.NewReader(conn).ReadBytes('\n')
			conn.Close()
			if err == nil || len(response) != 0 {
				t.Fatal("uncertain commit produced an answer")
			}
			err = cmd.Wait()
			var exit *exec.ExitError
			if !errors.As(err, &exit) || exit.ExitCode() != 23 {
				t.Fatalf("uncertain owner did not exit nonzero: %v", err)
			}
			local := openLocal(t, runtime, config)
			store, err := local.OpenJobStore()
			if err != nil {
				t.Fatal(err)
			}
			defer store.Close()
			servers, err := registry.New(registryPath)
			if err != nil {
				t.Fatal(err)
			}
			service, err := NewService(Config{Store: store, Servers: servers})
			if err != nil {
				t.Fatal(err)
			}
			got, err := readWire(t, service, executorwire.GetRequest{ProtoVersion: 1, Kind: executorwire.KindGet, RequestID: st.ID(1)}, executorwire.KindGet)
			if mode == "landed" {
				if err != nil || got.Job.ExecutionStatus != "submitted" {
					t.Fatal(got, err)
				}
			} else {
				requireCode(t, err, "not_found")
			}
		})
	}
}

func TestServeStopClosesIdleAndAwaitConnections(t *testing.T) {
	s, store, _, _ := submitService(t)
	if _, err := s.Submit(submitRequest(t, 1)); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- s.Serve(ctx, store.local) }()
	socket := store.local.listener.Addr().String()
	idle, err := net.Dial("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	defer idle.Close()
	await, err := net.Dial("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	defer await.Close()
	frame, _ := executorwire.MarshalRequest(executorwire.AwaitRequest{ProtoVersion: 1, Kind: executorwire.KindAwait, RequestIDs: []string{st.ID(1)}, WaitSeconds: 55})
	if _, err := await.Write(frame); err != nil {
		t.Fatal(err)
	}
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("shutdown did not join connections")
	}
	if store.commits != 1 {
		t.Fatal("shutdown wrote a job")
	}
}
