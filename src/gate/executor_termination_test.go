//go:build linux

package gate

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/karthikeyan5/sshgate/src/gate/confine"
)

func TestExecutorTermination(t *testing.T) {
	if os.Getenv("SSHGATE_TERMINATION_FIXTURE") != "1" {
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		c := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestExecutorTermination$", "-test.v")
		c.Env = append(os.Environ(), "SSHGATE_TERMINATION_FIXTURE=1")
		if out, err := c.CombinedOutput(); err != nil {
			t.Fatalf("termination fixture: %v\n%s", err, out)
		}
		return
	}
	original := confinedCommand
	defer func() { confinedCommand = original }()
	confinedCommand = func(spec *confine.Spec, ctx context.Context, body string) (*confine.Jailed, error) {
		jailed, err := original(spec, ctx, body)
		if err != nil {
			return nil, err
		}
		jailed.Cmd.Path = "/bin/sh"
		jailed.Cmd.Args = []string{"sh", "-c", `cat <&3 >/dev/null; printf 'I{"profile":"ro-v1","abi":1,"net":false,"lane2":false}\nX' >&4; ` + body}
		jailed.Cmd.SysProcAttr = nil
		return jailed, nil
	}
	opts := ExecOpts{Confine: &confine.Spec{Profile: confine.ProfileROv1}, CaptureLimit: 200000}
	t.Run("failed-cleanup-idle-source", func(t *testing.T) {
		// A separate pipe writer simulates a descendant cleanup cannot terminate.
		oldCleanup := cleanupConfinedDescendants
		cleanupConfinedDescendants = func() error { return errors.New("injected surviving writer") }
		defer func() { cleanupConfinedDescendants = oldCleanup }()
		pidfile := filepath.Join(t.TempDir(), "pid")
		started := time.Now()
		result, err := ExecWithRedaction(context.Background(), fmt.Sprintf(`sleep 30 4>&- & echo $! > %q; printf '\nW{"exit":23}\n' >&4; exit 23`, pidfile), opts)
		data, readErr := os.ReadFile(pidfile)
		if readErr != nil {
			t.Fatal(readErr)
		}
		var pid int
		fmt.Sscanf(string(data), "%d", &pid)
		if pid <= 0 {
			t.Fatal("missing descendant")
		}
		defer func() {
			syscall.Kill(pid, syscall.SIGKILL)
			var status syscall.WaitStatus
			syscall.Wait4(pid, &status, 0, nil)
		}()
		if err != nil || result.ExitCode != 23 || result.Transport.SourceTruncated != "live-writer-after-cleanup-failure" || !strings.Contains(result.CleanupError, "injected surviving writer") || !result.Transport.WorkerStatus.Known {
			t.Fatalf("result=%+v err=%v", result, err)
		}
		if elapsed := time.Since(started); elapsed < 450*time.Millisecond || elapsed > 2*time.Second {
			t.Fatalf("source bound %s", elapsed)
		}
	})
	t.Run("completed-sources-open-status", func(t *testing.T) {
		oldCleanup := cleanupConfinedDescendants
		cleanupConfinedDescendants = func() error { return errors.New("injected cleanup failure") }
		defer func() { cleanupConfinedDescendants = oldCleanup }()
		pidfile := filepath.Join(t.TempDir(), "pid")
		result, err := ExecWithRedaction(context.Background(), fmt.Sprintf(`sleep 30 >/dev/null 2>/dev/null & echo $! > %q; printf '\nW{"exit":23}\n' >&4; exit 23`, pidfile), opts)
		data, readErr := os.ReadFile(pidfile)
		if readErr != nil {
			t.Fatal(readErr)
		}
		var pid int
		fmt.Sscanf(string(data), "%d", &pid)
		if pid <= 0 {
			t.Fatal("missing descendant")
		}
		defer func() {
			syscall.Kill(pid, syscall.SIGKILL)
			var status syscall.WaitStatus
			syscall.Wait4(pid, &status, 0, nil)
		}()
		if err != nil || result.ExitCode != 23 || result.Transport.SourceTruncated != "" || !strings.Contains(result.CleanupError, "status pipe remained open") {
			t.Fatalf("result=%+v error=%v", result, err)
		}
	})
	t.Run("worker-exit-before-escalation", func(t *testing.T) {
		ready := filepath.Join(t.TempDir(), "ready")
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		go func() {
			for {
				if _, err := os.Stat(ready); err == nil {
					cancel()
					return
				}
				select {
				case <-ctx.Done():
					return
				case <-time.After(time.Millisecond):
				}
			}
		}()
		result, err := ExecWithRedaction(ctx, fmt.Sprintf(`trap '' TERM; printf '\nW{"exit":23}\n' >&4; touch %q; while :; do sleep 1; done`, ready), opts)
		if err != nil || result.ExitCode != 23 || !result.Cancelled || result.Transport.WorkerStatus.Code != 23 || !strings.Contains(result.CleanupError, "shim killed") {
			t.Fatalf("result=%+v err=%v", result, err)
		}
	})
	t.Run("slow-client-complete", func(t *testing.T) {
		reader, writer, err := os.Pipe()
		if err != nil {
			t.Fatal(err)
		}
		saved := os.Stdout
		os.Stdout = writer
		defer func() { os.Stdout = saved; reader.Close(); writer.Close() }()
		output := make(chan []byte, 1)
		go func() {
			var data []byte
			for range 4 {
				time.Sleep(550 * time.Millisecond)
				chunk := make([]byte, 32768)
				n, err := io.ReadFull(reader, chunk)
				data = append(data, chunk[:n]...)
				if err != nil {
					break
				}
			}
			output <- data
		}()
		result, err := ExecWithRedaction(context.Background(), `head -c 131072 /dev/zero; printf '\nW{"exit":0}\n' >&4`, opts)
		writer.Close()
		data := <-output
		if err != nil || result.ExitCode != 0 || len(data) != 131072 || result.StdoutBytes != 131072 || len(result.Stdout) != 131072 || result.Transport.DroppedBytes != 0 || result.Transport.SourceTruncated != "" {
			t.Fatalf("bytes=%d result=%+v err=%v", len(data), result, err)
		}
	})
	t.Run("sigpipe-default", func(t *testing.T) {
		for _, confined := range []bool{false, true} {
			option := opts
			if !confined {
				option.Confine = nil
			}
			command := "yes | head -n 1"
			if confined {
				command += `; printf '\nW{"exit":0}\n' >&4`
			}
			result, err := ExecWithRedaction(context.Background(), command, option)
			if err != nil || result.ExitCode != 0 || result.Stdout != "y\n" || result.Stderr != "" {
				t.Fatalf("confined=%v result=%+v err=%v", confined, result, err)
			}
		}
	})
}
