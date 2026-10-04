//go:build linux

package gate

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/karthikeyan5/sshgate/src/gate/confine"
	"github.com/karthikeyan5/sshgate/src/redact/rules"
	"golang.org/x/sys/unix"
)

// The protocol fixture exercises executor ownership without requiring a jail.
func TestExecutorOutputDelivery(t *testing.T) {
	if os.Getenv("SSHGATE_TEST_OUTPUT_DELIVERY") != "1" {
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		c := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestExecutorOutputDelivery$", "-test.v")
		c.Env = append(os.Environ(), "SSHGATE_TEST_OUTPUT_DELIVERY=1")
		if out, err := c.CombinedOutput(); err != nil {
			t.Fatalf("output fixture: %v\n%s", err, out)
		}
		return
	}
	original := confinedCommand
	defer func() { confinedCommand = original }()
	confinedCommand = func(spec *confine.Spec, ctx context.Context, command string) (*confine.Jailed, error) {
		jailed, err := original(spec, ctx, command)
		if err != nil {
			return nil, err
		}
		jailed.Cmd.Path = "/bin/sh"
		jailed.Cmd.Args = []string{"sh", "-c", "cat <&3 >/dev/null; printf 'I{\"profile\":\"ro-v1\",\"abi\":1,\"net\":false,\"lane2\":false}\\nX' >&4; " + command}
		jailed.Cmd.SysProcAttr = nil
		return jailed, nil
	}
	t.Run("normal", func(t *testing.T) {
		opts := ExecOpts{Confine: &confine.Spec{Profile: confine.ProfileROv1}, CaptureLimit: 4096, Rules: rules.Combined()}
		result, err := ExecWithRedaction(context.Background(), "printf 'one\\ntwo\\nAKIA1234567890ABCDEF'; printf 'err-tail' >&2", opts)
		if err != nil || result.ExitCode != 0 || result.CleanupError != "" {
			t.Fatalf("normal: %+v %v", result, err)
		}
		if !strings.HasPrefix(result.Stdout, "one\ntwo\n") || strings.Contains(result.Stdout, "AKIA1234567890ABCDEF") || len(result.Stdout) <= 8 || result.Stderr != "err-tail" || result.Lines != 2 || result.StdoutBytes != int64(len(result.Stdout)) || result.StderrBytes != 8 {
			t.Fatalf("output/counts: %+v", result)
		}
	})
	for _, redacted := range []bool{false, true} {
		t.Run(fmt.Sprint("blocked-", redacted), func(t *testing.T) {
			reader, writer, err := os.Pipe()
			if err != nil {
				t.Fatal(err)
			}
			defer reader.Close()
			defer writer.Close()
			capacity, err := unix.FcntlInt(writer.Fd(), unix.F_GETPIPE_SZ, 0)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := writer.Write(make([]byte, capacity)); err != nil {
				t.Fatal(err)
			}
			saved := os.Stdout
			os.Stdout = writer
			defer func() { os.Stdout = saved }()
			pidfile := t.TempDir() + "/pid"
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			opts := ExecOpts{Confine: &confine.Spec{Profile: confine.ProfileROv1}, CaptureLimit: 4096}
			if redacted {
				opts.Rules = rules.Combined()
			}
			type outcome struct {
				result ExecResult
				err    error
			}
			done := make(chan outcome, 1)
			go func() {
				result, err := ExecWithRedaction(ctx, "setsid sleep 60 & child=$!; printf tail; echo $child > '"+pidfile+"'; wait", opts)
				done <- outcome{result, err}
			}()
			var pid int
			deadline := time.Now().Add(3 * time.Second)
			for pid == 0 && time.Now().Before(deadline) {
				data, _ := os.ReadFile(pidfile)
				pid, _ = strconv.Atoi(strings.TrimSpace(string(data)))
				if pid == 0 {
					time.Sleep(10 * time.Millisecond)
				}
			}
			if pid == 0 {
				t.Fatal("descendant not started")
			}
			pidfd, err := unix.PidfdOpen(pid, 0)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = unix.PidfdSendSignal(pidfd, unix.SIGKILL, nil, 0); _ = unix.Close(pidfd) }()
			started := time.Now()
			cancel()
			select {
			case got := <-done:
				if got.err != nil || got.result.ExitCode != 128+int(syscall.SIGTERM) || (!got.result.Transport.Abandoned || got.result.Transport.DroppedBytes != int64(4+len("gate-jail: cleanup: shim ended before worker status was published\n")) || got.result.CleanupError != "shim ended before worker status was published" || !got.result.Cancelled) || got.result.Stdout != "" || got.result.Stderr != "" {
					t.Fatalf("abandonment: %+v %v", got.result, got.err)
				}
				if elapsed := time.Since(started); elapsed < 450*time.Millisecond || elapsed > 2*time.Second {
					t.Fatalf("join bound: %s", elapsed)
				}
				if err := syscall.Kill(pid, 0); err != syscall.ESRCH {
					t.Fatalf("descendant survives: %v", err)
				}
			case <-time.After(3 * time.Second):
				t.Fatal("blocked output prevented cancellation")
			}
		})
	}
}
