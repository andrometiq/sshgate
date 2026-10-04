//go:build linux

package gate

import (
	"bufio"
	"context"
	"github.com/karthikeyan5/sshgate/src/gate/confine"
	"github.com/karthikeyan5/sshgate/src/redact/rules"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestExecWithRedactionConfineLifecycle(t *testing.T) {
	requireUserns(t)
	if os.Getenv("SSHGATE_TEST_EXEC_LIFECYCLE") != "1" {
		ctx, cancel := context.WithTimeout(context.Background(), 40*time.Second)
		defer cancel()
		command := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestExecWithRedactionConfineLifecycle$", "-test.v")
		command.Env = append(os.Environ(), "SSHGATE_TEST_EXEC_LIFECYCLE=1")
		output, err := command.CombinedOutput()
		if err != nil {
			t.Fatalf("executor fixture: %v\n%s", err, output)
		}
		return
	}
	for _, mode := range []string{"cancel", "stopped-shim", "dead-shim", "blocked-output"} {
		t.Run(mode, func(t *testing.T) {
			reader, writer, err := os.Pipe()
			if err != nil {
				t.Fatal(err)
			}
			defer reader.Close()
			defer writer.Close()
			original := os.Stdout
			os.Stdout = writer
			defer func() { os.Stdout = original }()
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			done := make(chan struct {
				result ExecResult
				err    error
			}, 1)
			go func() {
				spec := confine.Spec{Profile: confine.ProfileROv1, Net: true}
				command := "setsid sh -c 'echo CHILD=$$; sleep 20' & sh -c \"setsid sh -c 'echo CHILD=\\$\\$; sleep 20' &\"; echo SHIM=$PPID; sleep 20"
				if mode == "blocked-output" {
					command = strings.TrimSuffix(command, "sleep 20") + "while :; do printf 'xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx\\n'; done"
				}
				result, err := ExecWithRedaction(ctx, command, ExecOpts{Confine: &spec, CaptureLimit: 4096})
				done <- struct {
					result ExecResult
					err    error
				}{result, err}
			}()
			ready := make(chan []int, 1)
			go func() {
				scan := bufio.NewScanner(reader)
				var pids []int
				shim := 0
				for scan.Scan() {
					line := scan.Text()
					key, value, _ := strings.Cut(line, "=")
					pid, _ := strconv.Atoi(value)
					if key == "CHILD" {
						pids = append(pids, pid)
					}
					if key == "SHIM" {
						shim = pid
					}
					if len(pids) == 2 && shim > 0 {
						ready <- append(pids, shim)
						return
					}
				}
			}()
			var pids []int
			select {
			case pids = <-ready:
			case outcome := <-done:
				t.Fatalf("executor before readiness: %+v %v", outcome.result, outcome.err)
			case <-time.After(10 * time.Second):
				t.Fatal("executor readiness timeout")
			}
			started := time.Now()
			shim := pids[2]
			switch mode {
			case "blocked-output":
				time.Sleep(200 * time.Millisecond)
				cancel()
			case "cancel":
				cancel()
			case "stopped-shim":
				if err := syscall.Kill(shim, syscall.SIGSTOP); err != nil {
					t.Fatal(err)
				}
				cancel()
			case "dead-shim":
				if err := syscall.Kill(shim, syscall.SIGKILL); err != nil {
					t.Fatal(err)
				}
			}
			select {
			case outcome := <-done:
				if outcome.err != nil || outcome.result.ExitCode <= 0 {
					t.Errorf("execution evidence lost: %+v %v", outcome.result, outcome.err)
				}
				if mode == "dead-shim" && outcome.result.ExitCode != 128+int(syscall.SIGKILL) {
					t.Errorf("SIGKILL status lost: %+v", outcome.result)
				}
				if mode == "stopped-shim" && (outcome.result.ExitCode != 143 || !outcome.result.Cancelled) {
					t.Errorf("cancellation precedence lost: %+v", outcome.result)
				}
				if mode == "stopped-shim" && time.Since(started) < 450*time.Millisecond {
					t.Error("stopped shim bypassed the cancellation grace period")
				}
				if mode == "blocked-output" && (!outcome.result.Transport.Abandoned || outcome.result.Transport.DroppedBytes == 0 || !outcome.result.Cancelled) {
					t.Errorf("blocked output was not abandoned safely: %+v", outcome.result)
				}
				if time.Since(started) > 3*time.Second {
					t.Error("executor cleanup not prompt")
				}
				for _, pid := range pids {
					if err := syscall.Kill(pid, 0); err != syscall.ESRCH {
						_ = syscall.Kill(pid, syscall.SIGKILL)
						t.Errorf("descendant %d remains: %v", pid, err)
					}
				}
			case <-time.After(8 * time.Second):
				t.Fatal("executor blocked on orphan output")
			}
		})
	}
}

func TestExecWithRedactionConfinedOutputCounts(t *testing.T) {
	requireUserns(t)
	opts := ExecOpts{Confine: &confine.Spec{Profile: confine.ProfileROv1, Net: true}, CaptureLimit: 4096, Rules: rules.Combined()}
	result, err := ExecWithRedaction(context.Background(), "printf 'one\\ntwo\\nAKIA1234567890ABCDEF'; printf 'err-tail' >&2", opts)
	if err != nil || result.ExitCode != 0 || result.CleanupError != "" {
		t.Fatalf("normal confined read: %+v %v", result, err)
	}
	if !strings.HasPrefix(result.Stdout, "one\ntwo\n") || strings.Contains(result.Stdout, "AKIA1234567890ABCDEF") || len(result.Stdout) <= 8 || result.Stderr != "err-tail" || result.Lines != 2 || result.StdoutBytes != int64(len(result.Stdout)) || result.StderrBytes != 8 {
		t.Fatalf("confined output/counts: %+v", result)
	}
}
