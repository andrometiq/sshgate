//go:build linux

package confine

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"golang.org/x/sys/unix"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestSubreaperDetachedCleanup(t *testing.T) {
	if os.Getenv("SSHGATE_TEST_SUBREAPER") != "1" {
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		command := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestSubreaperDetachedCleanup$", "-test.v")
		command.Env = append(os.Environ(), "SSHGATE_TEST_SUBREAPER=1")
		output, err := command.CombinedOutput()
		if err != nil {
			t.Fatalf("subreaper subprocess: %v\n%s", err, output)
		}
		return
	}
	if err := EnableSubreaper(); err != nil {
		t.Fatal(err)
	}
	for _, mode := range []string{"normal", "cancel", "fallback", "cleanup-error"} {
		t.Run(mode, func(t *testing.T) {
			reader, writer, err := os.Pipe()
			if err != nil {
				t.Fatal(err)
			}
			defer reader.Close()
			command := exec.Command("/bin/sh", "-c", "setsid sh -c 'echo $$; sleep 20' & sh -c \"setsid sh -c 'echo \\$\\$; sleep 20' &\"; sleep 1")
			if mode == "cleanup-error" {
				command.Args[len(command.Args)-1] += "; exit 23"
			}
			command.Stdout = writer
			command.Stderr = writer
			if err := command.Start(); err != nil {
				writer.Close()
				t.Fatal(err)
			}
			writer.Close()
			scan := bufio.NewScanner(reader)
			var children []int
			for i := 0; i < 2; i++ {
				if !scan.Scan() {
					t.Fatal("no descendant readiness")
				}
				pid, err := strconv.Atoi(scan.Text())
				if err != nil {
					t.Fatal(err)
				}
				children = append(children, pid)
			}
			stopped := make(chan os.Signal, 1)
			if mode == "cancel" {
				stopped <- unix.SIGTERM
			}
			started := time.Now()
			var report bytes.Buffer
			cleanup := CleanupDescendants
			if mode == "fallback" {
				cleanup = func() error {
					return cleanupDescendants(func() (map[int]bool, error) { return childPIDsFromStat("/proc", os.Getpid()) }, 5*time.Second)
				}
			}
			if mode == "cleanup-error" {
				cleanup = func() error {
					if err := CleanupDescendants(); err != nil {
						return err
					}
					return errors.New("injected cleanup error")
				}
			}
			code := reapWithCleanup(command.Process.Pid, stopped, &report, cleanup)
			if mode == "cancel" && report.String() != "\nW{\"unavailable\":\"cancelled before worker reap\"}\n" {
				t.Fatalf("cancellation report %q", report.String())
			}
			if mode == "cleanup-error" && report.String() != "\nW{\"exit\":23}\n\nCinjected cleanup error\n" {
				t.Fatalf("cleanup report %q", report.String())
			}
			command.Process.Release()
			want := 0
			if mode == "cleanup-error" {
				want = 23
			}
			if mode == "cancel" {
				want = 143
			}
			if code != want {
				t.Errorf("status=%d want=%d", code, want)
			}
			if time.Since(started) > 3*time.Second {
				t.Fatal("cleanup blocked on orphan-held pipes")
			}
			for _, pid := range children {
				if err := unix.Kill(pid, 0); err != unix.ESRCH {
					_ = unix.Kill(pid, unix.SIGKILL)
					t.Error(fmt.Sprintf("descendant %d remains: %v", pid, err))
				}
			}
			if scan.Scan() {
				t.Fatal("unexpected descendant output", scan.Text())
			}
			if err := scan.Err(); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestCleanupInactiveSubreaper(t *testing.T) {
	if os.Getenv("SSHGATE_TEST_INACTIVE_SUBREAPER") != "1" {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		command := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestCleanupInactiveSubreaper$", "-test.v")
		command.Env = append(os.Environ(), "SSHGATE_TEST_INACTIVE_SUBREAPER=1")
		output, err := command.CombinedOutput()
		if err != nil {
			t.Fatalf("inactive fixture: %v %s", err, output)
		}
		return
	}
	if err := unix.Prctl(unix.PR_SET_CHILD_SUBREAPER, 0, 0, 0, 0); err != nil {
		t.Fatal(err)
	}
	command := exec.Command("sleep", "20")
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { command.Process.Kill(); command.Wait() }()
	if err := CleanupDescendants(); err != nil {
		t.Fatal(err)
	}
	if err := unix.Kill(command.Process.Pid, 0); err != nil {
		t.Fatalf("inactive cleanup touched unrelated child: %v", err)
	}
}

func TestStatParentPID(t *testing.T) {
	for _, test := range []struct {
		raw     string
		want    int
		invalid bool
	}{
		{"123 (simple) S 42 1 2", 42, false}, {"123 (comm with spaces) R 42 1", 42, false},
		{"123 (a ) ( nested )) S 42 1", 42, false}, {"123 (line\nbreak) S 42 1", 42, false}, {"1 (init) S 0 1", 0, false},
		{"123 comm S 42", 0, true}, {"123 (bad) S", 0, true}, {"123 (bad) S -1", 0, true}, {"123 (bad) S nope", 0, true},
	} {
		got, err := statParentPID(test.raw)
		if (err != nil) != test.invalid || got != test.want {
			t.Errorf("%q: %d, %v", test.raw, got, err)
		}
	}
}

func TestChildEnumerationFallback(t *testing.T) {
	root := t.TempDir()
	for _, test := range []struct{ pid, parent int }{{100, 42}, {101, 1}} {
		dir := filepath.Join(root, strconv.Itoa(test.pid))
		if err := os.Mkdir(dir, 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "stat"), []byte(fmt.Sprintf("%d (with (parentheses)) S %d 1", test.pid, test.parent)), 0600); err != nil {
			t.Fatal(err)
		}
	}
	children, err := childPIDsFrom(root, 42)
	if err != nil || len(children) != 1 || !children[100] {
		t.Fatalf("fallback: %v %v", children, err)
	}
	if err := os.WriteFile(filepath.Join(root, "101/stat"), []byte("corrupt"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := childPIDsFrom(root, 42); err == nil {
		t.Fatal("corrupt stat treated as no child")
	}
}

func TestCleanupEnumerationErrorDeadline(t *testing.T) {
	calls := 0
	started := time.Now()
	err := cleanupDescendants(func() (map[int]bool, error) { calls++; return nil, unix.EACCES }, 20*time.Millisecond)
	if !errors.Is(err, unix.EACCES) || calls < 2 || time.Since(started) < 20*time.Millisecond || !strings.Contains(err.Error(), "enumerate descendants") {
		t.Fatalf("enumeration failure: calls=%d error=%v", calls, err)
	}
}

func TestWorkerStatusPublishedBeforeCleanup(t *testing.T) {
	if os.Getenv("SSHGATE_TEST_WORKER_STATUS") != "1" {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		command := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestWorkerStatusPublishedBeforeCleanup$")
		command.Env = append(os.Environ(), "SSHGATE_TEST_WORKER_STATUS=1")
		if output, err := command.CombinedOutput(); err != nil {
			t.Fatalf("worker status fixture: %v\n%s", err, output)
		}
		return
	}
	for _, script := range []string{"exit 139", "ulimit -c 0; kill -SEGV $$", "exit 23"} {
		command := exec.Command("/bin/sh", "-c", script)
		if err := command.Start(); err != nil {
			t.Fatal(err)
		}
		var report bytes.Buffer
		code := reapWithCleanup(command.Process.Pid, make(chan os.Signal), &report, func() error {
			_, status, _, err := splitStatusRecords("X" + report.String())
			if err != nil || !status.Known {
				t.Fatalf("worker status not available before cleanup: %q %v", report.String(), err)
			}
			if script == "ulimit -c 0; kill -SEGV $$" {
				if status.Exited || status.Signal != unix.SIGSEGV {
					t.Fatalf("lost signal: %+v", status)
				}
			} else if !status.Exited {
				t.Fatalf("exit reported as signal: %+v", status)
			}
			time.Sleep(20 * time.Millisecond)
			return nil
		})
		command.Process.Release()
		want := 139
		if script == "exit 23" {
			want = 23
		}
		if code != want {
			t.Fatalf("code %d want %d", code, want)
		}
	}
}

func TestWorkerStatusCancellationWaitsForReportOwner(t *testing.T) {
	var report bytes.Buffer
	terminated := make(chan os.Signal, 1)
	terminated <- unix.SIGTERM
	code := reapWithCleanup(0, terminated, &report, func() error {
		if report.Len() != 0 {
			t.Fatalf("shim wrote while worker owns status: %q", report.String())
		}
		// Model a worker finishing setup after cancellation but before cleanup stops it.
		return writeExecReport(&report, Facts{Profile: ProfileROv1, ABI: 1})
	})
	_, tail, _ := strings.Cut(report.String(), "\n")
	head, status, _, err := splitStatusRecords(tail)
	if code != 143 || err != nil || head != "X" || status.Unavailable != "cancelled before worker reap" {
		t.Fatalf("cancelled report=%q status=%+v code=%d err=%v", report.String(), status, code, err)
	}
}

func TestWorkerStatusCancellationFailedCleanupKeepsWorkerPipe(t *testing.T) {
	command := exec.Command("sleep", "30")
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { command.Process.Kill(); command.Wait() }()
	terminated := make(chan os.Signal, 1)
	terminated <- unix.SIGTERM
	var report bytes.Buffer
	code := reapWithCleanup(command.Process.Pid, terminated, &report, func() error { return errors.New("worker still alive") })
	if code != 143 || report.Len() != 0 {
		t.Fatalf("concurrent shim record: code=%d report=%q", code, report.String())
	}
}
