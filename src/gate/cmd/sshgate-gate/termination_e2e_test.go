//go:build linux

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"github.com/karthikeyan5/sshgate/src/gate"
	"github.com/karthikeyan5/sshgate/src/gate/confine"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestTerminationBinaryDestinations(t *testing.T) {
	dir := t.TempDir()
	binary := filepath.Join(dir, "gate")
	build := exec.Command("go", "build", "-o", binary, ".")
	build.Env = append(os.Environ(), "CGO_ENABLED=0")
	if output, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build gate: %v\n%s", err, output)
	}
	auditPath := filepath.Join(dir, "audit.log")
	newCommand := func() *exec.Cmd {
		t.Helper()
		_ = os.Remove(auditPath)
		command := exec.Command(binary)
		command.Env = append(os.Environ(), "SSH_ORIGINAL_COMMAND=rm /must-not-run")
		return command
	}
	record := func(t *testing.T) map[string]any {
		t.Helper()
		contents, err := os.ReadFile(auditPath)
		if err != nil {
			t.Fatal(err)
		}
		var result map[string]any
		if err := json.Unmarshal(bytes.TrimSpace(contents), &result); err != nil {
			t.Fatal(err)
		}
		if result["exit_code"] != float64(77) || result["approval_status"] != "denied" {
			t.Fatalf("denial changed: %#v", result)
		}
		return result
	}
	t.Run("closed-stderr-diagnostic", func(t *testing.T) {
		reader, writer, err := os.Pipe()
		if err != nil {
			t.Fatal(err)
		}
		reader.Close()
		defer writer.Close()
		command := newCommand()
		command.Stderr = writer
		if err := command.Start(); err != nil {
			t.Fatal(err)
		}
		terminationWait(t, command, 77)
		result := record(t)
		if result["delivery_error"] != "stderr:EPIPE" || result["dropped_bytes"].(float64) <= 0 {
			t.Fatalf("lost closed-reader metadata: %#v", result)
		}
	})
	t.Run("full-fifo-cancellation", func(t *testing.T) {
		fifo := filepath.Join(dir, "stderr.fifo")
		if err := unix.Mkfifo(fifo, 0600); err != nil {
			t.Fatal(err)
		}
		readFD, err := unix.Open(fifo, unix.O_RDONLY|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
		if err != nil {
			t.Fatal(err)
		}
		defer unix.Close(readFD)
		writeFD, err := unix.Open(fifo, unix.O_WRONLY|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
		if err != nil {
			t.Fatal(err)
		}
		writer := os.NewFile(uintptr(writeFD), fifo)
		defer writer.Close()
		for {
			_, err = unix.Write(writeFD, make([]byte, 4096))
			if errors.Is(err, unix.EAGAIN) {
				break
			}
			if err != nil {
				t.Fatal(err)
			}
		}
		if err := unix.SetNonblock(writeFD, false); err != nil {
			t.Fatal(err)
		}
		command := newCommand()
		command.Stderr = writer
		if err := command.Start(); err != nil {
			t.Fatal(err)
		}
		terminationAwaitSignalHandler(t, command)
		if err := command.Process.Signal(syscall.SIGTERM); err != nil {
			t.Fatal(err)
		}
		terminationWait(t, command, 77)
		result := record(t)
		if result["abandoned"] != true || result["dropped_bytes"].(float64) <= 0 {
			t.Fatalf("lost cancellation metadata: %#v", result)
		}
	})
	t.Run("regular-file-destination", func(t *testing.T) {
		output, err := os.Create(filepath.Join(dir, "output"))
		if err != nil {
			t.Fatal(err)
		}
		defer output.Close()
		command := newCommand()
		command.Stdout, command.Stderr = output, output
		if err := command.Start(); err != nil {
			t.Fatal(err)
		}
		terminationWait(t, command, 77)
		if result := record(t); result["output_destination"] != "file" {
			t.Fatalf("missing file residual: %#v", result)
		}
	})
	t.Run("fifo-audit-refused", func(t *testing.T) {
		fifo := filepath.Join(dir, "audit.fifo")
		if err := unix.Mkfifo(fifo, 0600); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "audit-path"), []byte(fifo), 0600); err != nil {
			t.Fatal(err)
		}
		command := newCommand()
		if err := command.Start(); err != nil {
			t.Fatal(err)
		}
		terminationWait(t, command, 77)
		if _, err := os.Stat(auditPath); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("unexpected audit: %v", err)
		}
	})
}

func terminationWait(t *testing.T, command *exec.Cmd, exit int) {
	t.Helper()
	done := make(chan error, 1)
	go func() { done <- command.Wait() }()
	select {
	case err := <-done:
		if command.ProcessState.ExitCode() != exit {
			t.Fatalf("gate exit = %v (%v), want %d", command.ProcessState, err, exit)
		}
	case <-time.After(5 * time.Second):
		_ = command.Process.Kill()
		<-done
		t.Fatal("gate did not terminate within five seconds")
	}
}

func terminationAwaitSignalHandler(t *testing.T, command *exec.Cmd) {
	t.Helper()
	root := "/proc/" + strconv.Itoa(command.Process.Pid) + "/fd"
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		target, err := os.Readlink(root + "/2")
		if err != nil {
			t.Fatal(err)
		}
		descriptors, err := os.ReadDir(root)
		if err != nil {
			t.Fatal(err)
		}
		for _, descriptor := range descriptors {
			fd, err := strconv.Atoi(descriptor.Name())
			if err != nil || fd <= 2 {
				continue
			}
			destination, _ := os.Readlink(root + "/" + descriptor.Name())
			// The sink duplicates stderr after run has installed NotifyContext.
			if destination == target {
				return
			}
		}
		time.Sleep(time.Millisecond)
	}
	_ = command.Process.Kill()
	_ = command.Wait()
	t.Fatal("gate did not initialize its diagnostic sink")
}

func TestTerminationBinaryConfined(t *testing.T) {
	liveRung(t)
	dir := t.TempDir()
	binary := filepath.Join(dir, "gate")
	build := exec.Command("go", "build", "-o", binary, ".")
	build.Env = append(os.Environ(), "CGO_ENABLED=0")
	if output, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build gate: %v\n%s", err, output)
	}
	data := filepath.Join(dir, "data")
	if err := os.WriteFile(data, bytes.Repeat([]byte("ordinary output\n"), 100000), 0600); err != nil {
		t.Fatal(err)
	}
	t.Run("closed-stdout-mid-output", func(t *testing.T) {
		reader, writer, err := os.Pipe()
		if err != nil {
			t.Fatal(err)
		}
		defer reader.Close()
		defer writer.Close()
		command := exec.Command(binary)
		command.Env = append(os.Environ(), "SSH_ORIGINAL_COMMAND=cat "+data)
		command.Stdout = writer
		var stderr bytes.Buffer
		command.Stderr = &stderr
		if err := command.Start(); err != nil {
			t.Fatal(err)
		}
		_ = writer.Close()
		if _, err := io.ReadFull(reader, make([]byte, 128)); err != nil {
			_ = command.Process.Kill()
			_ = command.Wait()
			t.Fatalf("no command output: %v; stderr=%s", err, &stderr)
		}
		_ = reader.Close()
		terminationWait(t, command, 0)
		records := auditRecords(t, dir)
		if len(records) != 1 || records[0]["delivery_error"] != "stdout:EPIPE" || records[0]["dropped_bytes"].(float64) <= 0 {
			t.Fatalf("closed stdout audit: %#v; stderr=%s", records, &stderr)
		}
	})
	t.Run("full-stderr-cancellation", func(t *testing.T) {
		_ = os.Remove(filepath.Join(dir, "audit.log"))
		reader, writer, err := os.Pipe()
		if err != nil {
			t.Fatal(err)
		}
		defer reader.Close()
		defer writer.Close()
		command := exec.Command(binary)
		command.Env = append(os.Environ(), "SSH_ORIGINAL_COMMAND=cat "+data+" >&2")
		command.Stderr = writer
		if err := command.Start(); err != nil {
			t.Fatal(err)
		}
		_ = writer.Close()

		capacity, err := unix.FcntlInt(reader.Fd(), unix.F_GETPIPE_SZ, 0)
		if err != nil {
			t.Fatal(err)
		}
		deadline := time.Now().Add(5 * time.Second)
		for {
			pending, err := unix.IoctlGetInt(int(reader.Fd()), unix.TIOCINQ)
			if err != nil {
				t.Fatal(err)
			}
			if pending == capacity {
				break
			}
			if time.Now().After(deadline) {
				_ = command.Process.Kill()
				_ = command.Wait()
				t.Fatal("worker did not fill stderr")
			}
			time.Sleep(time.Millisecond)
		}
		// The reader remains open and unread until the gate has fully exited.
		if err := command.Process.Signal(syscall.SIGTERM); err != nil {
			t.Fatal(err)
		}
		done := make(chan error, 1)
		go func() { done <- command.Wait() }()
		select {
		case <-done:
		case <-time.After(8 * time.Second):
			_ = command.Process.Kill()
			<-done
			t.Fatal("gate stalled on command stderr")
		}
		records := auditRecords(t, dir)
		if len(records) != 1 || records[0]["abandoned"] != true || records[0]["dropped_bytes"].(float64) <= 0 || records[0]["exit_code"] != float64(command.ProcessState.ExitCode()) {
			t.Fatalf("cancelled audit: %#v; process=%v", records, command.ProcessState)
		}
	})
}

func TestTerminationDefaultSIGPIPE(t *testing.T) {
	for _, confined := range []bool{false, true} {
		t.Run(strconv.FormatBool(confined), func(t *testing.T) {
			plan := execPlan{}
			if confined {
				liveRung(t)
				plan.confine = &confine.Spec{Profile: confine.ProfileROv1}
			}
			var rc int
			var stdout string
			stderr := captureStderr(t, func() { stdout = captureStdout(t, func() { rc, _, _ = execChild("yes | head -n 1", false, 0, plan) }) })
			if rc != 0 || stdout != "y\n" || stderr != "" {
				t.Fatalf("pipeline exit=%d stdout=%q stderr=%q", rc, stdout, stderr)
			}
		})
	}
}

func TestTerminationErrorHelper(t *testing.T) {
	mode := os.Getenv("SSHGATE_TERMINATION_TEST_ERROR")
	if mode == "" {
		return
	}
	dir := os.Getenv("SSHGATE_TERMINATION_TEST_DIR")
	withGateDir(t, dir)
	detectFn = func() confine.Report { return confine.Report{Rung: confine.Rung1Full} }
	executeCommand = func(context.Context, string, gate.ExecOpts) (gate.ExecResult, error) {
		result := gate.ExecResult{ExitCode: 23, Transport: gate.TransportMetadata{CleanupError: "fixture cleanup failure", SourceTruncated: "live-writer-after-cleanup-failure", SourceBytesRead: 42, WorkerStatus: confine.WorkerStatus{Unavailable: "fixture worker unavailable"}}}
		if mode == "setup" {
			result.ExitCode = -1
		}
		return result, errors.New("fixture execution error")
	}
	os.Exit(run())
}

func TestTerminationErrorAudit(t *testing.T) {
	for _, mode := range []string{"setup", "wait"} {
		t.Run(mode, func(t *testing.T) {
			dir := t.TempDir()
			reader, writer, err := os.Pipe()
			if err != nil {
				t.Fatal(err)
			}
			defer reader.Close()
			defer writer.Close()
			fd := int(writer.Fd())
			if err := unix.SetNonblock(fd, true); err != nil {
				t.Fatal(err)
			}
			for {
				_, err = unix.Write(fd, make([]byte, 4096))
				if errors.Is(err, unix.EAGAIN) {
					break
				}
				if err != nil {
					t.Fatal(err)
				}
			}
			if err := unix.SetNonblock(fd, false); err != nil {
				t.Fatal(err)
			}
			command := exec.Command(os.Args[0], "-test.run=^TestTerminationErrorHelper$")
			command.Env = append(os.Environ(), "SSHGATE_TERMINATION_TEST_ERROR="+mode, "SSHGATE_TERMINATION_TEST_DIR="+dir, "SSH_ORIGINAL_COMMAND=cat /etc/hostname")
			command.Stderr = writer
			if err := command.Start(); err != nil {
				t.Fatal(err)
			}
			terminationAwaitSignalHandler(t, command)
			if err := command.Process.Signal(syscall.SIGTERM); err != nil {
				t.Fatal(err)
			}
			want := 23
			approval := "unsigned"
			if mode == "setup" {
				want, approval = 77, "denied"
			}
			terminationWait(t, command, want)
			records := auditRecords(t, dir)
			if len(records) != 1 {
				t.Fatalf("audit records: %#v", records)
			}
			record := records[0]
			if record["exit_code"] != float64(want) || record["approval_status"] != approval || record["abandoned"] != true || record["dropped_bytes"].(float64) <= 0 || record["source_bytes_read"] != float64(42) || record["cleanup_error"] != "fixture cleanup failure" || record["source_truncated"] != "live-writer-after-cleanup-failure" {
				t.Fatalf("lost error transport: %#v", record)
			}
		})
	}
}
