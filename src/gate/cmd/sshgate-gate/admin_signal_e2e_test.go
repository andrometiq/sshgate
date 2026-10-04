//go:build linux

package main

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/karthikeyan5/sshgate/src/hostkey"
	"github.com/karthikeyan5/sshgate/src/xferwire"
)

// TestAdminVerbsDieOfSIGTERM runs the real gate binary on validly signed admin
// verbs that block (on the client's stdin, or on a source FIFO), and requires a
// SIGTERM to kill the process by that signal, as before the session-wide
// signal context existed.
func TestAdminVerbsDieOfSIGTERM(t *testing.T) {
	hosts, err := hostkey.LoadHostFingerprints()
	if err != nil || len(hosts) == 0 {
		t.Skipf("no OpenSSH host keys to bind a signed command to: %v", err)
	}
	dir := t.TempDir()
	binary := filepath.Join(dir, "gate")
	build := exec.Command("go", "build", "-o", binary, ".")
	build.Env = append(os.Environ(), "CGO_ENABLED=0")
	if output, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build gate: %v\n%s", err, output)
	}
	pub, priv := genKey(t)
	seedPub(t, dir, pub, 0o644)
	box, id := genXferKeys(t)
	seedXferKeyFiles(t, dir, box, id)
	start := func(t *testing.T, verb string) (*exec.Cmd, *os.File) {
		t.Helper()
		payload := freshPayload(verb)
		payload.Host = hosts[0]
		reader, writer, err := os.Pipe()
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { reader.Close(); writer.Close() })
		command := exec.Command(binary)
		command.Env = append(os.Environ(), "SSH_ORIGINAL_COMMAND="+signedLine(t, priv, payload))
		command.Stdin = reader
		var stderr strings.Builder
		command.Stderr = &stderr
		if err := command.Start(); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() {
			if command.ProcessState == nil {
				_ = command.Process.Kill()
				_ = command.Wait()
			}
			if t.Failed() {
				t.Logf("gate stderr: %s", stderr.String())
			}
		})
		return command, writer
	}
	// awaitStdinRead proves the verb is reading its stdin: the one byte offered
	// is consumed while the stream stays open.
	awaitStdinRead := func(t *testing.T, command *exec.Cmd, stdin *os.File) {
		t.Helper()
		if _, err := stdin.Write([]byte{0x7f}); err != nil {
			t.Fatal(err)
		}
		awaitBlocked(t, command, func() bool {
			pending, err := unix.IoctlGetInt(int(stdin.Fd()), unix.TIOCINQ)
			if err != nil {
				t.Fatal(err)
			}
			return pending == 0
		})
	}
	t.Run("update", func(t *testing.T) {
		command, stdin := start(t, updateVerbPrefix+strings.Repeat("ab", 32))
		awaitStdinRead(t, command, stdin)
		requireSIGTERMDeath(t, command)
	})
	t.Run("xfer-recv", func(t *testing.T) {
		verb, err := xferwire.EncodeRecv(id.Public(), testXferID, testSrcFP, testDestFP, "0600", filepath.Join(dir, "delivered"))
		if err != nil {
			t.Fatal(err)
		}
		command, stdin := start(t, verb)
		awaitStdinRead(t, command, stdin)
		requireSIGTERMDeath(t, command)
	})
	t.Run("xfer-send", func(t *testing.T) {
		source := filepath.Join(dir, "source.fifo")
		if err := unix.Mkfifo(source, 0o600); err != nil {
			t.Fatal(err)
		}
		verb, err := xferwire.EncodeSend(box.Public(), testXferID, testDestFP, source)
		if err != nil {
			t.Fatal(err)
		}
		command, _ := start(t, verb)
		// A non-blocking write open succeeds only once the gate is opening the
		// FIFO for reading; holding it open then keeps the gate reading the source.
		var fifo int
		awaitBlocked(t, command, func() bool {
			fifo, err = unix.Open(source, unix.O_WRONLY|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
			if errors.Is(err, unix.ENXIO) {
				return false
			}
			if err != nil {
				t.Fatal(err)
			}
			return true
		})
		defer unix.Close(fifo)
		requireSIGTERMDeath(t, command)
	})
}

func awaitBlocked(t *testing.T, command *exec.Cmd, ready func() bool) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for !ready() {
		if time.Now().After(deadline) {
			t.Fatal("gate did not reach the admin verb's blocking read")
		}
		if err := command.Process.Signal(syscall.Signal(0)); err != nil {
			t.Fatalf("gate exited before blocking: %v", err)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func requireSIGTERMDeath(t *testing.T, command *exec.Cmd) {
	t.Helper()
	if err := command.Process.Signal(syscall.SIGTERM); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- command.Wait() }()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		_ = command.Process.Kill()
		<-done
		t.Fatal("admin verb survived SIGTERM")
	}
	status, ok := command.ProcessState.Sys().(syscall.WaitStatus)
	if !ok || !status.Signaled() || status.Signal() != syscall.SIGTERM {
		t.Fatalf("gate ended %v, want death by SIGTERM", command.ProcessState)
	}
}
