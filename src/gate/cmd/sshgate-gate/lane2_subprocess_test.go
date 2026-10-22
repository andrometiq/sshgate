//go:build linux

package main

import (
	"bufio"
	"encoding/json"
	"errors"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func lane2PSListener(t *testing.T) (string, <-chan string) {
	t.Helper()
	dir, err := os.MkdirTemp("/tmp", "sg-ps-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	path := filepath.Join(dir, "docker")
	listener, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { listener.Close() })
	lines := make(chan string, 16)
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
			scanner := bufio.NewScanner(conn)
			for scanner.Scan() {
				lines <- scanner.Text()
			}
			conn.Close()
		}
	}()
	return path, lines
}

func requireLane2PS(t *testing.T, lines <-chan string, nonce string) {
	t.Helper()
	select {
	case line := <-lines:
		if line != "SG-PS "+nonce {
			t.Fatalf("daemon received %q; want nonce %q", line, nonce)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("fixture did not reach the parent-owned daemon")
	}
}

func TestLane2ClientPsConnect(t *testing.T) {
	dir := buildLane2Fixtures(t)
	socket, lines := lane2PSListener(t)
	args := []string{"--host=unix://" + socket, "ps"}
	client := filepath.Join(dir, "docker")
	out, err := exec.Command(client, args...).CombinedOutput()
	if err == nil || string(out) != "SG-FIXTURE no mode\n" {
		t.Fatalf("without ps-connect: output=%q err=%v", out, err)
	}
	t.Cleanup(func() { os.Remove(filepath.Join(dir, "ps-connect")) })
	for _, suffix := range [][]string{nil, {"--all"}} {
		nonce := strings.TrimPrefix(lane2Mode(t, "ps"), "sg-ps.")
		lane2FixtureFile(t, dir, "ps-connect", nonce)
		out, err = exec.Command(client, append(args, suffix...)...).CombinedOutput()
		if err != nil || string(out) != "CONTAINER ID   IMAGE   COMMAND   CREATED   STATUS   PORTS   NAMES\n" {
			t.Fatalf("ps-connect: output=%q err=%v", out, err)
		}
		requireLane2PS(t, lines, nonce)
	}
}

func TestSubprocessLane2Fixtures(t *testing.T) {
	socket, lines := lane2PSListener(t)
	binary, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(t.TempDir(), "fixtures")
	sentinel := exec.Command(binary, sentinelLane2Fixtures, dir, socket)
	sentinel.Dir = t.TempDir()
	out, err := sentinel.CombinedOutput()
	if err != nil {
		t.Fatalf("fixture sentinel: %v\n%s", err, out)
	}
	var fixture testLane2Config
	if err := json.Unmarshal(out, &fixture); err != nil {
		t.Fatalf("fixture JSON: %v: %s", err, out)
	}
	if fixture.BinDir != dir || fixture.Endpoints["docker"] != socket {
		t.Fatalf("fixture config: %+v", fixture)
	}
	// Both controls exclude host clients from fixed-directory admission and PATH.
	isolationDir := t.TempDir()
	config := testGateConfig{Dir: t.TempDir(), Absent: true, Lane2: &fixture, Lane2IsolationDir: isolationDir}
	run := func() ([]byte, error) {
		raw, err := json.Marshal(config)
		if err != nil {
			t.Fatal(err)
		}
		command := exec.Command(binary)
		command.Env = []string{testGateEnv + "=" + string(raw), "SSH_ORIGINAL_COMMAND=docker ps", "PATH=" + isolationDir, "GORACE=atexit_sleep_ms=0"}
		return command.CombinedOutput()
	}
	nonce := strings.TrimPrefix(lane2Mode(t, "ps"), "sg-ps.")
	lane2FixtureFile(t, dir, "ps-connect", nonce)
	t.Cleanup(func() { os.Remove(filepath.Join(dir, "ps-connect")) })
	if out, err := run(); err != nil {
		t.Fatalf("unsigned control: %v\n%s", err, out)
	}
	requireLane2PS(t, lines, nonce)

	nonce = strings.TrimPrefix(lane2Mode(t, "ps"), "sg-ps.")
	lane2FixtureFile(t, dir, "ps-connect", nonce)
	config.Lane2 = nil
	out, err = run()
	select {
	case line := <-lines:
		t.Fatalf("without Lane2 reached fixture daemon: %q", line)
	case <-time.After(100 * time.Millisecond):
	}
	var exit *exec.ExitError
	if !errors.As(err, &exit) || exit.ExitCode() != 127 || (!strings.Contains(string(out), "docker:") || !strings.Contains(string(out), "not found")) {
		t.Fatalf("without Lane2 should find no client: %v\n%s", err, out)
	}
}
