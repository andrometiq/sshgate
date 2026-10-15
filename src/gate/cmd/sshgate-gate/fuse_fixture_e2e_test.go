//go:build linux && jail_e2e

package main

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/karthikeyan5/sshgate/src/gate/confine/jailmut/harness"
	"golang.org/x/sys/unix"
)

// A port of confine's FUSE fixture (cover_fixture_e2e_test.go) for the gate's
// legs: a FUSE mount needs CAP_SYS_ADMIN over a mount namespace, so a FUSE leg
// re-runs itself in a fresh user and mount namespace and forwards the child's
// one proof line.

const gateFuseNamespaceEnv = "SSHGATE_GATE_FUSE_NAMESPACE"

// gateFuseTools are the FUSE server and the probe, the probe planted as `cat`
// so a jailed gate read can run it.
type gateFuseTools struct{ server, bin string }

// gateFuseNamespace returns tools when it runs inside the leg's namespace.
// Outside it, it re-runs the leg there (or omits it when this host has no
// FUSE) and returns nil.
func gateFuseNamespace(t *testing.T, name string) *gateFuseTools {
	t.Helper()
	if os.Getenv(gateFuseNamespaceEnv) == t.Name() {
		if err := unix.Mount("", "/", "", unix.MS_REC|unix.MS_PRIVATE, ""); err != nil {
			t.Fatalf("SETUP: private mounts: %v", err)
		}
		return &gateFuseTools{server: os.Getenv("SSHGATE_GATE_FUSE_SERVER"), bin: os.Getenv("SSHGATE_GATE_FUSE_BIN")}
	}
	for _, check := range []func() error{
		func() error { _, err := os.Stat("/dev/fuse"); return err },
		func() error { _, err := exec.LookPath("fusermount3"); return err },
	} {
		if err := check(); err != nil {
			if os.Getenv("SSHGATE_JAIL_CI") == "1" {
				t.Fatalf("SETUP: FUSE unavailable: %v", err)
			}
			newProof(t, name).Omit("fuse-unavailable")
			return nil
		}
	}
	tools := t.TempDir()
	if err := os.Chmod(tools, 0o755); err != nil {
		t.Fatal(err)
	}
	bin := filepath.Join(tools, "bin")
	server := filepath.Join(tools, "fuseioctl")
	for _, item := range []struct{ output, source string }{{filepath.Join(bin, "cat"), "../../confine/testdata/probe"}, {server, "../../confine/testdata/fuseioctl"}} {
		build := exec.Command("go", "build", "-o", item.output, item.source)
		build.Env = append(os.Environ(), "CGO_ENABLED=0")
		if out, err := build.CombinedOutput(); err != nil {
			t.Fatalf("SETUP: helper build: %v\n%s", err, out)
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	run := "^" + strings.ReplaceAll(regexp.QuoteMeta(t.Name()), "/", "$/^") + "$"
	child := exec.CommandContext(ctx, os.Args[0], "-test.run="+run, "-test.v", "-test.count=1")
	child.Env = append(os.Environ(), gateFuseNamespaceEnv+"="+t.Name(), "SSHGATE_GATE_FUSE_SERVER="+server, "SSHGATE_GATE_FUSE_BIN="+bin)
	uid, gid := os.Getuid(), os.Getgid()
	child.SysProcAttr = &syscall.SysProcAttr{Cloneflags: unix.CLONE_NEWNS, Pdeathsig: syscall.SIGKILL}
	if uid != 0 {
		child.SysProcAttr = &syscall.SysProcAttr{
			Cloneflags:  unix.CLONE_NEWUSER | unix.CLONE_NEWNS,
			UidMappings: []syscall.SysProcIDMap{{ContainerID: uid, HostID: uid, Size: 1}},
			GidMappings: []syscall.SysProcIDMap{{ContainerID: gid, HostID: gid, Size: 1}},
			AmbientCaps: []uintptr{unix.CAP_SYS_ADMIN, unix.CAP_SETPCAP},
			Pdeathsig:   syscall.SIGKILL,
		}
	}
	output, err := child.CombinedOutput()
	forwardGateProof(t, name, output, err)
	return nil
}

// forwardGateProof relays the child's one proof line after checking it
// against this leg's case.
func forwardGateProof(t *testing.T, name string, output []byte, childErr error) {
	t.Helper()
	if childErr != nil {
		t.Fatalf("SETUP: FUSE leg child: %v\n%s", childErr, output)
	}
	var lines []string
	for _, line := range strings.Split(string(output), "\n") {
		if index := strings.Index(line, "PROOF-"); index >= 0 {
			lines = append(lines, line[index:])
		}
	}
	index := slices.IndexFunc(gateProofCases(), func(c harness.Case) bool { return c.Name == name })
	if len(lines) != 1 || index < 0 {
		t.Fatalf("SETUP: FUSE leg child gave %d proofs\n%s", len(lines), output)
	}
	record, err := harness.ParseProof(lines[0])
	if err == nil && (record.Leg != name || gateProofCases()[index].Names[record.ABI] != t.Name()) {
		err = fmt.Errorf("proof %s %s does not belong to %s", record.Leg, record.ABI, t.Name())
	}
	if err == nil {
		err = harness.CheckProof(gateProofCases()[index], record, os.Getuid() == 0, os.Getenv("SSHGATE_JAIL_CI") == "1")
	}
	if err != nil {
		t.Fatalf("SETUP: FUSE leg child proof: %v\n%s", err, output)
	}
	t.Log(lines[0])
}

// gateFuse is one running FUSE server and its request log.
type gateFuse struct {
	point, log string
	command    *exec.Cmd
	stderr     *lockedBuffer
	stopped    bool
}

type lockedBuffer struct {
	mu   sync.Mutex
	data bytes.Buffer
}

func (b *lockedBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.data.Write(p)
}
func (b *lockedBuffer) String() string { b.mu.Lock(); defer b.mu.Unlock(); return b.data.String() }

func startGateFuse(t *testing.T, server, point string) *gateFuse {
	t.Helper()
	if err := os.MkdirAll(point, 0o755); err != nil {
		t.Fatal(err)
	}
	f := &gateFuse{point: point, log: filepath.Join(t.TempDir(), "requests"), stderr: &lockedBuffer{}}
	f.command = exec.Command(server, "--mount", point, "--log", f.log)
	f.command.Stderr = f.stderr
	stdout, err := f.command.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := f.command.Start(); err != nil {
		t.Fatalf("SETUP: FUSE start: %v", err)
	}
	t.Cleanup(func() {
		if err := f.stop(); err != nil {
			t.Errorf("SETUP: FUSE stop: %v", err)
		}
	})
	ready := make(chan bool, 1)
	go func() {
		scanner := bufio.NewScanner(stdout)
		for scanner.Scan() {
			if strings.HasPrefix(scanner.Text(), "READY") {
				ready <- true
				return
			}
		}
		ready <- false
	}()
	select {
	case ok := <-ready:
		if !ok {
			t.Fatalf("SETUP: FUSE start: %s", f.stderr.String())
		}
	case <-time.After(10 * time.Second):
		t.Fatal("SETUP: FUSE readiness timeout")
	}
	return f
}

// mark is the log offset before an observation window.
func (f *gateFuse) mark(t *testing.T) int64 {
	t.Helper()
	state, err := os.Stat(f.log)
	if err != nil {
		t.Fatalf("SETUP: FUSE log: %v", err)
	}
	return state.Size()
}

// seal flushes every completed request through a barrier and returns the
// records logged since mark.
func (f *gateFuse) seal(t *testing.T, mark int64) []string {
	t.Helper()
	barrier := f.mark(t)
	if err := f.command.Process.Signal(syscall.SIGUSR1); err != nil {
		t.Fatalf("SETUP: FUSE barrier: %v: %s", err, f.stderr.String())
	}
	deadline := time.Now().Add(3 * time.Second)
	for {
		data, err := os.ReadFile(f.log)
		if err != nil || int64(len(data)) < barrier {
			t.Fatalf("SETUP: FUSE log: %v", err)
		}
		if index := strings.Index(string(data[barrier:]), "BARRIER\n"); index >= 0 {
			window := strings.ReplaceAll(string(data[mark:int(barrier)+index]), "BARRIER\n", "")
			return strings.Split(strings.TrimSuffix(window, "\n"), "\n")
		}
		if time.Now().After(deadline) || f.stderr.String() != "" {
			t.Fatalf("SETUP: inconclusive FUSE barrier: %s", f.stderr.String())
		}
		time.Sleep(time.Millisecond)
	}
}

// control shows the facility: an unjailed ioctl reaches the FUSE server.
func (f *gateFuse) control(t *testing.T, probe string) bool {
	t.Helper()
	mark := f.mark(t)
	out, err := exec.Command(probe, "fuse-ioctl", f.point+"/f", "0x40085301", "42").CombinedOutput()
	deadline := time.Now().Add(3 * time.Second)
	for !slices.Contains(f.seal(t, mark), "RELEASE") && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	return err == nil && strings.Contains(string(out), "ioctl=ok") && slices.Contains(f.seal(t, mark), "IOCTL 42")
}

func (f *gateFuse) stop() error {
	if f.stopped {
		return nil
	}
	f.stopped = true
	err := f.command.Process.Signal(syscall.SIGTERM)
	done := make(chan error, 1)
	go func() { done <- f.command.Wait() }()
	select {
	case waitErr := <-done:
		err = errors.Join(err, waitErr)
	case <-time.After(3 * time.Second):
		_ = f.command.Process.Kill()
		err = errors.Join(err, <-done, errors.New("FUSE shutdown timeout"))
	}
	if text := f.stderr.String(); text != "" {
		err = errors.Join(err, fmt.Errorf("FUSE stderr: %s", text))
	}
	data, readErr := os.ReadFile(f.log)
	if readErr != nil || !strings.HasSuffix(string(data), "VERDICT ok\n") {
		err = errors.Join(err, readErr, fmt.Errorf("FUSE missing clean final verdict"))
	}
	return err
}
