//go:build linux && jail_e2e

package main

import (
	"bytes"
	"context"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/karthikeyan5/sshgate/src/classify"
	"github.com/karthikeyan5/sshgate/src/gate/confine"
	"github.com/karthikeyan5/sshgate/src/redact"
)

// TestGateBinaryJailedRead drives the REAL gate binary the way sshd does — a
// forced command with no argv and the client's command in SSH_ORIGINAL_COMMAND —
// on a Tier-1 install (no gate.pub). The other read-path tests call run() inside
// the test binary, whose TestMain stands in for main()'s sentinel dispatch; this
// one proves the shipped binary's own re-exec path puts the read in the jail.
// In ONE invocation, a classifier-approved read that writes (readNamedWriter) must
// leave the file unchanged, the read of that file must arrive redacted, and the
// command's processes must carry the worker's NNP + seccomp and run under the
// binary's own shim. An unpinned host gives reads no network.
func TestGateBinaryJailedRead(t *testing.T) {
	readNamedWriter(t)
	requireJail(t)

	dir := t.TempDir() // under the jail-visible TMPDIR set by TestMain
	bin := filepath.Join(dir, "gate")
	build := exec.Command("go", "build", "-trimpath", "-o", bin, ".")
	build.Env = append(os.Environ(), "CGO_ENABLED=0")
	if out, err := build.CombinedOutput(); err != nil {
		unexpected(t, "build gate: %v\n%s", err, out)
		t.FailNow()
	}
	target := filepath.Join(dir, "target")
	const content = "orig AKIA1234567890ABCDEF\n"
	if err := os.WriteFile(target, []byte(content), 0o644); err != nil {
		unexpected(t, "%v", err)
		t.FailNow()
	}

	cmd := "stat " + target + " pwned" + " ; cat " + target +
		" ; grep -E '^(NoNewPrivs|Seccomp):' /proc/self/status ; awk 'FNR == 1 { n++ } n <= 2 && $1 == \"PPid:\" { ARGV[ARGC++] = \"/proc/\" $2 \"/status\"; if (n == 2) ARGV[ARGC++] = \"/proc/\" $2 \"/cmdline\" } n == 2 && $1 == \"NSpid:\" { print \"worker\", $0 } n == 3 && $1 == \"NSpid:\" { print \"shim\", $0 } n == 4 { print }' /proc/self/status ; echo done"
	if k := classify.Classify(cmd); k != classify.KindRead {
		unexpected(t, "precondition: the command must classify as a read, got %v", k)
		t.FailNow()
	}

	gate := exec.Command(bin) // no argv: the forced-command shape
	gate.Env = append(os.Environ(), "SSH_ORIGINAL_COMMAND="+cmd)
	var stdout, stderr bytes.Buffer
	gate.Stdout, gate.Stderr = &stdout, &stderr
	if err := gate.Run(); err != nil {
		unexpected(t, "gate: %v (stdout=%q stderr=%q)", err, stdout.String(), stderr.String())
		t.FailNow()
	}
	out := stdout.String()

	if b, _ := os.ReadFile(target); string(b) != content {
		unexpected(t, "the jailed in-place edit changed the file: %q", b)
	}
	if !strings.Contains(stderr.String(), "sed") {
		unexpected(t, "sed's write failure is missing from stderr: %q", stderr.String())
	}
	if !strings.Contains(out, "orig "+redact.MarkerPrefix) || strings.Contains(out, "AKIA1234567890ABCDEF") {
		unexpected(t, "read output = %q; want the unchanged file with the secret redacted", out)
	}
	if !strings.Contains(out, "NoNewPrivs:\t1") || !strings.Contains(out, "Seccomp:\t2") {
		unexpected(t, "the command did not run under the worker's NNP + seccomp filter: %q", out)
	}
	// Host /proc reports host PIDs; walk from awk to its shell to the shim.
	for _, role := range []string{"worker", "shim"} {
		match := regexp.MustCompile(`(?m)^` + role + ` NSpid:\s+(\d+)$`).FindStringSubmatch(out)
		if len(match) != 2 {
			unexpected(t, "invalid %s PID namespace identity: %q", role, out)
		}
	}
	if !strings.Contains(out, "/proc/self/exe\x00"+confine.SentinelShim+"\x00") {
		unexpected(t, "command parent is not the gate binary's %s shim: %q", confine.SentinelShim, out)
	}

	recs := auditRecords(t, dir)
	if len(recs) != 1 || recs[0]["classification"] != "read" || recs[0]["approval_status"] != "unsigned" || recs[0]["enforcement"] != "kernel" || recs[0]["net"] != false {
		unexpected(t, "audit = %v, want one unsigned kernel read without network", recs)
	}

	// A test-owned cat on PATH lets the existing syscall probe exercise a
	// classifier-approved read through the production forced-command path.
	probe := filepath.Join(dir, "cat")
	build = exec.Command("go", "build", "-trimpath", "-o", probe, "../../confine/testdata/probe")
	build.Env = append(os.Environ(), "CGO_ENABLED=0")
	if out, err := build.CombinedOutput(); err != nil {
		unexpected(t, "build INET probe: %v\n%s", err, out)
		t.FailNow()
	}
	for _, network := range []string{"tcp4", "tcp6"} {
		t.Run(network, func(t *testing.T) {
			address, operation := "127.0.0.1:0", "dial-inet"
			if network == "tcp6" {
				address, operation = "[::1]:0", "dial-inet6"
			}
			listener, err := net.Listen(network, address)
			if err != nil {
				if network == "tcp6" {
					t.Skipf("IPv6 loopback unavailable: %v", err)
				}
				unexpected(t, "%v", err)
				t.FailNow()
			}
			defer listener.Close()
			tcpListener := listener.(*net.TCPListener)
			port := strconv.Itoa(tcpListener.Addr().(*net.TCPAddr).Port)
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			control, err := exec.CommandContext(ctx, probe, operation, port).CombinedOutput()
			if err != nil || string(control) != "socket=ok\nconnect=ok\n" {
				unexpected(t, "unjailed connect: %v, output=%q", err, control)
				t.FailNow()
			}
			if err := tcpListener.SetDeadline(time.Now().Add(time.Second)); err != nil {
				unexpected(t, "%v", err)
				t.FailNow()
			}
			connection, err := listener.Accept()
			if err != nil {
				unexpected(t, "accept unjailed control: %v", err)
				t.FailNow()
			}
			connection.Close()

			command := "cat " + operation + " " + port
			if kind := classify.Classify(command); kind != classify.KindRead {
				unexpected(t, "precondition: INET command classified %v", kind)
				t.FailNow()
			}
			gate := exec.CommandContext(ctx, bin)
			gate.Env = append(os.Environ(), "PATH="+dir+":"+os.Getenv("PATH"), "SSH_ORIGINAL_COMMAND="+command)
			var stdout, stderr bytes.Buffer
			gate.Stdout, gate.Stderr = &stdout, &stderr
			err = gate.Run()
			// An unpinned host gives reads no network: the jailed socket is
			// refused with EPERM and nothing connects.
			if exit, ok := err.(*exec.ExitError); !ok || exit.ExitCode() != 1 || stdout.String() != "socket=1\n" {
				unexpected(t, "jailed connect: %v, stdout=%q stderr=%q; want socket EPERM and exit 1", err, stdout.String(), stderr.String())
			}
			if err := tcpListener.SetDeadline(time.Now().Add(time.Second)); err != nil {
				unexpected(t, "%v", err)
				t.FailNow()
			}
			if connection, err := listener.Accept(); err == nil {
				connection.Close()
				unexpected(t, "a jailed read without network connected")
			}
		})
	}
}

// TestGateBinaryNetworkPin drives the real gate binary under each network pin:
// net=deny refuses the jailed read an INET socket, net=allow connects, and a
// network tool that fails without network gets the gate's hint.
func TestGateBinaryNetworkPin(t *testing.T) {
	requireJail(t)
	dir := t.TempDir()
	bin := filepath.Join(dir, "gate")
	tools := filepath.Join(dir, "tools")
	for _, item := range []struct{ output, source string }{{bin, "."}, {filepath.Join(tools, "cat"), "../../confine/testdata/probe"}, {filepath.Join(tools, "curl"), "../../confine/testdata/probe"}} {
		build := exec.Command("go", "build", "-trimpath", "-o", item.output, item.source)
		build.Env = append(os.Environ(), "CGO_ENABLED=0")
		if out, err := build.CombinedOutput(); err != nil {
			unexpected(t, "build %s: %v\n%s", item.source, err, out)
			t.FailNow()
		}
	}
	runGate := func(t *testing.T, command string) (int, string, string) {
		t.Helper()
		gate := exec.Command(bin)
		gate.Env = append(os.Environ(), "PATH="+tools+":"+os.Getenv("PATH"), "SSH_ORIGINAL_COMMAND="+command)
		var stdout, stderr bytes.Buffer
		gate.Stdout, gate.Stderr = &stdout, &stderr
		code := 0
		if err := gate.Run(); err != nil {
			code = -1
			if exit, ok := err.(*exec.ExitError); ok {
				code = exit.ExitCode()
			}
		}
		return code, stdout.String(), stderr.String()
	}
	for _, pin := range []string{pinDeny, pinAllow} {
		plantPin(t, dir, pin, 0o644)
		for _, network := range []string{"tcp4", "tcp6"} {
			t.Run(strings.TrimSpace(strings.Split(pin, "\n")[1])+"/"+network, func(t *testing.T) {
				address, operation := "127.0.0.1:0", "dial-inet"
				if network == "tcp6" {
					address, operation = "[::1]:0", "dial-inet6"
				}
				listener, err := net.Listen(network, address)
				if err != nil {
					if network == "tcp6" {
						t.Skipf("IPv6 loopback unavailable: %v", err)
					}
					unexpected(t, "%v", err)
					t.FailNow()
				}
				defer listener.Close()
				tcp := listener.(*net.TCPListener)
				port := strconv.Itoa(tcp.Addr().(*net.TCPAddr).Port)
				code, out, stderr := runGate(t, "cat "+operation+" "+port)
				_ = tcp.SetDeadline(time.Now().Add(time.Second))
				connection, acceptErr := listener.Accept()
				if acceptErr == nil {
					connection.Close()
				}
				if pin == pinAllow && (code != 0 || out != "socket=ok\nconnect=ok\n" || acceptErr != nil) {
					unexpected(t, "net=allow: exit %d, stdout %q, stderr %q, accept %v", code, out, stderr, acceptErr)
				}
				if pin == pinDeny && (code != 1 || out != "socket=1\n" || acceptErr == nil) {
					unexpected(t, "net=deny: exit %d, stdout %q, stderr %q, accept %v", code, out, stderr, acceptErr)
				}
			})
		}
	}
	plantPin(t, dir, pinDeny, 0o644)
	code, _, stderr := runGate(t, "curl dial-inet 1")
	if code != 1 || !strings.Contains(stderr, "gate: "+networkHintLine) {
		unexpected(t, "network hint: exit %d, stderr %q", code, stderr)
	}
}

// TestGateBinaryLane2: the real gate binary, with its production seams, runs a
// real daemon read in the read jail: the installed systemctl answers over its
// pinned socket, and the audit says it ran jailed without network. Anything
// else, including an unjailed fallback, fails.
func TestGateBinaryLane2(t *testing.T) {
	requireJail(t)
	dir := t.TempDir()
	bin := filepath.Join(dir, "gate")
	build := exec.Command("go", "build", "-trimpath", "-o", bin, ".")
	build.Env = append(os.Environ(), "CGO_ENABLED=0")
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build gate: %v\n%s", err, out)
	}
	gate := exec.Command(bin)
	gate.Env = append(os.Environ(), "SSH_ORIGINAL_COMMAND=systemctl show --property=Version")
	var stdout, stderr bytes.Buffer
	gate.Stdout, gate.Stderr = &stdout, &stderr
	if err := gate.Run(); err != nil || !strings.HasPrefix(stdout.String(), "Version=") {
		t.Fatalf("gate: %v (stdout=%q stderr=%q)", err, stdout.String(), stderr.String())
	}
	records := auditRecords(t, dir)
	if len(records) != 1 || records[0]["enforcement"] != "daemon-read" || records[0]["profile"] != "ro-v1" || records[0]["net"] != false {
		t.Fatalf("audit = %v, want one jailed daemon read without network", records)
	}
}
