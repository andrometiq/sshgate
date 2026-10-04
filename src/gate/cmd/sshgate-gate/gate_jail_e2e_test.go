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
// In ONE invocation, a classifier-approved read that writes (`sed --i`) must
// leave the file unchanged, the read of that file must arrive redacted, and the
// command's processes must carry the worker's NNP + seccomp (and, on rung 1, run
// under the binary's own pid-1 shim).
func TestGateBinaryJailedRead(t *testing.T) {
	rung := liveRung(t)

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

	cmd := "sed --i 's/orig/pwned/' " + target + " ; cat " + target +
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
	if rung == confine.Rung1Full {
		for _, role := range []string{"worker", "shim"} {
			match := regexp.MustCompile(`(?m)^` + role + ` NSpid:\s+(\d+)$`).FindStringSubmatch(out)
			if len(match) != 2 {
				unexpected(t, "invalid %s PID namespace identity: %q", role, out)
			}
		}
	}
	if rung == confine.Rung1Full && !strings.Contains(out, "/proc/self/exe\x00"+confine.SentinelShim+"\x00") {
		unexpected(t, "command parent is not the gate binary's %s shim: %q", confine.SentinelShim, out)
	}

	recs := auditRecords(t, dir)
	if len(recs) != 1 || recs[0]["classification"] != "read" || recs[0]["approval_status"] != "unsigned" || recs[0]["rung"] != rung.String() {
		unexpected(t, "audit = %v, want one unsigned read at rung %s", recs, rung)
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
			if err := gate.Run(); err != nil || stdout.String() != "socket=ok\nconnect=ok\n" {
				unexpected(t, "jailed connect: %v, stdout=%q stderr=%q; want a connected socket and exit 0", err, stdout.String(), stderr.String())
			}
			if err := tcpListener.SetDeadline(time.Now().Add(time.Second)); err != nil {
				unexpected(t, "%v", err)
				t.FailNow()
			}
			connection, err = listener.Accept()
			if err != nil {
				unexpected(t, "accept jailed connection: %v; reads keep network access", err)
				t.FailNow()
			}
			connection.Close()
		})
	}
}
