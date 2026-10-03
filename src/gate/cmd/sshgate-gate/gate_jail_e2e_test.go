//go:build linux && jail_e2e

package main

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

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
		t.Fatalf("build gate: %v\n%s", err, out)
	}
	target := filepath.Join(dir, "target")
	const content = "orig AKIA1234567890ABCDEF\n"
	if err := os.WriteFile(target, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}

	cmd := "sed --i 's/orig/pwned/' " + target + " ; cat " + target +
		" ; grep -E '^(NoNewPrivs|Seccomp):' /proc/self/status ; awk 'FNR == 1 { n++ } n <= 2 && $1 == \"PPid:\" { ARGV[ARGC++] = \"/proc/\" $2 \"/status\"; if (n == 2) ARGV[ARGC++] = \"/proc/\" $2 \"/cmdline\" } n == 2 && $1 == \"NSpid:\" { print \"worker\", $0 } n == 3 && $1 == \"NSpid:\" { print \"shim\", $0 } n == 4 { print }' /proc/self/status ; echo done"
	if k := classify.Classify(cmd); k != classify.KindRead {
		t.Fatalf("precondition: the command must classify as a read, got %v", k)
	}

	gate := exec.Command(bin) // no argv: the forced-command shape
	gate.Env = append(os.Environ(), "SSH_ORIGINAL_COMMAND="+cmd)
	var stdout, stderr bytes.Buffer
	gate.Stdout, gate.Stderr = &stdout, &stderr
	if err := gate.Run(); err != nil {
		t.Fatalf("gate: %v (stdout=%q stderr=%q)", err, stdout.String(), stderr.String())
	}
	out := stdout.String()

	if b, _ := os.ReadFile(target); string(b) != content {
		t.Errorf("the jailed in-place edit changed the file: %q", b)
	}
	if !strings.Contains(stderr.String(), "sed") {
		t.Errorf("sed's write failure is missing from stderr: %q", stderr.String())
	}
	if !strings.Contains(out, "orig "+redact.MarkerPrefix) || strings.Contains(out, "AKIA1234567890ABCDEF") {
		t.Errorf("read output = %q; want the unchanged file with the secret redacted", out)
	}
	if !strings.Contains(out, "NoNewPrivs:\t1") || !strings.Contains(out, "Seccomp:\t2") {
		t.Errorf("the command did not run under the worker's NNP + seccomp filter: %q", out)
	}
	// Host /proc reports host PIDs; walk from awk to its shell to the shim.
	if rung == confine.Rung1Full {
		for _, role := range []string{"worker", "shim"} {
			match := regexp.MustCompile(`(?m)^` + role + ` NSpid:\s+(\d+)\s+(\d+)$`).FindStringSubmatch(out)
			if len(match) != 3 || match[1] == match[2] || (role == "shim" && match[2] != "1") {
				t.Errorf("invalid %s PID namespace identity: %q", role, out)
			}
		}
	}
	if rung == confine.Rung1Full && !strings.Contains(out, "/proc/self/exe\x00"+confine.SentinelShim+"\x00") {
		t.Errorf("pid 1 of the command's pid namespace is not the gate binary's %s shim: %q", confine.SentinelShim, out)
	}

	recs := auditRecords(t, dir)
	if len(recs) != 1 || recs[0]["classification"] != "read" || recs[0]["approval_status"] != "unsigned" || recs[0]["rung"] != rung.String() {
		t.Errorf("audit = %v, want one unsigned read at rung %s", recs, rung)
	}
}
