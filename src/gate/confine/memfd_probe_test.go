//go:build linux

package confine

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// memfdProbeEnv carries the probe's answer from the first test process to every
// child it starts (re-exec'd tests, the jail's shim and worker), so only that
// process builds and runs the helper.
const memfdProbeEnv = "SSHGATE_TEST_MEMFD_PROBE"

var memfdProbeOnce = sync.OnceValue(func() map[string]string {
	if cached := os.Getenv(memfdProbeEnv); cached != "" {
		answers := map[string]string{}
		for _, pair := range strings.Split(cached, ",") {
			abi, verdict, _ := strings.Cut(pair, "=")
			answers[abi] = verdict
		}
		return answers
	}
	answers, _ := runMemfdProbe(10 * time.Second)
	var pairs []string
	for _, abi := range []string{"native", "abi1"} {
		pairs = append(pairs, abi+"="+answers[abi])
	}
	_ = os.Setenv(memfdProbeEnv, strings.Join(pairs, ","))
	return answers
})

// memfdExecBlocked reports, per ABI name, whether narrow Landlock EXECUTE alone
// stops a memfd exec here. A probe that fails answers "runs": a jail lane then
// expects the memfd effect, and its control fails rather than mis-judges.
func memfdExecBlocked(abi string) bool { return memfdProbeOnce()[abi] == "blocked" }

// runMemfdProbe builds the helper (static, CGO_ENABLED=0) and runs it once per
// ABI name; the whole probe is bounded by limit.
func runMemfdProbe(limit time.Duration) (map[string]string, error) {
	dir, err := os.MkdirTemp("", "memfdprobe-")
	if err != nil {
		return map[string]string{"native": "runs", "abi1": "runs"}, err
	}
	defer os.RemoveAll(dir)
	binary := filepath.Join(dir, "memfdprobe")
	ctx, cancel := context.WithTimeout(context.Background(), limit)
	defer cancel()
	build := exec.CommandContext(ctx, "go", "build", "-o", binary, "./testdata/memfdprobe")
	build.Env = append(os.Environ(), "CGO_ENABLED=0")
	if output, err := build.CombinedOutput(); err != nil {
		return map[string]string{"native": "runs", "abi1": "runs"}, fmt.Errorf("build the memfd probe: %v: %s", err, output)
	}
	return probeWith(ctx, binary)
}

// probeWith runs helper once per ABI name; a failure, a bad answer or the
// context's end (a hung helper is killed) is a probe failure answering "runs".
func probeWith(ctx context.Context, helper string) (map[string]string, error) {
	answers := map[string]string{"native": "runs", "abi1": "runs"}
	for _, abi := range []string{"native", "abi1"} {
		output, err := exec.CommandContext(ctx, helper, abi).Output()
		verdict := strings.TrimSpace(string(output))
		if err != nil || verdict != "blocked" && verdict != "runs" {
			return map[string]string{"native": "runs", "abi1": "runs"}, fmt.Errorf("memfd probe %s: %v: %q", abi, err, output)
		}
		answers[abi] = verdict
	}
	return answers, nil
}

// TestMemfdProbeBounded: the real helper builds and answers for both ABI names
// within its bound; a probe starts exactly one child per ABI name; a helper
// that hangs is killed at the bound and reported as a failure.
func TestMemfdProbeBounded(t *testing.T) {
	start := time.Now()
	if _, err := runMemfdProbe(10 * time.Second); err != nil || time.Since(start) > 10*time.Second {
		t.Fatalf("probe: %v after %s", err, time.Since(start))
	}
	dir := t.TempDir()
	calls := filepath.Join(dir, "calls")
	counting, hanging := filepath.Join(dir, "counting"), filepath.Join(dir, "hanging")
	for path, script := range map[string]string{
		counting: "#!/bin/sh\necho \"$1\" >> " + calls + "\necho blocked\n",
		hanging:  "#!/bin/sh\nexec sleep 30\n",
	} {
		if err := os.WriteFile(path, []byte(script), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	answers, err := probeWith(context.Background(), counting)
	recorded, _ := os.ReadFile(calls)
	if err != nil || string(recorded) != "native\nabi1\n" || answers["native"] != "blocked" || answers["abi1"] != "blocked" {
		t.Fatalf("children %q, answers %v, %v", recorded, answers, err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	start = time.Now()
	answers, err = probeWith(ctx, hanging)
	if err == nil || time.Since(start) > 5*time.Second || answers["native"] != "runs" {
		t.Fatalf("hung helper: answers %v, %v after %s", answers, err, time.Since(start))
	}
}
