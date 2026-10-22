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

var memfdProbeOnce = sync.OnceValues(func() (map[string]string, error) {
	if cached := os.Getenv(memfdProbeEnv); cached != "" {
		answers := map[string]string{}
		for _, pair := range strings.Split(cached, ",") {
			abi, verdict, _ := strings.Cut(pair, "=")
			answers[abi] = verdict
		}
		return answers, nil
	}
	answers, err := runMemfdProbe(10 * time.Second)
	if err != nil {
		// Not cached: every process that builds the registry reports it.
		return answers, err
	}
	var pairs []string
	for _, abi := range []string{"native", "abi1"} {
		pairs = append(pairs, abi+"="+answers[abi])
	}
	_ = os.Setenv(memfdProbeEnv, strings.Join(pairs, ","))
	return answers, nil
})

// memfdExecBlocked reports, per ABI name, whether narrow Landlock EXECUTE alone
// stops a memfd exec here. A probe that fails answers "runs" and
// TestMutationRegistryJSON fails with its error, so the mutation harness
// refuses the run as an infrastructure failure rather than judge it.
func memfdExecBlocked(abi string) bool {
	answers, _ := memfdProbeOnce()
	return answers[abi] == "blocked"
}

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

// probeWith runs helper once per ABI name. "no-landlock" is an answer, not a
// failure: with no Landlock nothing blocks, so it is "runs". A failure, any
// other answer or the context's end (a hung helper is killed) is a probe
// failure answering "runs".
func probeWith(ctx context.Context, helper string) (map[string]string, error) {
	answers := map[string]string{"native": "runs", "abi1": "runs"}
	for _, abi := range []string{"native", "abi1"} {
		output, err := exec.CommandContext(ctx, helper, abi).Output()
		verdict := strings.TrimSpace(string(output))
		if err != nil || verdict != "blocked" && verdict != "runs" && verdict != "no-landlock" {
			return map[string]string{"native": "runs", "abi1": "runs"}, fmt.Errorf("memfd probe %s: %v: %q", abi, err, output)
		}
		answers[abi] = strings.Replace(verdict, "no-landlock", "runs", 1)
	}
	return answers, nil
}

// TestMemfdProbeBounded: the real helper builds and answers for both ABI names
// within its bound, and a host without Landlock answers "runs" without error;
// a probe starts exactly one child per ABI name; "no-landlock" maps to "runs";
// a helper that fails or hangs (killed at the bound) is reported as a failure.
func TestMemfdProbeBounded(t *testing.T) {
	start := time.Now()
	answers, err := runMemfdProbe(10 * time.Second)
	if err != nil || time.Since(start) > 10*time.Second {
		t.Fatalf("probe: %v after %s", err, time.Since(start))
	}
	if _, errno := probeLandlockABI(); errno != 0 && (answers["native"] != "runs" || answers["abi1"] != "runs") {
		t.Fatalf("no Landlock (%v), answers %v; want runs", errno, answers)
	}
	dir := t.TempDir()
	calls := filepath.Join(dir, "calls")
	scripts := map[string]string{
		"counting":    "#!/bin/sh\necho \"$1\" >> " + calls + "\necho blocked\n",
		"no-landlock": "#!/bin/sh\necho no-landlock\n",
		"failing":     "#!/bin/sh\necho 'error: memfd_create: permission denied'\nexit 1\n",
		"hanging":     "#!/bin/sh\nexec sleep 30\n",
	}
	for name, script := range scripts {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(script), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	answers, err = probeWith(context.Background(), filepath.Join(dir, "counting"))
	recorded, _ := os.ReadFile(calls)
	if err != nil || string(recorded) != "native\nabi1\n" || answers["native"] != "blocked" || answers["abi1"] != "blocked" {
		t.Fatalf("children %q, answers %v, %v", recorded, answers, err)
	}
	if answers, err = probeWith(context.Background(), filepath.Join(dir, "no-landlock")); err != nil || answers["native"] != "runs" || answers["abi1"] != "runs" {
		t.Fatalf("no-landlock helper: answers %v, %v", answers, err)
	}
	if answers, err = probeWith(context.Background(), filepath.Join(dir, "failing")); err == nil || answers["native"] != "runs" {
		t.Fatalf("failing helper: answers %v, %v", answers, err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	start = time.Now()
	answers, err = probeWith(ctx, filepath.Join(dir, "hanging"))
	if err == nil || time.Since(start) > 5*time.Second || answers["native"] != "runs" {
		t.Fatalf("hung helper: answers %v, %v after %s", answers, err, time.Since(start))
	}
}

// TestMemfdProbeNativeABI: "native" handles only the rights the kernel's ABI
// supports. A genuine ABI 1 kernel (stood in for by MEMFDPROBE_NATIVE_ABI=1,
// since REFER on a real ABI 1 kernel fails the ruleset with EINVAL) gets the
// ABI 1 rights through the native path; a newer kernel's native run adds
// REFER; forcing abi1 never does. Every run requests the fixture's memfd flags.
func TestMemfdProbeNativeABI(t *testing.T) {
	helper := filepath.Join(t.TempDir(), "memfdprobe")
	build := exec.Command("go", "build", "-o", helper, "./testdata/memfdprobe")
	build.Env = append(os.Environ(), "CGO_ENABLED=0")
	if output, err := build.CombinedOutput(); err != nil {
		t.Fatalf("SETUP: build the memfd probe: %v: %s", err, output)
	}
	run := func(abi, fake string) (verdict, report string) {
		t.Helper()
		cmd := exec.Command(helper, abi)
		if fake != "" {
			cmd.Env = append(os.Environ(), "MEMFDPROBE_NATIVE_ABI="+fake)
		}
		var stderr strings.Builder
		cmd.Stderr = &stderr
		out, err := cmd.Output()
		if err != nil {
			t.Fatalf("%s (native ABI %q): %v: %s %s", abi, fake, err, out, stderr.String())
		}
		return strings.TrimSpace(string(out)), strings.TrimSpace(stderr.String())
	}
	hostABI, errno := probeLandlockABI()
	if errno != 0 {
		// No Landlock: nothing to mask, and the answer is explicit.
		if verdict, _ := run("native", ""); verdict != "no-landlock" {
			t.Fatalf("no Landlock (%v): native answered %q, want no-landlock", errno, verdict)
		}
		return
	}
	const abi1Rights, refer = "handled=0xd", "handled=0x200d"
	for _, row := range []struct{ abi, fake, want string }{
		{"native", "1", "abi=1 " + abi1Rights},
		{"abi1", "", fmt.Sprintf("abi=%d %s", hostABI, abi1Rights)},
		{"native", "", fmt.Sprintf("abi=%d %s", hostABI, map[bool]string{true: refer, false: abi1Rights}[hostABI >= 2])},
	} {
		verdict, report := run(row.abi, row.fake)
		if verdict != "blocked" && verdict != "runs" || report != row.want+" flags=0x11" {
			t.Errorf("%s (native ABI %q): %q, %q; want a verdict and %q", row.abi, row.fake, verdict, report, row.want+" flags=0x11")
		}
	}
}
