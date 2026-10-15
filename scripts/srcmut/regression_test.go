package main

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestAmbientOverlayFalseDetection(t *testing.T) {
	for _, source := range []string{"ambient", "entry", "goenv"} {
		t.Run(source, func(t *testing.T) {
			root, err := moduleRoot()
			if err != nil {
				t.Fatal(err)
			}
			dir := t.TempDir()
			repair := filepath.Join(dir, "repair.go")
			writeRegressionFile(t, repair, []byte("package fixture\nfunc Guard() bool { return false }\n"))
			data, err := json.Marshal(struct{ Replace map[string]string }{map[string]string{
				filepath.Join(root, fixtureEntry().File): repair,
			}})
			if err != nil {
				t.Fatal(err)
			}
			overlay := filepath.Join(dir, "overlay.json")
			writeRegressionFile(t, overlay, data)
			e := fixtureEntry()
			e.File = "scripts/srcmut/testdata/dependency/guard.go"
			e.Red[0].Test = "TestAmbientOverlay"
			e.Green = nil
			if source == "ambient" {
				t.Setenv("GOFLAGS", "-overlay="+overlay)
			} else if source == "goenv" {
				config := filepath.Join(dir, "goenv")
				writeRegressionFile(t, config, []byte("GOFLAGS=-overlay="+overlay+"\n"))
				t.Setenv("GOENV", config)
				t.Setenv("GOFLAGS", "")
			} else {
				e.Env = map[string]string{"GOFLAGS": "-overlay=" + overlay}
			}
			r := testRunner(t)
			if err := r.check(e); err == nil || !strings.Contains(err.Error(), "baseline:") {
				t.Fatalf("unexercised mutation must fail baseline, never count as detected: %v", err)
			}
		})
	}
}

// Use only the small fixture inputs, with read-only access to the real HEAD.
func regressionFixtureRoot(t *testing.T, r *runner) string {
	t.Helper()
	root := t.TempDir()
	command := exec.Command("git", "rev-parse", "--absolute-git-dir")
	command.Dir = r.root
	gitDir, err := command.Output()
	if err != nil {
		t.Fatal(err)
	}
	writeRegressionFile(t, filepath.Join(root, ".git"), []byte("gitdir: "+strings.TrimSpace(string(gitDir))+"\n"))
	for _, name := range []string{"go.mod", "internal/srcmut/effect.go", "scripts/srcmut/testdata/dependency/guard.go", "scripts/srcmut/testdata/fixture/guard.go", "scripts/srcmut/testdata/fixture/guard_test.go"} {
		data, err := os.ReadFile(filepath.Join(r.root, name))
		if err != nil {
			t.Fatal(err)
		}
		writeRegressionFile(t, filepath.Join(root, name), data)
	}
	return root
}

func writeRegressionFile(t *testing.T, path string, data []byte) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
}

func TestHEADTarget(t *testing.T) {
	r := testRunner(t)
	originalRoot := r.root
	for _, kind := range []string{"clean", "dirty", "dirty-introduces-old", "untracked"} {
		t.Run(kind, func(t *testing.T) {
			r.root = originalRoot
			root := regressionFixtureRoot(t, r)
			r.root = root
			e := fixtureEntry()
			want := ""
			switch kind {
			case "dirty":
				writeRegressionFile(t, filepath.Join(root, e.File), []byte("package fixture\nfunc Guard() bool { return true } // dirty\n"))
				want = "differs from HEAD"
			case "dirty-introduces-old":
				writeRegressionFile(t, filepath.Join(root, e.File), []byte("package fixture\nfunc Guard() bool { return (true) }\n"))
				e.Old = "return (true)"
				want = "patch no longer applies"
			case "untracked":
				writeRegressionFile(t, filepath.Join(root, e.File), []byte("package fixture\n"))
				e.File = "scripts/srcmut/testdata/fixture/untracked.go"
				writeRegressionFile(t, filepath.Join(root, e.File), []byte("package fixture\nfunc Guard() bool { return true }\n"))
				want = "unavailable at HEAD"
			}
			err := r.check(e)
			if want == "" {
				if err != nil {
					t.Fatal(err)
				}
			} else if err == nil || !strings.Contains(err.Error(), want) {
				t.Fatalf("%s target: got %v, want %s", kind, err, want)
			}
		})
	}
}

func TestOrdinaryTimeoutCleanup(t *testing.T) {
	r := testRunner(t)
	r.timeout = 2 * time.Second
	e := fixtureEntry()
	e.Red[0].Test = "TestOrdinaryTimeout"
	e.Green = nil
	path := filepath.Join(t.TempDir(), "pids")
	e.Env = map[string]string{"DESCENDANT_PIDS": path}
	run := r.execute(e, "")
	if run.timedOut || !strings.Contains(string(run.stream), "panic: test timed out") || judge(e, run, false) == nil {
		t.Fatalf("wanted Go timeout before outer deadline: %+v", run)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	pids := strings.Fields(string(data))
	if len(pids) != 2 {
		t.Fatalf("missing process IDs: %q", data)
	}
	for _, value := range pids {
		pid, err := strconv.Atoi(value)
		if err != nil {
			t.Fatal(err)
		}
		// Clean up even when running with the protection deliberately reverted.
		t.Cleanup(func() { _ = syscall.Kill(pid, syscall.SIGKILL) })
		gone := false
		for i := 0; i < 200; i++ {
			if syscall.Kill(pid, 0) == syscall.ESRCH {
				gone = true
				break
			}
			time.Sleep(10 * time.Millisecond)
		}
		if !gone {
			t.Errorf("process %d survived Go timeout", pid)
		}
	}
}
