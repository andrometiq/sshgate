//go:build linux

package main

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"testing"

	"github.com/karthikeyan5/sshgate/src/redact"
)

// buildLane2Fixtures builds the C daemon-read client (testdata/lane2client)
// with cc, installs it by copy as systemctl and docker in a 0755 directory, and
// points lane2BinDirs at that directory for the test. It returns the
// directory. The client's report carries random temp paths the production
// redactor would scrub as high-entropy, so the test compares output raw.
func buildLane2Fixtures(t *testing.T) string {
	t.Helper()
	cc, err := exec.LookPath("cc")
	if err != nil {
		t.Fatalf("SETUP: cc: %v", err)
	}
	client := filepath.Join(t.TempDir(), "lane2client")
	if output, err := exec.Command(cc, "-O2", "-Wall", "-Werror", "-o", client, "testdata/lane2client/main.c").CombinedOutput(); err != nil {
		t.Fatalf("SETUP: build the daemon-read client: %v\n%s", err, output)
	}
	data, err := os.ReadFile(client)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	for _, name := range []string{"systemctl", "docker"} {
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, data, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(path, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Chmod(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	previousDirs, previousRules := lane2BinDirs, redactRules
	lane2BinDirs, redactRules = []string{dir}, []redact.Rule{}
	t.Cleanup(func() { lane2BinDirs, redactRules = previousDirs, previousRules })
	return dir
}

// lane2Mode is a positional that selects the client's mode: sg-<mode>.<nonce>.
func lane2Mode(t *testing.T, mode string) string {
	t.Helper()
	nonce := make([]byte, 8)
	if _, err := rand.Read(nonce); err != nil {
		t.Fatal(err)
	}
	return "sg-" + mode + "." + hex.EncodeToString(nonce)
}

// lane2Reported reports whether output is the client's report line for the
// positional mode with every one of args in its argv.
func lane2Reported(output []byte, mode string, args ...string) bool {
	var report execReport
	if json.Unmarshal(output, &report) != nil || !slices.Contains(report.Args, mode) {
		return false
	}
	for _, arg := range args {
		if !slices.Contains(report.Args, arg) {
			return false
		}
	}
	return true
}
