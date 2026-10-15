//go:build linux

package main

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
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
	plugins := filepath.Join(dir, "plugins")
	if err := os.Mkdir(plugins, 0o755); err != nil {
		t.Fatal(err)
	}
	if output, err := exec.Command(cc, "-O2", "-Wall", "-Werror", "-o", filepath.Join(plugins, "sg-plugin"), "testdata/lane2client/sg-plugin.c").CombinedOutput(); err != nil {
		t.Fatalf("SETUP: build the plugin: %v\n%s", err, output)
	}
	for _, path := range []string{plugins, dir} {
		if err := os.Chmod(path, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	withLane2Seams(t, dir)
	previousRules := redactRules
	redactRules = []redact.Rule{}
	t.Cleanup(func() { redactRules = previousRules })
	return dir
}

// lane2Replacement builds, in dir, a client that only prints REPLACED-RAN
// <nonce>, for a leg to rename over an admitted object.
func lane2Replacement(t *testing.T, dir string) string {
	t.Helper()
	path := filepath.Join(dir, ".sg-replacement")
	if output, err := exec.Command("cc", "-O2", "-Wall", "-Werror", "-DSG_REPLACEMENT", "-o", path, "testdata/lane2client/main.c").CombinedOutput(); err != nil {
		t.Fatalf("SETUP: build the replacement: %v\n%s", err, output)
	}
	return path
}

// lane2FixtureFile writes the lines a client mode reads from its own
// directory: sockets, abstract or tcp.
func lane2FixtureFile(t *testing.T, dir, name string, lines ...string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, name), []byte(strings.Join(lines, "\n")+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
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

func withLane2Seams(t *testing.T, dir string) {
	t.Helper()
	previousDirs, previousUIDs, previousEndpoints := lane2BinDirs, lane2TrustedUIDs, lane2SystemEndpoints
	lane2BinDirs, lane2TrustedUIDs = []string{dir}, []uint32{0, uint32(os.Getuid())}
	// Unix socket paths are limited to 108 bytes; proof subtest names make
	// t.TempDir paths too long under the jail-visible test cache.
	socketDir, err := os.MkdirTemp("", "l2-sockets-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(socketDir) })
	if err := os.Chmod(socketDir, 0755); err != nil {
		t.Fatal(err)
	}
	listen := func(name string) string {
		path := filepath.Join(socketDir, name)
		listener, err := net.Listen("unix", path)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { listener.Close() })
		return path
	}
	lane2SystemEndpoints = lane2Endpoints{docker: listen("docker"), bus: listen("bus"), private: listen("private")}
	t.Cleanup(func() {
		lane2BinDirs, lane2TrustedUIDs, lane2SystemEndpoints = previousDirs, previousUIDs, previousEndpoints
	})
}
