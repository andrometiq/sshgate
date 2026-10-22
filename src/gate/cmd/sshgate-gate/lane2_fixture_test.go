//go:build linux

package main

import (
	"crypto/rand"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"fmt"
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
	dir := t.TempDir()
	if err := buildLane2FixtureFiles(dir); err != nil {
		t.Fatal(err)
	}
	withLane2Seams(t, dir)
	previousRules := redactRules
	redactRules = []redact.Rule{}
	t.Cleanup(func() { redactRules = previousRules })
	return dir
}

//go:embed testdata/lane2client/main.c
var lane2ClientSource string

//go:embed testdata/lane2client/sg-plugin.c
var lane2PluginSource string

// buildLane2FixtureFiles also serves the subprocess fixture sentinel.
func buildLane2FixtureFiles(dir string) error {
	cc, err := exec.LookPath("cc")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	client := filepath.Join(dir, "docker")
	command := exec.Command(cc, "-O2", "-Wall", "-Werror", "-x", "c", "-o", client, "-")
	command.Stdin = strings.NewReader(lane2ClientSource)
	if output, err := command.CombinedOutput(); err != nil {
		return fmt.Errorf("build daemon-read client: %w: %s", err, output)
	}
	data, err := os.ReadFile(client)
	if err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(dir, "systemctl"), data, 0o755); err != nil {
		return err
	}
	plugins := filepath.Join(dir, "plugins")
	if err := os.Mkdir(plugins, 0o755); err != nil {
		return err
	}
	command = exec.Command(cc, "-O2", "-Wall", "-Werror", "-x", "c", "-o", filepath.Join(plugins, "sg-plugin"), "-")
	command.Stdin = strings.NewReader(lane2PluginSource)
	if output, err := command.CombinedOutput(); err != nil {
		return fmt.Errorf("build plugin: %w: %s", err, output)
	}
	for _, path := range []string{dir, plugins, client, filepath.Join(dir, "systemctl"), filepath.Join(plugins, "sg-plugin")} {
		if err := os.Chmod(path, 0o755); err != nil {
			return err
		}
	}
	return nil
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
	applyLane2TestConfig(testLane2Config{BinDir: dir, TrustedUIDs: []uint32{0, uint32(os.Getuid())}, Endpoints: map[string]string{"docker": listen("docker"), "bus": listen("bus"), "private": listen("private")}})
	t.Cleanup(func() {
		lane2BinDirs, lane2TrustedUIDs, lane2SystemEndpoints = previousDirs, previousUIDs, previousEndpoints
	})
}

// TestLane2FixtureMemfdFlags: the fixture's memfd mode requests MFD_CLOEXEC|
// MFD_EXEC (0x11), the confine memfd probe's flags, also when built as with
// headers that lack MFD_EXEC, and either build runs its memfd copy unjailed.
func TestLane2FixtureMemfdFlags(t *testing.T) {
	dir := buildLane2Fixtures(t)
	oldHeaders := filepath.Join(dir, "old-headers")
	if output, err := exec.Command("cc", "-O2", "-Wall", "-Werror", "-DSG_UNDEF_MFD_EXEC", "-o", oldHeaders, "testdata/lane2client/main.c").CombinedOutput(); err != nil {
		t.Fatalf("SETUP: build without MFD_EXEC: %v\n%s", err, output)
	}
	for _, client := range []string{filepath.Join(dir, "systemctl"), oldHeaders} {
		if out, err := exec.Command(client, "status", "sg-memfd-flags.0").Output(); err != nil || string(out) != "memfd-flags:0x11\n" {
			t.Errorf("%s: %q, %v; want memfd-flags:0x11", client, out, err)
		}
		mode := lane2Mode(t, "memfd")
		if out, err := exec.Command(client, "status", mode).Output(); err != nil || string(out) != "PLUGIN-RAN "+strings.TrimPrefix(mode, "sg-memfd.")+"\n" {
			t.Errorf("%s memfd: %q, %v", client, out, err)
		}
	}
}
