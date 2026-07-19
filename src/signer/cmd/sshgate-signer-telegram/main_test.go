package main

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/karthikeyan5/sshgate/pkg/signerkit"
)

// ---------------------------------------------------------------------------
// loadConfig
// ---------------------------------------------------------------------------

const validConfig = `
[paths]
key       = "/x/gate.key"
pubkey    = "/x/gate.pub"
audit_log = "/x/approvals.log"
socket    = "/x/sock"

[backend]
type = "stub"
`

// writeTOML drops s into a temp file and returns its path.
func writeTOML(t *testing.T, s string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "config.toml")
	if err := os.WriteFile(p, []byte(s), 0o600); err != nil {
		t.Fatalf("write toml: %v", err)
	}
	return p
}

// TestLoadConfig_ValidAndEachMissingField checks the happy path plus each
// required-field-missing path produces a DISTINCT, field-naming error, so
// an operator with a half-filled config gets pointed at the exact key.
func TestLoadConfig_ValidAndEachMissingField(t *testing.T) {
	t.Parallel()

	// Happy path.
	cfg, err := loadConfig(writeTOML(t, validConfig))
	if err != nil {
		t.Fatalf("loadConfig(valid) = %v; want nil", err)
	}
	if cfg.Paths.Key != "/x/gate.key" || cfg.Backend.Type != "stub" {
		t.Errorf("loadConfig parsed wrong: %+v", cfg)
	}

	cases := []struct {
		name       string
		toml       string
		wantSubstr string
	}{
		{
			name: "missing key",
			toml: `
[paths]
audit_log = "/x/approvals.log"
socket    = "/x/sock"
[backend]
type = "stub"
`,
			wantSubstr: "paths.key",
		},
		{
			name: "missing audit_log",
			toml: `
[paths]
key    = "/x/gate.key"
socket = "/x/sock"
[backend]
type = "stub"
`,
			wantSubstr: "paths.audit_log",
		},
		{
			name: "missing socket",
			toml: `
[paths]
key       = "/x/gate.key"
audit_log = "/x/approvals.log"
[backend]
type = "stub"
`,
			wantSubstr: "paths.socket",
		},
		{
			name: "missing backend type",
			toml: `
[paths]
key       = "/x/gate.key"
audit_log = "/x/approvals.log"
socket    = "/x/sock"
`,
			wantSubstr: "backend.type",
		},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			_, err := loadConfig(writeTOML(t, tc.toml))
			if err == nil {
				t.Fatalf("loadConfig(%s) = nil error; want one naming %q", tc.name, tc.wantSubstr)
			}
			if !strings.Contains(err.Error(), tc.wantSubstr) {
				t.Errorf("loadConfig(%s) error = %q; want it to name %q", tc.name, err, tc.wantSubstr)
			}
		})
	}
}

// TestLoadConfig_CorruptAndMissing covers the two decode-level failures:
// a syntactically broken TOML and an absent file. Both must surface a
// "decode" error (wrapped from toml.DecodeFile) rather than the
// field-validation errors above.
func TestLoadConfig_CorruptAndMissing(t *testing.T) {
	t.Parallel()

	t.Run("corrupt toml", func(t *testing.T) {
		t.Parallel()
		p := writeTOML(t, "this is = not valid = toml [[[")
		_, err := loadConfig(p)
		if err == nil {
			t.Fatal("loadConfig(corrupt) = nil; want a decode error")
		}
		if !strings.Contains(err.Error(), "decode") {
			t.Errorf("error = %q; want a decode error", err)
		}
	})

	t.Run("missing file", func(t *testing.T) {
		t.Parallel()
		p := filepath.Join(t.TempDir(), "does-not-exist.toml")
		_, err := loadConfig(p)
		if err == nil {
			t.Fatal("loadConfig(missing) = nil; want a decode error")
		}
		if !strings.Contains(err.Error(), "decode") {
			t.Errorf("error = %q; want a decode error", err)
		}
	})
}

// ---------------------------------------------------------------------------
// buildBackend
// ---------------------------------------------------------------------------

// TestBuildBackend_StubAndUnknown asserts "stub" yields the StubBackend
// and any unrecognised type is rejected with "unknown backend type". The
// stub branch does no I/O, so this needs no key/socket on disk.
func TestBuildBackend_StubAndUnknown(t *testing.T) {
	t.Parallel()

	cfg, err := loadConfig(writeTOML(t, validConfig))
	if err != nil {
		t.Fatalf("loadConfig: %v", err)
	}
	bk, err := buildBackend(t.Context(), cfg.Backend, [32]byte{}, nil)
	if err != nil {
		t.Fatalf("buildBackend(stub) = %v; want nil", err)
	}
	if _, ok := bk.(signerkit.StubBackend); !ok {
		t.Errorf("buildBackend(stub) returned %T; want signerkit.StubBackend", bk)
	}

	cfg.Backend.Type = "nope-not-a-backend"
	_, err = buildBackend(t.Context(), cfg.Backend, [32]byte{}, nil)
	if err == nil {
		t.Fatal("buildBackend(unknown) = nil error; want rejection")
	}
	if !strings.Contains(err.Error(), "unknown backend type") {
		t.Errorf("error = %q; want %q", err, "unknown backend type")
	}
}

// ---------------------------------------------------------------------------
// buildHostedBackend / buildTelegramBackend / buildExplainer
//
// All three must fail validation (missing field OR empty key file) BEFORE
// any HTTP / getMe call, so these tests need no network and never touch a
// real endpoint.
// ---------------------------------------------------------------------------

func TestBuildHosted_MissingFields(t *testing.T) {
	t.Parallel()
	keyFile := writeKeyFile(t, "secret-token")
	cases := []struct {
		name       string
		cfg        hostedConfig
		wantSubstr string
	}{
		{"missing base_url", hostedConfig{APIKeyFile: keyFile, ClientID: "c1"}, "base_url"},
		{"missing api_key_file", hostedConfig{BaseURL: "https://h", ClientID: "c1"}, "api_key_file"},
		{"missing client_id", hostedConfig{BaseURL: "https://h", APIKeyFile: keyFile}, "client_id"},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			_, err := buildHostedBackend(tc.cfg)
			if err == nil {
				t.Fatalf("buildHostedBackend(%s) = nil; want error naming %q", tc.name, tc.wantSubstr)
			}
			if !strings.Contains(err.Error(), tc.wantSubstr) {
				t.Errorf("error = %q; want it to name %q", err, tc.wantSubstr)
			}
		})
	}
}

func TestBuildHosted_EmptyKeyFile(t *testing.T) {
	t.Parallel()
	empty := writeKeyFile(t, "   \n\t  ") // whitespace-only => trimmed empty
	_, err := buildHostedBackend(hostedConfig{
		BaseURL:    "https://signer.example.com",
		APIKeyFile: empty,
		ClientID:   "laptop-1",
	})
	if err == nil {
		t.Fatal("buildHostedBackend(empty key) = nil; want error before any HTTP")
	}
	if !strings.Contains(err.Error(), "empty") {
		t.Errorf("error = %q; want it to mention the key file is empty", err)
	}
}

func TestBuildHosted_RefusesGroupOrWorldReadableKey(t *testing.T) {
	t.Parallel()
	path := writeKeyFile(t, "secret")
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
	_, err := buildHostedBackend(hostedConfig{
		BaseURL: "https://signer.example.com", APIKeyFile: path, ClientID: "laptop-1",
	})
	if err == nil || !strings.Contains(err.Error(), "group/world bits must be off") {
		t.Fatalf("buildHostedBackend(0644) err=%v; want insecure-mode refusal", err)
	}
}

func TestBuildTelegram_MissingFields(t *testing.T) {
	t.Parallel()
	tokenFile := writeKeyFile(t, "123:abc")
	cases := []struct {
		name       string
		cfg        telegramConfig
		wantSubstr string
	}{
		{"missing token_path", telegramConfig{AllowedUserID: 42, ChatStorePath: "/x/cs.json"}, "token_path"},
		{"missing allowed_user_id", telegramConfig{TokenPath: tokenFile, ChatStorePath: "/x/cs.json"}, "allowed_user_id"},
		{"missing chatstore_path", telegramConfig{TokenPath: tokenFile, AllowedUserID: 42}, "chatstore_path"},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			// ctx is never used because validation fails before any
			// network call; pass the test context for hygiene.
			_, err := buildTelegramBackend(t.Context(), tc.cfg, [32]byte{}, nil)
			if err == nil {
				t.Fatalf("buildTelegramBackend(%s) = nil; want error naming %q", tc.name, tc.wantSubstr)
			}
			if !strings.Contains(err.Error(), tc.wantSubstr) {
				t.Errorf("error = %q; want it to name %q", err, tc.wantSubstr)
			}
		})
	}
}

func TestBuildTelegram_EmptyKeyFile(t *testing.T) {
	t.Parallel()
	empty := writeKeyFile(t, "\n   \n")
	_, err := buildTelegramBackend(t.Context(), telegramConfig{
		TokenPath:     empty,
		AllowedUserID: 42,
		ChatStorePath: filepath.Join(t.TempDir(), "cs.json"),
	}, [32]byte{}, nil)
	if err == nil {
		t.Fatal("buildTelegramBackend(empty token) = nil; want error before getMe")
	}
	if !strings.Contains(err.Error(), "empty") {
		t.Errorf("error = %q; want it to mention the token file is empty", err)
	}
}

func TestBuildExplainer_MissingFields(t *testing.T) {
	t.Parallel()
	keyFile := writeKeyFile(t, "sk-test")
	cases := []struct {
		name       string
		cfg        explainerConfig
		wantSubstr string
	}{
		{"missing endpoint", explainerConfig{Model: "m", APIKeyPath: keyFile}, "endpoint"},
		{"missing model", explainerConfig{Endpoint: "https://e", APIKeyPath: keyFile}, "model"},
		{"missing api_key_path", explainerConfig{Endpoint: "https://e", Model: "m"}, "api_key_path"},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			_, err := buildExplainer(tc.cfg)
			if err == nil {
				t.Fatalf("buildExplainer(%s) = nil; want error naming %q", tc.name, tc.wantSubstr)
			}
			if !strings.Contains(err.Error(), tc.wantSubstr) {
				t.Errorf("error = %q; want it to name %q", err, tc.wantSubstr)
			}
		})
	}
}

func TestBuildExplainer_EmptyKeyFile(t *testing.T) {
	t.Parallel()
	empty := writeKeyFile(t, "  \t\n")
	_, err := buildExplainer(explainerConfig{
		Endpoint:   "https://api.example.com/v1/chat/completions",
		Model:      "gpt-4o-mini",
		APIKeyPath: empty,
	})
	if err == nil {
		t.Fatal("buildExplainer(empty key) = nil; want error before any HTTP")
	}
	if !strings.Contains(err.Error(), "empty") {
		t.Errorf("error = %q; want it to mention the key file is empty", err)
	}
}

// writeKeyFile drops content into a 0600 temp file and returns its path.
func writeKeyFile(t *testing.T, content string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "key")
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatalf("write key file: %v", err)
	}
	return p
}

// ---------------------------------------------------------------------------
// assertNonRoot
// ---------------------------------------------------------------------------

// TestAssertNonRoot asserts the daemon refuses to run as euid 0. We can
// only positively assert the non-root branch when the test itself is not
// root; if run as root we can assert the refusal directly.
func TestAssertNonRoot(t *testing.T) {
	t.Parallel()
	err := assertNonRoot()
	if os.Geteuid() == 0 {
		if err == nil {
			t.Error("assertNonRoot() = nil while euid 0; want a refusal")
		}
		return
	}
	if err != nil {
		t.Errorf("assertNonRoot() = %v while non-root; want nil", err)
	}
}

// ---------------------------------------------------------------------------
// flockOrFail
// ---------------------------------------------------------------------------

// TestFlockOrFail_SecondLockBlocks proves singleton enforcement: the
// first flock succeeds and stamps the PID into the lockfile; a second
// flock on the same path returns an EWOULDBLOCK-derived error; releasing
// the first lets a third acquire it. All within a t.TempDir(), no privilege.
func TestFlockOrFail_SecondLockBlocks(t *testing.T) {
	t.Parallel()
	lockPath := filepath.Join(t.TempDir(), "sock.lock")

	release1, err := flockOrFail(lockPath)
	if err != nil {
		t.Fatalf("first flockOrFail: %v", err)
	}

	// The lockfile must carry this process's PID.
	data, err := os.ReadFile(lockPath)
	if err != nil {
		t.Fatalf("read lockfile: %v", err)
	}
	wantPID := strconv.Itoa(os.Getpid())
	if got := strings.TrimSpace(string(data)); got != wantPID {
		t.Errorf("lockfile PID = %q; want %q", got, wantPID)
	}

	// Second acquire on the same path must fail (lock already held).
	if _, err := flockOrFail(lockPath); err == nil {
		t.Fatal("second flockOrFail = nil; want a busy/already-running error")
	} else if !strings.Contains(err.Error(), "another signer instance is running") {
		t.Errorf("second flockOrFail error = %q; want the 'another signer instance' message", err)
	}

	// Release the first; a fresh acquire must now succeed.
	release1()
	release2, err := flockOrFail(lockPath)
	if err != nil {
		t.Fatalf("flockOrFail after release: %v; want success", err)
	}
	release2()
}

// ---------------------------------------------------------------------------
// doInitFlow
// ---------------------------------------------------------------------------

// TestDoInitFlow_DevHappyPath runs --dev --init against a temp config
// path and asserts the full on-disk layout: keypair (0600/0644), config
// (0644-ish), audit + socket dirs created. Dev mode roots everything flat
// under the config dir, so no /run or /var/lib access is needed.
func TestDoInitFlow_DevHappyPath(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	configPath := filepath.Join(root, "config.toml")

	if err := doInitFlow(configPath, true /* dev */); err != nil {
		t.Fatalf("doInitFlow(dev) = %v; want nil", err)
	}

	keyPath := filepath.Join(root, "gate.key")
	pubPath := filepath.Join(root, "gate.pub")
	auditPath := filepath.Join(root, "approvals.log")

	// Key files exist with the documented modes.
	assertMode(t, keyPath, 0o600)
	assertMode(t, pubPath, 0o644)
	// Config exists; written with 0o640 — assert world bits are off.
	ci, err := os.Stat(configPath)
	if err != nil {
		t.Fatalf("stat config: %v", err)
	}
	if ci.Mode().Perm()&0o007 != 0 {
		t.Errorf("config mode = %#o; world bits must be off", ci.Mode().Perm())
	}

	// The config must parse and round-trip through loadConfig.
	cfg, err := loadConfig(configPath)
	if err != nil {
		t.Fatalf("loadConfig(generated) = %v; want a valid config", err)
	}
	if cfg.Paths.Key != keyPath {
		t.Errorf("generated config key = %q; want %q", cfg.Paths.Key, keyPath)
	}
	if cfg.Backend.Type != "stub" {
		t.Errorf("generated backend type = %q; want stub", cfg.Backend.Type)
	}
	if cfg.Paths.AuditLog != auditPath {
		t.Errorf("generated audit_log = %q; want %q", cfg.Paths.AuditLog, auditPath)
	}

	// The directory that will hold the audit log must exist.
	if _, err := os.Stat(filepath.Dir(auditPath)); err != nil {
		t.Errorf("audit dir not created: %v", err)
	}
}

// TestDoInitFlow_RefusesExistingConfig asserts a second --init that would
// overwrite an existing config is refused — an accidental re-init must
// never silently rotate the master key or clobber a hand-edited config.
func TestDoInitFlow_RefusesExistingConfig(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	configPath := filepath.Join(root, "config.toml")

	// Pre-plant a config file. doInitFlow generates keys first, then
	// refuses at the config-overwrite check.
	if err := os.WriteFile(configPath, []byte("# hand-edited\n"), 0o640); err != nil {
		t.Fatalf("plant config: %v", err)
	}
	err := doInitFlow(configPath, true /* dev */)
	if err == nil {
		t.Fatal("doInitFlow over an existing config = nil; want a refusal")
	}
	if !strings.Contains(err.Error(), "refusing to overwrite existing config") {
		t.Errorf("error = %q; want the refuse-overwrite message", err)
	}
	// The pre-planted config must be untouched.
	data, _ := os.ReadFile(configPath)
	if string(data) != "# hand-edited\n" {
		t.Errorf("config was modified: %q", string(data))
	}
}

func assertMode(t *testing.T, path string, want os.FileMode) {
	t.Helper()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat %s: %v", path, err)
	}
	if got := info.Mode().Perm(); got != want {
		t.Errorf("%s mode = %#o; want %#o", path, got, want)
	}
}

// ---------------------------------------------------------------------------
// run() — exit codes and lifecycle
// ---------------------------------------------------------------------------

// TestRun_Version asserts --version prints and exits 0.
func TestRun_Version(t *testing.T) {
	t.Parallel()
	if code := run([]string{"--version"}); code != 0 {
		t.Errorf("run(--version) = %d; want 0", code)
	}
}

// TestRun_BadFlag asserts an unknown flag exits 2 (flag.ContinueOnError
// path).
func TestRun_BadFlag(t *testing.T) {
	t.Parallel()
	if code := run([]string{"--this-flag-does-not-exist"}); code != 2 {
		t.Errorf("run(bad flag) = %d; want 2", code)
	}
}

// TestRun_BadConfig asserts a config that fails to load exits 1. Skipped
// under root because assertNonRoot would short-circuit to 1 first (same
// exit code, but for the wrong reason — we want to exercise the
// load-config failure specifically).
func TestRun_BadConfig(t *testing.T) {
	t.Parallel()
	if os.Geteuid() == 0 {
		t.Skip("running as root: assertNonRoot would pre-empt the load-config path")
	}
	missing := filepath.Join(t.TempDir(), "nope.toml")
	if code := run([]string{"--config", missing}); code != 1 {
		t.Errorf("run(missing config) = %d; want 1", code)
	}
}

// initDevTree runs the --init --dev flow and returns the config path and
// the socket path the daemon will bind. Used by the boot/shutdown tests.
func initDevTree(t *testing.T) (configPath, sockPath string) {
	t.Helper()
	root := t.TempDir()
	configPath = filepath.Join(root, "config.toml")
	if err := doInitFlow(configPath, true /* dev */); err != nil {
		t.Fatalf("doInitFlow(dev): %v", err)
	}
	cfg, err := loadConfig(configPath)
	if err != nil {
		t.Fatalf("loadConfig: %v", err)
	}
	return configPath, cfg.Paths.Socket
}

// TestRun_StubDaemonBootsAndShutsDown boots the real daemon against a
// --dev tree (stub backend), waits until it has bound its socket
// (i.e. logged "ready"), then sends SIGTERM. run() must shut down cleanly
// and return 0.
//
// We drive shutdown via a real SIGTERM rather than a context seam because
// run() owns its own signal-derived context (signal.NotifyContext). The
// signal is only sent AFTER the socket appears, by which point
// NotifyContext has certainly installed its handler, so the test process
// cannot be killed by an early/unhandled SIGTERM.
func TestRun_StubDaemonBootsAndShutsDown(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("running as root: the daemon refuses to boot as root")
	}
	// Not parallel: sends a process-directed signal.
	configPath, sockPath := initDevTree(t)

	done := make(chan int, 1)
	go func() { done <- run([]string{"--config", configPath}) }()

	waitForFile(t, sockPath)
	if err := syscall.Kill(os.Getpid(), syscall.SIGTERM); err != nil {
		t.Fatalf("send SIGTERM: %v", err)
	}

	select {
	case code := <-done:
		if code != 0 {
			t.Errorf("run() exit = %d; want 0 on clean SIGTERM shutdown", code)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("run() did not return within 5s of SIGTERM")
	}
}

// TestRun_SIGHUP asserts SIGHUP is logged as "restart to apply" and does
// NOT reload config (v1 contract, daemon.md §8.2). We capture stderr,
// boot the daemon, send SIGHUP, confirm the message, then SIGTERM to
// shut down and confirm a clean exit. The daemon staying up after SIGHUP
// (rather than restarting/exiting) is itself the "does not reload" proof.
func TestRun_SIGHUP(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("running as root: the daemon refuses to boot as root")
	}
	// Not parallel: redirects os.Stderr and sends process signals.
	configPath, sockPath := initDevTree(t)

	stderr, restore := captureStderr(t)
	defer restore()

	done := make(chan int, 1)
	go func() { done <- run([]string{"--config", configPath}) }()

	waitForFile(t, sockPath)

	// SIGHUP: must be logged and ignored (no reload, daemon stays up).
	if err := syscall.Kill(os.Getpid(), syscall.SIGHUP); err != nil {
		t.Fatalf("send SIGHUP: %v", err)
	}

	// Wait for the SIGHUP log line to show up (poll the captured buffer).
	if !waitForLog(stderr, "restart to apply", 3*time.Second) {
		t.Errorf("SIGHUP did not produce a 'restart to apply' log line; captured:\n%s", stderr.String())
	}

	// The daemon must still be alive: run() has NOT returned.
	select {
	case code := <-done:
		t.Fatalf("run() exited (code %d) on SIGHUP; it must stay up (no reload, no restart)", code)
	default:
	}

	// Now shut down for real.
	if err := syscall.Kill(os.Getpid(), syscall.SIGTERM); err != nil {
		t.Fatalf("send SIGTERM: %v", err)
	}
	select {
	case code := <-done:
		if code != 0 {
			t.Errorf("run() exit after SIGHUP+SIGTERM = %d; want 0", code)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("run() did not return within 5s of SIGTERM")
	}
}

// waitForFile polls until path exists or fails the test after 3s.
func waitForFile(t *testing.T, path string) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for {
		if _, err := os.Stat(path); err == nil {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("%s did not appear within 3s (daemon never became ready)", path)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// safeBuffer is a goroutine-safe string accumulator used to capture
// stderr written by the daemon from another goroutine.
type safeBuffer struct {
	mu  sync.Mutex
	buf strings.Builder
}

func (b *safeBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *safeBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// captureStderr redirects os.Stderr to an os.Pipe whose read end is
// drained into a safeBuffer. It returns the buffer and a restore func.
// This is an in-package test hook (package main) using only os.Stderr
// reassignment — production behavior and the public API are unchanged.
func captureStderr(t *testing.T) (*safeBuffer, func()) {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	orig := os.Stderr
	os.Stderr = w

	sb := &safeBuffer{}
	drained := make(chan struct{})
	go func() {
		defer close(drained)
		buf := make([]byte, 4096)
		for {
			n, err := r.Read(buf)
			if n > 0 {
				_, _ = sb.Write(buf[:n])
			}
			if err != nil {
				return
			}
		}
	}()

	restore := func() {
		os.Stderr = orig
		_ = w.Close()
		<-drained
		_ = r.Close()
	}
	return sb, restore
}

// waitForLog polls sb until it contains substr or the deadline passes.
func waitForLog(sb *safeBuffer, substr string, within time.Duration) bool {
	deadline := time.Now().Add(within)
	for {
		if strings.Contains(sb.String(), substr) {
			return true
		}
		if time.Now().After(deadline) {
			return false
		}
		time.Sleep(10 * time.Millisecond)
	}
}
