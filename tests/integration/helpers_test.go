//go:build integration

// Helpers for the Phase-1 end-to-end test (task 1.6).
//
// The full integration stack uses a real linuxserver/openssh-server
// container as the remote target, a freshly cross-compiled gate
// binary installed into the container, the real signer.Server
// listening on a Unix socket under t.TempDir(), and the real MCP
// tools.Runner directly (we don't stand up the JSON-RPC server — the
// in-process Runner is the meaningful integration boundary).
//
// Each helper is small, t.Helper()'d, and skips with a clear message
// when Docker isn't available, so contributors without a Docker
// daemon can still run `go test -tags=integration ./tests/integration`
// and see a clean SKIP rather than a confusing failure.
package integration_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	sshlib "golang.org/x/crypto/ssh"

	"github.com/karthikeyan5/sshgate/src/mcp/registry"
	signpkg "github.com/karthikeyan5/sshgate/src/mcp/sign"
	sshpkg "github.com/karthikeyan5/sshgate/src/mcp/ssh"
	"github.com/karthikeyan5/sshgate/src/mcp/tools"
	"github.com/karthikeyan5/sshgate/src/signer"
	"github.com/karthikeyan5/sshgate/src/signer/backend"
)

const (
	// composeService is the service name inside docker-compose.yml.
	composeService = "sshd"
	// sshContainerPort is the host-side port the compose file maps to.
	sshContainerPort = 2222
	// containerHome is the linuxserver/openssh-server image's home dir
	// for testuser; everything we deploy lives under it.
	containerHome = "/config"
	// remoteUser is the USER_NAME set in docker-compose.yml.
	remoteUser = "testuser"
)

// repoRoot returns the SSHGate repository root by walking up from
// this test file's working dir until a go.mod is found. This keeps
// docker compose invocations independent of how `go test` was run.
func repoRoot(t *testing.T) string {
	t.Helper()
	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	dir := wd
	for i := 0; i < 8; i++ {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}
	t.Fatalf("could not locate go.mod above %s", wd)
	return ""
}

// composeFile returns the absolute path to the integration
// docker-compose.yml.
func composeFile(t *testing.T) string {
	t.Helper()
	return filepath.Join(repoRoot(t), "tests", "integration", "docker-compose.yml")
}

// dockerCompose returns the argv for `docker compose -f <file>`. We
// prefer the v2 plugin form (`docker compose`); the helper falls
// back to the legacy `docker-compose` binary only if the plugin
// isn't installed. If neither is present, callers Skip.
func dockerCompose(t *testing.T, args ...string) *exec.Cmd {
	t.Helper()
	if _, err := exec.LookPath("docker"); err == nil {
		// Probe `docker compose version` once; if it works we use the plugin.
		if err := exec.Command("docker", "compose", "version").Run(); err == nil {
			full := append([]string{"compose", "-f", composeFile(t)}, args...)
			return exec.Command("docker", full...)
		}
	}
	if _, err := exec.LookPath("docker-compose"); err == nil {
		full := append([]string{"-f", composeFile(t)}, args...)
		return exec.Command("docker-compose", full...)
	}
	t.Skip("docker compose not available; skipping integration e2e")
	return nil
}

// bootContainer brings the SSH target up and waits for its banner.
// Returns a cleanup func that calls `docker compose down -v`. If
// Docker (or compose) isn't available, the test is skipped.
//
// The container reads the SSHGate public key from a bind-mounted
// fixtures dir, so callers MUST call generateSSHKey before
// bootContainer to populate the .pub file.
func bootContainer(t *testing.T) func() {
	t.Helper()

	// Pre-flight: ensure docker daemon answers. `docker compose ps`
	// would fail cryptically if the daemon is dead, so test it
	// directly with a fast `docker info`.
	if cmd := exec.Command("docker", "info"); cmd != nil {
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Skipf("docker daemon not reachable: %v\n%s", err, out)
		}
	}

	up := dockerCompose(t, "up", "-d", "--force-recreate", "--remove-orphans")
	up.Stdout = os.Stderr
	up.Stderr = os.Stderr
	if err := up.Run(); err != nil {
		t.Skipf("docker compose up failed (likely no Docker permissions or image pull blocked): %v", err)
	}

	// Wait for SSH banner on host:port. linuxserver image takes ~5s
	// to render authorized_keys and start sshd; budget 60s with a
	// 500ms poll.
	if err := waitForSSHBanner("127.0.0.1", sshContainerPort, 60*time.Second); err != nil {
		// Tear down so a subsequent test run starts clean.
		down := dockerCompose(t, "down", "-v")
		down.Stdout = os.Stderr
		down.Stderr = os.Stderr
		_ = down.Run()
		t.Fatalf("ssh banner never appeared: %v", err)
	}

	return func() {
		down := dockerCompose(t, "down", "-v")
		down.Stdout = os.Stderr
		down.Stderr = os.Stderr
		if err := down.Run(); err != nil {
			t.Logf("docker compose down: %v", err)
		}
	}
}

// waitForSSHBanner dials host:port and reads up to 16 bytes,
// expecting to see "SSH-". It retries every pollInterval until
// total elapses.
func waitForSSHBanner(host string, port int, total time.Duration) error {
	deadline := time.Now().Add(total)
	var lastErr error
	for time.Now().Before(deadline) {
		conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", host, port), 500*time.Millisecond)
		if err != nil {
			lastErr = err
			time.Sleep(500 * time.Millisecond)
			continue
		}
		_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
		buf := make([]byte, 16)
		n, err := conn.Read(buf)
		_ = conn.Close()
		if err == nil && n >= 4 && string(buf[:4]) == "SSH-" {
			return nil
		}
		lastErr = err
		time.Sleep(500 * time.Millisecond)
	}
	if lastErr == nil {
		lastErr = errors.New("timeout")
	}
	return lastErr
}

// generateSSHKey creates a fresh Ed25519 keypair for SSH client auth,
// writes the PEM-encoded private to t.TempDir() (mode 0600), and
// installs the OpenSSH-format public key at the path the docker-
// compose volume mount points to. Returns the private and public
// paths.
//
// The .pub file is intentionally written under the repo so the
// bind-mounted /keys volume in the container sees it; t.Cleanup
// removes the .pub after the test so the working tree stays clean.
func generateSSHKey(t *testing.T) (privPath, pubPath string) {
	t.Helper()

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate ed25519: %v", err)
	}

	// PEM-encode the private key (the ssh.Client requires PEM).
	block, err := sshlib.MarshalPrivateKey(priv, "sshgate-e2e")
	if err != nil {
		t.Fatalf("marshal private key: %v", err)
	}
	privPath = filepath.Join(t.TempDir(), "id_ed25519")
	if err := os.WriteFile(privPath, pem.EncodeToMemory(block), 0o600); err != nil {
		t.Fatalf("write private key: %v", err)
	}

	// OpenSSH-format pubkey: "ssh-ed25519 <base64> sshgate@e2e\n"
	sshPub, err := sshlib.NewPublicKey(pub)
	if err != nil {
		t.Fatalf("ssh.NewPublicKey: %v", err)
	}
	// MarshalAuthorizedKey produces "ssh-ed25519 <b64>\n" — exactly
	// what the linuxserver entrypoint copies into authorized_keys.
	pubBytes := sshlib.MarshalAuthorizedKey(sshPub)

	pubDir := filepath.Join(repoRoot(t), "tests", "integration", "fixtures", "keys")
	if err := os.MkdirAll(pubDir, 0o755); err != nil {
		t.Fatalf("mkdir fixtures dir: %v", err)
	}
	pubPath = filepath.Join(pubDir, "sshgate_ed25519.pub")
	if err := os.WriteFile(pubPath, pubBytes, 0o644); err != nil {
		t.Fatalf("write public key: %v", err)
	}
	t.Cleanup(func() {
		// Generated each run; remove so `git status` stays clean.
		_ = os.Remove(pubPath)
	})
	return privPath, pubPath
}

// generateGateKeyPair creates a fresh Ed25519 master signing key
// pair via signer.GenerateKeyPair, in t.TempDir(). Returns the
// private and public file paths.
func generateGateKeyPair(t *testing.T) (privPath, pubPath string) {
	t.Helper()
	dir := t.TempDir()
	privPath = filepath.Join(dir, "gate.key")
	pubPath = filepath.Join(dir, "gate.pub")
	if err := signer.GenerateKeyPair(privPath, pubPath); err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	return privPath, pubPath
}

// generateStandaloneSSHKey creates a fresh Ed25519 SSH client keypair
// in t.TempDir() and returns the private and public file paths. Unlike
// generateSSHKey it does NOT touch the fixtures dir or the container —
// it's used for the SSHGate-dedicated key in Phase-3 auto-setup tests.
func generateStandaloneSSHKey(t *testing.T) (privPath, pubPath string) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate ed25519: %v", err)
	}
	block, err := sshlib.MarshalPrivateKey(priv, "sshgate-dedicated")
	if err != nil {
		t.Fatalf("marshal private key: %v", err)
	}
	dir := t.TempDir()
	privPath = filepath.Join(dir, "sshgate_ed25519")
	if err := os.WriteFile(privPath, pem.EncodeToMemory(block), 0o600); err != nil {
		t.Fatalf("write private key: %v", err)
	}
	sshPub, err := sshlib.NewPublicKey(pub)
	if err != nil {
		t.Fatalf("ssh.NewPublicKey: %v", err)
	}
	pubBytes := sshlib.MarshalAuthorizedKey(sshPub)
	pubPath = filepath.Join(dir, "sshgate_ed25519.pub")
	if err := os.WriteFile(pubPath, pubBytes, 0o644); err != nil {
		t.Fatalf("write public key: %v", err)
	}
	return privPath, pubPath
}

// buildGateLinux cross-compiles gate for linux/amd64 into
// <repoRoot>/bin/gate-linux-amd64 and returns its path. We invoke
// `go build` directly rather than `make gate-linux` so the test
// is independent of Makefile changes.
func buildGateLinux(t *testing.T) string {
	t.Helper()
	root := repoRoot(t)
	out := filepath.Join(root, "bin", "gate-linux-amd64")
	if err := os.MkdirAll(filepath.Dir(out), 0o755); err != nil {
		t.Fatalf("mkdir bin: %v", err)
	}
	cmd := exec.Command("go", "build",
		"-trimpath",
		"-ldflags", "-s -w",
		"-o", out,
		"./src/gate/cmd/sshgate-gate",
	)
	cmd.Dir = root
	cmd.Env = append(os.Environ(), "CGO_ENABLED=0", "GOOS=linux", "GOARCH=amd64")
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("build gate-linux: %v\n%s", err, output)
	}
	return out
}

// dockerExec runs `docker compose exec -T <service> sh -c <shCmd>`.
// stdin is fed from r if non-nil. Returns combined stdout/stderr +
// an error wrapping the exit status.
func dockerExec(t *testing.T, r io.Reader, shCmd string) ([]byte, error) {
	t.Helper()
	cmd := dockerCompose(t, "exec", "-T", composeService, "sh", "-c", shCmd)
	if r != nil {
		cmd.Stdin = r
	}
	return cmd.CombinedOutput()
}

// dockerCp copies a host file into the container at containerPath.
// We pipe via stdin to a redirected `sh -c "cat > path"` because
// `docker compose cp` requires container names (not service names)
// in some versions; the pipe is uniform across versions.
func dockerCp(t *testing.T, hostPath, containerPath string) {
	t.Helper()
	f, err := os.Open(hostPath)
	if err != nil {
		t.Fatalf("open %s: %v", hostPath, err)
	}
	defer f.Close()
	out, err := dockerExec(t, f, fmt.Sprintf("cat > %s", containerPath))
	if err != nil {
		t.Fatalf("docker cp into %s: %v\n%s", containerPath, err, out)
	}
}

// deployGateBinary installs the cross-compiled gate binary
// into the running container along with the master signing pubkey,
// and rewrites authorized_keys so every connection on the SSHGate
// key is forced through gate. Idempotent within a test run.
func deployGateBinary(t *testing.T, pubKeyPath string) {
	t.Helper()
	binPath := buildGateLinux(t)

	// Make ~/.sshgate-gate; install the binary and the pubkey.
	if out, err := dockerExec(t, nil, fmt.Sprintf(
		"mkdir -p %[1]s/.sshgate-gate && chown %[2]s:%[2]s %[1]s/.sshgate-gate && chmod 700 %[1]s/.sshgate-gate",
		containerHome, remoteUser)); err != nil {
		t.Fatalf("mkdir .gate: %v\n%s", err, out)
	}
	dockerCp(t, binPath, containerHome+"/.sshgate-gate/gate")
	dockerCp(t, pubKeyPath, containerHome+"/.sshgate-gate/gate.pub")
	if out, err := dockerExec(t, nil, fmt.Sprintf("chown %s:%s %s/.sshgate-gate/gate %s/.sshgate-gate/gate.pub && chmod 755 %s/.sshgate-gate/gate && chmod 644 %s/.sshgate-gate/gate.pub", remoteUser, remoteUser, containerHome, containerHome, containerHome, containerHome)); err != nil {
		t.Fatalf("chown/chmod gate files: %v\n%s", err, out)
	}

	// Rewrite authorized_keys: prepend the command="..." forcing on
	// every line. The linuxserver image deposits the pubkey at
	// /config/.ssh/authorized_keys verbatim.
	authPath := containerHome + "/.ssh/authorized_keys"
	rewrite := fmt.Sprintf(`
set -e
test -f %s
tmp=$(mktemp)
while IFS= read -r line; do
  if [ -z "$line" ]; then continue; fi
  # strip any existing options up to the first space
  case "$line" in
    ssh-*) key="$line" ;;
    *) key=$(echo "$line" | sed -E 's/^[^ ]+ +(ssh-[a-z0-9-]+ +)/\1/') ;;
  esac
  echo 'restrict,command="%s/.sshgate-gate/gate",no-pty,no-port-forwarding,no-X11-forwarding,no-agent-forwarding '"$key" >> "$tmp"
done < %s
mv "$tmp" %s
chown %s:%s %s
chmod 600 %s
`,
		authPath,
		containerHome,
		authPath,
		authPath,
		remoteUser, remoteUser, authPath,
		authPath,
	)
	if out, err := dockerExec(t, nil, rewrite); err != nil {
		t.Fatalf("rewrite authorized_keys: %v\n%s", err, out)
	}
}

// pasteSSHGatePlainLine appends the SSHGate dedicated key's PLAIN
// authorized_keys line to the container's ~/.ssh/authorized_keys,
// mirroring the out-of-band step a human performs before running
// `sshgate add` (paste `sshgate pubkey`'s output into the target's
// authorized_keys). Provision then dials with the dedicated key itself
// and rewrites this plain line into the restricted forced-command line.
//
// pubKeyPath is the dedicated key's .pub file (a single
// "ssh-ed25519 AAAA... comment" line). We strip the trailing newline and
// single-quote the line for the remote shell (OpenSSH pubkey lines never
// contain single quotes, so single-quote wrapping is safe), then chown +
// chmod 600 so sshd accepts the file (matches deployGateBinary's perms).
func pasteSSHGatePlainLine(t *testing.T, pubKeyPath string) {
	t.Helper()
	body, err := os.ReadFile(pubKeyPath)
	if err != nil {
		t.Fatalf("read dedicated pubkey %s: %v", pubKeyPath, err)
	}
	line := strings.TrimRight(string(body), "\r\n")
	if strings.ContainsAny(line, "\n'") {
		t.Fatalf("dedicated pubkey line %q is not a single quote-safe line", line)
	}
	authPath := containerHome + "/.ssh/authorized_keys"
	shCmd := fmt.Sprintf(
		"set -e; mkdir -p %[1]s/.ssh && touch %[2]s && printf '%%s\\n' '%[3]s' >> %[2]s && "+
			"chown %[4]s:%[4]s %[2]s && chmod 600 %[2]s",
		containerHome, authPath, line, remoteUser)
	if out, err := dockerExec(t, nil, shCmd); err != nil {
		t.Fatalf("paste dedicated plain line into authorized_keys: %v\n%s", err, out)
	}
}

// startSigner spins up a real signer.Server in a goroutine,
// bound to a socket under t.TempDir() and backed by StubBackend
// (which denies every request). Returns the socket path and a
// cleanup func that cancels the server context and waits for the
// goroutine to exit. Use t.Cleanup to invoke cleanup so a t.Fatal
// in the test body still tears down the server.
func startSigner(t *testing.T, masterKeyPath string) (socketPath string, cleanup func()) {
	t.Helper()

	priv, err := signer.LoadKey(masterKeyPath)
	if err != nil {
		t.Fatalf("LoadKey: %v", err)
	}

	auditPath := filepath.Join(t.TempDir(), "approvals.log")
	audit, err := signer.OpenAuditLog(auditPath)
	if err != nil {
		t.Fatalf("OpenAuditLog: %v", err)
	}

	daemon := &signer.Daemon{
		Key:     priv,
		Backend: backend.StubBackend{},
		Audit:   audit,
	}
	socketPath = filepath.Join(t.TempDir(), "signer.sock")
	srv := &signer.Server{
		Path:           socketPath,
		Handler:        daemon,
		HandlerTimeout: 10 * time.Second,
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	var serveErr error
	go func() {
		defer close(done)
		serveErr = srv.Listen(ctx)
	}()

	// Wait briefly for the socket file to appear so callers can
	// dial without races.
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(socketPath); err == nil {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}

	var once sync.Once
	cleanup = func() {
		once.Do(func() {
			cancel()
			<-done
			_ = audit.Close()
			if serveErr != nil {
				t.Logf("signer Listen returned: %v", serveErr)
			}
		})
	}
	return socketPath, cleanup
}

// runMCPRunTool builds a real registry + sign.Client + ssh.Client
// + tools.Runner around the live socket and SSH key, registers the
// test server under alias, and calls Runner.Run. We exercise the
// in-process Runner rather than the MCP JSON-RPC layer because the
// orchestration is what matters here.
func runMCPRunTool(t *testing.T, socketPath, sshKeyPath string, alias, host string, port int, user, cmd string) (tools.RunOutput, error) {
	t.Helper()

	regPath := filepath.Join(t.TempDir(), "servers.json")
	servers, err := registry.New(regPath)
	if err != nil {
		t.Fatalf("registry.New: %v", err)
	}
	if err := servers.Add(alias, registry.Entry{
		Host:    host,
		Port:    port,
		User:    user,
		AddedAt: time.Now(),
	}); err != nil {
		t.Fatalf("registry.Add: %v", err)
	}

	signClient := &signpkg.Client{
		SocketPath: socketPath,
		Timeout:    15 * time.Second,
	}
	sshClient := &sshpkg.Client{
		KeyPath:        sshKeyPath,
		KnownHostsPath: filepath.Join(t.TempDir(), "known_hosts"),
		Timeout:        15 * time.Second,
	}
	runner := &tools.Runner{
		Servers:     servers,
		Sign:        signClient,
		SSH:         sshClient,
		WriteTTLSec: 60,
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	return runner.Run(ctx, tools.RunInput{Alias: alias, Command: cmd})
}

// directUnsignedSSH dials the container with the SSHGate key and
// executes cmd raw (no signed prefix). It's the "Claude tries to
// bypass MCP" path. Returns stdout, stderr, exit, and the raw error
// from the ssh library so callers can inspect both.
func directUnsignedSSH(t *testing.T, sshKeyPath, host string, port int, user, cmd string) (stdout, stderr []byte, exit int, err error) {
	t.Helper()
	c := &sshpkg.Client{
		KeyPath:        sshKeyPath,
		KnownHostsPath: filepath.Join(t.TempDir(), "known_hosts"),
		Timeout:        10 * time.Second,
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	return c.Run(ctx, host, user, port, cmd)
}

// trimAll returns s with all surrounding whitespace and trailing
// newlines removed; convenience for assertions on remote output.
func trimAll(s string) string {
	return strings.TrimSpace(s)
}
