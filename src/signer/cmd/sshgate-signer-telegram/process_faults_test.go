//go:build linux

package main

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	ap "github.com/karthikeyan5/sshgate/src/approvalplan"
	st "github.com/karthikeyan5/sshgate/src/approvalplan/statetest"
)

// Process tests run a signer binary built with the sshgate_faults tag, so
// faultpoint cutpoints and process-level ownership are real in every test run.

var signerBinary struct {
	once      sync.Once
	dir, path string
	err       error
}

func TestMain(m *testing.M) {
	code := m.Run()
	if signerBinary.dir != "" {
		os.RemoveAll(signerBinary.dir)
	}
	os.Exit(code)
}

func buildSigner(t *testing.T) string {
	t.Helper()
	if os.Geteuid() == 0 {
		t.Skip("the signer refuses to run as root")
	}
	signerBinary.once.Do(func() {
		signerBinary.dir, signerBinary.err = os.MkdirTemp("", "signer-process-test-")
		if signerBinary.err != nil {
			return
		}
		signerBinary.path = filepath.Join(signerBinary.dir, "signer")
		out, err := exec.Command("go", "build", "-tags=sshgate_faults", "-o", signerBinary.path, ".").CombinedOutput()
		if err != nil {
			signerBinary.err = fmt.Errorf("build: %v: %s", err, out)
		}
	})
	if signerBinary.err != nil {
		t.Fatal(signerBinary.err)
	}
	return signerBinary.path
}

type signerProcess struct {
	cmd    *exec.Cmd
	stderr *safeBuffer
	done   chan error
}

func startSigner(t *testing.T, configPath string, env ...string) *signerProcess {
	t.Helper()
	return startSignerCommand(t, exec.Command(buildSigner(t), "--config", configPath), env...)
}

func startSignerCommand(t *testing.T, cmd *exec.Cmd, env ...string) *signerProcess {
	t.Helper()
	p := &signerProcess{cmd: cmd, stderr: &safeBuffer{}, done: make(chan error, 1)}
	cmd.Env = append(os.Environ(), env...)
	cmd.Stderr = p.stderr
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	go func() { p.done <- cmd.Wait() }()
	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		<-p.done
	})
	return p
}

// exitCode waits for a process that must stop on its own.
func (p *signerProcess) exitCode(t *testing.T) int {
	t.Helper()
	select {
	case err := <-p.done:
		p.done <- err
		var exit *exec.ExitError
		if errors.As(err, &exit) {
			return exit.ExitCode()
		}
		if err != nil {
			t.Fatal(err)
		}
		return 0
	case <-time.After(20 * time.Second):
		t.Fatalf("signer did not exit; stderr:\n%s", p.stderr.String())
		return -1
	}
}

func (p *signerProcess) isRunning() bool {
	select {
	case err := <-p.done:
		p.done <- err
		return false
	default:
		return true
	}
}

func (p *signerProcess) terminate(t *testing.T) {
	t.Helper()
	if err := p.cmd.Process.Signal(syscall.SIGTERM); err != nil {
		t.Fatal(err)
	}
	if code := p.exitCode(t); code != 0 {
		t.Fatalf("SIGTERM exit %d; stderr:\n%s", code, p.stderr.String())
	}
}

// initSignerTree runs the binary's --init --dev and returns the config.
func initSignerTree(t *testing.T) (string, tomlConfig) {
	t.Helper()
	configPath := filepath.Join(t.TempDir(), "config.toml")
	if out, err := exec.Command(buildSigner(t), "--init", "--dev", "--config", configPath).CombinedOutput(); err != nil {
		t.Fatalf("init: %v: %s", err, out)
	}
	cfg, err := loadConfig(configPath)
	if err != nil {
		t.Fatal(err)
	}
	return configPath, cfg
}

// contenderConfig shares the key, audit log, policy journal and approval
// journal but not the socket, so only the journal ownership flock refuses it.
func contenderConfig(t *testing.T, configPath, journalRoot string) (string, string) {
	t.Helper()
	cfg, err := loadConfig(configPath)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	socket := filepath.Join(dir, "sock")
	body := fmt.Sprintf("[paths]\nkey = %q\npubkey = %q\naudit_log = %q\nsocket = %q\npolicy_journal = %q\n\n[approvals]\njournal_root = %q\n\n[backend]\ntype = \"stub\"\n",
		cfg.Paths.Key, cfg.Paths.PubKey, cfg.Paths.AuditLog, socket, cfg.Paths.PolicyJournal, journalRoot)
	path := filepath.Join(dir, "config.toml")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return path, socket
}

func waitForSocket(t *testing.T, p *signerProcess, socket string) {
	t.Helper()
	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		if conn, err := net.Dial("unix", socket); err == nil {
			conn.Close()
			return
		}
		if !p.isRunning() {
			t.Fatalf("signer exited before listening; stderr:\n%s", p.stderr.String())
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("socket %s never accepted; stderr:\n%s", socket, p.stderr.String())
}

func listApprovals(t *testing.T, socket string) string {
	t.Helper()
	return approvalCall(t, socket, []byte("{\"approval_proto\":1,\"kind\":\"approval_list_v2\",\"limit\":50}"))
}

func approvalCall(t *testing.T, socket string, request []byte) string {
	t.Helper()
	conn, err := net.Dial("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
	if _, err := conn.Write(append(request, '\n')); err != nil {
		t.Fatal(err)
	}
	line, err := bufio.NewReader(conn).ReadString('\n')
	if err != nil {
		t.Fatalf("read list response: %v (%q)", err, line)
	}
	return line
}

// seedRecord writes one valid pending record owned by this test's uid.
func seedRecord(t *testing.T, journalRoot string, n int) string {
	t.Helper()
	now := time.Now().UTC().Truncate(time.Second)
	draft := st.JobDraft(st.ID(n), ap.CoordinatorExecutor, now, st.Write("true", 60))
	principal := fmt.Sprintf("local-uid:%d", os.Geteuid())
	record, answer := ap.Apply(nil, st.SubmitOf(draft, principal, now, time.Hour), ap.Now{Wall: now}, ap.Inputs{Epoch: st.Epoch(1), Settings: ap.LocalSettings})
	if answer.Code != "" {
		t.Fatal(answer)
	}
	data, err := ap.EncodeR1(record)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(journalRoot, ap.RecordKey(principal, st.ID(n))), data, 0o600); err != nil {
		t.Fatal(err)
	}
	return st.ID(n)
}

// snapshotDirectory records each entry's inode, mtime and bytes, so a
// rewrite with identical content still shows.
func snapshotDirectory(t *testing.T, dir string) string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	var snapshot strings.Builder
	for _, entry := range entries {
		path := filepath.Join(dir, entry.Name())
		var stat syscall.Stat_t
		if err := syscall.Lstat(path, &stat); err != nil {
			t.Fatal(err)
		}
		data, _ := os.ReadFile(path)
		fmt.Fprintf(&snapshot, "%s ino=%d mtime=%d.%09d %x\n", entry.Name(), stat.Ino, stat.Mtim.Sec, stat.Mtim.Nsec, data)
	}
	return snapshot.String()
}

func assertRefusedBeforeListen(t *testing.T, p *signerProcess, socket, wantLog string) {
	t.Helper()
	if code := p.exitCode(t); code == 0 {
		t.Fatalf("contender exited 0; stderr:\n%s", p.stderr.String())
	}
	isLogged := false
	for _, line := range strings.Split(p.stderr.String(), "\n") {
		isLogged = isLogged || strings.HasPrefix(line, "signer: fatal: approval store ") && strings.Contains(line, wantLog)
	}
	if !isLogged {
		t.Fatalf("no one-line fatal store log containing %q:\n%s", wantLog, p.stderr.String())
	}
	if strings.Contains(p.stderr.String(), "ready (socket=") {
		t.Fatalf("contender reached Listen:\n%s", p.stderr.String())
	}
	if _, err := os.Lstat(socket); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("contender created its socket: %v", err)
	}
}

func TestProcessSecondSignerOnOneJournalExitsBeforeListen(t *testing.T) {
	configPath, cfg := initSignerTree(t)
	requestID := seedRecord(t, cfg.Approvals.JournalRoot, 1)
	first := startSigner(t, configPath)
	waitForSocket(t, first, cfg.Paths.Socket)
	before := listApprovals(t, cfg.Paths.Socket)
	if !strings.Contains(before, `"ok":true`) || !strings.Contains(before, requestID) {
		t.Fatalf("first signer does not serve the journal: %s", before)
	}
	policyBefore := snapshotDirectory(t, cfg.Paths.PolicyJournal)

	symlinkParent := filepath.Join(t.TempDir(), "parent-link")
	if err := os.Symlink(filepath.Dir(cfg.Approvals.JournalRoot), symlinkParent); err != nil {
		t.Fatal(err)
	}
	for name, root := range map[string]string{
		"same path":        cfg.Approvals.JournalRoot,
		"symlinked parent": filepath.Join(symlinkParent, filepath.Base(cfg.Approvals.JournalRoot)),
	} {
		t.Run(name, func(t *testing.T) {
			contender, socket := contenderConfig(t, configPath, root)
			second := startSigner(t, contender)
			assertRefusedBeforeListen(t, second, socket, "approval store "+root+" is held by another signer process")
		})
	}
	t.Run("bind mount", func(t *testing.T) {
		unshare, err := exec.LookPath("unshare")
		if err != nil {
			t.Skip("unshare(1) unavailable; bind mount needs an unprivileged user and mount namespace")
		}
		mountPoint := filepath.Join(t.TempDir(), "bound")
		if err := os.Mkdir(mountPoint, 0o700); err != nil {
			t.Fatal(err)
		}
		contender, socket := contenderConfig(t, configPath, mountPoint)
		// Exit 97 marks a namespace or mount failure, never the signer's.
		script := `mount --bind "$1" "$2" || exit 97; exec "$3" --config "$4"`
		second := startSignerCommand(t, exec.Command(unshare, "--user", "--map-current-user", "--mount", "--keep-caps",
			"sh", "-c", script, "sh", cfg.Approvals.JournalRoot, mountPoint, buildSigner(t), contender))
		if code := second.exitCode(t); code == 97 || strings.Contains(second.stderr.String(), "unshare:") {
			t.Skipf("unprivileged bind mount unavailable (exit %d): %s", code, second.stderr.String())
		}
		assertRefusedBeforeListen(t, second, socket, "approval store "+mountPoint+" is held by another signer process")
	})

	if !first.isRunning() {
		t.Fatalf("first signer died; stderr:\n%s", first.stderr.String())
	}
	if after := listApprovals(t, cfg.Paths.Socket); after != before {
		t.Fatalf("contenders changed the owner's records:\nbefore %s\nafter  %s", before, after)
	}
	if policyAfter := snapshotDirectory(t, cfg.Paths.PolicyJournal); policyAfter != policyBefore {
		t.Fatalf("contenders touched the owner's policy journal:\nbefore %s\nafter  %s", policyBefore, policyAfter)
	}
	first.terminate(t)
}

func TestProcessFlockEBADFExitsBeforeListen(t *testing.T) {
	configPath, cfg := initSignerTree(t)
	p := startSigner(t, configPath, "SSHGATE_TEST_FAULT=filestore.flock")
	assertRefusedBeforeListen(t, p, cfg.Paths.Socket, "approval store "+cfg.Approvals.JournalRoot+" requires a local filesystem with working flock")
}

func TestProcessReopenUsesHeldDescriptorAfterRename(t *testing.T) {
	configPath, cfg := initSignerTree(t)
	root := cfg.Approvals.JournalRoot
	requestID := seedRecord(t, root, 2)
	fifo := filepath.Join(root, "blocker")
	if err := syscall.Mkfifo(fifo, 0o600); err != nil {
		t.Fatal(err)
	}
	var held syscall.Stat_t
	if err := syscall.Stat(root, &held); err != nil {
		t.Fatal(err)
	}
	first := startSigner(t, configPath)
	waitForSocket(t, first, cfg.Paths.Socket)
	if !strings.Contains(first.stderr.String(), "approval lifecycle unavailable") {
		t.Fatalf("initial load failure not diagnosed:\n%s", first.stderr.String())
	}
	if response := listApprovals(t, cfg.Paths.Socket); !strings.Contains(response, string(ap.CodeLifecycleUnavailable)) {
		t.Fatalf("v2 served before a successful load: %s", response)
	}

	contender, socket := contenderConfig(t, configPath, root)
	third := startSigner(t, contender)
	assertRefusedBeforeListen(t, third, socket, "is held by another signer process")

	moved := root + ".moved"
	if err := os.Rename(root, moved); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(root, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(moved, "blocker")); err != nil {
		t.Fatal(err)
	}
	var response string
	deadline := time.Now().Add(45 * time.Second)
	for {
		response = listApprovals(t, cfg.Paths.Socket)
		if strings.Contains(response, `"ok":true`) || time.Now().After(deadline) {
			break
		}
		time.Sleep(200 * time.Millisecond)
	}
	if !strings.Contains(response, requestID) {
		t.Fatalf("reopen did not serve the held inode's records: %s\nstderr:\n%s", response, first.stderr.String())
	}
	var stillHeld syscall.Stat_t
	if err := syscall.Stat(moved, &stillHeld); err != nil || stillHeld.Ino != held.Ino || stillHeld.Dev != held.Dev {
		t.Fatalf("moved directory is not the held inode: %v", err)
	}
	entries, err := os.ReadDir(root)
	if err != nil || len(entries) != 0 {
		t.Fatalf("the replacement directory at the path was used: %v %v", entries, err)
	}
	first.terminate(t)
}

func TestProcessDevStoreReloadEqualsPreCrashState(t *testing.T) {
	configPath, cfg := initSignerTree(t)
	if want := filepath.Join(filepath.Dir(cfg.Paths.Key), "approvals"); cfg.Approvals.JournalRoot != want {
		t.Fatalf("--dev journal_root %q, want under the dev key directory %q", cfg.Approvals.JournalRoot, want)
	}
	requestID := seedRecord(t, cfg.Approvals.JournalRoot, 3)
	first := startSigner(t, configPath)
	waitForSocket(t, first, cfg.Paths.Socket)
	if listed := listApprovals(t, cfg.Paths.Socket); !strings.Contains(listed, requestID) {
		t.Fatalf("seeded record not served: %s", listed)
	}
	// The canonical wire fixture, with only its submit window moved to now.
	fixture, err := os.ReadFile("../../../approvalwire/testdata/local/request-submit-write.json")
	if err != nil {
		t.Fatal(err)
	}
	const window = `"submit_not_after":"2026-10-15T10:30:00Z"`
	if !bytes.Contains(fixture, []byte(window)) {
		t.Fatalf("fixture lacks %s", window)
	}
	request := bytes.TrimSpace(bytes.Replace(fixture, []byte(window), []byte(`"submit_not_after":"`+time.Now().UTC().Add(5*time.Minute).Format(time.RFC3339)+`"`), 1))
	if response := approvalCall(t, cfg.Paths.Socket, request); !strings.Contains(response, `"ok":true`) {
		t.Fatalf("submit was not committed: %s", response)
	}
	const committedID = "a2_AAAAAAAAAAAAAAAAAAAAAA"
	before := listApprovals(t, cfg.Paths.Socket)
	if !strings.Contains(before, committedID) {
		t.Fatalf("committed submit not listed: %s", before)
	}
	if err := first.cmd.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	first.exitCode(t)
	second := startSigner(t, configPath)
	waitForSocket(t, second, cfg.Paths.Socket)
	if after := listApprovals(t, cfg.Paths.Socket); !bytes.Equal([]byte(after), []byte(before)) {
		t.Fatalf("reload differs from pre-crash state:\nbefore %s\nafter  %s", before, after)
	}
	second.terminate(t)
}
