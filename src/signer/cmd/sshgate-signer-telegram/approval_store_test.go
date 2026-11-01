//go:build linux

package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/karthikeyan5/sshgate/internal/elapsed"
	"github.com/karthikeyan5/sshgate/pkg/signerkit"
	"github.com/karthikeyan5/sshgate/pkg/signerkit/assist"
	"github.com/karthikeyan5/sshgate/pkg/signerkit/lifecycle"
	ap "github.com/karthikeyan5/sshgate/src/approvalplan"
)

func stubApprovalService(t *testing.T) (*signerkit.Service, *signerkit.AuditLog) {
	t.Helper()
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	audit, err := signerkit.OpenAuditLog(filepath.Join(t.TempDir(), "audit.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { audit.Close() })
	svc, err := signerkit.New(signerkit.Config{Signer: key, Backend: signerkit.StubBackend{}, Audit: audit})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { svc.Close() })
	return svc, audit
}

func stubApprovalConfig(journalRoot string) tomlConfig {
	var cfg tomlConfig
	cfg.Backend.Type = "stub"
	cfg.Approvals.JournalRoot = journalRoot
	return cfg
}

// isPoolClosed probes admission with a cancelled job, so an open pool runs
// nothing that can reach the provider and calls only the no-op callback.
func isPoolClosed(pool *assist.Pool) bool {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	return pool.TrySubmit(ctx, nil, assist.Input{}, time.Now(), func(assist.Snapshot) {}) == assist.Closed
}

// attachLocal acquires the store as runContext does, then attaches.
func attachLocal(svc *signerkit.Service, audit *signerkit.AuditLog, root string) (*signerkit.ApprovalRuntime, error) {
	store, err := newApprovalStore(root)
	if err != nil {
		return nil, err
	}
	return attachApprovals(svc, signerkit.StubBackend{}, stubApprovalConfig(root), audit, nil, store)
}

func TestApprovalEngineFactoryGivesEachGenerationAFreshPool(t *testing.T) {
	var pools []*assist.Pool
	previous := newAssistPool
	t.Cleanup(func() { newAssistPool = previous })
	newAssistPool = func(n int, timers assist.Timers) *assist.Pool {
		pool := previous(n, timers)
		pools = append(pools, pool)
		return pool
	}
	svc, _ := stubApprovalService(t)
	base := lifecycle.Config{Clock: elapsed.Real(), Freezer: svc.ApprovalFreezer(time.Hour), SnapshotBuilder: svc.ApprovalSnapshotBuilder(),
		Minter: svc.ApprovalMinter(), AuditWriter: svc.ApprovalAuditWriter(), AssistInputBuilder: approvalAssistInput{}}
	factory := approvalEngineFactory(base)
	var engines []*lifecycle.Engine
	for range 2 {
		engine, err := factory(&lifecycle.MemStore{})
		if err != nil {
			t.Fatal(err)
		}
		engines = append(engines, engine)
	}
	if len(pools) != 2 || pools[0] == pools[1] {
		t.Fatalf("generations share an assist pool: %v", pools)
	}
	engines[0].Close()
	if !isPoolClosed(pools[0]) || isPoolClosed(pools[1]) {
		t.Fatal("closing one generation must close only its own pool")
	}
	engines[1].Close()

	base.Freezer = nil
	if _, err := approvalEngineFactory(base)(&lifecycle.MemStore{}); err == nil {
		t.Fatal("construction without a freezer succeeded")
	}
	if len(pools) != 3 || !isPoolClosed(pools[2]) {
		t.Fatal("failed construction leaked its assist pool")
	}
}

func TestAttachApprovalsOwnsJournalRoot(t *testing.T) {
	svc, audit := stubApprovalService(t)
	root := filepath.Join(t.TempDir(), "approvals")
	runtime, err := attachLocal(svc, audit, root)
	if err != nil {
		t.Fatal(err)
	}
	defer runtime.Close()
	if err := runtime.Status(); err != nil {
		t.Fatalf("durable lifecycle not started: %v", err)
	}
	info, err := os.Lstat(root)
	if err != nil || !info.IsDir() || info.Mode().Perm() != 0o700 {
		t.Fatalf("journal root not created as a 0700 directory: %v %v", info, err)
	}

	second, _ := stubApprovalService(t)
	symlinkParent := filepath.Join(t.TempDir(), "link")
	if err := os.Symlink(filepath.Dir(root), symlinkParent); err != nil {
		t.Fatal(err)
	}
	symlinkRoot := filepath.Join(t.TempDir(), "approvals-link")
	if err := os.Symlink(root, symlinkRoot); err != nil {
		t.Fatal(err)
	}
	for name, path := range map[string]string{
		"same path":        root,
		"symlinked parent": filepath.Join(symlinkParent, "approvals"),
		"symlinked root":   symlinkRoot,
		"missing parent":   filepath.Join(t.TempDir(), "absent", "approvals"),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := attachLocal(second, audit, path); !errors.Is(err, lifecycle.ErrStoreFatal) {
				t.Fatalf("want ErrStoreFatal, got %v", err)
			} else if !strings.HasPrefix(err.Error(), "approval store "+path+": ") {
				t.Fatalf("fatal error does not name the directory: %v", err)
			}
		})
	}
	if err := runtime.Status(); err != nil {
		t.Fatalf("refused contender disturbed the owner: %v", err)
	}
}

func TestAttachApprovalsRecoverableLoadFailureKeepsOwnership(t *testing.T) {
	svc, audit := stubApprovalService(t)
	root := filepath.Join(t.TempDir(), "approvals")
	if err := os.Mkdir(root, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := syscall.Mkfifo(filepath.Join(root, "fifo"), 0o600); err != nil {
		t.Fatal(err)
	}
	runtime, err := attachLocal(svc, audit, root)
	if err != nil {
		t.Fatalf("a listing failure must not be fatal: %v", err)
	}
	defer runtime.Close()
	var coded *ap.CodeError
	if err := runtime.Status(); !errors.As(err, &coded) || coded.Code != ap.CodeLifecycleUnavailable || !strings.Contains(coded.Msg, "fifo") {
		t.Fatalf("want diagnosed lifecycle_unavailable naming the entry, got %v", err)
	}
	second, _ := stubApprovalService(t)
	if _, err := attachLocal(second, audit, root); !errors.Is(err, lifecycle.ErrStoreFatal) {
		t.Fatalf("ownership was not retained across the failed load: %v", err)
	}
}

func TestLoadConfigJournalRootMustBeAbsolute(t *testing.T) {
	_, err := loadConfig(writeTOML(t, validConfig+"\n[approvals]\njournal_root = \"relative/approvals\"\n"))
	if err == nil || !strings.Contains(err.Error(), "approvals.journal_root") {
		t.Fatalf("want journal_root refusal, got %v", err)
	}
	cfg, err := loadConfig(writeTOML(t, validConfig+"\n[approvals]\njournal_root = \"/srv/approvals\"\n"))
	if err != nil || cfg.Approvals.JournalRoot != "/srv/approvals" {
		t.Fatalf("configured journal_root: %q %v", cfg.Approvals.JournalRoot, err)
	}
	hosted := strings.Replace(validConfig, `type = "stub"`, `type = "hosted"`, 1)
	if _, err := loadConfig(writeTOML(t, hosted+"\n[approvals]\njournal_root = \"relative/approvals\"\n")); err != nil {
		t.Fatalf("hosted mode never opens journal_root but was refused: %v", err)
	}
}

func TestDoInitFlowStoreFailureWritesNoKey(t *testing.T) {
	root := t.TempDir()
	if err := os.Mkdir(filepath.Join(root, "approvals"), 0o755); err != nil {
		t.Fatal(err)
	}
	err := doInitFlow(filepath.Join(root, "config.toml"), true)
	if !errors.Is(err, lifecycle.ErrStoreFatal) {
		t.Fatalf("want approval store refusal, got %v", err)
	}
	for _, name := range []string{"gate.key", "gate.pub", "config.toml"} {
		if _, err := os.Lstat(filepath.Join(root, name)); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("%s written before the store was acquired: %v", name, err)
		}
	}
}

func TestDoInitFlowCreatesJournalRoot(t *testing.T) {
	configPath := filepath.Join(t.TempDir(), "config.toml")
	if err := doInitFlow(configPath, true); err != nil {
		t.Fatal(err)
	}
	cfg, err := loadConfig(configPath)
	if err != nil {
		t.Fatal(err)
	}
	want := filepath.Join(filepath.Dir(cfg.Paths.Key), "approvals")
	if cfg.Approvals.JournalRoot != want {
		t.Fatalf("journal_root %q, want %q", cfg.Approvals.JournalRoot, want)
	}
	info, err := os.Lstat(want)
	if err != nil {
		t.Fatal(err)
	}
	stat := info.Sys().(*syscall.Stat_t)
	if !info.IsDir() || info.Mode().Perm() != 0o700 || stat.Uid != uint32(os.Geteuid()) {
		t.Fatalf("journal root mode %v uid %d", info.Mode(), stat.Uid)
	}
	store, err := lifecycle.OpenFileStore(want, uint32(os.Geteuid()))
	if err != nil {
		t.Fatalf("daemon cannot open the initialized store: %v", err)
	}
	store.Close()
}
