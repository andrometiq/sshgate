package main

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/karthikeyan5/sshgate/pkg/signerkit/hosted"
	"github.com/karthikeyan5/sshgate/pkg/signerkit/sqlitestore"
)

func captureStartup(t *testing.T, args ...string) (int, string) {
	t.Helper()
	f, err := os.CreateTemp(t.TempDir(), "stderr")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	previous := os.Stderr
	os.Stderr = f
	defer func() { os.Stderr = previous }()
	code := run(args)
	data, err := os.ReadFile(f.Name())
	if err != nil {
		t.Fatal(err)
	}
	return code, string(data)
}

func TestOrdinaryStartupFlagGuards(t *testing.T) {
	for _, tc := range []struct{ flag, value, message string }{
		{"approval-validity", "4m", "approval-validity must be"},
		{"approval-validity", "169h", "approval-validity must be"},
		{"approval-retention", "-1s", "approval-retention and"},
		{"approval-max-age", "-1s", "approval-retention and"},
		{"legacy-v1-pending-ttl", "0", "approval-retention and"},
		{"approval-report-horizon", "59m", "approval-report-horizon must be"},
		{"approval-report-horizon", "169h", "approval-report-horizon must be"},
		{"approval-max-full-rows", "0", "approval row ceilings"},
		{"approval-max-rows", "0", "approval row ceilings"},
		{"approval-max-rows", "4095", "approval row ceilings"},
		{"assist-timeout", "0", "assist-timeout must be"},
		{"assist-endpoint", "bad", "assist: endpoint"},
	} {
		t.Run(tc.flag+tc.value, func(t *testing.T) {
			db := filepath.Join(t.TempDir(), "absent.db")
			code, output := captureStartup(t, "--db", db, "--"+tc.flag, tc.value)
			if code != 1 || !strings.Contains(output, tc.message) {
				t.Fatalf("code %d: %s", code, output)
			}
			if _, err := os.Stat(db); !os.IsNotExist(err) {
				t.Fatalf("database touched: %v", err)
			}
		})
	}
}

func TestBootstrapAdminSeparateRole(t *testing.T) {
	dir := t.TempDir()
	db, err := sqlitestore.Open(filepath.Join(dir, "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	cfg := hosted.AuthConfig{SessionTTL: time.Hour, RPID: "signer.example.com", RPOrigins: []string{"https://signer.example.com"}}
	for i := 0; i < 2; i++ {
		if err := bootstrapAccount(context.Background(), db, cfg, "administrator", filepath.Join(dir, "enrollment"), "admin"); err != nil {
			t.Fatal(err)
		}
	}
	user, err := db.GetUserByName(context.Background(), "administrator")
	if err != nil || user.Role != "admin" {
		t.Fatalf("role: %#v %v", user, err)
	}
	if err := bootstrapAccount(context.Background(), db, cfg, "administrator", filepath.Join(dir, "enrollment"), "operator"); err == nil || !strings.Contains(err.Error(), "different role") {
		t.Fatalf("role changed: %v", err)
	}
}

func TestBootstrapAdminRefusedUntilRoleBarrier(t *testing.T) {
	for _, name := range []string{"administrator", " "} {
		dir := t.TempDir()
		db, artifact := filepath.Join(dir, "state.db"), filepath.Join(dir, "enrollment")
		code, output := captureStartup(t, "--bootstrap-admin", name, "--db", db, "--bootstrap-output-file", artifact, "--rp-id", "signer.example.com", "--rp-origin", "https://signer.example.com")
		if code != 1 || !strings.Contains(output, "bootstrap admin: disabled") || !strings.Contains(output, "README.md") {
			t.Fatalf("admin not refused: %d %s", code, output)
		}
		entries, err := os.ReadDir(dir)
		if err != nil || len(entries) != 0 {
			t.Fatalf("refusal wrote bootstrap state: %v %v", entries, err)
		}
	}
}

func TestHostedProcessDiagnosticWiring(t *testing.T) {
	source, err := os.ReadFile("main.go")
	if err != nil {
		t.Fatal(err)
	}
	text := string(source)
	checkHostedDiagnosticClosure(t)
	// fd 2 is handed only to the process transport, never to another writer.
	if strings.Count(text, "os.Stderr") != 1 || !strings.Contains(text, "hosted.NewProcessAuditSink(os.Stderr)") {
		t.Fatal("direct stderr writer on hosted process path")
	}
	for _, binding := range []string{"log.SetOutput(transport)", "fs.SetOutput(transport)", "log.New(transport,", "ErrorLog:", "Audit:  transport", "server.StartApprovals(database, core, transport, ordinary)", "defer func() { _ = srv.Close() }()"} {
		if !strings.Contains(text, binding) {
			t.Errorf("missing transport/lifecycle binding %s", binding)
		}
	}
	code, output := captureStartup(t, "--help")
	if code != 2 || !strings.Contains(output, "approval-validity") {
		t.Fatalf("diagnostic not drained: %d %s", code, output)
	}
}

func TestAssistStartupKeyValidation(t *testing.T) {
	key := filepath.Join(t.TempDir(), "key")
	if err := os.WriteFile(key, []byte("test-token"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(key, 0644); err != nil {
		t.Fatal(err)
	}
	args := []string{"--assist-endpoint", "https://assist.example.com/v1/chat/completions", "--assist-model", "test-model", "--assist-key-file", key}
	if code, output := captureStartup(t, args...); code != 1 || !strings.Contains(output, "permission bits") {
		t.Fatalf("insecure key: %d %s", code, output)
	}
	if err := os.Chmod(key, 0600); err != nil {
		t.Fatal(err)
	}
	if code, output := captureStartup(t, args...); code != 1 || !strings.Contains(output, "--api-key-file is required") {
		t.Fatalf("valid provider failed offline validation: %d %s", code, output)
	}
}
