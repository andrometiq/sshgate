package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRequiredApprovalsLimitBeforeStoreOpen(t *testing.T) {
	for _, ui := range []bool{false, true} {
		t.Run(map[bool]string{false: "machine", true: "human"}[ui], func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "must-not-exist.db")
			captured := runCapturingStderr(t, "257", path, ui)
			if !strings.Contains(captured, "--required-approvals must not exceed 256") {
				t.Fatalf("missing limit: %s", captured)
			}
			if _, err := os.Stat(path); !os.IsNotExist(err) {
				t.Fatalf("database touched: %v", err)
			}
		})
	}
}

// The largest allowed quorum passes the limit check and fails later, on the
// first missing startup flag instead.
func TestRequiredApprovalsLimitAcceptsMaximum(t *testing.T) {
	for ui, next := range map[bool]string{false: "--api-key-file is required", true: "--rp-id is required with --ui"} {
		t.Run(map[bool]string{false: "machine", true: "human"}[ui], func(t *testing.T) {
			captured := runCapturingStderr(t, "256", filepath.Join(t.TempDir(), "signer.db"), ui)
			if strings.Contains(captured, "must not exceed") || !strings.Contains(captured, next) {
				t.Fatalf("256 not accepted by the limit check: %s", captured)
			}
		})
	}
}

func runCapturingStderr(t *testing.T, requiredApprovals, path string, ui bool) string {
	t.Helper()
	args := []string{"--required-approvals", requiredApprovals, "--db", path}
	if ui {
		args = append(args, "--ui")
	}
	output, err := os.CreateTemp(t.TempDir(), "stderr")
	if err != nil {
		t.Fatal(err)
	}
	defer output.Close()
	previous := os.Stderr
	os.Stderr = output
	defer func() { os.Stderr = previous }()
	if code := run(args); code == 0 {
		t.Fatal("startup succeeded with an incomplete configuration")
	}
	captured, err := os.ReadFile(output.Name())
	if err != nil {
		t.Fatal(err)
	}
	return string(captured)
}
