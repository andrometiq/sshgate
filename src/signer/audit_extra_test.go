package signer_test

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/karthikeyan5/sshgate/pkg/signerkit"
)

// TestAuditLog_WriteAfterCloseErrors pins the file-backed contract that
// the daemon's shutdown path relies on: once Close() has released the
// underlying *os.File, a subsequent Write must return an error (not panic,
// not silently succeed). audit.go documents "After Close, Write will
// return an error from the kernel"; the existing mem-pipe test covers the
// pipe variant, this covers the real OpenAuditLog/disk variant.
func TestAuditLog_WriteAfterCloseErrors(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "approvals.log")
	log, err := signerkit.OpenAuditLog(path)
	if err != nil {
		t.Fatalf("OpenAuditLog: %v", err)
	}

	ev := signerkit.AuditEvent{
		TS:        time.Unix(1000, 0).UTC(),
		RequestID: "r_pre",
		Status:    "approved",
		Commands:  []string{"echo ok"},
		Servers:   []string{"prod"},
	}
	if err := log.Write(ev); err != nil {
		t.Fatalf("Write before Close: %v", err)
	}
	if err := log.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	// Second Close is a no-op (f is nil'd) and must not error.
	if err := log.Close(); err != nil {
		t.Errorf("second Close = %v; want nil (idempotent close)", err)
	}

	// Write after Close must error rather than panic on the nil *os.File.
	post := signerkit.AuditEvent{
		TS:        time.Unix(1001, 0).UTC(),
		RequestID: "r_post",
		Status:    "approved",
		Commands:  []string{"echo nope"},
		Servers:   []string{"prod"},
	}
	if err := log.Write(post); err == nil {
		t.Error("Write after Close returned nil; want an error from the released file handle")
	}
}
