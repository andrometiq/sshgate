//go:build linux

package signerkit

import (
	"os"
	"testing"
)

func TestServiceClosesApprovalsBeforePolicyJournal(t *testing.T) {
	root := t.TempDir()
	if err := os.Chmod(root, 0700); err != nil {
		t.Fatal(err)
	}
	journal, err := openLocalPolicyJournal(root)
	if err != nil {
		t.Fatal(err)
	}
	store := &runtimeStore{close: func() error {
		if err := journal.view(func(*policyJournalDisk) error { return nil }); err != nil {
			t.Errorf("journal closed before approvals: %v", err)
		}
		return nil
	}}
	runtime, err := NewApprovalRuntime(runtimeConfig(t, store))
	if err != nil {
		t.Fatal(err)
	}
	service := &Service{daemon: &Daemon{policyJournal: journal}}
	if err := service.AttachApprovals(runtime); err != nil {
		t.Fatal(err)
	}
	if err := service.Close(); err != nil {
		t.Fatal(err)
	}
	if err := journal.view(func(*policyJournalDisk) error { return nil }); err == nil {
		t.Fatal("journal left open")
	}
	if err := service.Close(); err != nil {
		t.Fatal(err)
	}
}
