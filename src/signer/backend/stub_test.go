package backend_test

import (
	"context"
	"testing"
	"time"

	"github.com/karthikeyan5/sshgate/pkg/signerkit"
)

func TestStubBackend_DeniesImmediately(t *testing.T) {
	t.Parallel()
	var b signerkit.StubBackend
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	ch, err := b.Request(ctx, signerkit.ApprovalRequest{
		RequestID: "r_stub",
		Commands:  []signerkit.CommandReq{{Server: "x", Cmd: "echo hi", TTLSec: 60}},
		Submitted: time.Now(),
	})
	if err != nil {
		t.Fatalf("Request returned err: %v", err)
	}
	select {
	case got := <-ch:
		if got.Status != signerkit.StatusDenied {
			t.Errorf("status = %v; want StatusDenied", got.Status)
		}
		if got.ApprovedBy != "" {
			t.Errorf("ApprovedBy = %q; want empty", got.ApprovedBy)
		}
	case <-time.After(time.Second):
		t.Fatal("stub did not resolve within 1s")
	}
}

func TestStubBackend_DeniesEvenWhenCtxAlive(t *testing.T) {
	t.Parallel()
	// The stub MUST NOT block on ctx — its whole point is "policy = deny
	// without consulting any external channel."
	var b signerkit.StubBackend
	ch, err := b.Request(context.Background(), signerkit.ApprovalRequest{RequestID: "r"})
	if err != nil {
		t.Fatalf("Request err: %v", err)
	}
	select {
	case got := <-ch:
		if got.Status != signerkit.StatusDenied {
			t.Errorf("status = %v; want denied", got.Status)
		}
	case <-time.After(200 * time.Millisecond):
		t.Fatal("stub did not deny within 200ms")
	}
}

// Compile-time assertion that StubBackend satisfies the interface.
var _ signerkit.Backend = (*signerkit.StubBackend)(nil)
