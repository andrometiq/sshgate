package hosted

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"testing"

	"github.com/karthikeyan5/sshgate/pkg/signerkit/policystore"
)

func TestAttachPolicyRejectsInvalidMachineClientIdentity(t *testing.T) {
	database, store, core, audit, input := newHostedPolicyHarness(t, 1)
	defer database.Close()
	engine := newTestEngine(t, store, core, audit, input.Now, nil)
	lease, archive := testPolicyArchive(t)
	defer lease.Close()
	server := NewServer("secret", nil, nil)
	server.Human = &HumanAPI{}
	server.MachineClientID = strings.Repeat("x", policystore.MaxIdentityBytes+1)
	err := server.AttachPolicy(&PolicyAPIConfig{
		Engine: engine, Handler: http.NotFoundHandler(), Archive: archive,
		Lease: lease, DurableAudit: audit,
	})
	if !errors.Is(err, policystore.ErrInvalidIdentity) {
		t.Fatalf("AttachPolicy invalid MachineClientID = %v", err)
	}
	if engine.Readiness().Ready() {
		t.Fatal("invalid MachineClientID made policy ready")
	}
	if _, err := store.VerifyAuthorityBinding(context.Background()); err != nil {
		t.Fatalf("test binding was unexpectedly changed: %v", err)
	}
}
