package hosted_test

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/karthikeyan5/sshgate/pkg/signerkit/hosted"
	"github.com/karthikeyan5/sshgate/src/approvalplan"
)

func TestOrdinaryRequiredApprovalsBound(t *testing.T) {
	core, db := newAPICore(t)
	for _, human := range []bool{false, true} {
		for _, n := range []int{-1, 0, 1, 256, 257} {
			cfg := hosted.Config{Core: core, Store: db, APIKey: "key", MachineClientID: "client", RequiredApprovals: n}
			if human {
				cfg.Auth = hosted.AuthConfig{RPID: "localhost", RPOrigins: []string{"https://localhost"}, SessionTTL: time.Hour}
			}
			server, err := hosted.New(cfg)
			if n > 256 || (human && n <= 0) {
				if server != nil || !errors.Is(err, hosted.ErrInvalidRequiredApprovals) {
					t.Fatalf("human=%v N=%d: server=%v error=%v", human, n, server, err)
				}
				continue
			}
			if err != nil {
				t.Fatalf("human=%v N=%d: %v", human, n, err)
			}
			want := n
			if want <= 0 {
				want = 1
			}
			if server.RequiredApprovals != want {
				t.Fatalf("N=%d: got %d", n, server.RequiredApprovals)
			}
			server.Close()
		}
	}
}

func TestOrdinarySnapshotRedactsAndPersistsWithoutSalt(t *testing.T) {
	raw, err := os.ReadFile("../../../src/approvalplan/testdata/plans/write.json")
	if err != nil {
		t.Fatal(err)
	}
	var plan approvalplan.ApprovalPlanV1
	if err := json.Unmarshal(raw, &plan); err != nil {
		t.Fatal(err)
	}
	plan.Rationale = "Rotate PASSWORD=ordinary-review-secret"
	step := &plan.CommandJob.Steps[0]
	step.ExactCommand = "PASSWORD=ordinary-command-secret ./deploy"
	step.CommandSHA256 = fmt.Sprintf("%x", sha256.Sum256([]byte(step.ExactCommand)))
	first, err := hosted.BuildApprovalSnapshot(plan)
	if err != nil {
		t.Fatal(err)
	}
	second, err := hosted.BuildApprovalSnapshot(plan)
	if err != nil {
		t.Fatal(err)
	}
	a, err := first.Encode()
	if err != nil {
		t.Fatal(err)
	}
	b, err := second.Encode()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(a, b) {
		t.Fatal("fresh salts changed persisted review")
	}
	if first.Steps[0].Command.HiddenBytes == 0 || bytes.Contains(a, []byte("ordinary-command-secret")) || first.Reason.HiddenBytes == 0 || bytes.Contains(a, []byte("ordinary-review-secret")) || bytes.Contains(a, []byte("salt")) {
		t.Fatalf("unsafe snapshot: %s", a)
	}
	plan.Version = 0
	if _, err := hosted.BuildApprovalSnapshot(plan); err == nil {
		t.Fatal("invalid plan accepted")
	}
}
