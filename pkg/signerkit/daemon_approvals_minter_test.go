package signerkit

import (
	"context"
	"crypto"
	"crypto/ed25519"
	"encoding/json"
	"io"
	"testing"
	"time"

	ap "github.com/karthikeyan5/sshgate/src/approvalplan"
	st "github.com/karthikeyan5/sshgate/src/approvalplan/statetest"
	"github.com/karthikeyan5/sshgate/src/sigwire"
)

type countingApprovalSigner struct {
	crypto.Signer
	calls int
}

func (s *countingApprovalSigner) Sign(r io.Reader, b []byte, opts crypto.SignerOpts) ([]byte, error) {
	s.calls++
	return s.Signer.Sign(r, b, opts)
}

func TestApprovalMinterRoutePayloads(t *testing.T) {
	key, public := goldenSignerKey()
	signer := &countingApprovalSigner{Signer: key}
	at := time.Date(2020, 1, 2, 3, 4, 5, 0, time.UTC)
	daemon := &Daemon{Signer: signer, NowFunc: func() time.Time { return at.Add(10 * 365 * 24 * time.Hour) }}
	mint := (&Service{daemon: daemon}).ApprovalMinter()
	reveal := st.Reveal("cat /etc/token")
	reveal.Alias = "db-1"
	plan := st.Freeze(st.JobDraft(st.ID(1), ap.CoordinatorExecutor, at,
		st.Read("df -h"), st.Write("touch /tmp/a", 47), st.Read("uptime"), reveal, st.Write("touch /tmp/b", 59)), st.PrincipalA, at, time.Hour)
	check := func(plan ap.ApprovalPlanV1, want []sigwire.SigPayload) {
		t.Helper()
		before := signer.calls
		signatures, err := mint.Mint(context.Background(), plan, at)
		if err != nil {
			t.Fatal(err)
		}
		if len(signatures) != len(want) || signer.calls-before != len(want) {
			t.Fatalf("signatures=%d signing calls=%d want=%d", len(signatures), signer.calls-before, len(want))
		}
		nonces := map[string]bool{}
		for i, encoded := range signatures {
			signature, payload, err := sigwire.DecodeSigned(encoded)
			if err != nil {
				t.Fatal(err)
			}
			raw, err := json.Marshal(payload)
			if err != nil || !ed25519.Verify(public, raw, signature) {
				t.Fatal("signature does not authenticate payload")
			}
			if payload.Nonce == "" || nonces[payload.Nonce] {
				t.Fatal("missing or reused nonce")
			}
			nonces[payload.Nonce] = true
			payload.Nonce = ""
			if payload != want[i] {
				t.Fatalf("leg %d: %+v want %+v", i, payload, want[i])
			}
		}
	}
	var expected []sigwire.SigPayload
	for _, step := range plan.CommandJob.Steps {
		if step.Route.Signed() {
			expected = append(expected, sigwire.SigPayload{Cmd: step.ExactCommand, Host: step.Target.TrustedHostFingerprint, TS: at.Unix(), Exp: at.Unix() + int64(step.SignatureTTLSeconds), Reveal: step.Route == ap.RouteSignedReveal})
		}
	}
	check(plan, expected)

	admin := st.Freeze(st.JobDraft(st.ID(4), ap.CoordinatorExecutor, at, st.StepSpec{Route: ap.RouteSignedAdmin, Command: "SSHGATE_REVOKE", TTL: 60, Alias: "web-1"}), st.PrincipalA, at, time.Hour)
	check(admin, []sigwire.SigPayload{{Cmd: "SSHGATE_REVOKE", Host: st.Fingerprint("web-1"), TS: at.Unix(), Exp: at.Unix() + 60}})
	before := signer.calls
	unsigned := st.Freeze(st.JobDraft(st.ID(2), ap.CoordinatorExecutor, at, st.Read("uptime")), st.PrincipalA, at, time.Hour)
	if signatures, err := mint.Mint(context.Background(), unsigned, at); err == nil || len(signatures) != 0 || signer.calls != before {
		t.Fatal("invalid unsigned-only plan reached signing")
	}

	transferService, draft := adapterTransfer(t, at)
	daemon.XferRegistry = transferService.daemon.XferRegistry
	plan, err := transferService.ApprovalFreezer(time.Hour).Freeze(context.Background(), draft, st.PrincipalA, "", at)
	if err != nil {
		t.Fatal(err)
	}
	transfer := plan.Transfer

	check(plan, []sigwire.SigPayload{
		{Cmd: transfer.SendCommand, Host: transfer.Source.Target.TrustedHostFingerprint, TS: at.Unix(), Exp: at.Unix() + 37},
		{Cmd: transfer.RecvCommand, Host: transfer.Destination.Target.TrustedHostFingerprint, TS: at.Unix(), Exp: at.Unix() + 37},
	})
}
