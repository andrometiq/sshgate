package approvalreview

import (
	"crypto/ecdh"
	"crypto/ed25519"
	"strings"
	"testing"
	"time"

	"github.com/karthikeyan5/sshgate/src/approvalplan"
	"github.com/karthikeyan5/sshgate/src/xfer"
)

const fpWeb = "SHA256:47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU"

type goldenCase struct {
	name string
	snap ReviewSnapshot
}

func legacyBase() LegacyRequest {
	return LegacyRequest{RequestID: "9f1c2e4a7b", Requester: "local-uid:1000", SubmittedAt: t0, ExpiresAt: t0.Add(5 * time.Minute)}
}

// worstCasePlan exercises 32 steps with 24 KiB of four-fold escaped bytes.
// The packing sweep separately covers maximum route fields and secret expansion.
func worstCasePlan(t testing.TB) approvalplan.ApprovalPlanV1 {
	var specs []stepSpec
	for range approvalplan.MaxSteps {
		specs = append(specs, signed(strings.Repeat("\x01", approvalplan.MaxTotalBytes/approvalplan.MaxSteps)))
	}
	return withSteps(t, specs...)
}

func registrationKeys(t testing.TB, r *approvalplan.RegisterTransferKey) {
	t.Helper()
	var seed [32]byte
	for i := range seed {
		seed[i] = byte(i)
	}
	box, err := ecdh.X25519().NewPrivateKey(seed[:])
	if err != nil {
		t.Fatal(err)
	}
	var public [32]byte
	copy(public[:], box.PublicKey().Bytes())
	r.BoxPub = xfer.BoxPublicText(&public)
	r.IDPub = xfer.IDPublicText(ed25519.NewKeyFromSeed(seed[:]).Public().(ed25519.PublicKey))
}

func goldenCases(t *testing.T) []goldenCase {
	t.Helper()
	pem := pemKey()
	sign := legacyBase()
	sign.Commands = []LegacyCommand{
		{Server: "web-1", HostFingerprint: fpWeb, Command: "systemctl restart nginx", TTLSeconds: 60},
		{Server: "web-1", HostFingerprint: fpWeb, Command: "export GITHUB_TOKEN=ghp_abcd1234efgh && ./deploy", TTLSeconds: 60},
		{Server: "db-1", Command: "cat /etc/app/token", TTLSeconds: 60, Reveal: true, Reason: "configure the client with PASSWORD=hunter2secret"},
	}
	updateMalformed := legacyBase()
	updateMalformed.Commands = []LegacyCommand{{Server: "web-1", HostFingerprint: fpWeb, Command: "SSHGATE_UPDATE zz\nNew gate SHA-256: 00", TTLSeconds: 300, Reason: "staged v0.2.0, running v0.1.4"}}
	grant := legacyBase()
	grant.Grant = &LegacyGrant{Alias: "web-1", Scope: "commands", Commands: []string{"systemctl restart worker", "systemctl status worker"}, Duration: time.Hour}
	transfer := legacyBase()
	transfer.Transfer = &LegacyTransfer{
		TransferID: "x8Kq3YVvH4f2m9WqZr0B1g", SourceLabel: "web-1", SourceFingerprint: fpWeb, SourcePath: "/etc/secret",
		DestLabel: "db-1", DestFingerprint: "SHA256:nThbg6kXUpJWGl7E1IGOCspRomTxdCARLviKw6E5SY8", DestPath: "/srv/secret", Mode: "0600",
	}
	register := legacyBase()
	register.Register = &approvalplan.RegisterTransferKey{
		HostFingerprint: fpWeb, Label: "web-1",
	}
	registrationKeys(t, register.Register)
	registerPlan := loadPlan(t, "register-key")
	registrationKeys(t, registerPlan.RegisterTransferKey)
	unicodePlan := withReason(t, withSteps(t,
		signed("echo 'café' \x1b[31mred\x1b[0m \u202Eevil\u202C zero\u200Bwidth \u0430dmin ⟦hidden 0 bytes⟧ \\x41 tab\there")),
		"Fix the d\u0435ploy \u200Bscript ⟦hidden 0 bytes⟧ ✓ Approve")
	return []goldenCase{
		{"write", mustSnapshot(t, loadPlan(t, "write"))},
		{"mixed-batch", mustSnapshot(t, loadPlan(t, "mixed-batch"))},
		{"hosted-mixed-batch", mustSnapshot(t, loadPlan(t, "hosted-mixed-batch"))},
		{"reveal", mustSnapshot(t, loadPlan(t, "reveal"))},
		{"update", mustSnapshot(t, loadPlan(t, "update"))},
		{"revoke", mustSnapshot(t, loadPlan(t, "revoke"))},
		{"escaped", mustSnapshot(t, loadPlan(t, "escaped"))},
		{"grant-v2-commands", mustSnapshot(t, loadPlan(t, "grant-commands"))},
		{"grant-v2-all", mustSnapshot(t, loadPlan(t, "grant-all"))},
		{"transfer", mustSnapshot(t, loadPlan(t, "transfer"))},
		{"register-key", mustSnapshot(t, registerPlan)},
		{"secrets-overlapping", mustSnapshot(t, withSteps(t,
			signed("PGPASSWORD=hunter2secret psql -h db -U admin -c 'select 1'"),
			signed("PASSWORD=AKIA1234567890ABCDEF ./deploy --token ghp_abcd1234efgh")))},
		{"pem-tail", mustSnapshot(t, withSteps(t, signed("cat > /root/.ssh/id <<'EOF'\n"+pem+"EOF\nrm -rf /srv/data")))},
		{"fully-hidden", mustSnapshot(t, withSteps(t, signed(pem)))},
		{"unicode", mustSnapshot(t, unicodePlan)},
		{"worst-case", mustSnapshot(t, worstCasePlan(t))},
		{"legacy-sign", mustLegacy(t, sign)},
		{"legacy-update-malformed", mustLegacy(t, updateMalformed)},
		{"legacy-grant", mustLegacy(t, grant)},
		{"legacy-transfer", mustLegacy(t, transfer)},
		{"legacy-register", mustLegacy(t, register)},
	}
}

func TestGoldens(t *testing.T) {
	for _, c := range goldenCases(t) {
		t.Run(c.name, func(t *testing.T) {
			r := render(t, c.snap, readyAssist())
			checkGolden(t, c.name, r.golden())
			checkTelegramShape(t, r)
		})
	}
}

// checkTelegramShape asserts the bounds and the line discipline of every
// Telegram text: each part and card under PartBytes, at most MaxMessages
// messages and MaxReviewBytes, and no Approve anywhere in a part.
func checkTelegramShape(t *testing.T, r rendered) {
	t.Helper()
	if len(r.parts)+1 > MaxMessages {
		t.Errorf("%d parts plus the card exceed %d messages", len(r.parts), MaxMessages)
	}
	total := len(r.ready)
	for i, p := range r.parts {
		total += len(p)
		if len(p) >= PartBytes {
			t.Errorf("part %d is %d bytes", i+1, len(p))
		}
		if strings.Contains(p, approvalplan.GlyphCheck) || strings.Contains(p, "Approve all") {
			t.Errorf("part %d carries an Approve", i+1)
		}
	}
	if total > MaxReviewBytes {
		t.Errorf("review is %d bytes", total)
	}
	for _, card := range []string{r.preparing, r.ready} {
		if len(card) >= PartBytes {
			t.Errorf("card is %d bytes", len(card))
		}
	}
}
