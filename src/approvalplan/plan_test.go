package approvalplan

import (
	"bytes"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"
)

var (
	t0      = time.Date(2026, 10, 15, 9, 30, 0, 0, time.UTC)
	fpA     = "SHA256:47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU"
	fpB     = "SHA256:nThbg6kXUpJWGl7E1IGOCspRomTxdCARLviKw6E5SY8"
	tokenA  = [32]byte{1, 2, 3}
	boxText = "sshgate-box-pub-v1 AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8="
	idText  = "sshgate-id-pub-v1 ICEiIyQlJicoKSorLC0uLzAxMjM0NTY3ODk6Ozw9Pj8="
)

func route(alias, fp string) RouteSnapshot {
	return RouteSnapshot{
		ServerAlias: alias, ResolvedHost: alias + ".example.net", ResolvedPort: 22, ResolvedUser: "deploy",
		TrustedHostFingerprint: fp, AddedAt: time.Date(2026, 9, 1, 8, 0, 0, 0, time.UTC),
	}
}

func step(ordinal int, r Route, cmd string, ttl int, target RouteSnapshot) Step {
	return Step{
		Ordinal: ordinal, Route: r, Target: target, RegistryEntryDigest: target.Digest(),
		ExactCommand: cmd, CommandSHA256: sha256Hex(cmd), SignatureTTLSeconds: ttl,
	}
}

func jobDraft(id, reason string, coord Coordinator, steps ...Step) ApprovalDraft {
	maxOut := int64(262144)
	if coord == CoordinatorInProcessSync {
		maxOut = 0
	}
	return ApprovalDraft{
		Version: DraftVersion, Kind: KindCommandJob, RequestID: id, Rationale: reason,
		ExecutorClaimTokenHash: ClaimTokenHash(tokenA), SubmitNotAfter: t0.Add(SubmitWindowMax), Coordinator: coord,
		CommandJob: &CommandJob{Steps: steps, StopPolicy: StopClassDefaultWritesOnly, MaxOutputBytes: maxOut},
	}
}

// freeze builds the plan a signer would freeze from d at t0. For a transfer
// it fills the signer-side fields with fixed values.
func freeze(d ApprovalDraft, principal, sub string) ApprovalPlanV1 {
	p := ApprovalPlanV1{
		Version: PlanVersion, Kind: d.Kind, RequestID: d.RequestID, RequesterPrincipal: principal, RequesterSub: sub,
		SubmittedAt: t0, RequestExpiresAt: t0.Add(ValidityDefault), Rationale: d.Rationale, RationaleOrigin: OriginAgent,
		ExecutorClaimTokenHash: d.ExecutorClaimTokenHash, SubmitNotAfter: d.SubmitNotAfter, Coordinator: d.Coordinator,
		CommandJob: d.CommandJob, StandingGrant: d.StandingGrant,
	}
	if d.Transfer != nil {
		tr := *d.Transfer
		tr.Source.KeyLabel, tr.Source.PublicKey, tr.Source.PublicKeySHA256, tr.Source.KeyEntryDigest = "web-1", idText, sha256Hex(idText), sha256Hex("src-entry")
		tr.Destination.KeyLabel, tr.Destination.PublicKey, tr.Destination.PublicKeySHA256, tr.Destination.KeyEntryDigest = "db-1", boxText, sha256Hex(boxText), sha256Hex("dst-entry")
		tr.TransferID = "x8Kq3YVvH4f2m9WqZr0B1g"
		tr.SendCommand = "SSHGATE_XFER_SEND Ym94 eDhL ZGVzdA L2V0Yy9zZWNyZXQ"
		tr.RecvCommand = "SSHGATE_XFER_RECV aWQ eDhL c3Jj ZGVzdA MDYwMA L3Nydi9zZWNyZXQ"
		tr.SendCommandSHA256, tr.RecvCommandSHA256 = sha256Hex(tr.SendCommand), sha256Hex(tr.RecvCommand)
		p.Transfer = &tr
	}
	return p
}

// fixture is one golden plan: its draft (absent for a plan-only kind) and plan.
type fixture struct {
	name  string
	draft *ApprovalDraft
	plan  ApprovalPlanV1
}

const (
	idOne   = "a2_AAAAAAAAAAAAAAAAAAAAAA"
	idTwo   = "a2_BBBBBBBBBBBBBBBBBBBBBB"
	idThree = "a2_x-_0123456789abcdefghi"
)

func fixtures() []fixture {
	web, db := route("web-1", fpA), route("db-1", fpB)
	ro := route("ro-1", "")
	ro.ReadOnly = true
	upd := step(1, RouteSignedAdmin, "SSHGATE_UPDATE "+strings.Repeat("ab", 32), 300, web)
	upd.TrustedDisplay = &TrustedDisplay{StagedBasename: "sshgate-gate-linux-amd64", StagedVersion: "v0.2.0", RunningVersion: "v0.1.4", Size: 6291456}
	escaped := jobDraft(idThree, "Rotate <tls> & reload — café", CoordinatorInProcessSync,
		step(1, RouteSignedWrite, `printf '<a href="x">&amp;</a>\n' > /srv/index.html`, 30, web))
	transfer := ApprovalDraft{
		Version: DraftVersion, Kind: KindTransfer, RequestID: idTwo, Rationale: "Copy the TLS key to the new database host",
		ExecutorClaimTokenHash: ClaimTokenHash(tokenA), SubmitNotAfter: t0.Add(SubmitWindowMax), Coordinator: CoordinatorExecutor,
		Transfer: &Transfer{
			Source:      TransferEndpoint{Target: web, RegistryEntryDigest: web.Digest(), Path: "/etc/secret"},
			Destination: TransferEndpoint{Target: db, RegistryEntryDigest: db.Digest(), Path: "/srv/secret"},
			Mode:        TransferMode, SignatureTTLSeconds: 300,
		},
	}
	grantCmds := ApprovalDraft{
		Version: DraftVersion, Kind: KindStandingGrant, RequestID: idOne, Rationale: "Restart the worker while I debug",
		SubmitNotAfter: t0.Add(SyncSubmitWindow),
		StandingGrant: &StandingGrant{
			Alias: "web-1", Scope: GrantScopeCommands, Commands: []string{"systemctl restart worker", "systemctl status worker"},
			DurationSeconds: 3600, TrustedHostFingerprint: fpA, RegistryEntryDigest: web.Digest(),
		},
	}
	grantAll := grantCmds
	grantAll.StandingGrant = &StandingGrant{Alias: "db-1", Scope: GrantScopeAll, DurationSeconds: 86400, TrustedHostFingerprint: fpB, RegistryEntryDigest: db.Digest()}
	drafts := []struct {
		name string
		d    ApprovalDraft
	}{
		{"write", jobDraft(idOne, "Restart nginx after the config change", CoordinatorExecutor,
			step(1, RouteSignedWrite, "systemctl restart nginx", 60, web))},
		{"mixed-batch", jobDraft(idOne, "Rotate logs and check disk", CoordinatorExecutor,
			step(1, RouteUnsignedRead, "df -h /var", 0, web),
			step(2, RouteSignedWrite, "logrotate -f /etc/logrotate.conf", 60, web),
			step(3, RouteUnsignedRead, "df -h /var", 0, ro))},
		{"reveal", jobDraft(idOne, "Read the API token to configure the client", CoordinatorInProcessSync,
			step(1, RouteSignedReveal, "cat /etc/app/token", 60, db))},
		{"revoke", jobDraft(idOne, "Decommission this host", CoordinatorInProcessSync,
			step(1, RouteSignedAdmin, "SSHGATE_REVOKE", 60, db))},
		{"update", jobDraft(idOne, "Upgrade the gate to v0.2.0", CoordinatorInProcessSync, upd)},
		{"escaped", escaped},
		{"grant-commands", grantCmds},
		{"grant-all", grantAll},
		{"transfer", transfer},
	}
	var out []fixture
	for _, d := range drafts {
		d := d
		out = append(out, fixture{name: d.name, draft: &d.d, plan: freeze(d.d, "local-uid:1000", "")})
	}
	hosted := out[1].plan
	hosted.RequesterPrincipal, hosted.RequesterSub = "machine-client", "local-uid:1000"
	out = append(out, fixture{name: "hosted-mixed-batch", draft: out[1].draft, plan: hosted})
	out = append(out, fixture{name: "register-key", plan: ApprovalPlanV1{
		Version: PlanVersion, Kind: KindRegisterTransferKey, RequestID: idOne, RequesterPrincipal: "local-uid:0",
		SubmittedAt: t0, RequestExpiresAt: t0.Add(ValidityMin), Rationale: CLIRationaleText, RationaleOrigin: OriginTrustedHumanCLI,
		SubmitNotAfter:      t0.Add(SubmitWindowMax),
		RegisterTransferKey: &RegisterTransferKey{HostFingerprint: fpB, Label: "db-1", BoxPub: boxText, IDPub: idText},
	}})
	return out
}

func TestFixturesAreValid(t *testing.T) {
	for _, f := range fixtures() {
		if f.draft != nil {
			if err := f.draft.Validate(); err != nil {
				t.Errorf("%s draft: %v", f.name, err)
			}
		}
		if err := f.plan.Validate(); err != nil {
			t.Errorf("%s plan: %v", f.name, err)
		}
	}
}

func mustCanon(t testing.TB, v any) []byte {
	t.Helper()
	b, err := Canonical(v)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func codeOf(err error) Code {
	var ce *CodeError
	if errors.As(err, &ce) {
		return ce.Code
	}
	return ""
}

func fieldOf(err error) string {
	var ce *CodeError
	if errors.As(err, &ce) {
		return ce.Field
	}
	return ""
}

func TestDecodeDraftRoundTripsEveryFixture(t *testing.T) {
	for _, f := range fixtures() {
		if f.draft == nil {
			continue
		}
		b := mustCanon(t, *f.draft)
		got, err := DecodeDraft(b)
		if err != nil {
			t.Fatalf("%s: %v", f.name, err)
		}
		if again := mustCanon(t, got); !bytes.Equal(again, b) {
			t.Fatalf("%s: round trip changed the bytes", f.name)
		}
	}
}

// editDraft returns the canonical draft with one textual substitution.
func editDraft(t *testing.T, d ApprovalDraft, old, replacement string) []byte {
	t.Helper()
	b := string(mustCanon(t, d))
	if !strings.Contains(b, old) {
		t.Fatalf("draft has no %q", old)
	}
	return []byte(strings.Replace(b, old, replacement, 1))
}

func TestDecodeDraftIsStrict(t *testing.T) {
	write := fixtures()[0].draft
	canon := mustCanon(t, *write)
	grant := *fixtures()[6].draft
	cases := map[string][]byte{
		"requester-chosen validity": editDraft(t, *write, `"version":1,`, `"version":1,"validity_seconds":600,`),
		"rationale origin":          editDraft(t, *write, `"version":1,`, `"version":1,"rationale_origin":"trusted_human_cli",`),
		"unknown step field":        editDraft(t, *write, `"ordinal":1,`, `"ordinal":1,"signed":true,`),
		"binary sha256 field":       editDraft(t, *write, `"ordinal":1,`, `"ordinal":1,"binary_sha256":"00",`),
		"trailing value":            append(append([]byte{}, canon...), []byte(` {}`)...),
		"trailing garbage":          append(append([]byte{}, canon...), 'x'),
		"leading whitespace":        append([]byte(" "), canon...),
		"duplicate key":             editDraft(t, *write, `"version":1,`, `"version":1,"version":1,`),
		"case-folded key":           editDraft(t, *write, `"version":1,`, `"Version":1,`),
		"escaped letter":            editDraft(t, *write, `"kind":"command_job"`, `"kind":"comm\u0061nd_job"`),
		"unescaped html":            editDraft(t, *fixtures()[5].draft, `\u003c`, `<`),
		"invalid utf-8":             editDraft(t, *write, "Restart nginx", "Restart \xffnginx"),
		"non-utc time":              editDraft(t, *write, `"submit_not_after":"2026-10-15T10:30:00Z"`, `"submit_not_after":"2026-10-15T12:30:00+02:00"`),
		"fractional zero time":      editDraft(t, *write, `"submit_not_after":"2026-10-15T10:30:00Z"`, `"submit_not_after":"2026-10-15T10:30:00.000Z"`),
		"empty claim token field":   editDraft(t, grant, `"submit_not_after"`, `"executor_claim_token_hash":"","submit_not_after"`),
		"float number":              editDraft(t, *write, `"ordinal":1`, `"ordinal":1.0`),
	}
	for name, b := range cases {
		if _, err := DecodeDraft(b); codeOf(err) != CodeInvalidRequest {
			t.Errorf("%s: DecodeDraft = %v, want invalid_request", name, err)
		}
	}
	big := make([]byte, MaxDraftBytes+1)
	if _, err := DecodeDraft(big); codeOf(err) != CodeRequestTooLarge {
		t.Errorf("oversized draft: %v", err)
	}
}

func TestDraftValidateRefusals(t *testing.T) {
	base := func() ApprovalDraft {
		web := route("web-1", fpA)
		return jobDraft(idOne, "Restart nginx", CoordinatorExecutor, step(1, RouteSignedWrite, "systemctl restart nginx", 60, web))
	}
	grant := func() ApprovalDraft { return *fixtures()[6].draft }
	transfer := func() ApprovalDraft { return *fixtures()[8].draft }
	cases := []struct {
		name  string
		draft func() ApprovalDraft
		code  Code
		field string
	}{
		{"version", func() ApprovalDraft { d := base(); d.Version = 2; return d }, CodeInvalidRequest, "version"},
		{"register kind", func() ApprovalDraft { d := base(); d.Kind = KindRegisterTransferKey; return d }, CodeInvalidRequest, "kind"},
		{"unknown kind", func() ApprovalDraft { d := base(); d.Kind = "shell"; return d }, CodeInvalidRequest, "kind"},
		{"request id", func() ApprovalDraft { d := base(); d.RequestID = "r_123"; return d }, CodeInvalidRequest, "request_id"},
		{"untrimmed reason", func() ApprovalDraft { d := base(); d.Rationale = " x "; return d }, CodeInvalidRequest, "reason"},
		{"empty reason", func() ApprovalDraft { d := base(); d.Rationale = ""; return d }, CodeInvalidRequest, "reason"},
		{"zero submit_not_after", func() ApprovalDraft { d := base(); d.SubmitNotAfter = time.Time{}; return d }, CodeInvalidRequest, "submit_not_after"},
		{"job without claim token", func() ApprovalDraft { d := base(); d.ExecutorClaimTokenHash = ""; return d }, CodeInvalidRequest, "executor_claim_token_hash"},
		{"job with uppercase claim token", func() ApprovalDraft {
			d := base()
			d.ExecutorClaimTokenHash = strings.ToUpper(d.ExecutorClaimTokenHash)
			return d
		}, CodeInvalidRequest, "executor_claim_token_hash"},
		{"transfer without claim token", func() ApprovalDraft { d := transfer(); d.ExecutorClaimTokenHash = ""; return d }, CodeInvalidRequest, "executor_claim_token_hash"},
		{"grant with claim token", func() ApprovalDraft { d := grant(); d.ExecutorClaimTokenHash = ClaimTokenHash(tokenA); return d }, CodeInvalidRequest, "executor_claim_token_hash"},
		{"grant with coordinator", func() ApprovalDraft { d := grant(); d.Coordinator = CoordinatorExecutor; return d }, CodeInvalidRequest, "coordinator"},
		{"job without coordinator", func() ApprovalDraft { d := base(); d.Coordinator = ""; return d }, CodeInvalidRequest, "coordinator"},
		{"two payloads", func() ApprovalDraft { d := base(); d.StandingGrant = grant().StandingGrant; return d }, CodeInvalidRequest, "command_job"},
		{"payload of another kind", func() ApprovalDraft { d := grant(); d.Kind = KindCommandJob; return d }, CodeInvalidRequest, ""},
		{"no steps", func() ApprovalDraft { d := base(); d.CommandJob.Steps = nil; return d }, CodeInvalidRequest, "command_job.steps"},
		{"33 steps", func() ApprovalDraft {
			d := base()
			for len(d.CommandJob.Steps) < MaxSteps+1 {
				d.CommandJob.Steps = append(d.CommandJob.Steps, step(len(d.CommandJob.Steps)+1, RouteUnsignedRead, "uptime", 0, route("web-1", fpA)))
			}
			return d
		}, CodeRequestTooLarge, "command_job.steps"},
		{"step over 4 KiB", func() ApprovalDraft {
			d := base()
			d.CommandJob.Steps[0] = step(1, RouteSignedWrite, strings.Repeat("x", MaxStepBytes+1), 60, route("web-1", fpA))
			return d
		}, CodeRequestTooLarge, "command_job.steps[0].exact_command"},
		{"total over 24 KiB", func() ApprovalDraft {
			d := base()
			d.CommandJob.Steps = nil
			for i := 1; i <= 7; i++ {
				d.CommandJob.Steps = append(d.CommandJob.Steps, step(i, RouteSignedWrite, strings.Repeat("x", 4000), 60, route("web-1", fpA)))
			}
			return d
		}, CodeRequestTooLarge, "command_job.steps"},
		{"ordinal gap", func() ApprovalDraft { d := base(); d.CommandJob.Steps[0].Ordinal = 2; return d }, CodeInvalidRequest, "command_job.steps[0].ordinal"},
		{"command hash", func() ApprovalDraft { d := base(); d.CommandJob.Steps[0].CommandSHA256 = sha256Hex("x"); return d }, CodeInvalidRequest, "command_job.steps[0].command_sha256"},
		{"registry digest", func() ApprovalDraft {
			d := base()
			d.CommandJob.Steps[0].RegistryEntryDigest = sha256Hex("x")
			return d
		}, CodeInvalidRequest, "command_job.steps[0].registry_entry_digest"},
		{"signed step without fingerprint", func() ApprovalDraft {
			d := base()
			d.CommandJob.Steps[0] = step(1, RouteSignedWrite, "touch /x", 60, route("web-1", ""))
			return d
		}, CodeInvalidRequest, "command_job.steps[0].target.trusted_host_fingerprint"},
		{"write ttl over 60", func() ApprovalDraft { d := base(); d.CommandJob.Steps[0].SignatureTTLSeconds = 61; return d }, CodeInvalidRequest, "command_job.steps[0].signature_ttl_seconds"},
		{"signed ttl zero", func() ApprovalDraft { d := base(); d.CommandJob.Steps[0].SignatureTTLSeconds = 0; return d }, CodeInvalidRequest, "command_job.steps[0].signature_ttl_seconds"},
		{"revoke ttl over 60", func() ApprovalDraft {
			d := base()
			d.CommandJob.Steps[0] = step(1, RouteSignedAdmin, "SSHGATE_REVOKE", 300, route("web-1", fpA))
			return d
		}, CodeInvalidRequest, "command_job.steps[0].signature_ttl_seconds"},
		{"read with ttl", func() ApprovalDraft {
			d := base()
			d.CommandJob.Steps = append(d.CommandJob.Steps, step(2, RouteUnsignedRead, "uptime", 60, route("web-1", fpA)))
			return d
		}, CodeInvalidRequest, "command_job.steps[1].signature_ttl_seconds"},
		{"no signed step", func() ApprovalDraft {
			d := base()
			d.CommandJob.Steps[0] = step(1, RouteUnsignedRead, "uptime", 0, route("web-1", fpA))
			return d
		}, CodeInvalidRequest, "command_job.steps"},
		{"admin step not alone", func() ApprovalDraft {
			d := base()
			d.CommandJob.Steps = append(d.CommandJob.Steps, step(2, RouteSignedAdmin, "SSHGATE_REVOKE", 60, route("web-1", fpA)))
			return d
		}, CodeInvalidRequest, "command_job.steps[1].route"},
		{"transfer verb in job", func() ApprovalDraft {
			d := base()
			d.CommandJob.Steps[0] = step(1, RouteSignedWrite, "SSHGATE_XFER_SEND a b c d", 60, route("web-1", fpA))
			return d
		}, CodeReservedVerb, "command_job.steps[0].exact_command"},
		{"trusted display on a write", func() ApprovalDraft {
			d := base()
			d.CommandJob.Steps[0].TrustedDisplay = &TrustedDisplay{StagedBasename: "x"}
			return d
		}, CodeInvalidRequest, "command_job.steps[0].trusted_display"},
		{"trusted display with a control", func() ApprovalDraft {
			d := *fixtures()[4].draft
			job := *d.CommandJob
			job.Steps = []Step{job.Steps[0]}
			td := *job.Steps[0].TrustedDisplay
			td.StagedVersion = "v1\x1b[31m"
			job.Steps[0].TrustedDisplay = &td
			d.CommandJob = &job
			return d
		}, CodeInvalidRequest, "command_job.steps[0].trusted_display.staged_version"},
		{"executor output unlimited", func() ApprovalDraft { d := base(); d.CommandJob.MaxOutputBytes = 0; return d }, CodeInvalidRequest, "command_job.max_output_bytes"},
		{"executor output over 1 MiB", func() ApprovalDraft { d := base(); d.CommandJob.MaxOutputBytes = MaxStreamOutputBytes + 1; return d }, CodeInvalidRequest, "command_job.max_output_bytes"},
		{"stop policy", func() ApprovalDraft { d := base(); d.CommandJob.StopPolicy = "sometimes"; return d }, CodeInvalidRequest, "command_job.stop_policy"},
		{"grant scope all with commands", func() ApprovalDraft {
			d := grant()
			g := *d.StandingGrant
			g.Scope = GrantScopeAll
			d.StandingGrant = &g
			return d
		}, CodeInvalidRequest, "standing_grant.exact_allowed_commands"},
		{"grant over 24h", func() ApprovalDraft {
			d := grant()
			g := *d.StandingGrant
			g.DurationSeconds = MaxGrantDurationSeconds + 1
			d.StandingGrant = &g
			return d
		}, CodeInvalidRequest, "standing_grant.duration_seconds"},
		{"grant admin verb", func() ApprovalDraft {
			d := grant()
			g := *d.StandingGrant
			g.Commands = []string{"SSHGATE_REVOKE"}
			d.StandingGrant = &g
			return d
		}, CodeReservedVerb, "standing_grant.exact_allowed_commands[0]"},
		{"grant without host", func() ApprovalDraft {
			d := grant()
			g := *d.StandingGrant
			g.TrustedHostFingerprint = ""
			d.StandingGrant = &g
			return d
		}, CodeInvalidRequest, "standing_grant.trusted_host_fingerprint"},
		{"transfer with signer fields", func() ApprovalDraft {
			d := transfer()
			tr := *d.Transfer
			tr.TransferID = "abc"
			d.Transfer = &tr
			return d
		}, CodeInvalidRequest, "transfer.transfer_id"},
		{"transfer with a key", func() ApprovalDraft {
			d := transfer()
			tr := *d.Transfer
			tr.Destination.PublicKey = boxText
			d.Transfer = &tr
			return d
		}, CodeInvalidRequest, "transfer.destination.public_key"},
		{"transfer relative path", func() ApprovalDraft {
			d := transfer()
			tr := *d.Transfer
			tr.Source.Path = "etc/secret"
			d.Transfer = &tr
			return d
		}, CodeInvalidRequest, "transfer.source.path"},
		{"transfer mode", func() ApprovalDraft {
			d := transfer()
			tr := *d.Transfer
			tr.Mode = "0644"
			d.Transfer = &tr
			return d
		}, CodeInvalidRequest, "transfer.mode"},
		{"transfer ttl", func() ApprovalDraft {
			d := transfer()
			tr := *d.Transfer
			tr.SignatureTTLSeconds = 301
			d.Transfer = &tr
			return d
		}, CodeInvalidRequest, "transfer.signature_ttl_seconds"},
	}
	for _, tc := range cases {
		err := tc.draft().Validate()
		if codeOf(err) != tc.code || (tc.field != "" && fieldOf(err) != tc.field) {
			t.Errorf("%s: got %v (field %q), want %s at %q", tc.name, err, fieldOf(err), tc.code, tc.field)
		}
	}
}

func TestPlanValidateRefusals(t *testing.T) {
	good := fixtures()[0].plan
	transfer := fixtures()[8].plan
	cases := map[string]func() ApprovalPlanV1{
		"origin":    func() ApprovalPlanV1 { p := good; p.RationaleOrigin = OriginSynthesizedLegacyV1; return p },
		"principal": func() ApprovalPlanV1 { p := good; p.RequesterPrincipal = ""; return p },
		"sub":       func() ApprovalPlanV1 { p := good; p.RequesterSub = "uid 7"; return p },
		"validity too long": func() ApprovalPlanV1 {
			p := good
			p.RequestExpiresAt = p.SubmittedAt.Add(ValidityMax + time.Second)
			return p
		},
		"validity too short": func() ApprovalPlanV1 {
			p := good
			p.RequestExpiresAt = p.SubmittedAt.Add(ValidityMin - time.Second)
			return p
		},
		"transfer without legs": func() ApprovalPlanV1 {
			p := transfer
			tr := *p.Transfer
			tr.SendCommand = ""
			p.Transfer = &tr
			return p
		},
		"transfer leg hash": func() ApprovalPlanV1 {
			p := transfer
			tr := *p.Transfer
			tr.RecvCommandSHA256 = sha256Hex("x")
			p.Transfer = &tr
			return p
		},
		"transfer key hash": func() ApprovalPlanV1 {
			p := transfer
			tr := *p.Transfer
			tr.Source.PublicKeySHA256 = sha256Hex("x")
			p.Transfer = &tr
			return p
		},
		"swapped legs": func() ApprovalPlanV1 {
			p := transfer
			tr := *p.Transfer
			tr.SendCommand, tr.RecvCommand = tr.RecvCommand, tr.SendCommand
			tr.SendCommandSHA256, tr.RecvCommandSHA256 = tr.RecvCommandSHA256, tr.SendCommandSHA256
			p.Transfer = &tr
			return p
		},
	}
	for name, mk := range cases {
		if err := mk().Validate(); codeOf(err) != CodeInvalidRequest {
			t.Errorf("%s: Validate = %v, want invalid_request", name, err)
		}
	}
}

func TestRouteSnapshotBounds(t *testing.T) {
	ok := route("web-1", fpA)
	at := func(f func(*RouteSnapshot)) RouteSnapshot { r := ok; f(&r); return r }
	accepted := []RouteSnapshot{
		ok,
		at(func(r *RouteSnapshot) { r.ServerAlias = strings.Repeat("a", MaxAliasBytes) }),
		at(func(r *RouteSnapshot) { r.ResolvedHost = strings.Repeat("h", MaxHostBytes) }),
		at(func(r *RouteSnapshot) { r.ResolvedUser = strings.Repeat("u", MaxUserBytes) }),
		at(func(r *RouteSnapshot) {
			r.TrustedHostFingerprint = "SHA256:" + strings.Repeat("x", MaxFingerprintBytes-7)
		}),
		at(func(r *RouteSnapshot) { r.TrustedHostFingerprint = "" }),
		at(func(r *RouteSnapshot) { r.ResolvedPort = 65535 }),
		at(func(r *RouteSnapshot) { r.AddedAt = time.Time{} }),
	}
	for i, r := range accepted {
		if err := ValidateRouteSnapshot(r); err != nil {
			t.Errorf("accepted[%d]: %v", i, err)
		}
	}
	refused := map[string]RouteSnapshot{
		"server_alias":             at(func(r *RouteSnapshot) { r.ServerAlias = strings.Repeat("a", MaxAliasBytes+1) }),
		"resolved_host":            at(func(r *RouteSnapshot) { r.ResolvedHost = strings.Repeat("h", MaxHostBytes+1) }),
		"resolved_user":            at(func(r *RouteSnapshot) { r.ResolvedUser = strings.Repeat("u", MaxUserBytes+1) }),
		"resolved_port":            at(func(r *RouteSnapshot) { r.ResolvedPort = 0 }),
		"trusted_host_fingerprint": at(func(r *RouteSnapshot) { r.TrustedHostFingerprint = "MD5:aa" }),
		"added_at":                 at(func(r *RouteSnapshot) { r.AddedAt = r.AddedAt.In(time.FixedZone("x", 3600)) }),
	}
	for field, r := range refused {
		if err := ValidateRouteSnapshot(r); codeOf(err) != CodeInvalidRequest || fieldOf(err) != field {
			t.Errorf("%s: %v", field, err)
		}
	}
	for _, bad := range []string{"<", ">", "&", `"`, `\`, " ", "\x7f", "é"} {
		for _, field := range []string{"server_alias", "resolved_host", "resolved_user"} {
			r := ok
			switch field {
			case "server_alias":
				r.ServerAlias = "a" + bad
			case "resolved_host":
				r.ResolvedHost = "h" + bad
			default:
				r.ResolvedUser = "u" + bad
			}
			if err := ValidateRouteSnapshot(r); fieldOf(err) != field {
				t.Errorf("%s with %q: %v", field, bad, err)
			}
		}
	}
	long := at(func(r *RouteSnapshot) {
		r.TrustedHostFingerprint = "SHA256:" + strings.Repeat("x", MaxFingerprintBytes-6)
	})
	if ValidateRouteSnapshot(long) == nil {
		t.Error("a 129-byte fingerprint was accepted")
	}
}

func TestRouteSnapshotDigestNormalizesZone(t *testing.T) {
	r := route("web-1", fpA)
	shifted := r
	shifted.AddedAt = r.AddedAt.In(time.FixedZone("IST", 5*3600+1800))
	if r.Digest() != shifted.Digest() {
		t.Fatal("the same instant in two zones digests differently")
	}
	moved := r
	moved.ReadOnly = true
	if r.Digest() == moved.Digest() {
		t.Fatal("a tier flip does not change the digest")
	}
	broken := r
	broken.AddedAt = time.Date(10000, 1, 1, 0, 0, 0, 0, time.UTC)
	if broken.Digest() != "" {
		t.Fatal("an unencodable snapshot must digest to empty")
	}
}

// worstDraft is the largest K19-legal draft: 32 signed steps whose 24 KiB of
// command bytes are all '<' (escaped to six bytes each), every route snapshot
// at its bounds with an escapable fingerprint, and a 500-byte reason of '<'.
func worstDraft() ApprovalDraft {
	target := RouteSnapshot{
		ServerAlias: strings.Repeat("a", MaxAliasBytes), ResolvedHost: strings.Repeat("h", MaxHostBytes),
		ResolvedPort: 65535, ResolvedUser: strings.Repeat("u", MaxUserBytes),
		TrustedHostFingerprint: "SHA256:" + strings.Repeat("<", MaxFingerprintBytes-7), ReadOnly: true,
		AddedAt: time.Date(2026, 9, 1, 8, 0, 0, 999999999, time.UTC),
	}
	var steps []Step
	for i := 1; i <= MaxSteps; i++ {
		steps = append(steps, step(i, RouteSignedWrite, strings.Repeat("<", MaxTotalBytes/MaxSteps), 60, target))
	}
	d := jobDraft(idOne, strings.Repeat("<", MaxRationaleBytes), CoordinatorExecutor, steps...)
	d.CommandJob.StopPolicy = StopClassDefaultWritesOnly
	d.CommandJob.MaxOutputBytes = MaxStreamOutputBytes
	return d
}

func TestWorstCaseDraftWithinMaxDraftBytes(t *testing.T) {
	d := worstDraft()
	if err := d.Validate(); err != nil {
		t.Fatal(err)
	}
	b := mustCanon(t, d)
	t.Logf("worst-case draft: %d bytes encoded (MaxDraftBytes %d)", len(b), MaxDraftBytes)
	if len(b)*6/5 > MaxDraftBytes {
		t.Fatalf("worst draft %d bytes leaves under 20%% margin to %d", len(b), MaxDraftBytes)
	}
	if _, err := DecodeDraft(b); err != nil {
		t.Fatal(err)
	}
}

func TestPlanJSONNamesAreSpecNames(t *testing.T) {
	b := mustCanon(t, route("web-1", fpA))
	want := `{"server_alias":"web-1","resolved_host":"web-1.example.net","resolved_port":22,"resolved_user":"deploy","trusted_host_fingerprint":"` + fpA + `","read_only":false,"added_at":"2026-09-01T08:00:00Z"}`
	if string(b) != want {
		t.Fatalf("RouteSnapshot encodes as\n%s\nwant\n%s", b, want)
	}
	var m map[string]any
	if err := json.Unmarshal(mustCanon(t, fixtures()[0].plan), &m); err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{"version", "kind", "request_id", "requester_principal", "submitted_at", "request_expires_at", "reason", "rationale_origin", "executor_claim_token_hash", "submit_not_after", "coordinator", "command_job"} {
		if _, ok := m[k]; !ok {
			t.Errorf("plan has no %q", k)
		}
	}
}

func FuzzDecodeDraft(f *testing.F) {
	for _, fx := range fixtures() {
		if fx.draft != nil {
			f.Add(mustCanon(f, *fx.draft))
		}
	}
	f.Add([]byte(`{}`))
	f.Add([]byte(`{"version":1,"kind":"command_job"}`))
	f.Fuzz(func(t *testing.T, b []byte) {
		d, err := DecodeDraft(b)
		if err != nil {
			if codeOf(err) == "" {
				t.Fatalf("refusal without a code: %v", err)
			}
			return
		}
		if again := mustCanon(t, d); !bytes.Equal(again, b) {
			t.Fatal("an accepted draft does not re-encode byte-equal")
		}
		if err := d.Validate(); err != nil {
			t.Fatalf("an accepted draft fails Validate: %v", err)
		}
	})
}
