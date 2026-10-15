package jobplan

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/karthikeyan5/sshgate/src/approvalplan"
)

func draftFixture() (DraftOptions, approvalplan.RouteSnapshot) {
	stamp := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	return DraftOptions{RequestID: "a2_" + strings.Repeat("a", 22), Reason: "  Maintain the service  ", ClaimTokenHash: strings.Repeat("b", 64), SubmitNotAfter: stamp.Add(120 * time.Second), Coordinator: approvalplan.CoordinatorInProcessSync, MaxOutputBytes: 262144}, approvalplan.RouteSnapshot{ServerAlias: "node", ResolvedHost: "example.test", ResolvedPort: 22, ResolvedUser: "operator", TrustedHostFingerprint: "SHA256:" + strings.Repeat("A", 43), AddedAt: stamp}
}

func TestDraftKinds(t *testing.T) {
	options, target := draftFixture()
	display := approvalplan.TrustedDisplay{StagedBasename: "gate", StagedVersion: "v1", RunningVersion: "v0", Size: 123}
	cases := []struct {
		name    string
		build   func() (approvalplan.ApprovalDraft, error)
		route   approvalplan.Route
		ttl     int
		command string
	}{
		{"write", func() (approvalplan.ApprovalDraft, error) { return BuildRun(options, target, "touch /tmp/file", false) }, approvalplan.RouteSignedWrite, 60, "touch /tmp/file"},
		{"reveal read", func() (approvalplan.ApprovalDraft, error) {
			return BuildRun(options, target, "cat /etc/hostname", true)
		}, approvalplan.RouteSignedReveal, 60, "cat /etc/hostname"},
		{"reveal write", func() (approvalplan.ApprovalDraft, error) { return BuildRun(options, target, "touch /tmp/file", true) }, approvalplan.RouteSignedReveal, 60, "touch /tmp/file"},
		{"revoke", func() (approvalplan.ApprovalDraft, error) { return BuildRevoke(options, target) }, approvalplan.RouteSignedAdmin, 60, "SSHGATE_REVOKE"},
		{"update", func() (approvalplan.ApprovalDraft, error) {
			return BuildUpdate(options, target, strings.Repeat("c", 64), display)
		}, approvalplan.RouteSignedAdmin, 300, "SSHGATE_UPDATE " + strings.Repeat("c", 64)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			d, err := tc.build()
			if err != nil {
				t.Fatal(err)
			}
			if err = d.Validate(); err != nil {
				t.Fatal(err)
			}
			s := d.CommandJob.Steps[0]
			if s.Route != tc.route || s.SignatureTTLSeconds != tc.ttl || s.ExactCommand != tc.command || s.Ordinal != 1 {
				t.Fatalf("wrong step: %+v", s)
			}
			sum := sha256.Sum256([]byte(tc.command))
			if s.CommandSHA256 != hex.EncodeToString(sum[:]) || s.RegistryEntryDigest != target.Digest() || s.Target != target {
				t.Fatal("command or target binding lost")
			}
			if d.RequestID != options.RequestID || d.SubmitNotAfter != options.SubmitNotAfter || d.Coordinator != options.Coordinator || d.ExecutorClaimTokenHash != options.ClaimTokenHash || d.Rationale != "Maintain the service" {
				t.Fatalf("envelope changed: %+v", d)
			}
			if tc.name == "update" {
				if s.TrustedDisplay == nil || *s.TrustedDisplay != display {
					t.Fatal("missing update metadata")
				}
			} else if s.TrustedDisplay != nil {
				t.Fatal("unexpected metadata")
			}
		})
	}
}

func TestDraftBatchOrderingAndPolicy(t *testing.T) {
	for _, coordinator := range []approvalplan.Coordinator{approvalplan.CoordinatorInProcessSync, approvalplan.CoordinatorExecutor} {
		for _, setting := range []string{"default", "stop", "continue"} {
			t.Run(string(coordinator)+"/"+setting, func(t *testing.T) {
				options, target := draftFixture()
				options.Coordinator = coordinator
				if coordinator == approvalplan.CoordinatorExecutor {
					options.SubmitNotAfter = options.SubmitNotAfter.Add(3480 * time.Second)
				}
				var stop *bool
				want := approvalplan.StopClassDefaultWritesOnly
				if setting != "default" {
					value := setting == "stop"
					stop = &value
					want = approvalplan.StopNever
					if value {
						want = approvalplan.StopAnyNonzero
					}
				}
				commands := []string{"cat /etc/hostname", "touch /tmp/file", "printf 'done\\n'"}
				original := append([]string(nil), commands...)
				d, err := BuildBatch(options, target, commands, stop)
				if err != nil {
					t.Fatal(err)
				}
				commands[0] = "changed"
				if d.CommandJob.StopPolicy != want || d.CommandJob.MaxOutputBytes != options.MaxOutputBytes || d.SubmitNotAfter != options.SubmitNotAfter {
					t.Fatal("policy, output cap or caller window changed")
				}
				for i, s := range d.CommandJob.Steps {
					route := approvalplan.RouteUnsignedRead
					ttl := 0
					if i == 1 {
						route = approvalplan.RouteSignedWrite
						ttl = 60
					}
					if s.Ordinal != i+1 || s.ExactCommand != original[i] || s.Route != route || s.SignatureTTLSeconds != ttl {
						t.Fatalf("step %d: %+v", i, s)
					}
				}
			})
		}
	}
}

func TestDraftGrantAndTransfer(t *testing.T) {
	options, target := draftFixture()
	grantOptions := options
	grantOptions.Coordinator = ""
	grantOptions.ClaimTokenHash = ""
	commands := []string{"touch /tmp/file"}
	for _, scope := range []approvalplan.GrantScope{approvalplan.GrantScopeAll, approvalplan.GrantScopeCommands} {
		allowed := commands
		if scope == approvalplan.GrantScopeAll {
			allowed = nil
		}
		d, err := BuildGrant(grantOptions, target, scope, allowed, 3600)
		if err != nil {
			t.Fatal(err)
		}
		g := d.StandingGrant
		if d.Kind != approvalplan.KindStandingGrant || g.Scope != scope || g.DurationSeconds != 3600 || g.Alias != target.ServerAlias || g.TrustedHostFingerprint != target.TrustedHostFingerprint || g.RegistryEntryDigest != target.Digest() || !reflect.DeepEqual(g.Commands, allowed) {
			t.Fatalf("grant: %+v", g)
		}
		if scope == approvalplan.GrantScopeCommands {
			commands[0] = "changed"
			if g.Commands[0] != "touch /tmp/file" {
				t.Fatal("grant aliases caller slice")
			}
		}
	}
	destination := target
	destination.ServerAlias = "destination"
	d, err := BuildTransfer(options, target, "/source", destination, "/destination", "")
	if err != nil {
		t.Fatal(err)
	}
	x := d.Transfer
	if d.Kind != approvalplan.KindTransfer || x.Mode != "0600" || x.SignatureTTLSeconds != 300 || x.Source.Target != target || x.Destination.Target != destination || x.Source.Path != "/source" || x.Destination.Path != "/destination" || x.Source.RegistryEntryDigest != target.Digest() || x.Destination.RegistryEntryDigest != destination.Digest() {
		t.Fatalf("transfer: %+v", x)
	}
	if x.TransferID != "" || x.SendCommand != "" || x.RecvCommand != "" || x.Source.PublicKey != "" || x.Destination.PublicKey != "" {
		t.Fatal("builder froze signer fields")
	}
}

func TestDraftRefusals(t *testing.T) {
	cases := []struct {
		name     string
		change   func(*DraftOptions, *approvalplan.RouteSnapshot)
		commands []string
		code     approvalplan.Code
	}{
		{"empty fingerprint", func(_ *DraftOptions, r *approvalplan.RouteSnapshot) { r.TrustedHostFingerprint = "" }, []string{"touch /x"}, approvalplan.CodeInvalidRequest},
		{"read only", func(_ *DraftOptions, r *approvalplan.RouteSnapshot) { r.ReadOnly = true }, []string{"touch /x"}, approvalplan.CodeInvalidRequest},
		{"reason", func(o *DraftOptions, _ *approvalplan.RouteSnapshot) { o.Reason = "" }, []string{"touch /x"}, approvalplan.CodeInvalidRequest},
		{"window", func(o *DraftOptions, _ *approvalplan.RouteSnapshot) { o.SubmitNotAfter = time.Time{} }, []string{"touch /x"}, approvalplan.CodeInvalidRequest},
		{"token", func(o *DraftOptions, _ *approvalplan.RouteSnapshot) { o.ClaimTokenHash = "" }, []string{"touch /x"}, approvalplan.CodeInvalidRequest},
		{"coordinator", func(o *DraftOptions, _ *approvalplan.RouteSnapshot) { o.Coordinator = "" }, []string{"touch /x"}, approvalplan.CodeInvalidRequest},
		{"executor cap", func(o *DraftOptions, _ *approvalplan.RouteSnapshot) {
			o.Coordinator = approvalplan.CoordinatorExecutor
			o.MaxOutputBytes = 0
		}, []string{"touch /x"}, approvalplan.CodeInvalidRequest},
		{"empty", nil, nil, approvalplan.CodeInvalidRequest},
		{"all read", nil, []string{"cat /etc/hostname"}, approvalplan.CodeInvalidRequest},
		{"reserved", nil, []string{"SSHGATE_REVOKE"}, approvalplan.CodeReservedVerb},
		{"transfer verb", nil, []string{"SSHGATE_XFER_SEND forged"}, approvalplan.CodeReservedVerb},
		{"step bytes", nil, []string{strings.Repeat("x", 4097)}, approvalplan.CodeRequestTooLarge},
		{"total bytes", nil, []string{strings.Repeat("x", 4096), strings.Repeat("x", 4096), strings.Repeat("x", 4096), strings.Repeat("x", 4096), strings.Repeat("x", 4096), strings.Repeat("x", 4096), "x"}, approvalplan.CodeRequestTooLarge},
		{"step count", nil, strings.Fields(strings.Repeat("touch ", 33)), approvalplan.CodeRequestTooLarge},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			o, r := draftFixture()
			if tc.change != nil {
				tc.change(&o, &r)
			}
			d, err := BuildBatch(o, r, tc.commands, nil)
			var coded *approvalplan.CodeError
			if !errors.As(err, &coded) || coded.Code != tc.code {
				t.Fatalf("error %v; want %s", err, tc.code)
			}
			if !reflect.DeepEqual(d, approvalplan.ApprovalDraft{}) {
				t.Fatal("refusal returned a usable draft")
			}
		})
	}
}

func TestDraftAdministrativeAndTransferRefusals(t *testing.T) {
	o, r := draftFixture()
	builders := map[string]func() (approvalplan.ApprovalDraft, error){
		"run reserved":    func() (approvalplan.ApprovalDraft, error) { return BuildRun(o, r, "SSHGATE_REVOKE", false) },
		"reveal reserved": func() (approvalplan.ApprovalDraft, error) { return BuildRun(o, r, "SSHGATE_REVOKE", true) },
		"update hash": func() (approvalplan.ApprovalDraft, error) {
			return BuildUpdate(o, r, "invalid", approvalplan.TrustedDisplay{StagedBasename: "gate"})
		},
		"update metadata": func() (approvalplan.ApprovalDraft, error) {
			return BuildUpdate(o, r, strings.Repeat("c", 64), approvalplan.TrustedDisplay{})
		},
		"transfer path": func() (approvalplan.ApprovalDraft, error) { return BuildTransfer(o, r, "relative", r, "/dest", "") },
		"transfer mode": func() (approvalplan.ApprovalDraft, error) { return BuildTransfer(o, r, "/source", r, "/dest", "0644") },
		"grant invalid route": func() (approvalplan.ApprovalDraft, error) {
			g := o
			g.Coordinator = ""
			g.ClaimTokenHash = ""
			bad := r
			bad.ResolvedHost = ""
			return BuildGrant(g, bad, approvalplan.GrantScopeAll, nil, 3600)
		},
		"transfer missing fingerprint": func() (approvalplan.ApprovalDraft, error) {
			bad := r
			bad.TrustedHostFingerprint = ""
			return BuildTransfer(o, r, "/source", bad, "/dest", "")
		},
		"grant reserved": func() (approvalplan.ApprovalDraft, error) {
			g := o
			g.Coordinator = ""
			g.ClaimTokenHash = ""
			return BuildGrant(g, r, approvalplan.GrantScopeCommands, []string{"SSHGATE_REVOKE"}, 3600)
		},
	}
	for name, build := range builders {
		t.Run(name, func(t *testing.T) {
			if _, err := build(); err == nil {
				t.Fatal("accepted invalid request")
			}
		})
	}
	for _, kind := range []string{"reveal", "revoke", "update", "grant", "source", "destination"} {
		t.Run("read only/"+kind, func(t *testing.T) {
			ro := r
			ro.ReadOnly = true
			var err error
			switch kind {
			case "reveal":
				_, err = BuildRun(o, ro, "cat /etc/hostname", true)
			case "revoke":
				_, err = BuildRevoke(o, ro)
			case "update":
				_, err = BuildUpdate(o, ro, strings.Repeat("c", 64), approvalplan.TrustedDisplay{StagedBasename: "gate"})
			case "grant":
				g := o
				g.Coordinator = ""
				g.ClaimTokenHash = ""
				_, err = BuildGrant(g, ro, approvalplan.GrantScopeAll, nil, 3600)
			case "source":
				_, err = BuildTransfer(o, ro, "/source", r, "/dest", "")
			case "destination":
				_, err = BuildTransfer(o, r, "/source", ro, "/dest", "")
			}
			if err == nil {
				t.Fatal("accepted read-only target")
			}
		})
	}
}

func TestDraftBoundsAccepted(t *testing.T) {
	options, target := draftFixture()
	for _, commands := range [][]string{
		strings.Fields(strings.Repeat("touch ", approvalplan.MaxSteps)),
		{strings.Repeat("x", 4096), strings.Repeat("x", 4096), strings.Repeat("x", 4096), strings.Repeat("x", 4096), strings.Repeat("x", 4096), strings.Repeat("x", 4096)},
	} {
		d, err := BuildBatch(options, target, commands, nil)
		if err != nil {
			t.Fatal(err)
		}
		if len(d.CommandJob.Steps) != len(commands) {
			t.Fatal("truncated batch")
		}
	}
	options.MaxOutputBytes = 0
	if _, err := BuildRun(options, target, "touch /x", false); err != nil {
		t.Fatalf("sync unlimited: %v", err)
	}
	options.Coordinator = approvalplan.CoordinatorExecutor
	options.MaxOutputBytes = approvalplan.MaxStreamOutputBytes
	if _, err := BuildRun(options, target, "touch /x", false); err != nil {
		t.Fatalf("executor maximum: %v", err)
	}
	options.MaxOutputBytes++
	if _, err := BuildRun(options, target, "touch /x", false); err == nil {
		t.Fatal("accepted oversized executor output")
	}
}

func TestDraftBlankCommands(t *testing.T) {
	options, target := draftFixture()
	for _, command := range []string{"", " \t\n "} {
		for _, reveal := range []bool{false, true} {
			if _, err := BuildRun(options, target, command, reveal); err == nil {
				t.Fatal("accepted blank run")
			}
		}
		if _, err := BuildBatch(options, target, []string{"touch /x", command}, nil); err == nil {
			t.Fatal("accepted blank batch command")
		}
	}
}
