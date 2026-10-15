package approvalreview

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/karthikeyan5/sshgate/src/approvalplan"
	"github.com/karthikeyan5/sshgate/src/redact"
	"github.com/karthikeyan5/sshgate/src/xfer"
)

func TestRevealIndependentOfAdminDispatch(t *testing.T) {
	for _, command := range []string{"SSHGATE_X=1 cat /etc/app/token", "SSHGATE_REVOKE", "SSHGATE_UPDATE " + strings.Repeat("a", 64), "SSHGATE_REVOKE extra", "SSHGATE_UPDATE", "SSHGATE_XFER_SEND invalid"} {
		t.Run(command, func(t *testing.T) {
			req := legacyBase()
			req.Commands = []LegacyCommand{{Server: "web", Command: command, Reveal: true, TTLSeconds: 60}}
			s := mustLegacy(t, req)
			r := render(t, s, readyAssist())
			if !strings.Contains(r.view.ApproveLabel, "SECRET-REVEAL") {
				t.Fatal("missing reveal button")
			}
			for _, text := range []string{strings.Join(r.parts, "\n"), r.preparing, r.ready, string(r.viewJSON)} {
				if !strings.Contains(text, headlineReveal) {
					t.Fatal("missing reveal headline")
				}
			}
			admin := command == "SSHGATE_REVOKE" || strings.HasPrefix(command, "SSHGATE_UPDATE ") || strings.HasPrefix(command, "SSHGATE_XFER_")
			if (s.Steps[0].Route == approvalplan.RouteSignedAdmin) != admin {
				t.Fatalf("wrong dispatch route: %s", s.Steps[0].Route)
			}
			if strings.HasPrefix(command, "SSHGATE_UPDATE ") && (!strings.Contains(r.ready, "GATE BINARY UPDATE") || !strings.Contains(r.view.ApproveLabel, "GATE UPDATE")) {
				t.Fatal("update capability lost")
			}
		})
	}
}

func TestRenderedRationalePersistence(t *testing.T) {
	for _, count := range []int{20, 40} {
		p := withReason(t, loadPlan(t, "write"), strings.TrimSpace(strings.Repeat("passwd=abcd ", count)))
		s, err := BuildSnapshot(p, saltPointer(), testRules)
		if count == 40 {
			var ce *approvalplan.CodeError
			if !errors.As(err, &ce) || ce.Code != approvalplan.CodeRequestTooLarge || ce.Field != "rationale_redacted" {
				t.Fatalf("overflow: %v", err)
			}
			continue
		}
		if err != nil {
			t.Fatal(err)
		}
		raw, err := os.ReadFile("../approvalplan/testdata/r1-write.json")
		if err != nil {
			t.Fatal(err)
		}
		rec, err := approvalplan.DecodeR1(raw)
		if err != nil {
			t.Fatal(err)
		}
		rec.Payload.Plan = p
		rec.Header.PlanHash = s.PlanHash
		rec.Header.RationaleRedacted = renderDisplay(s.Reason)
		rec.Payload.ReviewSnapshot, err = s.Encode()
		if err != nil {
			t.Fatal(err)
		}
		encoded, err := approvalplan.EncodeR1(rec)
		if err != nil {
			t.Fatal(err)
		}
		back, err := approvalplan.DecodeR1(encoded)
		if err != nil || back.Header.RationaleRedacted != renderDisplay(s.Reason) {
			t.Fatalf("persistence: %v", err)
		}
	}
}

func TestGrantRegistryDigestRendered(t *testing.T) {
	for _, name := range []string{"grant-all", "grant-commands"} {
		p := loadPlan(t, name)
		s := mustSnapshot(t, p)
		if s.Grant.RegistryEntryDigest != p.StandingGrant.RegistryEntryDigest {
			t.Fatal("digest dropped at freeze")
		}
		r := render(t, s, readyAssist())
		for _, text := range []string{strings.Join(r.parts, "\n"), string(r.viewJSON), string(r.snapshotRaw)} {
			if !strings.Contains(text, p.StandingGrant.RegistryEntryDigest) {
				t.Fatal("digest missing from review")
			}
		}
	}
}

func TestFreezeReservesEveryAdvisoryCard(t *testing.T) {
	for _, size := range []int{3000, 3178} {
		req := legacyBase()
		req.Commands = []LegacyCommand{{Server: strings.Repeat("a", size), HostFingerprint: fpWeb, Command: "SSHGATE_UPDATE " + strings.Repeat("b", 64), TTLSeconds: 300}}
		s, err := BuildLegacySnapshot(req, saltPointer(), testRules)
		if size == 3178 {
			if !isTooLarge(err) {
				t.Fatalf("late-overflow request accepted at freeze: %v", err)
			}
			continue
		}
		if err != nil {
			t.Fatal(err)
		}
		a := readyAssist()
		a.Result.Summary = strings.Repeat("x", approvalplan.MaxAssistSummaryBytes)
		for len(a.Result.Effects) < approvalplan.MaxAssistEffects {
			a.Result.Effects = append(a.Result.Effects, "effect")
		}
		for len(a.Result.Concerns) < approvalplan.MaxAssistConcerns {
			a.Result.Concerns = append(a.Result.Concerns, approvalplan.Concern{Severity: approvalplan.SeverityHigh, Text: "concern"})
		}
		for _, state := range []Assist{{State: approvalplan.AssistPreparing}, a, {State: approvalplan.AssistUnavailable, Reason: strings.Repeat("x", PartBytes)}} {
			r := render(t, s, state)
			checkTelegramShape(t, r)
			if state.State == approvalplan.AssistReady && !strings.Contains(r.ready, "omitted") {
				t.Fatal("missing mandatory omission notice")
			}
		}
	}
}

func TestIdentitySecretsRefusedAtFreeze(t *testing.T) {
	const secret = "PASSWORD=hunter2secret"
	for _, field := range []string{"alias", "user", "host", "requester", "grant.alias", "source.alias", "source.user", "source.host", "source.label", "destination.alias", "destination.user", "destination.host", "destination.label", "register.label"} {
		t.Run(field, func(t *testing.T) {
			p := loadPlan(t, "write")
			want := field
			switch {
			case field == "requester":
				p.RequesterPrincipal = secret
			case field == "grant.alias":
				p = loadPlan(t, "grant-all")
				p.StandingGrant.Alias = secret
			case field == "register.label":
				p = loadPlan(t, "register-key")
				p.RegisterTransferKey.Label = secret
			case strings.HasPrefix(field, "source.") || strings.HasPrefix(field, "destination."):
				p = loadPlan(t, "transfer")
				end := &p.Transfer.Source
				if strings.HasPrefix(field, "destination.") {
					end = &p.Transfer.Destination
				}
				switch strings.Split(field, ".")[1] {
				case "alias":
					end.Target.ServerAlias = secret
				case "user":
					end.Target.ResolvedUser = secret
				case "host":
					end.Target.ResolvedHost = secret
				case "label":
					end.KeyLabel = secret
				}
				end.RegistryEntryDigest = end.Target.Digest()
			default:
				st := &p.CommandJob.Steps[0]
				switch field {
				case "alias":
					st.Target.ServerAlias = secret
				case "user":
					st.Target.ResolvedUser = secret
				case "host":
					st.Target.ResolvedHost = secret
				}
				st.RegistryEntryDigest = st.Target.Digest()
				want = "steps[0].target." + field
			}
			_, err := BuildSnapshot(p, saltPointer(), testRules)
			assertRefusalField(t, err, want)
		})
	}
	for _, field := range []string{"request_id", "requester", "commands[0].server", "grant.alias", "grant.scope", "source.label", "destination.label", "transfer_id", "mode", "register.label"} {
		t.Run("legacy/"+field, func(t *testing.T) {
			req := legacyBase()
			req.Commands = []LegacyCommand{{Server: "web", Command: "true"}}
			switch field {
			case "request_id":
				req.RequestID = secret
			case "requester":
				req.Requester = secret
			case "commands[0].server":
				req.Commands[0].Server = secret
			case "grant.alias", "grant.scope":
				req.Commands = nil
				req.Grant = &LegacyGrant{Alias: "web", Scope: "all"}
				if field == "grant.alias" {
					req.Grant.Alias = secret
				} else {
					req.Grant.Scope = secret
				}
			case "register.label":
				req.Commands = nil
				req.Register = loadPlan(t, "register-key").RegisterTransferKey
				req.Register.Label = secret
			default:
				req.Commands = nil
				req.Transfer = &LegacyTransfer{}
				switch field {
				case "source.label":
					req.Transfer.SourceLabel = secret
				case "destination.label":
					req.Transfer.DestLabel = secret
				case "transfer_id":
					req.Transfer.TransferID = secret
				case "mode":
					req.Transfer.Mode = secret
				}
			}
			_, err := BuildLegacySnapshot(req, saltPointer(), testRules)
			assertRefusalField(t, err, field)
		})
	}
}

func assertRefusalField(t *testing.T, err error, field string) {
	t.Helper()
	var ce *approvalplan.CodeError
	if !errors.As(err, &ce) || ce.Code != approvalplan.CodeRequestUnrenderable || ce.Field != field {
		t.Fatalf("got %v; want request_unrenderable field %s", err, field)
	}
}

func TestLegacyFingerprintValidation(t *testing.T) {
	for _, field := range []string{"commands[0].host_fingerprint", "source.fingerprint", "destination.fingerprint", "register.host_fingerprint"} {
		req := legacyBase()
		switch field {
		case "commands[0].host_fingerprint":
			req.Commands = []LegacyCommand{{Server: "web", Command: "true", HostFingerprint: "PASSWORD=hunter2secret"}}
		case "source.fingerprint":
			req.Transfer = &LegacyTransfer{SourceFingerprint: "PASSWORD=hunter2secret"}
		case "destination.fingerprint":
			req.Transfer = &LegacyTransfer{DestFingerprint: "PASSWORD=hunter2secret"}
		case "register.host_fingerprint":
			req.Register = loadPlan(t, "register-key").RegisterTransferKey
			req.Register.HostFingerprint = "PASSWORD=hunter2secret"
		}
		_, err := BuildLegacySnapshot(req, saltPointer(), testRules)
		assertRefusalField(t, err, field)
	}
}

func TestRegistrationPublicKeyIdentity(t *testing.T) {
	var box, id [32]byte
	for i := range box {
		box[i] = byte(i)
		id[i] = byte(i + 32)
	}
	registration := func() *approvalplan.RegisterTransferKey {
		return &approvalplan.RegisterTransferKey{HostFingerprint: fpWeb, Label: "web", BoxPub: xfer.BoxPublicText(&box), IDPub: xfer.IDPublicText(ed25519.PublicKey(id[:]))}
	}
	req := legacyBase()
	req.Register = registration()
	forceSpans(t, func(s string, salt [32]byte, rules []redact.Rule) (redact.SpanResult, bool) {
		if strings.Contains(s, "sshgate-xfer-") {
			t.Fatal("public key reached the secret detector")
		}
		return redact.RedactSpans(s, salt, rules)
	})
	first := render(t, mustLegacy(t, req), readyAssist())
	for _, key := range [][32]byte{box, id} {
		sum := sha256.Sum256(key[:])
		fp := "SHA256:" + base64.RawStdEncoding.EncodeToString(sum[:])
		if !strings.Contains(strings.Join(first.parts, "\n"), fp) {
			t.Fatal("missing canonical parsed-key fingerprint")
		}
	}
	for _, field := range []string{"box", "id"} {
		t.Run(field, func(t *testing.T) {
			req.Register = registration()
			if field == "box" {
				other := box
				other[0]++
				req.Register.BoxPub = xfer.BoxPublicText(&other)
			} else {
				other := id
				other[0]++
				req.Register.IDPub = xfer.IDPublicText(ed25519.PublicKey(other[:]))
			}
			second := render(t, mustLegacy(t, req), readyAssist())
			if strings.Join(first.parts, "\n") == strings.Join(second.parts, "\n") {
				t.Fatal("different key has identical review")
			}
			p := loadPlan(t, "register-key")
			p.RegisterTransferKey = req.Register
			v2 := render(t, mustSnapshot(t, p), readyAssist())
			if !strings.Contains(strings.Join(v2.parts, "\n"), "sshgate-xfer-") {
				t.Fatal("key type omitted")
			}
		})
	}
	req.Register = registration()
	req.Register.IDPub += " operator PASSWORD=hunter2secret"
	commented := render(t, mustLegacy(t, req), readyAssist())
	for _, text := range commented.texts() {
		if strings.Contains(text, "hunter2secret") {
			t.Fatal("key comment leaked")
		}
	}
	if !strings.Contains(strings.Join(commented.parts, "\n"), "operator") {
		t.Fatal("key comment lost")
	}
	for _, field := range []string{"box_pub", "id_pub"} {
		req.Register = registration()
		if field == "box_pub" {
			req.Register.BoxPub = "sshgate-xfer-box-x25519 YQ=="
		} else {
			req.Register.IDPub = "sshgate-xfer-id-ed25519 YQ=="
		}
		_, err := BuildLegacySnapshot(req, saltPointer(), testRules)
		assertRefusalField(t, err, "register."+field)
	}
}

func TestFingerprintBase64Validation(t *testing.T) {
	for _, bad := range []string{"SHA256:PASSWORD=hunter2secret", "SHA256:YQ", "SHA256:" + strings.Repeat("A", 42) + "B", "SHA256:" + strings.Repeat("A", 43) + "="} {
		for _, field := range []string{"step", "grant", "source", "destination", "register"} {
			t.Run(field+"/"+bad, func(t *testing.T) {
				p := loadPlan(t, "write")
				want := "steps[0].target.fingerprint"
				switch field {
				case "step":
					p.CommandJob.Steps[0].Target.TrustedHostFingerprint = bad
					p.CommandJob.Steps[0].RegistryEntryDigest = p.CommandJob.Steps[0].Target.Digest()
				case "grant":
					p = loadPlan(t, "grant-all")
					p.StandingGrant.TrustedHostFingerprint = bad
					want = "grant.fingerprint"
				case "source", "destination":
					p = loadPlan(t, "transfer")
					e := &p.Transfer.Source
					if field == "destination" {
						e = &p.Transfer.Destination
					}
					e.Target.TrustedHostFingerprint = bad
					e.RegistryEntryDigest = e.Target.Digest()
					want = field + ".fingerprint"
				case "register":
					p = loadPlan(t, "register-key")
					p.RegisterTransferKey.HostFingerprint = bad
					want = "register.host_fingerprint"
				}
				_, err := BuildSnapshot(p, saltPointer(), testRules)
				assertRefusalField(t, err, want)
			})
		}
	}
}
