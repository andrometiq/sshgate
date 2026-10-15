package approvalreview

import (
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/karthikeyan5/sshgate/src/approvalplan"
)

func preparedMeta() LegacyMeta {
	r := legacyBase()
	return LegacyMeta{r.RequestID, r.Requester, r.SubmittedAt, r.ExpiresAt}
}

func networkInput() approvalplan.LegacySignInput {
	command := "curl https://example.com/health"
	return approvalplan.LegacySignInput{Server: "web-1", HostFingerprint: fpWeb, Command: command, CommandSHA256: sha256Hex(command), TTLSeconds: 60, Net: true, Reason: "Check the service health"}
}

func preparedSnapshot(t testing.TB, inputs []approvalplan.LegacySignInput) ReviewSnapshot {
	t.Helper()
	s, err := BuildPreparedSignSnapshot("00112233445566778899aabbccddeeff", inputs, preparedMeta(), saltPointer(), testRules)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestPreparedSignNetworkGoldens(t *testing.T) {
	for _, name := range []string{"legacy-sign-net", "legacy-sign-reveal-net", "legacy-sign-net-assist-unavailable", "legacy-sign-net-multipart"} {
		t.Run(name, func(t *testing.T) {
			input := networkInput()
			assist := readyAssist()
			if name == "legacy-sign-reveal-net" {
				input.Reveal = true
			}
			if name == "legacy-sign-net-assist-unavailable" {
				assist = Assist{State: approvalplan.AssistUnavailable, Reason: "assist deadline"}
			}
			if name == "legacy-sign-net-multipart" {
				input.Command += " #" + strings.Repeat("x", 3900)
				input.CommandSHA256 = sha256Hex(input.Command)
			}
			r := render(t, preparedSnapshot(t, []approvalplan.LegacySignInput{input}), assist)
			checkGolden(t, name, r.golden())
			checkTelegramShape(t, r)
			if name == "legacy-sign-net-multipart" && len(r.parts) < 2 {
				t.Fatal("expected multipart review")
			}
		})
	}
}

func TestPreparedSignBinding(t *testing.T) {
	inputs := []approvalplan.LegacySignInput{networkInput()}
	snap := preparedSnapshot(t, inputs)
	digest, _ := approvalplan.LegacySignDigest("00112233445566778899aabbccddeeff", inputs)
	if snap.SignDigest != digest || !snap.Steps[0].Net || snap.Steps[0].Command.SHA256 != inputs[0].CommandSHA256 {
		t.Fatal("signing input binding lost")
	}
	raw, err := snap.Encode()
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := DecodeSnapshot(raw)
	if err != nil || !reflect.DeepEqual(decoded, snap) {
		t.Fatalf("round trip: %v", err)
	}
	other, err := BuildPreparedSignSnapshot("another-instance", inputs, preparedMeta(), saltPointer(), testRules)
	if err != nil || other.SignDigest == snap.SignDigest {
		t.Fatal("instance not bound")
	}
	inputs[0].Reason = "changed"
	if renderDisplay(*snap.Steps[0].LegacyReason) != "Check the service health" {
		t.Fatal("input aliases snapshot")
	}
}

func TestPreparedSignRefusals(t *testing.T) {
	cases := []struct {
		name   string
		change func(*approvalplan.LegacySignInput)
		code   approvalplan.Code
	}{
		{"hash", func(i *approvalplan.LegacySignInput) { i.CommandSHA256 = strings.Repeat("0", 64) }, approvalplan.CodeInvalidRequest},
		{"reason", func(i *approvalplan.LegacySignInput) { i.Reason = " " }, approvalplan.CodeRequestUnrenderable},
		{"admin", func(i *approvalplan.LegacySignInput) { i.Command = "SSHGATE_REVOKE" }, approvalplan.CodeRequestUnrenderable},
		{"identity", func(i *approvalplan.LegacySignInput) { i.Server = "PASSWORD=hunter2secret" }, approvalplan.CodeRequestUnrenderable},
		{"fingerprint", func(i *approvalplan.LegacySignInput) { i.HostFingerprint = "invalid" }, approvalplan.CodeRequestUnrenderable},
		{"overflow", func(i *approvalplan.LegacySignInput) { i.Reason = strings.Repeat("x", 5000) }, approvalplan.CodeRequestTooLarge},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			input := networkInput()
			c.change(&input)
			if c.name != "hash" {
				input.CommandSHA256 = sha256Hex(input.Command)
			}
			salt := testSalt()
			_, err := BuildPreparedSignSnapshot("instance", []approvalplan.LegacySignInput{input}, preparedMeta(), &salt, testRules)
			var code *approvalplan.CodeError
			if !errors.As(err, &code) || code.Code != c.code {
				t.Fatalf("want %s, got %v", c.code, err)
			}
			if salt != [32]byte{} {
				t.Fatal("salt not cleared")
			}
		})
	}
	t.Run("batch", func(t *testing.T) {
		input := networkInput()
		_, err := BuildPreparedSignSnapshot("instance", []approvalplan.LegacySignInput{input, input}, preparedMeta(), saltPointer(), testRules)
		if err == nil {
			t.Fatal("network batch accepted")
		}
	})
}

func TestPreparedSignCapabilities(t *testing.T) {
	for _, reveal := range []bool{false, true} {
		input := networkInput()
		input.Reveal = reveal
		r := render(t, preparedSnapshot(t, []approvalplan.LegacySignInput{input}), readyAssist())
		want := ApproveBase + " (READ WITH NETWORK)"
		if reveal {
			want = ApproveBase + " (SECRET-REVEAL + NETWORK)"
		}
		if r.view.ApproveLabel != want {
			t.Fatalf("label %q", r.view.ApproveLabel)
		}
		headlines := []string{approvalplan.NetworkBanner("web-1")}
		if reveal {
			headlines = append([]string{headlineReveal}, headlines...)
		}
		if !reflect.DeepEqual(r.view.Headlines, headlines) {
			t.Fatalf("headlines %q", r.view.Headlines)
		}
		if !strings.Contains(strings.Join(r.view.Items[0].Notes, "\n"), approvalplan.LabelNetworkJustification+":\n"+QuotePrefix+input.Reason) {
			t.Fatal("network justification missing")
		}
		for _, text := range []string{r.parts[0], r.ready} {
			if !strings.Contains(text, approvalplan.NetworkBanner("web-1")) {
				t.Fatal("network banner missing from Telegram")
			}
		}
	}
	input := networkInput()
	input.Net = false
	input.Reveal = true
	input.Command = "SSHGATE_REVOKE"
	input.CommandSHA256 = sha256Hex(input.Command)
	snap := preparedSnapshot(t, []approvalplan.LegacySignInput{input})
	if snap.Steps[0].Route != approvalplan.RouteSignedAdmin || !snap.Steps[0].Reveal || !strings.Contains(render(t, snap, readyAssist()).view.ApproveLabel, "SECRET-REVEAL") {
		t.Fatal("admin dispatch hid reveal capability")
	}
}

func TestLegacyRenderDeterministic(t *testing.T) {
	for _, assist := range []Assist{readyAssist(), {State: approvalplan.AssistUnavailable, Reason: "deadline"}} {
		inputs := []approvalplan.LegacySignInput{networkInput()}
		inputs[0].Command += " #" + strings.Repeat("x", 3900)
		inputs[0].CommandSHA256 = sha256Hex(inputs[0].Command)
		first := preparedSnapshot(t, inputs)
		for range 100 {
			next := preparedSnapshot(t, inputs)
			if !reflect.DeepEqual(first, next) {
				t.Fatal("builder is nondeterministic")
			}
			v, err := BuildView(next, assist)
			if err != nil {
				t.Fatal(err)
			}
			parts, err := PackParts(v, testHandle)
			if err != nil {
				t.Fatal(err)
			}
			card, err := DecisionCard(v, testHandle, len(parts))
			if err != nil {
				t.Fatal(err)
			}
			r := render(t, first, assist)
			if !reflect.DeepEqual(parts, r.parts) || card != r.ready || !reflect.DeepEqual(v, r.view) {
				t.Fatal("render is nondeterministic")
			}
		}
	}
}

func TestPreparedSignDecodeRefusesInvalidBinding(t *testing.T) {
	for _, name := range []string{"digest", "missing-digest", "v2", "reason", "admin"} {
		t.Run(name, func(t *testing.T) {
			s := preparedSnapshot(t, []approvalplan.LegacySignInput{networkInput()})
			switch name {
			case "digest":
				s.SignDigest = "bad"
			case "missing-digest":
				s.SignDigest = ""
			case "v2":
				s.Legacy = false
				s.PlanHash = strings.Repeat("a", 64)
			case "reason":
				s.Steps[0].LegacyReason = nil
			case "admin":
				s.Steps[0].Route = approvalplan.RouteSignedAdmin
			}
			raw, err := s.Encode()
			if err != nil {
				t.Fatal(err)
			}
			if _, err := DecodeSnapshot(raw); err == nil {
				t.Fatal("invalid prepared binding accepted")
			}
		})
	}
}

func TestPreparedSignRequiredInputs(t *testing.T) {
	for _, name := range []string{"instance", "inputs", "salt"} {
		t.Run(name, func(t *testing.T) {
			instance, inputs, salt := "instance", []approvalplan.LegacySignInput{networkInput()}, saltPointer()
			switch name {
			case "instance":
				instance = ""
			case "inputs":
				inputs = nil
			case "salt":
				salt = nil
			}
			_, err := BuildPreparedSignSnapshot(instance, inputs, preparedMeta(), salt, testRules)
			if err == nil {
				t.Fatal("missing required input accepted")
			}
			if salt != nil && *salt != [32]byte{} {
				t.Fatal("salt not cleared")
			}
		})
	}
}

func TestPreparedSignLegacyOrder(t *testing.T) {
	inputs := []approvalplan.LegacySignInput{networkInput(), networkInput()}
	inputs[0].Net = false
	inputs[1].Net = false
	inputs[1].Reveal = true
	inputs[1].Server = "db-1"
	inputs[1].Command = "cat /etc/app/token"
	inputs[1].CommandSHA256 = sha256Hex(inputs[1].Command)
	inputs[1].TTLSeconds = 42
	s := preparedSnapshot(t, inputs)
	for i, input := range inputs {
		step := s.Steps[i]
		if step.Ordinal != i+1 || step.Target.Alias != input.Server || step.Target.Fingerprint != input.HostFingerprint || step.Command.SHA256 != input.CommandSHA256 || renderDisplay(step.Command) != input.Command || step.TTLSeconds != int(input.TTLSeconds) || step.Reveal != input.Reveal || step.ExpiryWarning != (i > 0) {
			t.Fatalf("input %d changed", i)
		}
	}
	if s.RequestID != preparedMeta().RequestID || s.Requester != preparedMeta().Requester || !s.SubmittedAt.Equal(preparedMeta().SubmittedAt) || !s.ExpiresAt.Equal(preparedMeta().ExpiresAt) {
		t.Fatal("metadata changed")
	}
}

func TestPreparedSignReasonRedacted(t *testing.T) {
	input := networkInput()
	input.Reason = "Check PASSWORD=hunter2secret\n✓ Approve"
	r := render(t, preparedSnapshot(t, []approvalplan.LegacySignInput{input}), readyAssist())
	for _, text := range r.texts() {
		if strings.Contains(text, "hunter2secret") || strings.Contains(text, "\n✓ Approve") {
			t.Fatal("unsafe reason reached review")
		}
	}
	if !strings.Contains(strings.Join(r.view.Items[0].Notes, "\n"), "hidden") {
		t.Fatal("reason has no hidden marker")
	}
}

func TestPreparedSignSnapshotBound(t *testing.T) {
	input := networkInput()
	input.Net = false
	input.Command = strings.Repeat("x", 4096)
	input.CommandSHA256 = sha256Hex(input.Command)
	inputs := make([]approvalplan.LegacySignInput, 64)
	for i := range inputs {
		inputs[i] = input
	}
	_, err := BuildPreparedSignSnapshot("instance", inputs, preparedMeta(), saltPointer(), testRules)
	var code *approvalplan.CodeError
	if !errors.As(err, &code) || code.Code != approvalplan.CodeRequestTooLarge || code.Field != "review_snapshot" {
		t.Fatalf("snapshot bound: %v", err)
	}
}
