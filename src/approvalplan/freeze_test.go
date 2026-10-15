package approvalplan

import (
	"bytes"
	"os"
	"reflect"
	"testing"
	"time"
)

func freezeInputs(p ApprovalPlanV1) FreezeInputs {
	f := FreezeInputs{RequesterPrincipal: p.RequesterPrincipal, RequesterSub: p.RequesterSub, Now: p.SubmittedAt, Validity: p.RequestExpiresAt.Sub(p.SubmittedAt)}
	if p.Transfer != nil {
		key := func(e TransferEndpoint) TransferKeySnapshot {
			return TransferKeySnapshot{e.Target.TrustedHostFingerprint, e.KeyLabel, e.PublicKey, e.KeyEntryDigest}
		}
		f.Transfer = &TransferFreezeInputs{key(p.Transfer.Source), key(p.Transfer.Destination), p.Transfer.TransferID, p.Transfer.SendCommand, p.Transfer.RecvCommand}
	}
	return f
}

func TestFreezeDraftGoldens(t *testing.T) {
	for _, fixture := range fixtures() {
		if fixture.draft == nil {
			continue
		}
		t.Run(fixture.name, func(t *testing.T) {
			p, err := FreezeDraft(*fixture.draft, freezeInputs(fixture.plan))
			if err != nil {
				t.Fatal(err)
			}
			got, err := Canonical(p)
			if err != nil {
				t.Fatal(err)
			}
			want, err := os.ReadFile("testdata/plans/" + fixture.name + ".json")
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(got, want) {
				t.Fatalf("frozen bytes differ from golden")
			}
		})
	}
}

func TestFreezeDraftRefusals(t *testing.T) {
	tests := []struct {
		name, fixture string
		change        func(*ApprovalDraft, *FreezeInputs)
	}{
		{"draft-version", "write", func(d *ApprovalDraft, f *FreezeInputs) { d.Version = 0 }},
		{"principal", "write", func(d *ApprovalDraft, f *FreezeInputs) { f.RequesterPrincipal = "" }},
		{"sub", "write", func(d *ApprovalDraft, f *FreezeInputs) { f.RequesterSub = "admin" }},
		{"clock", "write", func(d *ApprovalDraft, f *FreezeInputs) { f.Now = time.Time{} }},
		{"short-validity", "write", func(d *ApprovalDraft, f *FreezeInputs) { f.Validity = ValidityMin - time.Nanosecond }},
		{"long-validity", "write", func(d *ApprovalDraft, f *FreezeInputs) { f.Validity = ValidityMax + time.Nanosecond }},
		{"write-ttl", "write", func(d *ApprovalDraft, f *FreezeInputs) { d.CommandJob.Steps[0].SignatureTTLSeconds = 61 }},
		{"reveal-ttl", "reveal", func(d *ApprovalDraft, f *FreezeInputs) { d.CommandJob.Steps[0].SignatureTTLSeconds = 61 }},
		{"revoke-ttl", "revoke", func(d *ApprovalDraft, f *FreezeInputs) { d.CommandJob.Steps[0].SignatureTTLSeconds = 61 }},
		{"update-ttl", "update", func(d *ApprovalDraft, f *FreezeInputs) { d.CommandJob.Steps[0].SignatureTTLSeconds = 301 }},
		{"transfer-ttl", "transfer", func(d *ApprovalDraft, f *FreezeInputs) { d.Transfer.SignatureTTLSeconds = 301 }},
		{"update-hash", "update", func(d *ApprovalDraft, f *FreezeInputs) {
			s := &d.CommandJob.Steps[0]
			s.ExactCommand = "SSHGATE_UPDATE bad"
			s.CommandSHA256 = sha256Hex(s.ExactCommand)
		}},
		{"display-on-revoke", "revoke", func(d *ApprovalDraft, f *FreezeInputs) {
			d.CommandJob.Steps[0].TrustedDisplay = &TrustedDisplay{StagedBasename: "gate"}
		}},
		{"missing-transfer", "transfer", func(d *ApprovalDraft, f *FreezeInputs) { f.Transfer = nil }},
		{"extra-transfer", "write", func(d *ApprovalDraft, f *FreezeInputs) { f.Transfer = &TransferFreezeInputs{} }},
		{"source-binding", "transfer", func(d *ApprovalDraft, f *FreezeInputs) { f.Transfer.Source.HostFingerprint = fpB }},
		{"destination-binding", "transfer", func(d *ApprovalDraft, f *FreezeInputs) { f.Transfer.Destination.HostFingerprint = fpA }},
		{"key", "transfer", func(d *ApprovalDraft, f *FreezeInputs) { f.Transfer.Source.PublicKey = "bad" }},
		{"digest", "transfer", func(d *ApprovalDraft, f *FreezeInputs) { f.Transfer.Destination.EntryDigest = "" }},
		{"leg", "transfer", func(d *ApprovalDraft, f *FreezeInputs) { f.Transfer.SendCommand = "echo unsafe" }},
		{"id", "transfer", func(d *ApprovalDraft, f *FreezeInputs) { f.Transfer.TransferID = "" }},
		{"requester-key", "transfer", func(d *ApprovalDraft, f *FreezeInputs) { d.Transfer.Source.PublicKey = idText }},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			for _, fixture := range fixtures() {
				if fixture.name != tc.fixture {
					continue
				}
				d := *fixture.draft
				f := freezeInputs(fixture.plan)
				tc.change(&d, &f)
				p, err := FreezeDraft(d, f)
				if err == nil {
					t.Fatal("accepted invalid input")
				}
				if !reflect.DeepEqual(p, ApprovalPlanV1{}) {
					t.Fatal("returned partial plan")
				}
				return
			}
			t.Fatal("missing fixture")
		})
	}
}

func TestFreezeDraftOwnsPayload(t *testing.T) {
	for _, fixture := range fixtures() {
		if fixture.draft == nil {
			continue
		}
		t.Run(fixture.name, func(t *testing.T) {
			encoded, err := Canonical(*fixture.draft)
			if err != nil {
				t.Fatal(err)
			}
			d, err := DecodeDraft(encoded)
			if err != nil {
				t.Fatal(err)
			}
			f := freezeInputs(fixture.plan)
			p, err := FreezeDraft(d, f)
			if err != nil {
				t.Fatal(err)
			}
			before, _ := Canonical(p)
			if d.CommandJob != nil {
				d.CommandJob.MaxOutputBytes++
				d.CommandJob.Steps[0].ExactCommand = "changed"
				if display := d.CommandJob.Steps[0].TrustedDisplay; display != nil {
					display.Size++
				}
			}
			if d.StandingGrant != nil {
				d.StandingGrant.DurationSeconds++
				if len(d.StandingGrant.Commands) > 0 {
					d.StandingGrant.Commands[0] = "changed"
				}
			}
			if d.Transfer != nil {
				d.Transfer.Source.Path = "/changed"
				f.Transfer.Source.PublicKey = "changed"
			}
			after, _ := Canonical(p)
			if !bytes.Equal(before, after) {
				t.Fatal("caller mutation changed frozen plan")
			}
		})
	}
}

func TestFreezeDraftBounds(t *testing.T) {
	for _, validity := range []time.Duration{ValidityMin, ValidityMax} {
		for _, fixture := range fixtures() {
			if fixture.draft == nil {
				continue
			}
			d := *fixture.draft
			if d.CommandJob != nil {
				for i := range d.CommandJob.Steps {
					if d.CommandJob.Steps[i].Route.Signed() {
						d.CommandJob.Steps[i].SignatureTTLSeconds = 1
					}
				}
			}
			if d.Transfer != nil {
				d.Transfer.SignatureTTLSeconds = 1
			}
			f := freezeInputs(fixture.plan)
			f.Validity = validity
			p, err := FreezeDraft(d, f)
			if err != nil {
				t.Fatal(err)
			}
			if p.RequestExpiresAt != f.Now.Add(validity) {
				t.Fatal("wrong expiry")
			}
			if p.CommandJob != nil {
				for _, s := range p.CommandJob.Steps {
					if s.Route.Signed() && s.SignatureTTLSeconds != 1 {
						t.Fatal("TTL widened")
					}
				}
			}
			if p.Transfer != nil && p.Transfer.SignatureTTLSeconds != 1 {
				t.Fatal("transfer TTL widened")
			}
		}
	}
}
