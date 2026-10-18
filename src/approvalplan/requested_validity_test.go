package approvalplan

import (
	"bytes"
	"math"
	"testing"
)

func TestRequestedValidityValidation(t *testing.T) {
	for _, tc := range []struct {
		name    string
		seconds int
		valid   bool
	}{
		{"negative", -1, false},
		{"zero", 0, false},
		{"below-floor", 299, false},
		{"floor", 300, true},
		{"above-floor", 301, true},
		{"default", 86400, true},
		{"above-default", 86401, true},
		{"maximum", 604800, true},
		{"above-maximum", 604801, false},
		{"max-int", math.MaxInt, false},
		{"min-int", math.MinInt, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			d := *fixtures()[0].draft
			d.RequestedValiditySeconds = &tc.seconds
			if err := d.Validate(); (err == nil) != tc.valid {
				t.Fatalf("Validate = %v, valid = %v", err, tc.valid)
			}
			got, err := DecodeDraft(mustCanon(t, d))
			if (err == nil) != tc.valid {
				t.Fatalf("DecodeDraft = %v, valid = %v", err, tc.valid)
			}
			if tc.valid && (got.RequestedValiditySeconds == nil || *got.RequestedValiditySeconds != tc.seconds) {
				t.Fatal("requested validity did not round trip")
			}
			if !tc.valid && codeOf(err) != CodeInvalidRequest {
				t.Fatalf("DecodeDraft = %v, want invalid_request", err)
			}
		})
	}
}

func TestRequestedValidityStrictEncoding(t *testing.T) {
	d := *fixtures()[0].draft
	seconds := 300
	d.RequestedValiditySeconds = &seconds
	for _, value := range []string{"null", "300.0", "300.5", "3e2", `"300"`, "true", "9223372036854775808"} {
		t.Run(value, func(t *testing.T) {
			b := editDraft(t, d, `"requested_validity_seconds":300`, `"requested_validity_seconds":`+value)
			if _, err := DecodeDraft(b); codeOf(err) != CodeInvalidRequest {
				t.Fatalf("DecodeDraft = %v, want invalid_request", err)
			}
		})
	}
}

func TestRequestedValidityOmissionAndHash(t *testing.T) {
	for _, f := range fixtures() {
		if f.draft == nil {
			continue
		}
		t.Run(f.name, func(t *testing.T) {
			d := *f.draft
			original := mustCanon(t, d)
			if bytes.Contains(original, []byte("requested_validity_seconds")) {
				t.Fatal("absent member was encoded")
			}
			golden(t, "drafts/"+f.name+".json", original)
			if err := d.Validate(); err != nil {
				t.Fatal(err)
			}
			before, err := DraftHash(d)
			if err != nil {
				t.Fatal(err)
			}
			seconds := 300
			d.RequestedValiditySeconds = &seconds
			with := mustCanon(t, d)
			if !bytes.Contains(with, []byte(`"requested_validity_seconds":300`)) {
				t.Fatal("present member was omitted")
			}
			after, err := DraftHash(d)
			if err != nil || after == before {
				t.Fatalf("present member must change draft hash: %v", err)
			}
			seconds = 301
			changed, err := DraftHash(d)
			if err != nil || changed == after {
				t.Fatalf("changed validity must change draft hash: %v", err)
			}
			d.RequestedValiditySeconds = nil
			restored, err := DraftHash(d)
			if err != nil || restored != before || !bytes.Equal(mustCanon(t, d), original) {
				t.Fatalf("removing member must restore bytes and hash: %v", err)
			}
		})
	}
}
