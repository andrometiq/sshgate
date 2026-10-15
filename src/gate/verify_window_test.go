package gate_test

import (
	"errors"
	"testing"
	"time"

	"github.com/karthikeyan5/sshgate/src/gate"
	"github.com/karthikeyan5/sshgate/src/sigwire"
)

// TestVerifyAdmissionWindow pins admission to TS-30s <= now < Exp: a
// signature is admissible for at most 330 s of gate time, never earlier.
func TestVerifyAdmissionWindow(t *testing.T) {
	pub, priv := genKey(t)
	now := time.Unix(1_700_000_000, 0)
	line := func(ts time.Time, validity time.Duration) string {
		return signedLine(t, priv, sigwire.SigPayload{
			Cmd: "df -h", TS: ts.Unix(), Exp: ts.Add(validity).Unix(), Nonce: "nonce-window", Host: hostFP,
		})
	}

	cases := []struct {
		name    string
		ts      time.Time
		at      time.Time
		wantErr error
	}{
		{"timestamp 31 s ahead", now.Add(31 * time.Second), now, gate.ErrNotYetValid},
		{"timestamp 30 s ahead", now.Add(30 * time.Second), now, nil},
		{"timestamp now", now, now, nil},
		{"gate 31 s before ts", now, now.Add(-31 * time.Second), gate.ErrNotYetValid},
		{"gate 30 s before ts", now, now.Add(-30 * time.Second), nil},
		{"gate 299 s after ts", now, now.Add(299 * time.Second), nil},
		{"gate 300 s after ts", now, now.Add(300 * time.Second), gate.ErrExpired},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, _, err := gate.VerifySigned(line(c.ts, sigwire.MaxSigValidity), pub, c.at, hostAny)
			if c.wantErr == nil && err != nil {
				t.Fatalf("VerifySigned err = %v, want nil", err)
			}
			if c.wantErr != nil && !errors.Is(err, c.wantErr) {
				t.Fatalf("VerifySigned err = %v, want %v", err, c.wantErr)
			}
		})
	}
}
