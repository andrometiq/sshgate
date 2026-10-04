package main

import "testing"

func TestShimCapabilityReadiness(t *testing.T) {
	for _, tc := range []struct {
		name, status   string
		ready, invalid bool
	}{
		{"zero", "CapPrm: 0000\nCapEff: 0000\nCapAmb: 0000\n", true, false},
		{"permitted", "CapPrm: 0001\nCapEff: 0000\nCapAmb: 0000\n", false, false},
		{"effective", "CapPrm: 0000\nCapEff: 0001\nCapAmb: 0000\n", false, false},
		{"ambient", "CapPrm: 0000\nCapEff: 0000\nCapAmb: 0001\n", false, false},
		{"missing", "CapPrm: 0000\nCapEff: 0000\n", false, true},
		{"malformed", "CapPrm: nope\nCapEff: 0000\nCapAmb: 0000\n", false, true},
		{"duplicate", "CapPrm: 0000\nCapPrm: 0000\nCapEff: 0000\nCapAmb: 0000\n", false, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ready, err := shimCapabilitiesZero(tc.status)
			if ready != tc.ready || (err != nil) != tc.invalid {
				t.Fatalf("ready=%v err=%v", ready, err)
			}
		})
	}
}
