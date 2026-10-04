package harness

import (
	"bytes"
	"encoding/json"
	"testing"
)

func TestJudgeRequiresAllPass(t *testing.T) {
	leg := Leg{Name: "L-PROOF", Names: map[string]string{"native": "TestProof/native/L-PROOF"}, Markers: []string{"MUTATION-EFFECT write"}}
	for _, fault := range []string{"", "package-fail", "leg-fail", "ancestor-fail", "exit-one", "unfinalized", "duplicate-proof", "wrong-marker"} {
		t.Run(fault, func(t *testing.T) {
			var stream bytes.Buffer
			encoder := json.NewEncoder(&stream)
			emit := func(action, test, output string) {
				if err := encoder.Encode(Event{Action: action, Package: "proof", Test: test, Output: output}); err != nil {
					t.Fatal(err)
				}
			}
			line := "PROOF-COMPLETE L-PROOF native markers=EFFECT:write\n"
			if fault == "wrong-marker" {
				line = "PROOF-COMPLETE L-PROOF native markers=EFFECT:other\n"
			}
			if fault != "unfinalized" {
				emit("output", leg.Names["native"], line)
			}
			if fault == "duplicate-proof" {
				emit("output", leg.Names["native"], line)
			}
			terminal := "pass"
			if fault == "leg-fail" {
				terminal = "fail"
			}
			emit(terminal, leg.Names["native"], "")
			terminal = "pass"
			if fault == "ancestor-fail" {
				terminal = "fail"
			}
			emit(terminal, "TestProof", "")
			terminal = "pass"
			if fault == "package-fail" {
				terminal = "fail"
			}
			emit(terminal, "", "")
			status := 0
			if fault == "exit-one" {
				status = 1
			}
			err := Judge(&stream, "", status, []Leg{leg}, "native")
			if (err == nil) != (fault == "") {
				t.Fatalf("fault %s: %v", fault, err)
			}
		})
	}
}
