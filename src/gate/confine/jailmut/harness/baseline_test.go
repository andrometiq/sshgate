package harness

import (
	"bytes"
	"encoding/json"
	"testing"
)

func TestBaselineBindsProofToSuccessfulInvocation(t *testing.T) {
	for _, fault := range []string{"", "plain-failure", "nonzero-status", "missing-test-terminal", "missing-package-terminal", "unrelated-failure"} {
		t.Run(fault, func(t *testing.T) {
			var stream bytes.Buffer
			encoder := json.NewEncoder(&stream)
			emit := func(action, test, output string) {
				t.Helper()
				if err := encoder.Encode(Event{Action: action, Package: "fixture", Test: test, Output: output}); err != nil {
					t.Fatal(err)
				}
			}
			emit("output", "TestProof", "PROOF-COMPLETE L-PROOF native markers=EFFECT:write\n")
			if fault == "plain-failure" {
				emit("output", "TestProof", "ordinary unrelated assertion failed\n")
				emit("fail", "TestProof", "")
			} else if fault != "missing-test-terminal" {
				emit("pass", "TestProof", "")
			}
			if fault == "unrelated-failure" {
				emit("fail", "TestOther", "")
			}
			if fault != "missing-package-terminal" {
				emit("pass", "", "")
			}
			status := 0
			if fault == "nonzero-status" {
				status = 1
			}
			_, err := CheckBaseline(&stream, status, []Case{testCase()}, false, false)
			if (err == nil) != (fault == "") {
				t.Fatalf("fault %s: %v", fault, err)
			}
		})
	}
}

func TestBaselineDoesNotReinterpretNestedTestFrames(t *testing.T) {
	var stream bytes.Buffer
	encoder := json.NewEncoder(&stream)
	events := []Event{
		{Action: "output", Package: "fixture", Test: "TestProof", Output: "=== RUN   TestNested\n--- PASS: TestNested (0.00s)\nPASS\n"},
		{Action: "output", Package: "fixture", Test: "TestProof", Output: "PROOF-COMPLETE L-PROOF native markers=EFFECT:write\n"},
		{Action: "pass", Package: "fixture", Test: "TestProof"},
		{Action: "pass", Package: "fixture"},
	}
	for _, event := range events {
		if err := encoder.Encode(event); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := CheckBaseline(&stream, 0, []Case{testCase()}, false, false); err != nil {
		t.Fatal(err)
	}
}
