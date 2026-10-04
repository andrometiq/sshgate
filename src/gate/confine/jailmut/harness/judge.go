package harness

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"slices"
	"strings"
)

type Event struct{ Action, Package, Test, Output string }

type testResult struct {
	terminal string
	proofs   []ProofRecord
}

func markerLine(line string) string {
	// testing.T logs carry an indented file:line prefix; strip just that prefix.
	line = strings.TrimSpace(line)
	if i := strings.Index(line, ": "); i >= 0 && strings.Contains(line[:i], ".go:") {
		line = line[i+2:]
	}
	return line
}

// Judge checks a single package invocation, using full test names throughout.
func Judge(stream io.Reader, stderr string, status int, legs []Leg, abi string) error {
	if status != 0 {
		return fmt.Errorf("infrastructure: go test exit %d", status)
	}
	if suspicious(stderr) {
		return fmt.Errorf("infrastructure: stderr: %s", stderr)
	}
	results := map[string]*testResult{}
	packageTerminal := ""
	scanner := bufio.NewScanner(stream)
	scanner.Buffer(make([]byte, 4096), 4<<20)
	for scanner.Scan() {
		var event Event
		if err := json.Unmarshal(scanner.Bytes(), &event); err != nil {
			return fmt.Errorf("infrastructure: malformed JSON: %w", err)
		}
		if event.Action == "build-fail" || event.Action == "build-output" {
			return fmt.Errorf("infrastructure: build failure")
		}
		if suspicious(event.Output) {
			return fmt.Errorf("infrastructure: %s", strings.TrimSpace(event.Output))
		}
		if event.Test == "" {
			if event.Action == "pass" || event.Action == "fail" || event.Action == "skip" {
				if packageTerminal != "" {
					return fmt.Errorf("infrastructure: duplicate package terminal")
				}
				packageTerminal = event.Action
			}
			continue
		}
		result := results[event.Test]
		if result == nil {
			result = &testResult{}
			results[event.Test] = result
		}
		switch event.Action {
		case "pass", "fail", "skip":
			if result.terminal != "" {
				return fmt.Errorf("infrastructure: duplicate terminal for %s", event.Test)
			}
			result.terminal = event.Action
		case "output":
			for _, line := range strings.Split(event.Output, "\n") {
				line = markerLine(line)
				if strings.HasPrefix(line, "PROOF-") {
					proof, err := ParseProof(line)
					if err != nil {
						return fmt.Errorf("infrastructure: %w", err)
					}
					result.proofs = append(result.proofs, proof)
				}
			}
		}
	}
	if err := scanner.Err(); err != nil {
		return fmt.Errorf("infrastructure: JSON read: %w", err)
	}
	if packageTerminal != "pass" {
		return fmt.Errorf("infrastructure: package did not pass")
	}
	for name, result := range results {
		if result.terminal == "fail" || result.terminal == "skip" {
			return fmt.Errorf("infrastructure: failed or skipped test %s", name)
		}
	}
	for _, leg := range legs {
		name := leg.Names[abi]
		result := results[name]
		if result == nil || result.terminal != "pass" {
			return fmt.Errorf("infrastructure: %s missing PASS", name)
		}
		if len(result.proofs) != 1 {
			return fmt.Errorf("infrastructure: %s requires exactly one finalized proof", name)
		}
		proof := result.proofs[0]
		if proof.Leg != leg.Name || proof.ABI != abi {
			return fmt.Errorf("infrastructure: mismatched proof %s", name)
		}
		if proof.Outcome != "COMPLETE" {
			c := Case{Name: leg.Name, ABIs: []string{abi}, Root: leg.Root, CIOnly: leg.CIOnly, Omissions: leg.Omissions, Residuals: leg.Residuals}
			if err := CheckProof(c, proof, os.Geteuid() == 0, os.Getenv("SSHGATE_JAIL_CI") == "1"); err != nil {
				return fmt.Errorf("infrastructure: %w", err)
			}
			continue
		}
		var want []string
		for _, marker := range leg.ExpectedMarkers(abi) {
			parts := strings.Fields(marker)
			want = append(want, strings.TrimPrefix(parts[0], "MUTATION-")+":"+parts[1])
		}
		slices.Sort(want)
		if !slices.Equal(proof.Markers, want) {
			return fmt.Errorf("mutation not detected or wrong marker set: %s got %q want %q", name, proof.Markers, want)
		}
	}
	return nil
}

func suspicious(output string) bool {
	for _, line := range strings.Split(output, "\n") {
		line = markerLine(line)
		if strings.HasPrefix(line, "panic: ") || strings.HasPrefix(line, "fatal error: ") || strings.Contains(line, "test timed out after") || strings.Contains(line, "no tests to run") || strings.Contains(line, "SETUP:") || strings.Contains(line, "UNEXPECTED:") || strings.Contains(line, "CONTROL-SKIPPED") {
			return true
		}
	}
	return false
}
