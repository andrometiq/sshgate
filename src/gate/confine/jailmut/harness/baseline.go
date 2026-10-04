package harness

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"strings"
)

// CheckBaseline binds manifest records to successful test and package terminals.
// status is the aggregate producer/logger status, captured outside the pipeline.
func CheckBaseline(reader io.Reader, status int, cases []Case, root, ci bool) ([]ProofRecord, error) {
	if status != 0 {
		return nil, fmt.Errorf("infrastructure: baseline exit %d", status)
	}
	type result struct {
		terminal string
		proofs   []ProofRecord
	}
	packages := map[string]string{}
	tests := map[string]*result{}
	var manifest strings.Builder
	scanner := bufio.NewScanner(reader)
	scanner.Buffer(make([]byte, 4096), 4<<20)
	for scanner.Scan() {
		var event Event
		if err := json.Unmarshal(scanner.Bytes(), &event); err != nil {
			return nil, fmt.Errorf("baseline JSON: %w", err)
		}
		if event.Package == "" {
			return nil, fmt.Errorf("baseline event lacks package")
		}
		if _, ok := packages[event.Package]; !ok {
			packages[event.Package] = ""
		}
		if event.Action == "fail" || event.Action == "skip" || event.Action == "build-fail" || event.Action == "build-output" || suspicious(event.Output) {
			return nil, fmt.Errorf("infrastructure: baseline failure %s %s", event.Package, event.Test)
		}
		if event.Test == "" {
			if event.Action == "pass" {
				if packages[event.Package] != "" {
					return nil, fmt.Errorf("duplicate baseline package terminal")
				}
				packages[event.Package] = "pass"
			}
			for _, line := range strings.Split(event.Output, "\n") {
				if strings.HasPrefix(markerLine(line), "PROOF-") {
					return nil, fmt.Errorf("baseline proof without owning test")
				}
			}
			continue
		}
		key := event.Package + "/" + event.Test
		r := tests[key]
		if r == nil {
			r = &result{}
			tests[key] = r
		}
		if event.Action == "pass" {
			if r.terminal != "" {
				return nil, fmt.Errorf("duplicate baseline test terminal")
			}
			r.terminal = "pass"
		}
		for _, line := range strings.Split(event.Output, "\n") {
			line = markerLine(line)
			if !strings.HasPrefix(line, "PROOF-") {
				continue
			}
			if event.Action != "output" {
				return nil, fmt.Errorf("proof outside output event")
			}
			p, err := ParseProof(line)
			if err != nil {
				return nil, err
			}
			r.proofs = append(r.proofs, p)
			manifest.WriteString(line)
			manifest.WriteByte('\n')
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	if len(packages) == 0 {
		return nil, fmt.Errorf("missing baseline packages")
	}
	for name, terminal := range packages {
		if terminal != "pass" {
			return nil, fmt.Errorf("baseline package missing PASS: %s", name)
		}
	}
	for name, r := range tests {
		if r.terminal != "pass" {
			return nil, fmt.Errorf("baseline test missing PASS: %s", name)
		}
		if len(r.proofs) > 1 {
			return nil, fmt.Errorf("multiple proofs for baseline test %s", name)
		}
	}
	return CheckManifest(strings.NewReader(manifest.String()), cases, root, ci)
}
