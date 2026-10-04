package harness

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"
)

type Event struct{ Action, Package, Test, Output string }

type testResult struct {
	terminal string
	markers  []string
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
	if status != 0 && status != 1 {
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
				if strings.HasPrefix(line, "MUTATION-EFFECT ") || strings.HasPrefix(line, "MUTATION-ABORT ") {
					result.markers = append(result.markers, line)
				}
			}
		}
	}
	if err := scanner.Err(); err != nil {
		return fmt.Errorf("infrastructure: JSON read: %w", err)
	}
	accepted := map[string]bool{}
	expectedRed := 0
	for _, leg := range legs {
		name := leg.Names[abi]
		result := results[name]
		if result == nil || result.terminal == "" || result.terminal == "skip" {
			return fmt.Errorf("infrastructure: %s missing terminal or skipped", name)
		}
		var want []string
		for _, marker := range leg.ExpectedMarkers(abi) {
			parts := strings.SplitN(marker, " ", 2)
			want = append(want, parts[0]+" "+leg.Name+" "+parts[1])
		}
		if len(want) > 0 && result.terminal == "pass" {
			return fmt.Errorf("mutation not detected: %s", name)
		}
		sort.Strings(want)
		sort.Strings(result.markers)
		if strings.Join(want, "\n") != strings.Join(result.markers, "\n") {
			return fmt.Errorf("wrong marker set: %s got %q want %q", name, result.markers, want)
		}
		if len(want) == 0 {
			if result.terminal != "pass" {
				return fmt.Errorf("infrastructure: green leg %s failed", name)
			}
			continue
		}
		expectedRed++
		if result.terminal == "pass" {
			return fmt.Errorf("mutation not detected: %s", name)
		}
		accepted[name] = true
	}
	for name, result := range results {
		if result.terminal == "skip" {
			return fmt.Errorf("infrastructure: unexpected skip %s", name)
		}
		if result.terminal != "fail" {
			continue
		}
		if accepted[name] {
			continue
		}
		hasRed := false
		for red := range accepted {
			if strings.HasPrefix(red, name+"/") {
				hasRed = true
			}
		}
		if !hasRed || len(result.markers) > 0 {
			return fmt.Errorf("infrastructure: unlisted failure %s", name)
		}
		for child, descendant := range results {
			if strings.HasPrefix(child, name+"/") && descendant.terminal == "fail" && !accepted[child] {
				hasAcceptedChild := false
				for red := range accepted {
					if strings.HasPrefix(red, child+"/") {
						hasAcceptedChild = true
					}
				}
				if !hasAcceptedChild {
					return fmt.Errorf("infrastructure: non-red failing descendant %s", child)
				}
			}
		}
	}
	expectedStatus := 0
	expectedPackage := "pass"
	if expectedRed > 0 {
		expectedStatus = 1
		expectedPackage = "fail"
	}
	if status != expectedStatus || packageTerminal != expectedPackage {
		return fmt.Errorf("infrastructure: exit/package mismatch: %d/%s want %d/%s", status, packageTerminal, expectedStatus, expectedPackage)
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
