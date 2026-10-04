// jailmut runs the registry's mutation tests and validates their JSON events.
package main

import (
	"bytes"
	"debug/buildinfo"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"

	"github.com/karthikeyan5/sshgate/src/gate/confine/jailmut/harness"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run() error {
	render := flag.String("render-json", "", "render only Output fields from an authoritative go test JSON stream")
	proofLog := flag.String("proof-log", "", "baseline test2json log (requires .status companion)")
	manifest := flag.String("check-manifest", "", "validate a jail log against the proof case table")
	mutate := flag.String("mutate", "", "select protection IDs")
	reportPath := flag.String("report", "", "write checked lane report")
	union := flag.String("union", "", "comma-separated non-root and root CI reports")
	binary := flag.String("check-binary", "", "check release build metadata")
	flag.Parse()
	if *render != "" {
		file, err := os.Open(*render)
		if err != nil {
			return err
		}
		defer file.Close()
		return renderJSON(file, os.Stdout)
	}
	if *binary != "" {
		info, err := buildinfo.ReadFile(*binary)
		if err != nil {
			return err
		}
		for _, setting := range info.Settings {
			if setting.Key == "-tags" && strings.Contains(setting.Value, "jail_mutation") || setting.Key == "-ldflags" && strings.Contains(setting.Value, "jailmut") {
				return fmt.Errorf("mutation build setting: %s=%s", setting.Key, setting.Value)
			}
		}
		return nil
	}
	if *manifest != "" {
		cases, err := readCases()
		if err != nil {
			return err
		}
		file, err := os.Open(*manifest)
		if err != nil {
			return err
		}
		defer file.Close()
		status, statusErr := baselineStatus(*manifest)
		if statusErr != nil {
			return statusErr
		}
		_, err = harness.CheckBaseline(file, status, cases, os.Geteuid() == 0, os.Getenv("SSHGATE_JAIL_CI") == "1")
		return err
	}
	registry, err := readRegistry()
	if err != nil {
		return err
	}
	if *union != "" {
		var reports []harness.Report
		for _, path := range strings.Split(*union, ",") {
			data, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			var report harness.Report
			if err = json.Unmarshal(data, &report); err != nil {
				return err
			}
			reports = append(reports, report)
		}
		if err := harness.CheckUnion(registry, reports); err != nil {
			return err
		}
		cases, err := readCases()
		if err != nil {
			return err
		}
		if err := harness.CheckCaseUnion(cases, registry, reports); err != nil {
			return err
		}
		fmt.Println("mutation phase-end union: OK")
		return nil
	}
	report := harness.Report{Root: os.Geteuid() == 0, CI: os.Getenv("SSHGATE_JAIL_CI") == "1"}
	if len(registry) == 0 {
		if *mutate != "" {
			return fmt.Errorf("unknown MUTATE IDs %q: registry is empty", *mutate)
		}
		fmt.Println("test-jail-mutate: empty P1.1 registry; no protections or mutation sets ran")
	}
	sets, err := selectMutationSets(registry, *mutate)
	if err != nil {
		return err
	}
	for _, set := range sets {
		if err := runSet(set, &report, os.Stdout); err != nil {
			return err
		}
	}

	if *proofLog != "" {
		cases, err := readCases()
		if err != nil {
			return err
		}
		file, err := os.Open(*proofLog)
		if err != nil {
			return err
		}
		status, statusErr := baselineStatus(*proofLog)
		if statusErr != nil {
			file.Close()
			return statusErr
		}
		proofs, checkErr := harness.CheckBaseline(file, status, cases, report.Root, report.CI)
		closeErr := file.Close()
		if checkErr != nil {
			return checkErr
		}
		if closeErr != nil {
			return closeErr
		}
		report.Proofs = append(report.Proofs, proofs...)
	}
	if *reportPath != "" {
		data, err := json.MarshalIndent(report, "", "  ")
		if err != nil {
			return err
		}
		return os.WriteFile(*reportPath, append(data, '\n'), 0600)
	}
	return nil
}

func selectMutationSets(registry []harness.Protection, filter string) ([]harness.MutationSet, error) {
	requested := map[string]bool{}
	if filter != "" {
		for _, id := range strings.Split(filter, ",") {
			requested[id] = false
		}
		for _, protection := range registry {
			if _, ok := requested[protection.ID]; ok {
				requested[protection.ID] = true
			}
		}
		for id, known := range requested {
			if !known {
				return nil, fmt.Errorf("unknown MUTATE ID %q", id)
			}
		}
	}
	var sets []harness.MutationSet
	seen := map[string]bool{}
	for _, protection := range registry {
		for _, set := range protection.MutationSets {
			matches := filter == ""
			for _, id := range set.IDs {
				matches = matches || requested[id]
			}
			if matches && !seen[set.Name()] {
				sets = append(sets, set)
				seen[set.Name()] = true
			}
		}
	}
	return sets, nil
}

func runSet(set harness.MutationSet, report *harness.Report, output io.Writer) error {
	legs, omitted := harness.Select(set, report.Root, report.CI)
	for _, line := range omitted {
		fmt.Fprintln(output, line)
	}
	for _, abi := range []string{"native", "abi1"} {
		hasRed := false
		for _, leg := range legs {
			hasRed = hasRed || len(leg.ExpectedMarkers(abi)) > 0
		}
		if !hasRed {
			fmt.Fprintf(output, "NOT-RUN: %s %s (all expected red legs omitted)\n", set.Name(), abi)
		}
		for _, leg := range legs {
			proof, err := runLegProof(set, leg, abi)
			if err != nil {
				return fmt.Errorf("%s %s %s: %w", set.Name(), abi, leg.Name, err)
			}
			report.Proofs = append(report.Proofs, proof)
			if proof.Outcome == "COMPLETE" {
				report.Outcomes = append(report.Outcomes, harness.Outcome{Set: set.Name(), ABI: abi, Leg: leg.Name, Red: len(leg.ExpectedMarkers(abi)) > 0})
			}
		}
		if hasRed {
			fmt.Fprintf(output, "MUTATION-OK: %s %s root=%t\n", set.Name(), abi, report.Root)
		}
	}
	return nil
}

func readRegistry() ([]harness.Protection, error) {
	cmd := exec.Command("go", "test", "-count=1", "-run", "^TestMutationRegistryJSON$", "-v", "./src/gate/confine")
	output, err := cmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("registry test: %w\n%s", err, output)
	}
	var registry []harness.Protection
	found := false
	for _, line := range strings.Split(string(output), "\n") {
		if strings.HasPrefix(line, "JAILMUT-REGISTRY ") {
			if found {
				return nil, fmt.Errorf("duplicate registry output")
			}
			found = true
			if err := json.Unmarshal([]byte(strings.TrimPrefix(line, "JAILMUT-REGISTRY ")), &registry); err != nil {
				return nil, err
			}
		}
	}
	if !found {
		return nil, fmt.Errorf("missing registry output")
	}
	return registry, harness.Validate(registry)
}

func exactPattern(name string) string {
	parts := strings.Split(name, "/")
	for i, part := range parts {
		parts[i] = "^" + regexp.QuoteMeta(part) + "$"
	}
	return strings.Join(parts, "/")
}

func runLegProof(set harness.MutationSet, leg harness.Leg, abi string) (harness.ProofRecord, error) {
	args := []string{"test", "-count=1", "-tags=jail_e2e,jail_mutation", "-ldflags=-X github.com/karthikeyan5/sshgate/src/gate/confine/jailmut.IDs=" + set.Name(), "-run", exactPattern(leg.Names[abi]), "-json", leg.Package}
	// POSIX capture keeps go's status separate from stream/logging failures. The
	// parent reads JSON and stderr independently, never inferring red from exit 1.
	directory, err := os.MkdirTemp("", "sshgate-jailmut-")
	if err != nil {
		return harness.ProofRecord{}, err
	}
	defer os.RemoveAll(directory)
	statusPath := directory + "/status"
	command := exec.Command("/bin/sh", append([]string{"-c", `"$@"; result=$?; printf '%s\n' "$result" > "$JAILMUT_STATUS"`, "jailmut", "go"}, args...)...)
	command.Env = append(os.Environ(), "JAILMUT_STATUS="+statusPath)
	var stdout, stderr bytes.Buffer
	command.Stdout = &stdout
	command.Stderr = &stderr
	if err := command.Run(); err != nil {
		return harness.ProofRecord{}, fmt.Errorf("infrastructure: status capture: %w", err)
	}
	data, err := os.ReadFile(statusPath)
	if err != nil {
		return harness.ProofRecord{}, err
	}
	status := -1
	if _, err := fmt.Sscanf(string(data), "%d", &status); err != nil {
		return harness.ProofRecord{}, fmt.Errorf("infrastructure: invalid status: %w", err)
	}
	if err := harness.Judge(bytes.NewReader(stdout.Bytes()), stderr.String(), status, []harness.Leg{leg}, abi); err != nil {
		return harness.ProofRecord{}, err
	}
	decoder := json.NewDecoder(&stdout)
	for {
		var event harness.Event
		if err := decoder.Decode(&event); err != nil {
			return harness.ProofRecord{}, fmt.Errorf("judged proof missing: %w", err)
		}
		if event.Test != leg.Names[abi] {
			continue
		}
		for _, line := range strings.Split(event.Output, "\n") {
			if index := strings.Index(line, "PROOF-"); index >= 0 {
				return harness.ParseProof(line[index:])
			}
		}
	}
}

func readCases() ([]harness.Case, error) {
	command := exec.Command("go", "test", "-count=1", "-run", "^TestProofCasesJSON$", "-v", "./src/gate/confine")
	output, err := command.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("proof cases: %w\n%s", err, output)
	}
	var cases []harness.Case
	found := false
	for _, line := range strings.Split(string(output), "\n") {
		if !strings.HasPrefix(line, "JAIL-PROOF-CASES ") {
			continue
		}
		if found {
			return nil, fmt.Errorf("duplicate proof cases")
		}
		found = true
		if err := json.Unmarshal([]byte(strings.TrimPrefix(line, "JAIL-PROOF-CASES ")), &cases); err != nil {
			return nil, err
		}
	}
	if !found {
		return nil, fmt.Errorf("missing proof case table")
	}
	return cases, harness.ValidateCases(cases)
}

func baselineStatus(path string) (int, error) {
	data, err := os.ReadFile(path + ".status")
	if err != nil {
		return -1, fmt.Errorf("baseline status: %w", err)
	}
	status, err := strconv.Atoi(strings.TrimSpace(string(data)))
	if err != nil {
		return -1, fmt.Errorf("baseline status: %w", err)
	}
	return status, nil
}

func renderJSON(reader io.Reader, writer io.Writer) error {
	decoder := json.NewDecoder(reader)
	for {
		var event harness.Event
		if err := decoder.Decode(&event); err != nil {
			if err == io.EOF {
				return nil
			}
			return fmt.Errorf("render test JSON: %w", err)
		}
		if _, err := io.WriteString(writer, event.Output); err != nil {
			return fmt.Errorf("render test output: %w", err)
		}
	}
}
