package harness

import (
	"bufio"
	"fmt"
	"io"
	"slices"
	"strings"
)

// Case is one proof leg's declaration. Residuals is the legacy Residual-kind
// list (any lane may report one of its codes); ResidualABIs maps an ABI name to
// the one residual code that lane must report instead of completing.
type Case struct {
	CharacterisationOutcome                                                   string
	Name, Package, Kind, Mode                                                 string
	Names                                                                     map[string]string
	Modes, ABIs, Markers, Obligations, Omissions, Residuals, Characterisation []string
	ResidualABIs                                                              map[string]string
	Root, NonRoot, CIOnly, AcceptFactsABI0                                    bool
}

func ValidateCases(cases []Case) error {
	seen := map[string]bool{}
	for _, c := range cases {
		if c.Name == "" || seen[c.Name] || len(c.ABIs) == 0 {
			return fmt.Errorf("invalid or duplicate case %q", c.Name)
		}
		seen[c.Name] = true
		if c.Root && c.NonRoot {
			return fmt.Errorf("%s: both root-only and non-root-only", c.Name)
		}
		if slices.Contains(c.Omissions, "root-only") && !c.Root || slices.Contains(c.Omissions, "nonroot-only") && !c.NonRoot {
			return fmt.Errorf("%s: a lane omission without its lane mark", c.Name)
		}
		abis := map[string]bool{}
		for _, abi := range c.ABIs {
			if abi == "" || abis[abi] || strings.ContainsAny(abi, " \t\n") {
				return fmt.Errorf("%s: invalid ABI %q", c.Name, abi)
			}
			abis[abi] = true
		}
		markers := map[string]bool{}
		for _, marker := range c.Markers {
			if markers[marker] {
				return fmt.Errorf("%s: duplicate marker %s", c.Name, marker)
			}
			markers[marker] = true
			if _, err := ParseProof("PROOF-COMPLETE " + c.Name + " " + c.ABIs[0] + " markers=" + marker); err != nil {
				return err
			}
		}
		for _, residual := range c.Residuals {
			if !slices.Contains(DocumentedResiduals, residual) {
				return fmt.Errorf("%s: unknown proof residual %s", c.Name, residual)
			}
		}
		if (len(c.Residuals) > 0) != (c.Kind == "Residual") || c.Kind == "Residual" && len(c.ResidualABIs) > 0 {
			return fmt.Errorf("%s: Residuals belong to a Residual-kind case, ResidualABIs to any other", c.Name)
		}
		for abi, code := range c.ResidualABIs {
			if !abis[abi] || !slices.Contains(DocumentedResiduals, code) {
				return fmt.Errorf("%s: invalid residual %s for ABI %q", c.Name, code, abi)
			}
		}
		counts := map[string]int{}
		obligations := map[string]bool{}
		for _, obligation := range c.Obligations {
			prefix, name, ok := strings.Cut(obligation, ":")
			if !ok || name == "" || obligations[obligation] || !slices.Contains([]string{"control", "jailed", "observe", "unit"}, prefix) {
				return fmt.Errorf("%s: invalid obligation %q", c.Name, obligation)
			}
			obligations[obligation] = true
			counts[prefix]++
		}
		valid := len(c.Obligations) > 0
		switch c.Kind {
		case "Execution":
			valid = valid && counts["jailed"] > 0
		case "Effect":
			valid = valid && counts["jailed"] > 0 && counts["control"] > 0 && counts["observe"] > 0
		case "Abort":
			valid = valid && counts["jailed"] > 0 && slices.Contains([]string{"SetupAbort", "LaunchFailure", "ControlledHang"}, c.Mode)
		case "Unit":
			valid = valid && counts["jailed"] == 0 && (counts["unit"] > 0 || counts["control"] > 0)
		case "Residual":
			valid = len(c.Residuals) > 0
		default:
			valid = false
		}
		if !valid {
			return fmt.Errorf("%s: obligations below %s minimum", c.Name, c.Kind)
		}
	}
	return nil
}

type ProofRecord struct {
	Outcome, Leg, ABI, Code string
	Markers                 []string
}

func ParseProof(line string) (ProofRecord, error) {
	fields := strings.Fields(markerLine(line))
	var p ProofRecord
	if len(fields) != 4 {
		return p, fmt.Errorf("invalid proof line %q", line)
	}
	p.Outcome = strings.TrimPrefix(fields[0], "PROOF-")
	p.Leg = fields[1]
	p.ABI = fields[2]
	switch p.Outcome {
	case "COMPLETE":
		if !strings.HasPrefix(fields[3], "markers=") {
			return p, fmt.Errorf("missing markers")
		}
		value := strings.TrimPrefix(fields[3], "markers=")
		if value != "" {
			p.Markers = strings.Split(value, ",")
		}
		if !slices.IsSorted(p.Markers) {
			return p, fmt.Errorf("unsorted markers")
		}
		for i, m := range p.Markers {
			prefix, name, ok := strings.Cut(m, ":")
			if !ok || name == "" || !slices.Contains([]string{"EFFECT", "ABORT"}, prefix) || i > 0 && p.Markers[i-1] == m {
				return p, fmt.Errorf("invalid marker %q", m)
			}
		}
	case "OMITTED", "RESIDUAL":
		p.Code = fields[3]
	default:
		return p, fmt.Errorf("unknown proof outcome")
	}
	return p, nil
}

func CheckProof(c Case, p ProofRecord, root, ci bool) error {
	if p.Leg != c.Name || !slices.Contains(c.ABIs, p.ABI) {
		return fmt.Errorf("unknown proof case %s %s", p.Leg, p.ABI)
	}
	switch p.Outcome {
	case "COMPLETE":
		if c.ResidualABIs[p.ABI] != "" {
			return fmt.Errorf("%s: completed in %s, whose lane reports %s", c.Name, p.ABI, c.ResidualABIs[p.ABI])
		}
		for _, m := range p.Markers {
			if !slices.Contains(c.Markers, m) {
				return fmt.Errorf("%s: undeclared marker %s", c.Name, m)
			}
		}
	case "OMITTED":
		lane := p.Code == "root-only" && c.Root && !root || p.Code == "nonroot-only" && c.NonRoot && root || p.Code == "ci-only" && c.CIOnly && !ci
		if !lane && (ci || !slices.Contains(c.Omissions, p.Code)) {
			return fmt.Errorf("%s: forbidden omission %s", c.Name, p.Code)
		}
	case "RESIDUAL":
		// The lane's outcome is fixed by the declaration, never the leg's choice.
		if !slices.Contains(c.Residuals, p.Code) && c.ResidualABIs[p.ABI] != p.Code {
			return fmt.Errorf("%s: undeclared residual %s in %s", c.Name, p.Code, p.ABI)
		}
	default:
		return fmt.Errorf("invalid proof outcome")
	}
	return nil
}

func CheckManifest(reader io.Reader, cases []Case, root, ci bool) ([]ProofRecord, error) {
	if err := ValidateCases(cases); err != nil {
		return nil, err
	}
	byName := map[string]Case{}
	for _, c := range cases {
		byName[c.Name] = c
	}
	seen := map[string]bool{}
	var records []ProofRecord
	scanner := bufio.NewScanner(reader)
	scanner.Buffer(make([]byte, 4096), 4<<20)
	for scanner.Scan() {
		line := markerLine(scanner.Text())
		if !strings.HasPrefix(line, "PROOF-") {
			continue
		}
		p, err := ParseProof(line)
		if err != nil {
			return nil, err
		}
		c, ok := byName[p.Leg]
		if !ok {
			return nil, fmt.Errorf("unlisted proof %s", p.Leg)
		}
		if err := CheckProof(c, p, root, ci); err != nil {
			return nil, err
		}
		key := p.Leg + "/" + p.ABI
		if seen[key] {
			return nil, fmt.Errorf("duplicate proof %s", key)
		}
		seen[key] = true
		records = append(records, p)
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	for _, c := range cases {
		for _, abi := range c.ABIs {
			if !seen[c.Name+"/"+abi] {
				return nil, fmt.Errorf("missing proof %s %s", c.Name, abi)
			}
		}
	}
	return records, nil
}

// CheckCaseUnion requires actual completion, never an omission, across lanes.
func CheckCaseUnion(cases []Case, registry []Protection, reports []Report) error {
	if err := ValidateCases(cases); err != nil {
		return err
	}
	for _, c := range cases {
		for _, abi := range c.ABIs {
			covered := false
			for _, report := range reports {
				for _, proof := range report.Proofs {
					if proof.Leg != c.Name || proof.ABI != abi {
						continue
					}
					if err := CheckProof(c, proof, report.Root, report.CI); err != nil {
						return err
					}
					// CheckProof admitted a residual only where the case declares it.
					covered = covered || proof.Outcome == "COMPLETE" || proof.Outcome == "RESIDUAL"
				}
			}
			if !covered {
				return fmt.Errorf("union lacks completed proof %s %s", c.Name, abi)
			}
		}
		for _, marker := range c.Markers {
			expected := slices.Contains(c.Characterisation, marker)
			for _, protection := range registry {
				for _, set := range protection.MutationSets {
					for _, leg := range set.Legs {
						if leg.Name != c.Name {
							continue
						}
						for _, abi := range c.ABIs {
							// A residual lane expects no marker on this host, but the
							// leg's markers are what it shows wherever the gap is closed.
							registeredMarkers := leg.ExpectedMarkers(abi)
							if leg.ResidualABIs[abi] != "" {
								registeredMarkers = leg.Markers
							}
							for _, registered := range registeredMarkers {
								parts := strings.Fields(registered)
								if len(parts) == 2 && strings.TrimPrefix(parts[0], "MUTATION-")+":"+parts[1] == marker {
									expected = true
								}
							}
						}
					}
				}
			}
			if !expected {
				return fmt.Errorf("%s: marker %s is neither registered nor characterised", c.Name, marker)
			}
		}
	}
	return nil
}
