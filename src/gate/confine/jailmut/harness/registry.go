// Package harness implements the test-only mutation registry and result checks.
// No gate package imports it.
package harness

import (
	"fmt"
	"reflect"
	"strings"
)

type Protection struct {
	ID           string
	Site         string
	Class        string
	Partners     []string
	DirectLeg    string
	EffectLegs   []string
	MutationSets []MutationSet
}

type MutationSet struct {
	IDs  []string
	Legs []Leg
}

// Names are complete go test names, indexed by native and abi1.
// Markers omit the leg field: for example "MUTATION-EFFECT write".
type Leg struct {
	Name       string
	Package    string
	Names      map[string]string
	Root       bool
	CIOnly     bool
	Markers    []string
	ABIMarkers map[string][]string
}

func (l Leg) ExpectedMarkers(abi string) []string {
	if markers, ok := l.ABIMarkers[abi]; ok {
		return markers
	}
	return l.Markers
}

func (s MutationSet) Name() string { return strings.Join(s.IDs, ",") }

func Validate(registry []Protection) error {
	ids := map[string]bool{}
	for _, p := range registry {
		if p.ID == "" || ids[p.ID] || p.Site == "" {
			return fmt.Errorf("invalid or duplicate protection %q", p.ID)
		}
		ids[p.ID] = true
	}
	sets := map[string]MutationSet{}
	for _, p := range registry {
		if p.Class != "single" && p.Class != "multi" && p.Class != "direct" {
			return fmt.Errorf("%s: invalid class", p.ID)
		}
		for _, partner := range p.Partners {
			if !ids[partner] {
				return fmt.Errorf("%s: unknown partner %s", p.ID, partner)
			}
		}
		if len(p.MutationSets) == 0 {
			return fmt.Errorf("%s: no mutation sets", p.ID)
		}
		declared := map[string]bool{}
		redByABI := map[string]bool{}
		for _, s := range p.MutationSets {
			if len(s.IDs) == 0 || len(s.Legs) == 0 {
				return fmt.Errorf("%s: empty mutation set", p.ID)
			}
			mutated := map[string]bool{}
			for _, id := range s.IDs {
				if !ids[id] || mutated[id] {
					return fmt.Errorf("%s: unknown or duplicate mutation %s", s.Name(), id)
				}
				mutated[id] = true
			}
			if !mutated[p.ID] {
				return fmt.Errorf("%s: set does not mutate its protection", p.ID)
			}
			if previous, ok := sets[s.Name()]; ok && !reflect.DeepEqual(previous, s) {
				return fmt.Errorf("%s: conflicting shared mutation set", s.Name())
			}
			sets[s.Name()] = s
			names := map[string]bool{}
			for _, leg := range s.Legs {
				if leg.Name == "" || leg.Package == "" || names[leg.Name] {
					return fmt.Errorf("%s: invalid leg %q", s.Name(), leg.Name)
				}
				names[leg.Name] = true
				declared[leg.Name] = true
				for _, abi := range []string{"native", "abi1"} {
					if leg.Names[abi] == "" {
						return fmt.Errorf("%s: %s missing %s full name", s.Name(), leg.Name, abi)
					}
					parts := strings.Split(leg.Names[abi], "/")
					if len(parts) < 2 || parts[len(parts)-1] != leg.Name {
						return fmt.Errorf("%s: %s full name does not identify its leg", leg.Name, abi)
					}
					if strings.HasPrefix(leg.Name, "L-") && (len(parts) < 3 || parts[len(parts)-2] != abi) {
						return fmt.Errorf("%s: %s full name does not identify its ABI", leg.Name, abi)
					}
					markers := map[string]bool{}
					for _, marker := range leg.ExpectedMarkers(abi) {
						fields := strings.Fields(marker)
						if len(fields) != 2 || (fields[0] != "MUTATION-EFFECT" && fields[0] != "MUTATION-ABORT") || markers[marker] {
							return fmt.Errorf("%s: invalid marker %q", leg.Name, marker)
						}
						markers[marker] = true
					}
				}
			}
			for _, abi := range []string{"native", "abi1"} {
				hasRed := false
				for _, leg := range s.Legs {
					hasRed = hasRed || len(leg.ExpectedMarkers(abi)) > 0
				}
				redByABI[abi] = redByABI[abi] || hasRed
			}
		}
		for _, abi := range []string{"native", "abi1"} {
			if !redByABI[abi] {
				return fmt.Errorf("%s: no expected red leg at %s", p.ID, abi)
			}
		}
		for _, name := range append([]string{p.DirectLeg}, p.EffectLegs...) {
			if name != "" && !declared[name] {
				return fmt.Errorf("%s: unregistered proof leg %s", p.ID, name)
			}
		}
	}
	return nil
}

// Select applies lane marks before constructing go test patterns.
func Select(s MutationSet, root, ci bool) (legs []Leg, omitted []string) {
	for _, leg := range s.Legs {
		reason := ""
		if leg.Root && !root {
			reason = "root"
		} else if leg.CIOnly && !ci {
			reason = "ci-only"
		}
		if reason != "" {
			omitted = append(omitted, fmt.Sprintf("MUTATE-OMITTED(%s): %s %s", reason, s.Name(), leg.Name))
			continue
		}
		legs = append(legs, leg)
	}
	return
}
