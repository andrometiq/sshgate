//go:build linux

package confine

import (
	"github.com/karthikeyan5/sshgate/src/gate/confine/jailmut/harness"
	"testing"
)

func hostPIDLeg(name string, markers ...string) harness.Leg {
	return harness.Leg{Name: name, Package: "./src/gate/confine", Names: map[string]string{"native": "TestJailMatrixP15c/native/" + name, "abi1": "TestJailMatrixP15c/abi1/" + name}, Markers: markers}
}
func userRetuneLeg() harness.Leg {
	leg := hostPIDLeg("L-SCHED-USER", "MUTATION-EFFECT errno", "MUTATION-EFFECT retuned")
	leg.Root = true
	leg.CIOnly = true
	return leg
}
func asyncScopeMutationSet() harness.MutationSet {
	return harness.MutationSet{IDs: []string{"P-SC-ASYNC-OWNER", "P-LL-SCOPE-SIGNAL"}, Legs: []harness.Leg{hostPIDLeg("L-ASYNC-SCOPE", "MUTATION-EFFECT errno", "MUTATION-EFFECT signal")}}
}
func hostPIDRegistry() []prot {
	var result []prot
	for _, row := range []struct {
		id, unit string
		effects  []harness.Leg
	}{
		{"P-SC-PROCESS-MRELEASE", "U-Mrelease", []harness.Leg{hostPIDLeg("L-PROCESS-MRELEASE", "MUTATION-EFFECT errno", "MUTATION-EFFECT memory")}},
		{"P-SC-SIGNAL", "U-Signal", []harness.Leg{hostPIDLeg("L-SIGNAL-HOST", "MUTATION-EFFECT signal"), hostPIDLeg("L-SIGNAL-OWN-GROUP")}},
		{"P-SC-ASYNC-OWNER", "U-AsyncOwner", []harness.Leg{hostPIDLeg("L-ASYNC-OWNER", "MUTATION-EFFECT errno", "MUTATION-EFFECT signal")}},
		{"P-SC-RETUNE", "U-Retune", []harness.Leg{hostPIDLeg("L-RETUNE", "MUTATION-EFFECT errno", "MUTATION-EFFECT retuned")}},
		{"P-SESSION", "", []harness.Leg{hostPIDLeg("L-SESSION", "MUTATION-EFFECT session")}},
		{"P-SUBREAPER", "", []harness.Leg{hostPIDLeg("L-LIFECYCLE", "MUTATION-EFFECT alive")}},
	} {
		legs := row.effects
		if row.unit != "" {
			legs = append([]harness.Leg{p15Unit("TestHostPIDFilters", row.unit)}, legs...)
		}
		result = append(result, prot{ID: row.id, Site: "host PID process walls", Class: "single", DirectLeg: legs[0].Name, MutationSets: []harness.MutationSet{{IDs: []string{row.id}, Legs: legs}}})
	}
	for i := range result {
		if result[i].ID == "P-SC-RETUNE" {
			result[i].MutationSets[0].Legs = append(result[i].MutationSets[0].Legs, userRetuneLeg())
		}
		if result[i].ID == "P-SC-SIGNAL" {
			result[i].Class = "multi"
			result[i].Partners = []string{"P-LL-SCOPE-SIGNAL"}
			scope := hostPIDLeg("L-SIGNAL-SCOPE")
			if probeLandlockABI() < 6 {
				scope.Markers = []string{"MUTATION-EFFECT signal"}
			}
			scope.ABIMarkers = map[string][]string{"abi1": {"MUTATION-EFFECT signal"}}
			result[i].MutationSets[0].Legs = append(result[i].MutationSets[0].Legs, scope)
		}
		if result[i].ID == "P-SC-ASYNC-OWNER" {
			result[i].Class = "multi"
			result[i].Partners = []string{"P-LL-SCOPE-SIGNAL"}
			scope := hostPIDLeg("L-ASYNC-SCOPE", "MUTATION-EFFECT errno")
			if probeLandlockABI() < 6 {
				scope.Markers = append(scope.Markers, "MUTATION-EFFECT signal")
			}
			scope.ABIMarkers = map[string][]string{"abi1": {"MUTATION-EFFECT errno", "MUTATION-EFFECT signal"}}
			result[i].MutationSets[0].Legs = append(result[i].MutationSets[0].Legs, scope)
			result[i].MutationSets = append(result[i].MutationSets, asyncScopeMutationSet())
		}
	}
	return result
}

// These syscall numbers and encodings are independent of the generated table.
func TestHostPIDFilters(t *testing.T) {
	t.Run("U-Mrelease", func(t *testing.T) {
		filterTableCheck(t, "U-Mrelease", func(check func(bool)) {
			for _, abi := range []int{1, 5, 6, 10} {
				check(evalFilter(t, buildFilter(filterParams{abi: abi}), dataFor(448, x8664, 7, 0)) != actDeny)
			}
		})
	})
	t.Run("U-Signal", func(t *testing.T) {
		filterTableCheck(t, "U-Signal", func(check func(bool)) {
			for _, abi := range []int{1, 5, 6, 10} {
				f := buildFilter(filterParams{abi: abi})
				for _, pid := range []uint64{0, 1, 0xffffffff, 0xffffffffffffffff, 0x80000000, 0xffffffff80000000, 1 << 32, 1<<32 | 1} {
					for _, sig := range []uint64{0, 15, 1 << 32, 1<<32 | 15} {
						want := actDeny
						if abi >= 6 || uint32(pid) == 0 || uint32(sig) == 0 {
							want = actAllow
						}
						check(evalFilter(t, f, dataFor(62, x8664, pid, sig)) != want)
					}
				}
				for _, nr := range []uint32{200, 234, 129, 297, 424} {
					want := actDeny
					if abi >= 6 {
						want = actAllow
					}
					check(evalFilter(t, f, dataFor(nr, x8664, 1, 1, 15)) != want)
				}
			}
		})
	})
	t.Run("U-AsyncOwner", func(t *testing.T) {
		filterTableCheck(t, "U-AsyncOwner", func(check func(bool)) {
			for _, abi := range []int{1, 5, 6, 10} {
				f := buildFilter(filterParams{abi: abi})
				for _, owner := range []uint64{0, 1, 0xffffffff, 0xffffffffffffffff, 0x80000000, 0xffffffff80000000, 1 << 32, 1<<32 | 1} {
					want := actDeny
					if uint32(owner) == 0 {
						want = actAllow
					}
					check(evalFilter(t, f, dataFor(72, x8664, 0, 8, owner)) != want)
					check(evalFilter(t, f, dataFor(72, x8664, 0, 15, owner)) != actDeny)
					check(evalFilter(t, f, dataFor(72, x8664, 0, 10, owner)) != actAllow)
				}
				for _, request := range []uint64{0x8901, 0x8902, 0x5410, 0x100008901, 0x100008902, 0x100005410} {
					check(evalFilter(t, f, dataFor(16, x8664, 0, request, 0)) != actDeny)
				}
			}
		})
	})
	t.Run("U-Retune", func(t *testing.T) {
		filterTableCheck(t, "U-Retune", func(check func(bool)) {
			for _, abi := range []int{1, 5, 6, 10} {
				f := buildFilter(filterParams{abi: abi})
				for _, pid := range []uint64{0, 1, 0xffffffff, 0xffffffffffffffff, 0x80000000, 0xffffffff80000000, 1 << 32, 1<<32 | 1} {
					for _, nr := range []uint32{142, 144, 203, 314, 256, 279} {
						want := actDeny
						if uint32(pid) == 0 {
							want = actAllow
						}
						check(evalFilter(t, f, dataFor(nr, x8664, pid)) != want)
					}
					for _, nr := range []uint32{141, 251} {
						for _, which := range []uint64{0, 1, 2, 3, 0xffffffff, 1 << 32, 1<<32 | 1, 1<<32 | 2} {
							want := actDeny
							if uint32(pid) == 0 && (nr == 141 && uint32(which) < 2 || nr == 251 && (uint32(which) == 1 || uint32(which) == 2)) {
								want = actAllow
							}
							check(evalFilter(t, f, dataFor(nr, x8664, which, pid, 0)) != want)
						}
					}
					for _, ptr := range []uint64{0, 1, 1 << 32, 1<<32 | 1} {
						for _, resource := range []uint64{4, 7, 16} {
							want := actDeny
							if ptr == 0 || uint32(pid) == 0 && resource == 7 {
								want = actAllow
							}
							check(evalFilter(t, f, dataFor(302, x8664, pid, resource, ptr)) != want)
						}
					}
				}
			}
		})
	})
}
