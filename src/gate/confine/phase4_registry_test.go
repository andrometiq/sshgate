package confine

import "github.com/karthikeyan5/sshgate/src/gate/confine/jailmut/harness"

func phase4Leg(name string, markers ...string) harness.Leg {
	for _, c := range proofCasesPhase4() {
		if c.Name == name {
			return harness.Leg{Name: name, Package: c.Package, Names: c.Names, Markers: markers, Omissions: c.Omissions}
		}
	}
	panic("unknown Phase4 leg: " + name)
}

func phase4Registry() []prot {
	rows := []struct {
		id, site, direct string
		effects          []string
		marker           string
	}{
		{"P-G-ENVELOPE", "parseEnvelope byte grammar", "U-EnvelopeParse", []string{"G-ENVELOPE-GRAMMAR"}, "agent-bytes"},
		{"P-G-ENVELOPE-NO-NET", "runEnvelope readFlags never grants network", "U-EnvelopeFlags", []string{"G-ENVELOPE-NO-NET-UNPINNED", "G-ENVELOPE-NO-NET-DENY"}, "connected"},
		{"P-G-ENVELOPE-EXPECT-NET", "execRead checks the admission pin network", "U-EnvelopeExpectNet", []string{"G-ENVELOPE-PIN-SNAPSHOT"}, "ran-without-network"},
		{"P-G-NET-DAEMON-READ", "execRead refuses daemon network requests", "U-DaemonReadNetRefused", []string{"G-NET-LANE2-AVAILABLE"}, "lane2-ran"},
	}
	var result []prot
	for _, row := range rows {
		legs := []harness.Leg{phase4Leg(row.direct, "MUTATION-EFFECT decision")}
		for _, name := range row.effects {
			legs = append(legs, phase4Leg(name, "MUTATION-EFFECT "+row.marker))
		}
		if row.id == "P-G-ENVELOPE-NO-NET" {
			legs = append(legs, phase4Leg("G-ENVELOPE-NET-ALLOW"))
		}
		result = append(result, prot{ID: row.id, Site: row.site, Class: "single", DirectLeg: row.direct, EffectLegs: row.effects, MutationSets: []harness.MutationSet{{IDs: []string{row.id}, Legs: legs}}})
	}
	return result
}

func phase4Extend(registry []prot) {
	for i := range registry {
		p := &registry[i]
		if p.ID == "P-G-CONFINE-REQUIRED" {
			p.EffectLegs = append(p.EffectLegs, "G-ENVELOPE-ABSENT")
			p.MutationSets[0].Legs = append(p.MutationSets[0].Legs, phase4Leg("G-ENVELOPE-ABSENT", "MUTATION-EFFECT ran-unconfined"), phase4Leg("G-ENVELOPE-ABSENT-TWIN"))
		}
		if p.ID == "P-G-NET-STRICT" {
			p.EffectLegs = append(p.EffectLegs, "G-ENVELOPE-UNMET")
		}
		for j := range p.MutationSets {
			set := &p.MutationSets[j]
			if p.ID != "P-G-NET-STRICT" && p.ID != "P-G-STRICT" && p.ID != "P-COVERS" {
				continue
			}
			for _, leg := range set.Legs {
				if leg.Name == "G-NET-STRICT-UNMET-FUSE" {
					set.Legs = append(set.Legs, phase4Leg("G-ENVELOPE-UNMET", leg.Markers...))
					break
				}
			}
		}
	}
}
