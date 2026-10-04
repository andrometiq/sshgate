package confine

import "github.com/karthikeyan5/sshgate/src/gate/confine/jailmut/harness"

func credentialLeg(name string, markers ...string) harness.Leg {
	return harness.Leg{Name: name, Package: "./src/gate/confine", Names: map[string]string{"native": "TestJailMatrixCredentials/native/" + name, "abi1": "TestJailMatrixCredentials/abi1/" + name}, Markers: markers}
}

func credentialRegistry() []prot {
	credsAbort := harness.MutationSet{IDs: []string{"P-CAPS"}, Legs: []harness.Leg{credentialLeg("L-SELFCHECK-CREDS", "MUTATION-ABORT selfcheck")}}
	credsEffect := harness.MutationSet{IDs: []string{"P-CAPS", "P-SELFCHECK-CREDS"}, Legs: []harness.Leg{credentialLeg("L-SELFCHECK-CREDS", "MUTATION-EFFECT credentials")}}
	llEffect := harness.MutationSet{IDs: []string{"P-LL-REQUIRED", "P-SELFCHECK-LL"}, Legs: []harness.Leg{credentialLeg("L-SELFCHECK-LL", "MUTATION-EFFECT reached-exec")}}
	return []prot{
		{ID: "P-NNP", Site: "setNoNewPrivs", Class: "single", DirectLeg: "L-NNP-LANDLOCK", MutationSets: []harness.MutationSet{{IDs: []string{"P-NNP"}, Legs: []harness.Leg{credentialLeg("L-NNP-LANDLOCK", "MUTATION-ABORT landlock")}}}},
		{ID: "P-CAPS", Site: "dropCaps", Class: "multi", DirectLeg: "L-SELFCHECK-CREDS", Partners: []string{"P-SELFCHECK-CREDS"}, MutationSets: []harness.MutationSet{credsAbort, credsEffect}},
		{ID: "P-SELFCHECK-CREDS", Site: "selfcheck S3", Class: "multi", DirectLeg: "L-SELFCHECK-CREDS", Partners: []string{"P-CAPS"}, MutationSets: []harness.MutationSet{credsEffect}},
		{ID: "P-SELFCHECK-LL", Site: "selfcheck S4", Class: "multi", DirectLeg: "L-SELFCHECK-LL", Partners: []string{"P-LL-REQUIRED"}, MutationSets: []harness.MutationSet{llEffect}},
	}
}
