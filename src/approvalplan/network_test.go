package approvalplan

import (
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func legacyNetCases() []struct {
	name            string
	n, i            int
	command, reason string
} {
	return []struct {
		name            string
		n, i            int
		command, reason string
	}{
		{"batch-first", 2, 0, "cat x", "diagnose"},
		{"batch-second", 2, 1, "cat x", "diagnose"},
		{"zero-commands", 0, 0, "cat x", "diagnose"},
		{"revoke", 1, 0, "SSHGATE_REVOKE", "diagnose"},
		{"update", 1, 0, "SSHGATE_UPDATE " + strings.Repeat("a", 64), "diagnose"},
		{"transfer", 1, 0, "SSHGATE_XFER_SEND x", "diagnose"},
		{"envelope", 1, 0, "SSHGATE_READ1 confined,net cat x", "diagnose"},
		{"empty-reason", 1, 0, "cat x", ""},
		{"whitespace-reason", 1, 0, "cat x", " \t\n\u2003"},
		{"invalid-reason", 1, 0, "cat x", "\xff"},
		{"empty-command", 1, 0, "", "diagnose"},
		{"long-command", 1, 0, strings.Repeat("x", MaxStepBytes+1), "diagnose"},
		{"invalid-command", 1, 0, "cat \xff", "diagnose"},
		{"nul-command", 1, 0, "cat\x00x", "diagnose"},
	}
}

func legacySignInputs() []LegacySignInput {
	return []LegacySignInput{
		{Server: "prod-db", HostFingerprint: "SHA256:host-a", Command: "cat x", CommandSHA256: fmt.Sprintf("%x", sha256.Sum256([]byte("cat x"))), TTLSeconds: 60, Net: true, Reason: "diagnose"},
		{Server: "web", HostFingerprint: "SHA256:host-b", Command: "cat y", CommandSHA256: fmt.Sprintf("%x", sha256.Sum256([]byte("cat y"))), TTLSeconds: 120, Reveal: true, Reason: "inspect"},
	}
}

const legacySignInstance = "00112233445566778899aabbccddeeff"

func TestNetworkCardGolden(t *testing.T) {
	lines := []string{NetworkBanner("prod-db"), LabelNetworkJustification}
	for _, tc := range legacyNetCases() {
		err, ok := ValidateLegacyNet(tc.n, tc.i, tc.command, tc.reason).(*CodeError)
		if !ok {
			t.Fatalf("%s: expected CodeError", tc.name)
		}
		lines = append(lines, fmt.Sprintf("%s: %s | %s | %s", tc.name, err.Code, err.Field, err.Msg))
	}
	digest, ok := LegacySignDigest(legacySignInstance, legacySignInputs())
	if !ok {
		t.Fatal("valid signing inputs refused")
	}
	lines = append(lines, "legacy_sign_digest "+digest)
	golden(t, "network.txt", []byte(strings.Join(lines, "\n")+"\n"))
}

func TestNetworkBannerMatchesP43(t *testing.T) {
	alias := "prod db 東京 100%"
	want := "🌐 READ WITH NETWORK on " + alias + ": may connect anywhere, including services on " + alias + " itself that can change state."
	if got := NetworkBanner(alias); got != want {
		t.Fatalf("banner = %q; want %q", got, want)
	}
}

func TestValidateLegacyNet(t *testing.T) {
	for _, reason := range []string{"diagnose", " 検査 ", strings.Repeat("r", MaxStepBytes+1)} {
		if err := ValidateLegacyNet(1, 0, "cat x", reason); err != nil {
			t.Fatal(err)
		}
	}
	if err := ValidateLegacyNet(1, 0, strings.Repeat("x", MaxStepBytes), "diagnose"); err != nil {
		t.Fatal(err)
	}
	for _, tc := range legacyNetCases() {
		t.Run(tc.name, func(t *testing.T) {
			err, ok := ValidateLegacyNet(tc.n, tc.i, tc.command, tc.reason).(*CodeError)
			if !ok || err.Code != CodeInvalidRequest || err.Field != fmt.Sprintf("commands[%d].net", tc.i) {
				t.Fatalf("refusal = %#v; want invalid_request at commands[%d].net", err, tc.i)
			}
		})
	}
}

func TestLegacySignDigest(t *testing.T) {
	base, ok := LegacySignDigest(legacySignInstance, legacySignInputs())
	if !ok {
		t.Fatal("valid inputs refused")
	}
	data, err := os.ReadFile("testdata/network.txt")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasSuffix(string(data), "legacy_sign_digest "+base+"\n") {
		t.Fatal("signing digest differs from golden")
	}
	mutations := []struct {
		name   string
		change func(*LegacySignInput)
	}{
		{"alias", func(v *LegacySignInput) { v.Server += "x" }},
		{"fingerprint", func(v *LegacySignInput) { v.HostFingerprint += "x" }},
		{"command", func(v *LegacySignInput) {
			v.Command += "\n"
			v.CommandSHA256 = fmt.Sprintf("%x", sha256.Sum256([]byte(v.Command)))
		}},
		{"hash", func(v *LegacySignInput) { v.CommandSHA256 = strings.Repeat("0", 64) }},
		{"ttl", func(v *LegacySignInput) { v.TTLSeconds++ }},
		{"reveal", func(v *LegacySignInput) { v.Reveal = !v.Reveal }},
		{"net", func(v *LegacySignInput) { v.Net = !v.Net }},
		{"reason", func(v *LegacySignInput) { v.Reason += "x" }},
	}
	for _, mutation := range mutations {
		t.Run(mutation.name, func(t *testing.T) {
			inputs := legacySignInputs()
			mutation.change(&inputs[0])
			got, ok := LegacySignDigest(legacySignInstance, inputs)
			if mutation.name == "hash" {
				if ok || got != "" {
					t.Fatal("mismatched command hash accepted")
				}
				return
			}
			if !ok || got == base {
				t.Fatal("changed signing input not bound")
			}
		})
	}
	t.Run("instance", func(t *testing.T) {
		got, ok := LegacySignDigest("ffeeddccbbaa99887766554433221100", legacySignInputs())
		if !ok || got == base {
			t.Fatal("instance not bound")
		}
	})
	t.Run("order", func(t *testing.T) {
		inputs := legacySignInputs()
		inputs[0], inputs[1] = inputs[1], inputs[0]
		got, ok := LegacySignDigest(legacySignInstance, inputs)
		if !ok || got == base {
			t.Fatal("input order not bound")
		}
	})
	for _, index := range []int{0, 1} {
		t.Run(fmt.Sprintf("hash-mismatch-%d", index), func(t *testing.T) {
			for _, hash := range []string{"", strings.Repeat("0", 64), strings.ToUpper(legacySignInputs()[index].CommandSHA256)} {
				inputs := legacySignInputs()
				inputs[index].CommandSHA256 = hash
				if got, ok := LegacySignDigest(legacySignInstance, inputs); ok || got != "" {
					t.Fatal("mismatched command hash accepted")
				}
			}
		})
	}
}

func TestA1aGoldensUnchanged(t *testing.T) {
	// Frozen before A1a-net; network.txt is the only addition allowed here.
	expected := map[string]string{
		"bounds.txt":                     "c51782e8645565b762e1a0b45c19f0a000d006415314b65c9da29a6a98bc321e",
		"codes.txt":                      "cd2e8fa27ab8ada89a7c13d10b93a6927acff3f97a37b78eb79a27195536c61c",
		"drafts/escaped.json":            "4253453334d978949f5c8306fa2d2f08828cb17de3b3c5114cccead7f1b193ed",
		"drafts/grant-all.json":          "0a52921603859e67e538e80ff7d71179b91ec6298bf261f5920be07a223be381",
		"drafts/grant-commands.json":     "8618279ee7f6e659a36974d12bc21377bf7ae31ad7f02c9ae4947768b5f88f04",
		"drafts/hosted-mixed-batch.json": "2953993e1be53d8eeab61070d58efa3d2cf27d516482b22a7a0399d5b8e023ef",
		"drafts/mixed-batch.json":        "2953993e1be53d8eeab61070d58efa3d2cf27d516482b22a7a0399d5b8e023ef",
		"drafts/reveal.json":             "ed376f0d61766ee46715576294f6847a8627ca702b76fcb6e3f2d8fe49590b1a",
		"drafts/revoke.json":             "e31d64fe1dd3d938bf86adee18f5b8433312755254951a09e96a41f3077c9ca6",
		"drafts/transfer.json":           "d1a468cf45fe4230e3d20eb8cf07a026401450566469821a0668dceefe02428e",
		"drafts/update.json":             "838ffa3a1288ab888d49cbce46c81726c2b1f2681504a9b73bca884fe53a7f8d",
		"drafts/write.json":              "4cc18d1fbddc649a022c41f407cf30ff41fc46ad2a0b5be16eb196fd46b5029f",
		"hashes.txt":                     "87ba1bdcd2c79748e22d1f06e4006480492e7e785ad01ed8b8f644e12082a517",
		"hidden_markers.txt":             "351c6f7f35e0a7d7818b924868be99c2040443b9bd4ba3591e45ba21e41627f0",
		"plans/escaped.json":             "b2fc0d97a40e312179d338ba13d24c1723947f7bfee4053ee563b374eda91a11",
		"plans/grant-all.json":           "915f1924ddea1529b932b39cc57cbac8aff99c635ab5702678234250b1ab4906",
		"plans/grant-commands.json":      "fac4f369d42a18a79fa2ff30cde4cc8b320eda5c00e561189408abe10111856b",
		"plans/hosted-mixed-batch.json":  "df4f7a8c1b9c4ad25ebb2c58e6af59edaf8ddd6856bcd5221b2420b0f116a6aa",
		"plans/mixed-batch.json":         "aa5f93476cfc7536070737aacff8e936f3bf86c97e79b286a7758a0f232b4cc4",
		"plans/register-key.json":        "f28171b903b60b09718c07bc7bbac1a6765bf2d2d5c43d61e20720c27972e9e8",
		"plans/reveal.json":              "1ff054a1e03ba888f7ed6942a68cbcf2075244defbedfc8f32c0ffde221cc818",
		"plans/revoke.json":              "0e6377bbaffe3b7fa35a07b4dfa619cf663e695d13978ba5b597693f3c158b0d",
		"plans/transfer.json":            "b684dd89c6f09aa96a5df4eec849e1ae6bf7a209797785d3ba443befb6191998",
		"plans/update.json":              "40c5086de4e98198d61016b0bc1120d941910002bea9837d1567d8fed2d16a23",
		"plans/write.json":               "706059174acb49cb496716b555235b32198107410b41cdb1d5c14ab730e43767",
		"r1-write-shed.json":             "7d1c34e5f17e95df29a677e340e4273c26fa83a2cab36d8d5b7c7ead0ee7faed",
		"r1-write.json":                  "b17282c743becad1e5956ed9e77d74fe86aa5ada0fc38a6ed9aeaf6dad26e51f",
		"r2-write.json":                  "55d02b335e9cb0e7bbed5b5f6b2fe78f4d69e75e67aaae49c80db2eb71426ba8",
	}
	seen := 0
	err := filepath.WalkDir("testdata", func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() {
			return nil
		}
		name, err := filepath.Rel("testdata", path)
		if err != nil {
			return err
		}
		if name == "network.txt" {
			return nil
		}
		want, ok := expected[name]
		if !ok {
			t.Errorf("unexpected golden %s", name)
			return nil
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		if got := fmt.Sprintf("%x", sha256.Sum256(data)); got != want {
			t.Errorf("frozen golden changed: %s", name)
		}
		seen++
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if seen != len(expected) {
		t.Fatalf("found %d frozen goldens, want %d", seen, len(expected))
	}
}
