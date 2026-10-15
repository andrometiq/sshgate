package approvalplan

import (
	"strings"
	"testing"
)

func TestValidateStepBytes(t *testing.T) {
	update := "SSHGATE_UPDATE " + strings.Repeat("0f", 32)
	routes := []Route{RouteUnsignedRead, RouteSignedWrite, RouteSignedReveal, RouteSignedAdmin}
	for _, r := range routes {
		for _, cmd := range []string{"SSHGATE_XFER_SEND a b c d", "SSHGATE_XFER_RECV a b c d e f", "SSHGATE_XFER_"} {
			if err := ValidateStepBytes(r, cmd); codeOf(err) != CodeReservedVerb {
				t.Errorf("%s %q: %v, want reserved_verb", r, cmd, err)
			}
		}
	}
	for _, r := range routes[:3] {
		for _, cmd := range []string{update, "SSHGATE_REVOKE", "SSHGATE_FOO", "SSHGATE_"} {
			if err := ValidateStepBytes(r, cmd); codeOf(err) != CodeReservedVerb {
				t.Errorf("%s %q: %v, want reserved_verb", r, cmd, err)
			}
		}
		if err := ValidateStepBytes(r, "systemctl restart nginx"); err != nil {
			t.Errorf("%s ordinary command: %v", r, err)
		}
		if err := ValidateStepBytes(r, " SSHGATE_REVOKE"); err != nil {
			t.Errorf("%s: a leading space is an ordinary shell command for the gate: %v", r, err)
		}
	}
	admin := map[string]Code{
		"SSHGATE_REVOKE":        "",
		update:                  "",
		"rm -rf /":              CodeInvalidRequest,
		"SSHGATE_UPDATE nothex": CodeReservedVerb,
		"SSHGATE_UPDATE " + strings.Repeat("0F", 32):       CodeReservedVerb,
		"SSHGATE_UPDATE " + strings.Repeat("0f", 32) + " ": CodeReservedVerb,
		"SSHGATE_UPDATE  " + strings.Repeat("0f", 32):      CodeReservedVerb,
		"SSHGATE_REVOKE extra":                             CodeReservedVerb,
		"SSHGATE_REVOKE\n":                                 CodeReservedVerb,
		"SSHGATE_FOO":                                      CodeReservedVerb,
		"":                                                 CodeInvalidRequest,
	}
	for cmd, want := range admin {
		if err := ValidateStepBytes(RouteSignedAdmin, cmd); codeOf(err) != want {
			t.Errorf("signed_admin %q: %v, want %q", cmd, err, want)
		}
	}
}

func TestMaxStepTTL(t *testing.T) {
	update := "SSHGATE_UPDATE " + strings.Repeat("ab", 32)
	cases := []struct {
		route Route
		cmd   string
		want  int
	}{
		{RouteUnsignedRead, "uptime", 0},
		{RouteSignedWrite, "touch x", 60},
		{RouteSignedReveal, "cat /etc/token", 60},
		{RouteSignedAdmin, "SSHGATE_REVOKE", 60},
		{RouteSignedAdmin, update, 300},
		{RouteSignedAdmin, "touch x", 0},
		{"bogus", "touch x", 0},
	}
	for _, c := range cases {
		if got := MaxStepTTL(c.route, c.cmd); got != c.want {
			t.Errorf("MaxStepTTL(%s, %q) = %d, want %d", c.route, c.cmd, got, c.want)
		}
	}
}

func TestValidateGrantEntry(t *testing.T) {
	for cmd, want := range map[string]Code{
		"systemctl restart worker": "",
		"SSHGATE_REVOKE":           CodeReservedVerb,
		"SSHGATE_XFER_SEND a":      CodeReservedVerb,
		"":                         CodeInvalidRequest,
		"bad\x00byte":              CodeInvalidRequest,
		strings.Repeat("x", 4097):  CodeRequestTooLarge,
		"\xff":                     CodeInvalidRequest,
	} {
		if err := ValidateGrantEntry(cmd); codeOf(err) != want {
			t.Errorf("ValidateGrantEntry(%q) = %v, want %q", cmd, err, want)
		}
	}
}

func FuzzValidateStepBytes(f *testing.F) {
	for _, s := range []string{"SSHGATE_REVOKE", "SSHGATE_UPDATE " + strings.Repeat("ab", 32), "SSHGATE_XFER_SEND x", "ls", "SSHGATE_"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, cmd string) {
		for _, r := range []Route{RouteUnsignedRead, RouteSignedWrite, RouteSignedReveal, RouteSignedAdmin} {
			err := ValidateStepBytes(r, cmd)
			if strings.HasPrefix(cmd, TransferVerbPrefix) && err == nil {
				t.Fatalf("%s accepted transfer verb %q", r, cmd)
			}
			if r != RouteSignedAdmin && strings.HasPrefix(cmd, AdminVerbPrefix) && err == nil {
				t.Fatalf("%s accepted admin verb %q", r, cmd)
			}
			if r == RouteSignedAdmin && err == nil && cmd != "SSHGATE_REVOKE" && !isUpdateCommand(cmd) {
				t.Fatalf("signed_admin accepted %q", cmd)
			}
		}
	})
}
