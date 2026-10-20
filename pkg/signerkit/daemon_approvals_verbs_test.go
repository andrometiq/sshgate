package signerkit

import (
	"errors"
	"strings"
	"testing"

	ap "github.com/karthikeyan5/sshgate/src/approvalplan"
	"github.com/karthikeyan5/sshgate/src/xferwire"
)

func TestApprovalReservedVerbDrift(t *testing.T) {
	if ap.AdminVerbPrefix != "SSHGATE_" || ap.TransferVerbPrefix != xferwire.VerbPrefix {
		t.Fatal("approvalplan reserved prefixes drifted from signer/gate prefixes")
	}
	for _, tc := range []struct {
		command                     string
		admin, transfer, validAdmin bool
	}{
		{"SSHGATE_REVOKE", true, false, true},
		{"SSHGATE_UPDATE " + strings.Repeat("a", 64), true, false, true},
		{"SSHGATE_UPDATE " + strings.Repeat("A", 64), true, false, false},
		{"SSHGATE_UPDATE " + strings.Repeat("a", 63), true, false, false},
		{"SSHGATE_UPDATE " + strings.Repeat("a", 64) + " ", true, false, false},
		{"SSHGATE_UPDATE", true, false, false},
		{"SSHGATE_REVOKE extra", true, false, false},
		{"SSHGATE_REVOKE\n", true, false, false},
		{"SSHGATE_", true, false, false},
		{"SSHGATE_FUTURE", true, false, false},
		{"SSHGATE_XFER_", true, true, false},
		{"SSHGATE_XFER_SEND payload", true, true, false},
		{"SSHGATE_XFER_RECV payload", true, true, false},
		{"SSHGATE_XFER_FUTURE", true, true, false},
		{"SSHGATE_XFER", true, false, false},
		{"SSHGATE", false, false, false},
		{"sshgate_xfer_send payload", false, false, false},
		{" SSHGATE_REVOKE", false, false, false},
		{"\tSSHGATE_XFER_SEND payload", false, false, false},
		{"echo SSHGATE_REVOKE", false, false, false},
		{"touch /tmp/file", false, false, false},
	} {
		t.Run(tc.command, func(t *testing.T) {
			if isAdminVerb(tc.command) != tc.admin || isTransferVerb(tc.command) != tc.transfer {
				t.Fatal("legacy reserved-verb classification drifted")
			}
			check := func(t *testing.T, err error, want ap.Code) {
				t.Helper()
				if want == "" && err == nil {
					return
				}
				var coded *ap.CodeError
				if want == "" || !errors.As(err, &coded) || coded.Code != want {
					t.Fatalf("got %v, want %q", err, want)
				}
			}
			grantCode := ap.Code("")
			if tc.admin {
				grantCode = ap.CodeReservedVerb
			}
			check(t, ap.ValidateGrantEntry(tc.command), grantCode)
			for _, route := range []ap.Route{ap.RouteUnsignedRead, ap.RouteSignedWrite, ap.RouteSignedReveal, ap.RouteSignedAdmin} {
				t.Run(string(route), func(t *testing.T) {
					code := ap.Code("")
					switch {
					case tc.transfer || tc.admin && (route != ap.RouteSignedAdmin || !tc.validAdmin):
						code = ap.CodeReservedVerb
					case route == ap.RouteSignedAdmin && !tc.validAdmin:
						code = ap.CodeInvalidRequest
					}
					check(t, ap.ValidateStepBytes(route, tc.command), code)
				})
			}
		})
	}
}
