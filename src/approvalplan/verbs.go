package approvalplan

import (
	"strings"
	"unicode/utf8"
)

// Reserved command prefixes, mirrored so approvalplan stays stdlib-only. A7
// asserts they equal their sources.
const (
	// AdminVerbPrefix mirrors signerkit's isAdminVerb prefix
	// (pkg/signerkit/daemon.go:1510).
	AdminVerbPrefix = "SSHGATE_"
	// TransferVerbPrefix mirrors xferwire.VerbPrefix (src/xferwire/xferwire.go:52).
	TransferVerbPrefix = "SSHGATE_XFER_"

	adminRevoke = "SSHGATE_REVOKE"
	// adminUpdatePrefix mirrors the gate's updateVerbPrefix
	// (src/gate/cmd/sshgate-gate/update.go:49).
	adminUpdatePrefix = "SSHGATE_UPDATE "
)

// ValidateStepBytes enforces E71 on one command_job step's exact bytes. A
// route is requester-supplied, so the bytes decide:
//   - an SSHGATE_XFER_ command is refused on every route (transfer legs exist
//     only inside a transfer payload, whose bytes the signer builds);
//   - any other SSHGATE_ command is allowed only on signed_admin, and only as
//     exactly "SSHGATE_REVOKE" or "SSHGATE_UPDATE <64 lowercase hex>";
//   - signed_admin with any other command is refused.
//
// That an admin step is its job's only step is checked over the whole job.
func ValidateStepBytes(route Route, command string) error {
	if strings.HasPrefix(command, TransferVerbPrefix) {
		return codeErr(CodeReservedVerb, "exact_command", "a transfer verb is never a command_job step")
	}
	isAdmin := command == adminRevoke || isUpdateCommand(command)
	switch {
	case route == RouteSignedAdmin && !isAdmin:
		if strings.HasPrefix(command, AdminVerbPrefix) {
			return codeErr(CodeReservedVerb, "exact_command", "signed_admin accepts only SSHGATE_REVOKE or SSHGATE_UPDATE <sha256>")
		}
		return invalid("exact_command", "signed_admin accepts only SSHGATE_REVOKE or SSHGATE_UPDATE <sha256>")
	case route != RouteSignedAdmin && strings.HasPrefix(command, AdminVerbPrefix):
		return codeErr(CodeReservedVerb, "exact_command", "an SSHGATE_ command is allowed only on route signed_admin")
	}
	return nil
}

// ValidateGrantEntry enforces E71 on one standing-grant command entry: a grant
// never covers an SSHGATE_ command. The entry is also bounded like a step.
func ValidateGrantEntry(command string) error {
	if strings.HasPrefix(command, AdminVerbPrefix) {
		return codeErr(CodeReservedVerb, "", "a standing grant never covers an SSHGATE_ command")
	}
	return validCommandBytes("", command, MaxStepBytes)
}

func isUpdateCommand(command string) bool {
	hash, ok := strings.CutPrefix(command, adminUpdatePrefix)
	return ok && ValidSHA256Hex(hash)
}

// validCommandBytes: 1..max bytes of valid UTF-8 with no NUL. Commands keep
// every other byte: they are what the signature covers.
func validCommandBytes(field, command string, max int) error {
	if command == "" {
		return invalid(field, "is empty")
	}
	if len(command) > max {
		return codeErr(CodeRequestTooLarge, field, "is %d bytes; maximum is %d", len(command), max)
	}
	if !utf8.ValidString(command) || strings.IndexByte(command, 0) >= 0 {
		return invalid(field, "must be valid UTF-8 without NUL")
	}
	return nil
}
