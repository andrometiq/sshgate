package approvalplan

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math"
	"strings"
	"time"
	"unicode/utf8"
)

// Version numbers of the stored encodings.
const (
	DraftVersion = 1
	PlanVersion  = 1
)

// MaxDraftBytes bounds an encoded draft before it is decoded. The worst
// K19-legal draft (every command byte escaped, every route snapshot at its
// bounds) encodes to about 196 KiB (TestWorstCaseDraftWithinMaxDraftBytes).
const MaxDraftBytes = 256 << 10

// Transfer bounds. A leg is built by the signer from a path of up to 4096
// bytes, base64url-wrapped, so it is longer than a K19 step (E34).
const (
	MaxTransferLegBytes  = 8192
	MaxTransferPathBytes = 4096 // xferwire.maxPathLen (src/xferwire/xferwire.go:77)
	MaxTransferIDBytes   = 64   // xferwire.maxXferIDLen (src/xferwire/xferwire.go:75)
	MaxKeyLabelBytes     = 128
	MaxPublicKeyBytes    = 128
	// TransferMode is the only mode xferwire accepts today
	// (src/xferwire/xferwire.go:82).
	TransferMode = "0600"
	// MaxPrincipalBytes bounds a requester principal or hosted client ID.
	MaxPrincipalBytes = 128
)

// RouteSnapshot is the route a step was resolved to. Its JSON names are spec
// §5's. "Trusted" means trusted by the requester's registry: the signer never
// reads servers.json, so it cannot verify any of these fields; the target's
// gate enforces the host binding (E35).
type RouteSnapshot struct {
	ServerAlias            string    `json:"server_alias"`
	ResolvedHost           string    `json:"resolved_host"`
	ResolvedPort           int       `json:"resolved_port"`
	ResolvedUser           string    `json:"resolved_user"`
	TrustedHostFingerprint string    `json:"trusted_host_fingerprint"`
	ReadOnly               bool      `json:"read_only"`
	AddedAt                time.Time `json:"added_at"`
}

// TrustedDisplay is an SSHGATE_UPDATE step's build metadata. The MCP generates
// it, never the agent, but the signer cannot verify it: surfaces label every
// field LabelBuildMetadataClient (E33).
type TrustedDisplay struct {
	StagedBasename string `json:"staged_basename"`
	StagedVersion  string `json:"staged_version"`
	RunningVersion string `json:"running_version"`
	Size           int64  `json:"size"`
}

// Step is one command of a command_job, in its original batch position.
type Step struct {
	Ordinal             int             `json:"ordinal"`
	Route               Route           `json:"route"`
	Target              RouteSnapshot   `json:"target"`
	RegistryEntryDigest string          `json:"registry_entry_digest"`
	ExactCommand        string          `json:"exact_command"`
	CommandSHA256       string          `json:"command_sha256"`
	SignatureTTLSeconds int             `json:"signature_ttl_seconds"`
	TrustedDisplay      *TrustedDisplay `json:"trusted_display,omitempty"`
}

// CommandJob is the full ordered batch, unsigned reads included (spec §5).
// MaxOutputBytes is the per-stream capture cap. The executor stores output,
// so its cap is 1..MaxStreamOutputBytes; the in-process synchronous
// coordinator keeps today's 0 = unlimited (E30, E56).
type CommandJob struct {
	Steps          []Step     `json:"steps"`
	StopPolicy     StopPolicy `json:"stop_policy"`
	MaxOutputBytes int64      `json:"max_output_bytes"`
}

// StandingGrant asks for a host-bound grant (E24).
type StandingGrant struct {
	Alias                  string     `json:"alias"`
	Scope                  GrantScope `json:"scope"`
	Commands               []string   `json:"exact_allowed_commands,omitempty"`
	DurationSeconds        int        `json:"duration_seconds"`
	TrustedHostFingerprint string     `json:"trusted_host_fingerprint"`
	RegistryEntryDigest    string     `json:"registry_entry_digest"`
}

// TransferEndpoint is one side of a transfer. The requester supplies the
// route, its digest and the path; the signer fills the key fields from its own
// transfer registry at freeze (E34). For the source the key is the sender's
// identity public key; for the destination, the recipient's box public key.
// PublicKeySHA256 is the SHA-256 of the key's canonical text line.
type TransferEndpoint struct {
	Target              RouteSnapshot `json:"target"`
	RegistryEntryDigest string        `json:"registry_entry_digest"`
	Path                string        `json:"path"`
	KeyLabel            string        `json:"key_label,omitempty"`
	PublicKey           string        `json:"public_key,omitempty"`
	PublicKeySHA256     string        `json:"public_key_sha256,omitempty"`
	KeyEntryDigest      string        `json:"key_entry_digest,omitempty"`
}

// Transfer moves one file between two registered gates (E34). In a draft only
// the endpoints' requester fields, the mode and the TTL are set; the signer
// mints the transfer ID and builds both legs before notification.
type Transfer struct {
	Source              TransferEndpoint `json:"source"`
	Destination         TransferEndpoint `json:"destination"`
	Mode                string           `json:"mode"`
	SignatureTTLSeconds int              `json:"signature_ttl_seconds"`
	TransferID          string           `json:"transfer_id,omitempty"`
	SendCommand         string           `json:"send_command,omitempty"`
	SendCommandSHA256   string           `json:"send_command_sha256,omitempty"`
	RecvCommand         string           `json:"recv_command,omitempty"`
	RecvCommandSHA256   string           `json:"recv_command_sha256,omitempty"`
}

// RegisterTransferKey records a human-only transfer-key enrollment. v0.2 has
// no v2 kind that submits one (E39); the type exists so the plan union is
// complete.
type RegisterTransferKey struct {
	HostFingerprint string `json:"host_fingerprint"`
	Label           string `json:"label"`
	BoxPub          string `json:"box_pub"`
	IDPub           string `json:"id_pub"`
}

// ApprovalDraft is what a requester submits: requester-supplied fields only.
// Requested validity is optional and bounded by K12 (OQ1); the signer applies
// its configured cap. Rationale origin remains signer-owned (E39).
type ApprovalDraft struct {
	Version                  int            `json:"version"`
	Kind                     Kind           `json:"kind"`
	RequestID                string         `json:"request_id"`
	Rationale                string         `json:"reason"`
	ExecutorClaimTokenHash   string         `json:"executor_claim_token_hash,omitempty"`
	SubmitNotAfter           time.Time      `json:"submit_not_after"`
	Coordinator              Coordinator    `json:"coordinator,omitempty"`
	CommandJob               *CommandJob    `json:"command_job,omitempty"`
	StandingGrant            *StandingGrant `json:"standing_grant,omitempty"`
	Transfer                 *Transfer      `json:"transfer,omitempty"`
	RequestedValiditySeconds *int           `json:"requested_validity_seconds,omitempty"`
}

// ApprovalPlanV1 is the frozen plan: the draft plus what the signer resolves
// at freeze. Exactly one payload is set, matching Kind. plan_hash covers every
// field.
type ApprovalPlanV1 struct {
	Version                int                  `json:"version"`
	Kind                   Kind                 `json:"kind"`
	RequestID              string               `json:"request_id"`
	RequesterPrincipal     string               `json:"requester_principal"`
	RequesterSub           string               `json:"requester_sub,omitempty"`
	SubmittedAt            time.Time            `json:"submitted_at"`
	RequestExpiresAt       time.Time            `json:"request_expires_at"`
	Rationale              string               `json:"reason"`
	RationaleOrigin        RationaleOrigin      `json:"rationale_origin"`
	ExecutorClaimTokenHash string               `json:"executor_claim_token_hash,omitempty"`
	SubmitNotAfter         time.Time            `json:"submit_not_after"`
	Coordinator            Coordinator          `json:"coordinator,omitempty"`
	CommandJob             *CommandJob          `json:"command_job,omitempty"`
	StandingGrant          *StandingGrant       `json:"standing_grant,omitempty"`
	Transfer               *Transfer            `json:"transfer,omitempty"`
	RegisterTransferKey    *RegisterTransferKey `json:"register_transfer_key,omitempty"`
}

// DecodeDraft strictly decodes one draft and validates it. Unknown fields,
// trailing data, a non-canonical encoding and every bound refusal answer a
// *CodeError.
func DecodeDraft(b []byte) (ApprovalDraft, error) {
	if len(b) > MaxDraftBytes {
		return ApprovalDraft{}, codeErr(CodeRequestTooLarge, "draft", "is %d bytes; maximum is %d", len(b), MaxDraftBytes)
	}
	var d ApprovalDraft
	if err := decodeCanonical(b, &d); err != nil {
		return ApprovalDraft{}, invalid("draft", "%v", err)
	}
	if err := d.Validate(); err != nil {
		return ApprovalDraft{}, err
	}
	return d, nil
}

// Validate checks every requester-supplied field of the draft.
func (d ApprovalDraft) Validate() error {
	if d.Version != DraftVersion {
		return invalid("version", "must be %d", DraftVersion)
	}
	if seconds := d.RequestedValiditySeconds; seconds != nil && (*seconds < int(ValidityMin/time.Second) || *seconds > int(ValidityMax/time.Second)) {
		return invalid("requested_validity_seconds", "must be %d..%d", int(ValidityMin/time.Second), int(ValidityMax/time.Second))
	}
	if d.Kind == KindRegisterTransferKey {
		return invalid("kind", "register_transfer_key has no v2 submission (E39)")
	}
	if err := validateEnvelope(d.Kind, d.RequestID, d.ExecutorClaimTokenHash, d.Coordinator, d.SubmitNotAfter); err != nil {
		return err
	}
	if t, err := ValidateRationale(d.Rationale); err != nil {
		return err
	} else if t != d.Rationale {
		return invalid("reason", "must be trimmed")
	}
	if err := checkOnePayload(d.Kind, d.CommandJob != nil, d.StandingGrant != nil, d.Transfer != nil, false); err != nil {
		return err
	}
	switch d.Kind {
	case KindCommandJob:
		return within("command_job", d.CommandJob.validate(d.Coordinator))
	case KindStandingGrant:
		return within("standing_grant", d.StandingGrant.validate())
	default:
		return within("transfer", d.Transfer.validate(false))
	}
}

// Validate checks a frozen plan, including what the signer resolved.
func (p ApprovalPlanV1) Validate() error {
	if p.Version != PlanVersion {
		return invalid("version", "must be %d", PlanVersion)
	}
	if err := validateEnvelope(p.Kind, p.RequestID, p.ExecutorClaimTokenHash, p.Coordinator, p.SubmitNotAfter); err != nil {
		return err
	}
	if !isRouteToken(p.RequesterPrincipal, MaxPrincipalBytes) {
		return invalid("requester_principal", "must be 1..%d plain ASCII bytes", MaxPrincipalBytes)
	}
	if p.RequesterSub != "" && !ValidRequesterSub(p.RequesterSub) {
		return invalid("requester_sub", "must match local-uid:<uid>")
	}
	if !validStamp(p.SubmittedAt, false) || !validStamp(p.RequestExpiresAt, false) {
		return invalid("submitted_at", "submitted_at and request_expires_at must be RFC 3339 UTC times")
	}
	if v := p.RequestExpiresAt.Sub(p.SubmittedAt); v < ValidityMin || v > ValidityMax {
		return invalid("request_expires_at", "validity %s is outside %s..%s", v, ValidityMin, ValidityMax)
	}
	if t, err := ValidateRationale(p.Rationale); err != nil {
		return err
	} else if t != p.Rationale {
		return invalid("reason", "must be trimmed")
	}
	wantOrigin := OriginAgent
	if p.Kind == KindRegisterTransferKey {
		wantOrigin = OriginTrustedHumanCLI
	}
	if p.RationaleOrigin != wantOrigin {
		return invalid("rationale_origin", "must be %q for kind %q", wantOrigin, p.Kind)
	}
	if err := checkOnePayload(p.Kind, p.CommandJob != nil, p.StandingGrant != nil, p.Transfer != nil, p.RegisterTransferKey != nil); err != nil {
		return err
	}
	switch p.Kind {
	case KindCommandJob:
		return within("command_job", p.CommandJob.validate(p.Coordinator))
	case KindStandingGrant:
		return within("standing_grant", p.StandingGrant.validate())
	case KindTransfer:
		return within("transfer", p.Transfer.validate(true))
	default:
		return within("register_transfer_key", p.RegisterTransferKey.validate())
	}
}

// validateEnvelope checks the fields drafts and plans share: the request ID,
// the submit window value, and the claim-token hash and coordinator, which are
// mandatory exactly where execution applies (E25, E26).
func validateEnvelope(kind Kind, requestID, claimTokenHash string, coordinator Coordinator, submitNotAfter time.Time) error {
	if !kind.Valid() {
		return invalid("kind", "unknown kind %q", kind)
	}
	if !ValidRequestID(requestID) {
		return invalid("request_id", "must match ^a2_[A-Za-z0-9_-]{22}$")
	}
	if !validStamp(submitNotAfter, false) {
		return invalid("submit_not_after", "must be an RFC 3339 UTC time")
	}
	if kind.ExecutionApplicable() {
		if !ValidSHA256Hex(claimTokenHash) {
			return invalid("executor_claim_token_hash", "is required: 64 lowercase hex")
		}
		if !coordinator.Valid() {
			return invalid("coordinator", "must be in_process_sync or executor")
		}
		return nil
	}
	if claimTokenHash != "" {
		return invalid("executor_claim_token_hash", "is not allowed for kind %q", kind)
	}
	if coordinator != "" {
		return invalid("coordinator", "is not allowed for kind %q", kind)
	}
	return nil
}

func checkOnePayload(kind Kind, job, grant, transfer, register bool) error {
	n := 0
	for _, set := range []bool{job, grant, transfer, register} {
		if set {
			n++
		}
	}
	want := map[Kind]bool{KindCommandJob: job, KindStandingGrant: grant, KindTransfer: transfer, KindRegisterTransferKey: register}[kind]
	if n != 1 || !want {
		return invalid(string(kind), "exactly one payload, matching kind, is required")
	}
	return nil
}

func (j *CommandJob) validate(coordinator Coordinator) error {
	if len(j.Steps) == 0 {
		return invalid("steps", "at least one step is required")
	}
	if len(j.Steps) > MaxSteps {
		return codeErr(CodeRequestTooLarge, "steps", "%d steps; maximum is %d", len(j.Steps), MaxSteps)
	}
	if !j.StopPolicy.Valid() {
		return invalid("stop_policy", "unknown stop policy %q", j.StopPolicy)
	}
	minOutput, maxOutput := int64(0), int64(math.MaxInt32)
	if coordinator == CoordinatorExecutor {
		minOutput, maxOutput = 1, MaxStreamOutputBytes
	}
	if j.MaxOutputBytes < minOutput || j.MaxOutputBytes > maxOutput {
		return invalid("max_output_bytes", "%d is outside %d..%d", j.MaxOutputBytes, minOutput, maxOutput)
	}
	total, signed := 0, false
	for i, s := range j.Steps {
		if err := s.validate(i + 1); err != nil {
			return within(fmt.Sprintf("steps[%d]", i), err)
		}
		if s.Route == RouteSignedAdmin && len(j.Steps) != 1 {
			return within(fmt.Sprintf("steps[%d]", i), invalid("route", "an admin step must be its job's only step"))
		}
		total += len(s.ExactCommand)
		signed = signed || s.Route.Signed()
	}
	if total > MaxTotalBytes {
		return codeErr(CodeRequestTooLarge, "steps", "%d command bytes; maximum is %d", total, MaxTotalBytes)
	}
	if !signed {
		return invalid("steps", "a command_job needs at least one signed step")
	}
	return nil
}

func (s Step) validate(ordinal int) error {
	if s.Ordinal != ordinal {
		return invalid("ordinal", "is %d; must be %d", s.Ordinal, ordinal)
	}
	if !s.Route.Valid() {
		return invalid("route", "unknown route %q", s.Route)
	}
	if err := validCommandBytes("exact_command", s.ExactCommand, MaxStepBytes); err != nil {
		return err
	}
	if err := ValidateStepBytes(s.Route, s.ExactCommand); err != nil {
		return err
	}
	if s.CommandSHA256 != sha256Hex(s.ExactCommand) {
		return invalid("command_sha256", "does not match exact_command")
	}
	if err := within("target", ValidateRouteSnapshot(s.Target)); err != nil {
		return err
	}
	if s.RegistryEntryDigest != s.Target.Digest() {
		return invalid("registry_entry_digest", "does not match target")
	}
	if s.Route.Signed() {
		if s.Target.TrustedHostFingerprint == "" {
			return invalid("target.trusted_host_fingerprint", "is required on a signed step")
		}
		if max := MaxStepTTL(s.Route, s.ExactCommand); s.SignatureTTLSeconds < 1 || s.SignatureTTLSeconds > max {
			return invalid("signature_ttl_seconds", "%d is outside 1..%d for this step", s.SignatureTTLSeconds, max)
		}
	} else if s.SignatureTTLSeconds != 0 {
		return invalid("signature_ttl_seconds", "must be 0 on unsigned_read")
	}
	if s.TrustedDisplay == nil {
		return nil
	}
	if s.Route != RouteSignedAdmin || !isUpdateCommand(s.ExactCommand) {
		return invalid("trusted_display", "is allowed only on an SSHGATE_UPDATE step")
	}
	return within("trusted_display", s.TrustedDisplay.validate())
}

func (t *TrustedDisplay) validate() error {
	if err := validText("staged_basename", t.StagedBasename, 1, MaxStagedBasenameBytes); err != nil {
		return err
	}
	if err := validText("staged_version", t.StagedVersion, 0, MaxVersionBytes); err != nil {
		return err
	}
	if err := validText("running_version", t.RunningVersion, 0, MaxVersionBytes); err != nil {
		return err
	}
	if t.Size < 0 {
		return invalid("size", "is negative")
	}
	return nil
}

func (g *StandingGrant) validate() error {
	if !isRouteToken(g.Alias, MaxAliasBytes) {
		return invalid("alias", "must be 1..%d plain ASCII bytes", MaxAliasBytes)
	}
	switch g.Scope {
	case GrantScopeAll:
		if len(g.Commands) != 0 {
			return invalid("exact_allowed_commands", "must be empty for scope all")
		}
	case GrantScopeCommands:
		if err := validateGrantCommands(g.Commands); err != nil {
			return err
		}
	default:
		return invalid("scope", "unknown scope %q", g.Scope)
	}
	if g.DurationSeconds < 1 || g.DurationSeconds > MaxGrantDurationSeconds {
		return invalid("duration_seconds", "%d is outside 1..%d", g.DurationSeconds, MaxGrantDurationSeconds)
	}
	if !ValidFingerprint(g.TrustedHostFingerprint) {
		return invalid("trusted_host_fingerprint", "is required: an OpenSSH SHA256: fingerprint")
	}
	if !ValidSHA256Hex(g.RegistryEntryDigest) {
		return invalid("registry_entry_digest", "must be 64 lowercase hex")
	}
	return nil
}

func validateGrantCommands(cmds []string) error {
	if len(cmds) == 0 {
		return invalid("exact_allowed_commands", "scope commands needs at least one command")
	}
	if len(cmds) > MaxSteps {
		return codeErr(CodeRequestTooLarge, "exact_allowed_commands", "%d commands; maximum is %d", len(cmds), MaxSteps)
	}
	total := 0
	for i, c := range cmds {
		if err := ValidateGrantEntry(c); err != nil {
			return within(fmt.Sprintf("exact_allowed_commands[%d]", i), err)
		}
		total += len(c)
	}
	if total > MaxTotalBytes {
		return codeErr(CodeRequestTooLarge, "exact_allowed_commands", "%d bytes; maximum is %d", total, MaxTotalBytes)
	}
	return nil
}

// validate checks a transfer. frozen says whether the signer's fields must be
// present (a plan) or absent (a draft).
func (t *Transfer) validate(frozen bool) error {
	if err := within("source", t.Source.validate(frozen)); err != nil {
		return err
	}
	if err := within("destination", t.Destination.validate(frozen)); err != nil {
		return err
	}
	if t.Mode != TransferMode {
		return invalid("mode", "must be %q", TransferMode)
	}
	if t.SignatureTTLSeconds < 1 || t.SignatureTTLSeconds > MaxTransferTTLSeconds {
		return invalid("signature_ttl_seconds", "%d is outside 1..%d", t.SignatureTTLSeconds, MaxTransferTTLSeconds)
	}
	signerFields := t.TransferID + t.SendCommand + t.SendCommandSHA256 + t.RecvCommand + t.RecvCommandSHA256
	if !frozen {
		if signerFields != "" {
			return invalid("transfer_id", "the transfer ID and legs are minted by the signer, never supplied")
		}
		return nil
	}
	if len(t.TransferID) < 1 || len(t.TransferID) > MaxTransferIDBytes || !allBytes(t.TransferID, isBase64URLByte) {
		return invalid("transfer_id", "must be 1..%d base64url characters", MaxTransferIDBytes)
	}
	if err := validLeg("send_command", t.SendCommand, t.SendCommandSHA256, TransferVerbPrefix+"SEND "); err != nil {
		return err
	}
	return validLeg("recv_command", t.RecvCommand, t.RecvCommandSHA256, TransferVerbPrefix+"RECV ")
}

func validLeg(field, cmd, sum, prefix string) error {
	if !strings.HasPrefix(cmd, prefix) || len(cmd) > MaxTransferLegBytes || !allBytes(cmd, func(c byte) bool { return c >= 0x20 && c < 0x7f }) {
		return invalid(field, "must be a %q leg of at most %d printable ASCII bytes", strings.TrimSpace(prefix), MaxTransferLegBytes)
	}
	if sum != sha256Hex(cmd) {
		return invalid(field+"_sha256", "does not match %s", field)
	}
	return nil
}

func (e TransferEndpoint) validate(frozen bool) error {
	if err := within("target", ValidateRouteSnapshot(e.Target)); err != nil {
		return err
	}
	if e.Target.TrustedHostFingerprint == "" {
		return invalid("target.trusted_host_fingerprint", "is required")
	}
	if e.RegistryEntryDigest != e.Target.Digest() {
		return invalid("registry_entry_digest", "does not match target")
	}
	if !validTransferPath(e.Path) {
		return invalid("path", "must be an absolute UTF-8 path of at most %d bytes without NUL, CR or LF", MaxTransferPathBytes)
	}
	keyFields := e.KeyLabel + e.PublicKey + e.PublicKeySHA256 + e.KeyEntryDigest
	if !frozen {
		if keyFields != "" {
			return invalid("public_key", "key fields come from the signer's registry, never the requester")
		}
		return nil
	}
	if err := validText("key_label", e.KeyLabel, 1, MaxKeyLabelBytes); err != nil {
		return err
	}
	if !validKeyText(e.PublicKey) {
		return invalid("public_key", "must be a '<tag> <base64>' line of at most %d bytes", MaxPublicKeyBytes)
	}
	if e.PublicKeySHA256 != sha256Hex(e.PublicKey) {
		return invalid("public_key_sha256", "does not match public_key")
	}
	if !ValidSHA256Hex(e.KeyEntryDigest) {
		return invalid("key_entry_digest", "must be 64 lowercase hex")
	}
	return nil
}

func (r *RegisterTransferKey) validate() error {
	if !ValidFingerprint(r.HostFingerprint) {
		return invalid("host_fingerprint", "must be an OpenSSH SHA256: fingerprint")
	}
	if err := validText("label", r.Label, 1, MaxKeyLabelBytes); err != nil {
		return err
	}
	if !validKeyText(r.BoxPub) {
		return invalid("box_pub", "must be a '<tag> <base64>' line of at most %d bytes", MaxPublicKeyBytes)
	}
	if !validKeyText(r.IDPub) {
		return invalid("id_pub", "must be a '<tag> <base64>' line of at most %d bytes", MaxPublicKeyBytes)
	}
	return nil
}

// validTransferPath mirrors xferwire.ValidPath (src/xferwire/xferwire.go:334)
// and also requires valid UTF-8: canonical JSON would replace an invalid byte
// with U+FFFD, so two distinct paths would share one draft_hash and the stored
// path would differ from the approved one.
func validTransferPath(p string) bool {
	return p != "" && len(p) <= MaxTransferPathBytes && strings.HasPrefix(p, "/") &&
		utf8.ValidString(p) && !strings.ContainsAny(p, "\x00\r\n")
}

// validKeyText accepts the "<tag> <base64>" shape of xfer's public key text
// (src/xfer/keys.go:79-88); xfer parses it at use.
func validKeyText(s string) bool {
	tag, b64, ok := strings.Cut(s, " ")
	return ok && len(s) <= MaxPublicKeyBytes && tag != "" && b64 != "" &&
		allBytes(s, func(c byte) bool { return c >= 0x20 && c < 0x7f }) && !strings.Contains(b64, " ")
}

func sha256Hex(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}
