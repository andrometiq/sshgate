package approvalplan

// Kind is the discriminator of an approval plan's payload.
type Kind string

const (
	KindCommandJob          Kind = "command_job"
	KindStandingGrant       Kind = "standing_grant"
	KindTransfer            Kind = "transfer"
	KindRegisterTransferKey Kind = "register_transfer_key"
)

// Valid reports whether k is one of the four plan kinds.
func (k Kind) Valid() bool {
	switch k {
	case KindCommandJob, KindStandingGrant, KindTransfer, KindRegisterTransferKey:
		return true
	}
	return false
}

// ExecutionApplicable reports whether an approval of this kind produces work
// that a coordinator claims and executes (E25). A grant produces a capability.
func (k Kind) ExecutionApplicable() bool {
	return k == KindCommandJob || k == KindTransfer
}

// Route says how a command_job step reaches its target and what an approval
// of it means.
type Route string

const (
	RouteUnsignedRead Route = "unsigned_read"
	RouteSignedWrite  Route = "signed_write"
	RouteSignedReveal Route = "signed_reveal"
	RouteSignedAdmin  Route = "signed_admin"
)

// Valid reports whether r is one of the four routes.
func (r Route) Valid() bool {
	switch r {
	case RouteUnsignedRead, RouteSignedWrite, RouteSignedReveal, RouteSignedAdmin:
		return true
	}
	return false
}

// Signed reports whether a step on this route carries a signature.
func (r Route) Signed() bool {
	return r == RouteSignedWrite || r == RouteSignedReveal || r == RouteSignedAdmin
}

// RationaleOrigin says where a request's reason came from (K3, E39). It is set
// from the request kind, never from request JSON.
type RationaleOrigin string

const (
	OriginAgent               RationaleOrigin = "agent"
	OriginTrustedHumanCLI     RationaleOrigin = "trusted_human_cli"
	OriginSynthesizedLegacyV1 RationaleOrigin = "synthesized_legacy_v1"
)

// Valid reports whether o is one of the three origins.
func (o RationaleOrigin) Valid() bool {
	switch o {
	case OriginAgent, OriginTrustedHumanCLI, OriginSynthesizedLegacyV1:
		return true
	}
	return false
}

// Coordinator names who claims and runs an approved execution-applicable
// request. It is requester-supplied; the signer enforces only the in-process
// claim deadline it implies (E25, E26).
type Coordinator string

const (
	CoordinatorInProcessSync Coordinator = "in_process_sync"
	CoordinatorExecutor      Coordinator = "executor"
)

// Valid reports whether c is one of the two coordinators.
func (c Coordinator) Valid() bool {
	return c == CoordinatorInProcessSync || c == CoordinatorExecutor
}

// StopPolicy is a command job's resolved stop_on_error setting (E30).
type StopPolicy string

const (
	StopClassDefaultWritesOnly StopPolicy = "class_default_writes_only"
	StopAnyNonzero             StopPolicy = "any_nonzero"
	StopNever                  StopPolicy = "never"
)

// Valid reports whether p is one of the three stop policies.
func (p StopPolicy) Valid() bool {
	return p == StopClassDefaultWritesOnly || p == StopAnyNonzero || p == StopNever
}

// GrantScope is a standing grant's scope: every command, or an exact list.
type GrantScope string

const (
	GrantScopeAll      GrantScope = "all"
	GrantScopeCommands GrantScope = "commands"
)

// Valid reports whether s is one of the two grant scopes.
func (s GrantScope) Valid() bool {
	return s == GrantScopeAll || s == GrantScopeCommands
}
