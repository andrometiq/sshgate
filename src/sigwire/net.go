package sigwire

// Fixed strings of the per-read network permission. The gate, the signer and
// the MCP compare these exact bytes, so they live here, in the one package all
// three link; TestNetWireConstants pins each value.
const (
	// EnvelopePrefix marks an attempted read envelope: a gate line starting
	// with these bytes is parsed as an envelope, and the MCP refuses an agent
	// command that starts with them.
	EnvelopePrefix = "SSHGATE_READ"
	// EnvelopeVerb is the version-1 read-envelope verb.
	EnvelopeVerb = "SSHGATE_READ1"
	// EnvelopeFlagConfined and EnvelopeFlagNet are the envelope's flags.
	EnvelopeFlagConfined = "confined"
	EnvelopeFlagNet      = "net"
	// EnvelopeConfinedNet is the one envelope the MCP sends: this prefix
	// followed directly by the command (note the trailing space).
	EnvelopeConfinedNet = "SSHGATE_READ1 confined,net "
)

// Gate deny lines. The gate prints each as "gate: " + constant; the MCP maps
// them to its own error identities.
const (
	GateDenyBadEnvelope     = "bad envelope"
	GateDenyNetNotPermitted = "network not permitted on this host"
	GateDenyNetReadsOnly    = "network grant covers reads only"
	GateDenyNetDaemonRead   = "network is not available for daemon-read verbs"
	GateDenyEnvelopeNotRead = "the read envelope carries reads only"
	GateDenySignedEnvelope  = "the read envelope is unsigned-only"
	// GateNetUnsupported is the text of a gate's refusal of a signed payload
	// with Net set, for gate builds that do not yet honour signed network
	// grants.
	GateNetUnsupported = "signed network grants are not supported by this gate build"
)

// SignerNetUnsupported prefixes a signer's refusal of a sign request that
// asks for network.
const SignerNetUnsupported = "net_unsupported:"

// OldStrictDecodeNet appears in the refusal of a gate or signer built before
// the net field: both decode strictly and report it as an unknown field.
const OldStrictDecodeNet = `unknown field "net"`
