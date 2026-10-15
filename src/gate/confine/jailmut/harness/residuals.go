package harness

// DocumentedResiduals are the only residual codes a proof may report. Each is
// an accepted gap named in docs/THREAT-MODEL.md.
var DocumentedResiduals = []string{
	"R-NUMA-EFFECT",            // "Proof gaps": the page-migration calls, proved only by errno
	"R-L2-LOADER-ROUTE",        // "Residual risks": a daemon read's interpreter can load another ELF
	"R-L2-SOCKET-BELOW-ABI9",   // "Residual risks": daemon-read socket targets below Landlock ABI 9
	"R-L2-ABSTRACT-BELOW-ABI6", // "Residual risks": abstract sockets below Landlock ABI 6
}

// ResidualBelowABI is the ResidualABIs of a protection that holds only from
// Landlock ABI minimum: the abi1 lane always, and the native lane when the
// judging host's ABI is below minimum. The manifest, the registry and the
// gate's copy of the manifest all compute it on the host that runs them.
func ResidualBelowABI(code string, hostABI, minimum int) map[string]string {
	lanes := map[string]string{"abi1": code}
	if hostABI < minimum {
		lanes["native"] = code
	}
	return lanes
}
