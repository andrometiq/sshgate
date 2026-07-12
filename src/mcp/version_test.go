package mcp_test

import (
	"testing"

	"github.com/karthikeyan5/sshgate/src/mcp"
)

// TestVersionDefault guards the T4 fix: mcp.Version MUST default to "dev" in an
// unstamped build (which is exactly what `go test` produces — the Makefile's
// version -ldflags are not applied here). The real, VERSION-stamped value is
// injected at link time via -X and proven end-to-end by `make verify-versions`.
//
// If this test ever sees a concrete version string, someone has reintroduced a
// hardcoded version into the source default — the precise drift T4 removed (a
// baked-in 0.2.0 while VERSION said 0.1.4). The source default must stay "dev";
// stamping is the build's job, not the source's.
func TestVersionDefault(t *testing.T) {
	if mcp.Version != "dev" {
		t.Fatalf("mcp.Version default = %q, want %q — stamping is done in the Makefile via -X; "+
			"the source default must stay \"dev\" so it can never drift from VERSION", mcp.Version, "dev")
	}
}
