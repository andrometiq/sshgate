package signerkit

import (
	"fmt"
	"strings"
	"testing"
)

// TestMockBackendDoubleResolvePanics asserts the fixture safety net: a
// second resolution of the same RequestID panics loudly rather than
// silently dropping the result. This protects every downstream test that
// relies on MockBackend from a green-but-wrong outcome. It travels with
// mock.go from src/signer/backend during the signerkit extraction.
func TestMockBackendDoubleResolvePanics(t *testing.T) {
	t.Parallel()
	m := NewMockBackend()
	m.Approve("r_dup", "operator")

	defer func() {
		r := recover()
		if r == nil {
			t.Fatal("second resolve did not panic; the double-resolve safety net is broken")
		}
		msg := fmt.Sprintf("%v", r)
		if !strings.Contains(msg, "double-resolve") || !strings.Contains(msg, "r_dup") {
			t.Errorf("panic = %q; want it to name 'double-resolve' and the request id 'r_dup'", msg)
		}
	}()

	// Second resolution of the same id → panic.
	m.Deny("r_dup")
}
