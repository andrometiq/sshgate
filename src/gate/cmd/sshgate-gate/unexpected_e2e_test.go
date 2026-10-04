//go:build linux && jail_e2e

package main

import (
	"github.com/karthikeyan5/sshgate/src/gate/confine/jailmut/harness"
	"testing"
)

func unexpected(t *testing.T, format string, args ...any) {
	t.Helper()
	harness.Unexpected(t, format, args...)
}
