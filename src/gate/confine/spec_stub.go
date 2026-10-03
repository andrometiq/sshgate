//go:build !linux

package confine

import (
	"context"
	"errors"
)

// errUnsupported is returned by every entry point off linux. The gate only ever
// ships linux/amd64; the stub exists so `go vet ./...` and `go build ./...` stay
// honest on a non-linux dev box or cross-vet.
var errUnsupported = errors.New("confine: kernel jail is only supported on linux")

func (s Spec) command(context.Context, string) (*Jailed, error) {
	return nil, errUnsupported
}

// detect reports no kernel wall off linux (rung 3), with the reason in ProbeErr
// so a caller fails closed rather than treating it as a usable rung.
func detect() Report {
	return Report{Rung: Rung3Unconfined, ProbeErr: errUnsupported}
}

// RunShim and RunWorker are never reached off linux (the sentinels are only
// dispatched by a linux gate re-execing itself); they exist so the type surface
// matches the linux build.
func RunShim([]string) int   { return ExitSetupFailed }
func RunWorker([]string) int { return ExitSetupFailed }
