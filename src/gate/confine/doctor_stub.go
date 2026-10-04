//go:build !linux

package confine

// RunProbe is never reached off linux (the sentinel is only dispatched by a
// linux gate re-execing itself); it exists so the type surface matches.
func RunProbe([]string) int { return ExitSetupFailed }

// SentinelProbe keeps the sentinel name available to the gate's main dispatch on
// every platform.
const SentinelProbe = "__jailprobe"
