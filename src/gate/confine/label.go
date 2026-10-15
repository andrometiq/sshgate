package confine

import "github.com/karthikeyan5/sshgate/src/gate/confine/jailmut"

// KernelLabelEnabled is the switch for the read-only label. While it is false,
// a pinned kernel run reports LabelKernelNoLabel instead of
// LabelReadOnlyKernel. Every caller of Label passes this constant.
const KernelLabelEnabled = false

// The label strings. Label is their only producer.
const (
	LabelReadOnlyKernel = "read-only (kernel)"
	LabelKernelNoLabel  = "kernel-jailed (read-only label not enabled in this build)"
	LabelNetworkOpen    = "kernel-jailed, network open — not read-only"
	LabelPinToClaim     = "classifier-only (jail available; pin to claim)"
	LabelClassifierOnly = "classifier-only"
	LabelDenied         = "reads denied (jail unavailable)"
)

// RunOutcome is how a read ran. The zero value is no outcome and labels as
// denied.
type RunOutcome int

const (
	// RunKernel: the read reached the command inside the jail.
	RunKernel RunOutcome = iota + 1
	// RunAbsent: the jail is Absent on this host.
	RunAbsent
	// RunFailed: the jail failed to set up.
	RunFailed
	// RunDaemonRead: a daemon-read verb ran outside the jail.
	RunDaemonRead
)

// LabelState is what Label needs to know about one run. Profile, ABI and
// Unmet come from the run's own facts.
type LabelState struct {
	Pinned, Damaged, Strict bool
	Outcome                 RunOutcome
	Profile                 string
	ABI                     int
	Unmet                   []string
	Binary                  string // the daemon-read verb's binary
}

// Label is the one label function. effectiveNet is whether the run had
// network; enabled is KernelLabelEnabled. The first matching rule wins, and
// anything unrecognised is denied.
func Label(s LabelState, effectiveNet, enabled bool) string {
	switch {
	case s.Damaged:
		return LabelDenied
	case s.Outcome == RunDaemonRead:
		if !printableName(s.Binary) {
			return LabelDenied
		}
		return "daemon read, limited verbs: " + s.Binary + " (not kernel read-only)"
	case s.Outcome == RunFailed:
		return LabelDenied
	case s.Outcome == RunAbsent:
		if s.Pinned || s.Strict {
			return LabelDenied
		}
		return LabelClassifierOnly
	case s.Outcome == RunKernel:
		return kernelLabel(s, effectiveNet, enabled)
	}
	return LabelDenied
}

func kernelLabel(s LabelState, effectiveNet, enabled bool) string {
	switch {
	case s.Profile != ProfileROv1 || s.ABI < 1:
		return LabelDenied
	case s.Strict && len(s.Unmet) > 0:
		return LabelDenied
	case s.Pinned && !s.Strict:
		// A pin always makes the run strict; anything else is not a claim.
		return LabelDenied
	case effectiveNet && !s.Strict:
		return LabelDenied
	case effectiveNet:
		return LabelNetworkOpen
	case s.Pinned:
		if enabled || jailmut.On("P-G-LABEL-SWITCH") {
			return LabelReadOnlyKernel
		}
		return LabelKernelNoLabel
	case len(s.Unmet) > 0:
		return LabelClassifierOnly
	}
	return LabelPinToClaim
}

// printableName reports whether name is non-empty printable ASCII with no
// spaces.
func printableName(name string) bool {
	if name == "" {
		return false
	}
	for i := 0; i < len(name); i++ {
		if name[i] <= ' ' || name[i] > '~' {
			return false
		}
	}
	return true
}
