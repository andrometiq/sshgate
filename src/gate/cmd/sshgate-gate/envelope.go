package main

import (
	"errors"
	"strings"

	"github.com/karthikeyan5/sshgate/src/sigwire"
)

type envelope struct {
	net bool
	cmd string
}

func parseEnvelope(raw string) (envelope, error) {
	rest, ok := strings.CutPrefix(raw, sigwire.EnvelopeVerb+" ")
	if !ok {
		return envelope{}, errors.New(sigwire.GateDenyBadEnvelope)
	}
	flags, cmd, ok := strings.Cut(rest, " ")
	if !ok || strings.TrimSpace(cmd) == "" {
		return envelope{}, errors.New(sigwire.GateDenyBadEnvelope)
	}
	// These are all possible nonempty, nonrepeating flag lists with confined.
	switch flags {
	case sigwire.EnvelopeFlagConfined:
		return envelope{cmd: cmd}, nil
	case sigwire.EnvelopeFlagConfined + "," + sigwire.EnvelopeFlagNet,
		sigwire.EnvelopeFlagNet + "," + sigwire.EnvelopeFlagConfined:
		return envelope{net: true, cmd: cmd}, nil
	default:
		return envelope{}, errors.New(sigwire.GateDenyBadEnvelope)
	}
}

func (e envelope) String() string {
	flags := sigwire.EnvelopeFlagConfined
	if e.net {
		flags += "," + sigwire.EnvelopeFlagNet
	}
	return sigwire.EnvelopeVerb + " " + flags + " " + e.cmd
}
