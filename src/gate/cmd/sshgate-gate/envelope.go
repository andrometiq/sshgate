package main

import (
	"errors"
	"strings"

	"github.com/karthikeyan5/sshgate/src/classify"
	"github.com/karthikeyan5/sshgate/src/gate"
	"github.com/karthikeyan5/sshgate/src/gate/confine/jailmut"
	"github.com/karthikeyan5/sshgate/src/sigwire"
)

type envelope struct {
	net bool
	cmd string
}

func parseEnvelope(raw string) (envelope, error) {
	if jailmut.On("P-G-ENVELOPE") {
		fields := strings.Fields(raw)
		if len(fields) >= 3 {
			return envelope{net: strings.Contains(fields[1], "net"), cmd: strings.Join(fields[2:], " ")}, nil
		}
	}
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

var envelopeParsedHook func()

func runEnvelope(audit *gate.AuditLogger, raw string) int {
	flags := readFlags{envelope: true}
	env, err := parseEnvelope(raw)
	if err != nil {
		logf("%s", sigwire.GateDenyBadEnvelope)
		auditReadDenied(audit, raw, "envelope:bad", exitNoPermVal, flags)
		return exitNoPermVal
	}
	if classify.Classify(env.cmd) != classify.KindRead {
		logf("%s", sigwire.GateDenyEnvelopeNotRead)
		auditNoExecReason(audit, env.cmd, "write", "denied", exitNoPermVal, "envelope:not-a-read", flags)
		return exitNoPermVal
	}
	if envelopeParsedHook != nil {
		envelopeParsedHook()
	}
	flags.expectNet = env.net
	if jailmut.On("P-G-ENVELOPE-NO-NET") {
		flags.netGrant = true
	}
	return execRead(audit, env.cmd, "unsigned", false, flags)
}
