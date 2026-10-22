package main

import (
	"context"
	"strings"
	"syscall"
	"testing"

	"github.com/karthikeyan5/sshgate/src/gate"
	"github.com/karthikeyan5/sshgate/src/gate/confine"
	"github.com/karthikeyan5/sshgate/src/sigwire"
)

func TestPhase4Tables(t *testing.T) {
	for _, abi := range []string{"native", "abi1"} {
		t.Run(abi, func(t *testing.T) {
			t.Run("U-EnvelopeParse", func(t *testing.T) {
				p := newProof(t, "U-EnvelopeParse")
				different := false
				for _, tc := range envelopeCases {
					got, err := parseEnvelope(tc.raw)
					different = different || (err == nil) != tc.valid || got != tc.want
				}
				p.Control("decision", true)
				p.Effect("decision", different)
				p.Finish()
			})
			t.Run("U-EnvelopeFlags", func(t *testing.T) { envelopeDecisionTable(t, "U-EnvelopeFlags") })
			t.Run("U-EnvelopeExpectNet", func(t *testing.T) { envelopeDecisionTable(t, "U-EnvelopeExpectNet") })
			t.Run("U-DaemonReadNetRefused", func(t *testing.T) { envelopeDecisionTable(t, "U-DaemonReadNetRefused") })
		})
	}
}

func envelopeDecisionTable(t *testing.T, name string) {
	p := newProof(t, name)
	different := false
	for _, pin := range []string{"", pinDeny, pinAllow, "damaged"} {
		for _, network := range []bool{false, true} {
			commands := []string{"cat /file"}
			if name == "U-DaemonReadNetRefused" {
				commands = []string{"docker ps", "systemctl status fixture.service"}
				if !network {
					continue
				}
			}
			for _, absent := range []bool{false, true} {
				for _, command := range commands {
					t.Run(pin+command+map[bool]string{false: "plain", true: "net"}[network], func(t *testing.T) {
						dir := t.TempDir()
						withGateDir(t, dir)
						if pin != "" {
							plantPin(t, dir, pin, 0600)
						}
						old := executeCommand
						calls := 0
						var spec *confine.Spec
						executeCommand = func(_ context.Context, _ string, opts gate.ExecOpts) (gate.ExecResult, error) {
							calls++
							spec = opts.Confine
							if absent {
								return setupFailure("landlock", syscall.ENOSYS)
							}
							return gate.ExecResult{ExitCode: 0}, nil
						}
						t.Cleanup(func() { executeCommand = old })
						flags := "confined"
						if network {
							flags += ",net"
						}
						code, _, stderr := runWith(t, "SSHGATE_READ1 "+flags+" "+command)
						denied := pin == "damaged" || network && pin != pinAllow || name == "U-DaemonReadNetRefused"
						if denied {
							different = different || code != exitNoPermVal || calls != 0
							if name == "U-DaemonReadNetRefused" {
								rows := auditRecords(t, dir)
								different = different || len(rows) != 1 || rows[0]["deny_reason"] != "net:daemon-read" || stderr != "gate: "+sigwire.GateDenyNetDaemonRead+"\n"
							}
						} else {
							wantCode := exitOK
							if absent {
								wantCode = exitNoPermVal
							}
							different = different || code != wantCode || calls != 1 || spec == nil
							if absent {
								different = different || !strings.Contains(stderr, "read jail unavailable")
							}
							if spec != nil {
								different = different || spec.Net != (pin == pinAllow) || !spec.Strict
							}
						}
					})
				}
			}
		}
	}
	p.Control("decision", true)
	p.Effect("decision", different)
	p.Finish()
}
