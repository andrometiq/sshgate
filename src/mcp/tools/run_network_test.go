package tools

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/karthikeyan5/sshgate/src/classify"
	"github.com/karthikeyan5/sshgate/src/mcp/registry"
	signpkg "github.com/karthikeyan5/sshgate/src/mcp/sign"
	"github.com/karthikeyan5/sshgate/src/sigwire"
)

type networkSigner struct {
	SignClient
	calls  [][]signpkg.CmdReq
	err    error
	events *[]string
}

func (s *networkSigner) Sign(_ context.Context, _ string, cmds []signpkg.CmdReq) (signpkg.SignResult, error) {
	s.calls = append(s.calls, append([]signpkg.CmdReq(nil), cmds...))
	*s.events = append(*s.events, "sign")
	return signpkg.SignResult{Signed: []signpkg.Signed{{Sig: "signed"}}, AuthMode: "human"}, s.err
}

type networkSSH struct {
	calls      []string
	capability string
	stderr     string
	exit       int
	err        error
	events     *[]string
}

func (s *networkSSH) Run(_ context.Context, host, user string, port int, cmd string) ([]byte, []byte, int, error) {
	s.calls = append(s.calls, cmd)
	*s.events = append(*s.events, cmd)
	if cmd == "SSHGATE_JAIL" {
		return []byte(s.capability), nil, 0, nil
	}
	return []byte("output"), []byte(s.stderr), s.exit, s.err
}
func networkRunner(t *testing.T, readOnly bool, capability *hostCap) (*Runner, *networkSigner, *networkSSH) {
	t.Helper()
	servers, err := registry.New(filepath.Join(t.TempDir(), "servers.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := servers.Add("test", registry.Entry{Host: "example.test", User: "user", Port: 22, Fingerprint: "trusted-host", ReadOnly: readOnly}); err != nil {
		t.Fatal(err)
	}
	events := []string{}
	signer := &networkSigner{events: &events}
	ssh := &networkSSH{capability: capReply, events: &events}
	return &Runner{Servers: servers, Sign: signer, SSH: ssh, caps: map[string]*hostCap{"test": capability}}, signer, ssh
}
func networkInput() RunInput {
	return RunInput{Alias: "test", Command: "cat /etc/hostname", Network: true, Reason: "inspect remote service"}
}
func networkCap(pinned, net bool) *hostCap {
	return &hostCap{V: 1, Enforcement: "kernel", Pinned: pinned, Net: net, NetGrants: true}
}
func networkVerdict(out RunOutput) string {
	if out.Denial == nil {
		return ""
	}
	return out.Denial.VerdictClass
}

func TestRunNetworkRoute(t *testing.T) {
	for _, tc := range []struct {
		name                     string
		readOnly, reveal         bool
		capability               *hostCap
		command, reason, verdict string
		signs, executions        int
	}{
		{"reason", false, false, networkCap(false, false), "cat x", " ", VerdictNetworkNeedsReason, 0, 0},
		{"write", false, false, networkCap(false, false), "touch x", "why", VerdictNetworkGrantReadOnly, 0, 0},
		{"daemon", false, false, networkCap(false, false), "docker ps", "why", VerdictNetworkGrantReadOnly, 0, 0},
		{"reveal-tier1", true, true, networkCap(true, true), "cat x", "why", VerdictReadOnlyServer, 0, 0},
		{"reveal-tier2", false, true, networkCap(true, true), "cat x", "why", "", 1, 1},
		{"envelope-tier1", true, false, networkCap(true, true), "cat x", "why", "", 0, 1},
		{"envelope-tier2", false, false, networkCap(true, true), "cat x", "why", "", 0, 1},
		{"tier1-denied", true, false, networkCap(false, false), "cat x", "why", VerdictNetworkNotPermitted, 0, 0},
		{"signed", false, false, networkCap(false, false), "cat x", "why", "", 1, 1},
		{"no-capability", false, false, nil, "cat x", "why", VerdictNetworkUnsupportedGate, 0, 0},
		{"old-gate", false, false, &hostCap{Enforcement: "kernel"}, "cat x", "why", VerdictNetworkUnsupportedGate, 0, 0},
		{"classifier", false, false, &hostCap{Enforcement: "classifier", NetGrants: true}, "cat x", "why", VerdictNetworkRequiresConfinement, 0, 0},
		{"unavailable", false, false, &hostCap{Enforcement: "unavailable", NetGrants: true}, "cat x", "why", VerdictNetworkRequiresConfinement, 0, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r, s, ssh := networkRunner(t, tc.readOnly, tc.capability)
			in := networkInput()
			in.Command = tc.command
			in.Reason = tc.reason
			in.Reveal = tc.reveal
			out, err := r.Run(context.Background(), in)
			if networkVerdict(out) != tc.verdict || (err != nil) != (tc.verdict != "") || len(s.calls) != tc.signs || len(ssh.calls) != tc.executions {
				t.Fatalf("out=%+v err=%v signs=%v ssh=%v", out, err, s.calls, ssh.calls)
			}
			if strings.HasPrefix(tc.verdict, "network_") {
				if _, ok := r.caps["test"]; ok {
					t.Fatal("refusal retained capability")
				}
			}
		})
	}
}

func TestRunRevealNetworkRoute(t *testing.T) {
	for _, pinned := range []bool{false, true} {
		for _, net := range []bool{false, true} {
			for _, tier1 := range []bool{false, true} {
				t.Run(fmt.Sprintf("pinned=%t/net=%t/tier1=%t", pinned, net, tier1), func(t *testing.T) {
					r, s, ssh := networkRunner(t, tier1, networkCap(pinned, net))
					in := networkInput()
					in.Reveal = true
					out, err := r.Run(context.Background(), in)
					if tier1 {
						if networkVerdict(out) != VerdictReadOnlyServer || err == nil || len(s.calls) != 0 || len(ssh.calls) != 0 {
							t.Fatalf("tier1 reached execution: %+v %v", out, err)
						}
						return
					}
					if err != nil || len(s.calls) != 1 || len(s.calls[0]) != 1 || len(ssh.calls) != 1 || ssh.calls[0] != "signed "+in.Command {
						t.Fatalf("combined route: %+v %v signs=%v ssh=%v", out, err, s.calls, ssh.calls)
					}
					want := signpkg.CmdReq{Server: in.Alias, Host: "trusted-host", Cmd: in.Command, TTLSec: DefaultWriteTTLSec, Reveal: true, Net: true, Reason: in.Reason}
					if s.calls[0][0] != want || !out.Revealed || !out.Approved || out.AuthMode != "human" {
						t.Fatalf("combined request/output: %v %+v", s.calls, out)
					}
				})
			}
		}
	}
}

func TestRunNetworkHostPolicyUsesEnvelope(t *testing.T) {
	for _, state := range []string{"absent", "older", "hosted"} {
		for _, tier1 := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/tier1=%t", state, tier1), func(t *testing.T) {
				r, s, ssh := networkRunner(t, tier1, networkCap(true, true))
				r.caps["test"].NetGrants = false
				switch state {
				case "absent":
					r.Sign = nil
				case "older":
					s.err = errors.New(sigwire.OldStrictDecodeNet)
				case "hosted":
					s.err = errors.New(sigwire.SignerNetUnsupported)
				}
				in := networkInput()
				out, err := r.Run(context.Background(), in)
				if err != nil || out.Approved || out.Revealed || len(s.calls) != 0 || !reflect.DeepEqual(ssh.calls, []string{sigwire.EnvelopeConfinedNet + in.Command}) {
					t.Fatalf("envelope: %+v %v signs=%v ssh=%v", out, err, s.calls, ssh.calls)
				}
			})
		}
	}
}
func checkNetworkSignerRefused(t *testing.T, message string) {
	t.Helper()
	r, s, ssh := networkRunner(t, false, networkCap(false, false))
	s.err = errors.New(message)
	out, err := r.Run(context.Background(), networkInput())
	if networkVerdict(out) != VerdictNetworkUnsupportedSigner || err == nil || len(s.calls) != 1 || !s.calls[0][0].Net || len(ssh.calls) != 0 {
		t.Fatalf("signer refusal: %+v %v signs=%v ssh=%v", out, err, s.calls, ssh.calls)
	}
	if _, ok := r.caps["test"]; ok {
		t.Fatal("refusal retained capability")
	}
}
func TestRunNetworkSignedOlderSigner(t *testing.T) {
	checkNetworkSignerRefused(t, `malformed request: json: unknown field "net"`)
}
func TestRunNetworkSignedHostedSigner(t *testing.T) {
	checkNetworkSignerRefused(t, "net_unsupported: hosted backend")
}

func TestRunNetworkJailUnavailable(t *testing.T) {
	r, s, ssh := networkRunner(t, false, networkCap(false, false))
	ssh.exit = 77
	ssh.stderr = "gate: read jail unavailable: setup failed; command may have started\n"
	out, err := r.Run(context.Background(), networkInput())
	if err == nil || networkVerdict(out) != VerdictNetworkRequiresConfinement || out.Stderr != ssh.stderr || len(s.calls) != 1 || len(ssh.calls) != 1 {
		t.Fatalf("jail refusal: %+v %v", out, err)
	}
	ssh.capability = strings.Replace(capReply, `"net":true`, `"net":false`, 1)
	ssh.exit = 0
	ssh.stderr = ""
	out, err = r.Run(context.Background(), networkInput())
	want := []string{"sign", "signed cat /etc/hostname", "SSHGATE_JAIL", "sign", "signed cat /etc/hostname"}
	if err != nil || out.Denial != nil || !reflect.DeepEqual(*ssh.events, want) {
		t.Fatalf("refresh order: %v %+v %v", *ssh.events, out, err)
	}
}

func TestRunNetworkNoFallback(t *testing.T) {
	for _, tc := range []struct {
		name, diagnostic, verdict string
		exit                      int
	}{
		{"policy", sigwire.GateDenyNetNotPermitted, VerdictNetworkNotPermitted, 77},
		{"write", sigwire.GateDenyNetReadsOnly, VerdictNetworkGrantReadOnly, 77},
		{"daemon", sigwire.GateDenyNetDaemonRead, VerdictNetworkGrantReadOnly, 77},
		{"inner-write", sigwire.GateDenyEnvelopeNotRead, VerdictNetworkGrantReadOnly, 77},
		{"jail", "read jail unavailable: command may have started", VerdictNetworkRequiresConfinement, 77},
		{"bad-envelope", sigwire.GateDenyBadEnvelope, VerdictNetworkUnsupportedGate, 77},
		{"old-envelope", "write commands require a SSHGATE_SIG prefix", VerdictNetworkUnsupportedGate, 77},
		{"old-tier1", "no signing key configured", VerdictNetworkUnsupportedGate, 77},
		{"old-net", sigwire.OldStrictDecodeNet, VerdictNetworkUnsupportedGate, 65},
		{"interim", sigwire.GateNetUnsupported, VerdictNetworkUnsupportedGate, 65},
	} {
		for _, envelope := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/envelope=%t", tc.name, envelope), func(t *testing.T) {
				r, s, ssh := networkRunner(t, false, networkCap(envelope, envelope))
				ssh.exit = tc.exit
				ssh.stderr = "gate: " + tc.diagnostic
				out, err := r.Run(context.Background(), networkInput())
				signs := 1
				if envelope {
					signs = 0
				}
				if err == nil || networkVerdict(out) != tc.verdict || out.Stderr != ssh.stderr || len(ssh.calls) != 1 || len(s.calls) != signs {
					t.Fatalf("refusal: %+v %v signs=%v ssh=%v", out, err, s.calls, ssh.calls)
				}
				if _, ok := r.caps["test"]; ok {
					t.Fatal("refusal retained capability")
				}
			})
		}
	}
}

func TestRunNetworkDaemonRead(t *testing.T) {
	for _, command := range []string{"docker ps", "systemctl status example", "cat x | docker ps", "cat x && systemctl status example", "cat x; docker ps", "cat x\nsystemctl status example", "env LANG=C docker ps", "LANG=C systemctl status example", "'docker' ps", `sys"tem"ctl status example`, `doc\ker ps`, "/usr/bin/docker ps"} {
		t.Run(command, func(t *testing.T) {
			r, s, ssh := networkRunner(t, false, networkCap(true, true))
			in := networkInput()
			in.Command = command
			out, err := r.Run(context.Background(), in)
			if err == nil || networkVerdict(out) != VerdictNetworkGrantReadOnly || len(s.calls) != 0 || len(ssh.calls) != 0 {
				t.Fatalf("daemon reached execution: %+v %v signs=%v ssh=%v", out, err, s.calls, ssh.calls)
			}
		})
	}
	for _, command := range []string{"cat docker", "printf 'systemctl | docker'", "cat 'x;docker'"} {
		t.Run(command, func(t *testing.T) {
			r, _, _ := networkRunner(t, false, networkCap(true, true))
			in := networkInput()
			in.Command = command
			if out, err := r.Run(context.Background(), in); err == nil || networkVerdict(out) != VerdictNetworkGrantReadOnly {
				t.Fatalf("daemon argument not refused: %+v %v", out, err)
			}
		})
	}
}

func TestRunNetworkKeyBeforeProbe(t *testing.T) {
	r, s, ssh := networkRunner(t, false, nil)
	delete(r.caps, "test")
	r.KeyPath = filepath.Join(t.TempDir(), "absent")
	out, err := r.Run(context.Background(), networkInput())
	if err == nil || networkVerdict(out) != VerdictNoSignerConfigured || len(s.calls) != 0 || len(ssh.calls) != 0 {
		t.Fatalf("key preflight: %+v %v", out, err)
	}
}
func TestRunNetworkClockSkew(t *testing.T) {
	r, _, ssh := networkRunner(t, false, networkCap(false, false))
	ssh.exit = 65
	ssh.stderr = "gate: signature not yet valid"
	out, err := r.Run(context.Background(), networkInput())
	if err == nil || networkVerdict(out) != VerdictBadSignature || !strings.Contains(strings.Join(out.Denial.HowTo, " "), "30 seconds") {
		t.Fatalf("clock guidance: %+v %v", out, err)
	}
}

// Each leaf observes the real signer or SSH boundary, not the routing helper.
func TestRunNetworkProtection(t *testing.T) {
	for _, name := range []string{"combined-net", "combined-reveal", "envelope-missing", "fallback-ran", "reason", "tier1", "batch", "daemon", "reveal-branch", "ordinary"} {
		t.Run(name, func(t *testing.T) {
			r, s, ssh := networkRunner(t, name == "tier1", networkCap(true, true))
			in := networkInput()
			var out RunOutput
			var err error
			switch name {
			case "combined-net", "combined-reveal", "reveal-branch":
				in.Reveal = true
			case "fallback-ran":
				ssh.exit, ssh.stderr = 77, "gate: "+sigwire.GateDenyNetNotPermitted
			case "reason":
				in.Reason = " \t"
			case "tier1":
				r.caps["test"] = networkCap(false, false)
			case "daemon":
				in.Command = "docker ps"
			case "ordinary":
				in.Network = false
			}
			if name == "batch" {
				_, err = r.RunBatch(context.Background(), RunBatchInput{Alias: in.Alias, Commands: []string{in.Command}, Network: true})
			} else {
				out, err = r.Run(context.Background(), in)
			}
			effect := false
			switch name {
			case "combined-net", "reveal-branch":
				effect = len(s.calls) == 1 && len(s.calls[0]) == 1 && !s.calls[0][0].Net
			case "combined-reveal":
				effect = len(ssh.calls) == 1 && ssh.calls[0] == sigwire.EnvelopeConfinedNet+in.Command
			case "envelope-missing":
				effect = len(ssh.calls) == 1 && ssh.calls[0] == in.Command
			case "fallback-ran":
				effect = len(ssh.calls) > 1 && ssh.calls[len(ssh.calls)-1] == in.Command
			case "reason", "tier1", "batch", "daemon":
				effect = len(s.calls) != 0 || len(ssh.calls) != 0
			case "ordinary":
				if err != nil || len(s.calls) != 0 || !reflect.DeepEqual(ssh.calls, []string{in.Command}) {
					t.Fatalf("ordinary control: %+v %v signs=%v ssh=%v", out, err, s.calls, ssh.calls)
				}
				return
			}
			if effect {
				t.Fatalf("MUTATION-EFFECT %s", name)
			}
			switch name {
			case "combined-net", "combined-reveal", "reveal-branch":
				if err != nil || len(s.calls) != 1 || len(s.calls[0]) != 1 || !s.calls[0][0].Net || !s.calls[0][0].Reveal || !out.Revealed || !reflect.DeepEqual(ssh.calls, []string{"signed " + in.Command}) {
					t.Fatalf("combined baseline: %+v %v signs=%v ssh=%v", out, err, s.calls, ssh.calls)
				}
			case "envelope-missing":
				if err != nil || len(s.calls) != 0 || !reflect.DeepEqual(ssh.calls, []string{sigwire.EnvelopeConfinedNet + in.Command}) {
					t.Fatalf("envelope baseline: %+v %v signs=%v ssh=%v", out, err, s.calls, ssh.calls)
				}
			default:
				if err == nil {
					t.Fatal("expected refusal")
				}
			}
		})
	}
}

func TestRunNetworkWrappedDaemon(t *testing.T) {
	for _, command := range []string{
		"LANG=C>&2 docker ps", "env LANG=C>&2 docker ps",
		"watch -n 1>&2 docker ps", "env LANG=C<&0 systemctl status x",
		`d"o"cker ps`, `do\cker ps`, "/usr/bin/docker ps", "ls /usr/bin/docker",
		"env -- docker ps", "env -- systemctl status x",
		"env LANG=C -- env -- docker ps",
		"LANG=C env -- LANG=C env systemctl status x",
		"watch -n 1 -- env -- docker ps",
		"env -- watch --interval 1 -t systemctl status x",
		"watch --interval=1 env LANG=C watch -n1 -- docker ps",
	} {
		t.Run(command, func(t *testing.T) {
			if command != "/usr/bin/docker ps" && classify.Classify(command) != classify.KindRead {
				t.Fatal("fixture is not an accepted read")
			}
			for _, envelope := range []bool{false, true} {
				t.Run(fmt.Sprintf("envelope=%t", envelope), func(t *testing.T) {
					r, s, ssh := networkRunner(t, false, networkCap(envelope, envelope))
					in := networkInput()
					in.Command = command
					out, err := r.Run(context.Background(), in)
					if err == nil || networkVerdict(out) != VerdictNetworkGrantReadOnly || len(s.calls) != 0 || len(ssh.calls) != 0 {
						t.Fatalf("wrapped daemon executed: %+v %v signs=%v ssh=%v", out, err, s.calls, ssh.calls)
					}
				})
			}
		})
	}
}

func TestRunNetworkUnterminatedDiagnostic(t *testing.T) {
	for _, envelope := range []bool{false, true} {
		t.Run(fmt.Sprintf("envelope=%t", envelope), func(t *testing.T) {
			r, s, ssh := networkRunner(t, false, networkCap(envelope, envelope))
			ssh.exit = 77
			ssh.stderr = "partial command stderrgate: read jail unavailable: setup failed; read may have started\ncommand output\nmore stderrgate: read jail unavailable: second warning\n"
			in := networkInput()
			cap := 8
			in.MaxOutputBytes = &cap
			out, err := r.Run(context.Background(), in)
			if err == nil || networkVerdict(out) != VerdictNetworkRequiresConfinement {
				t.Fatalf("missing refusal: %+v %v", out, err)
			}
			if out.Denial.Diagnostic != "gate: read jail unavailable: setup failed; read may have started\ngate: read jail unavailable: second warning" {
				t.Fatalf("lost diagnostic: %+v %v", out.Denial, err)
			}
			signs := 1
			if envelope {
				signs = 0
			}
			want, _ := capOutput(ssh.stderr, cap)
			if out.Stderr != want || len(ssh.calls) != 1 || len(s.calls) != signs {
				t.Fatalf("cap or execution count changed: %+v", out)
			}
		})
	}
}

func TestRunNetworkWrappedRead(t *testing.T) {
	for _, command := range []string{
		"env -- cat docker.log",
		"env LANG=C -- watch -n 1 -- cat systemctl.log",
		"watch --interval=1 env -- printf 'docker.log | systemctl.log'",
	} {
		t.Run(command, func(t *testing.T) {
			r, s, ssh := networkRunner(t, false, networkCap(true, true))
			in := networkInput()
			in.Command = command
			out, err := r.Run(context.Background(), in)
			if err != nil || out.Denial != nil || len(s.calls) != 0 || !reflect.DeepEqual(ssh.calls, []string{sigwire.EnvelopeConfinedNet + command}) {
				t.Fatalf("wrapped read refused: %+v %v signs=%v ssh=%v", out, err, s.calls, ssh.calls)
			}
		})
	}
}

func TestRunNetworkReadControls(t *testing.T) {
	for _, command := range []string{"cat /etc/hostname", "cat docker.log", "curl https://example.com"} {
		for _, envelope := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/envelope=%t", command, envelope), func(t *testing.T) {
				r, s, ssh := networkRunner(t, false, networkCap(envelope, envelope))
				in := networkInput()
				in.Command = command
				out, err := r.Run(context.Background(), in)
				signs, prefix := 1, "signed "
				if envelope {
					signs, prefix = 0, sigwire.EnvelopeConfinedNet
				}
				if err != nil || out.Denial != nil || len(s.calls) != signs || !reflect.DeepEqual(ssh.calls, []string{prefix + command}) {
					t.Fatalf("read route: %+v %v signs=%v ssh=%v", out, err, s.calls, ssh.calls)
				}
			})
		}
	}
}

func TestRunNetworkCappedDiagnostic(t *testing.T) {
	for _, envelope := range []bool{false, true} {
		t.Run(fmt.Sprintf("envelope=%t", envelope), func(t *testing.T) {
			r, s, ssh := networkRunner(t, false, networkCap(envelope, envelope))
			ssh.exit = 77
			ssh.stderr = "command output that must not ride along\ngate: read jail unavailable: setup failed; command may have started\n"
			in := networkInput()
			cap := 8
			in.MaxOutputBytes = &cap
			out, err := r.Run(context.Background(), in)
			if err == nil || networkVerdict(out) != VerdictNetworkRequiresConfinement {
				t.Fatalf("missing refusal: %+v %v", out, err)
			}
			if out.Denial.Diagnostic != "gate: read jail unavailable: setup failed; command may have started" {
				t.Fatalf("lost diagnostic: %+v %v", out.Denial, err)
			}
			signs := 1
			if envelope {
				signs = 0
			}
			want, _ := capOutput(ssh.stderr, cap)
			if out.Stderr != want || len(ssh.calls) != 1 || len(s.calls) != signs {
				t.Fatalf("cap or execution count changed: %+v", out)
			}
		})
	}
}
