package tools

import (
	"context"
	"errors"
	"fmt"
	"path"
	"strings"

	"github.com/karthikeyan5/sshgate/src/classify"
	"github.com/karthikeyan5/sshgate/src/mcp/registry"
	signpkg "github.com/karthikeyan5/sshgate/src/mcp/sign"
	"github.com/karthikeyan5/sshgate/src/sigwire"
)

func (r *Runner) runNetwork(ctx context.Context, in RunInput, entry registry.Entry, outputCap int) (out RunOutput, err error) {
	defer func() {
		if out.Denial != nil && strings.HasPrefix(out.Denial.VerdictClass, "network_") {
			r.invalidateCap(in.Alias)
		}
	}()
	if strings.TrimSpace(in.Reason) == "" {
		return networkRefusal(VerdictNetworkNeedsReason)
	}
	if classify.Classify(in.Command) != classify.KindRead || networkDaemonRead(in.Command) {
		return networkRefusal(VerdictNetworkGrantReadOnly)
	}
	if in.Reveal && entry.ReadOnly {
		return RunOutput{Kind: "write", Denial: newDenial(VerdictReadOnlyServer)}, readOnlyWriteErr(in.Alias, "")
	}
	if err := r.checkKeyReady(); err != nil {
		return RunOutput{Kind: "read", Denial: newDenial(VerdictNoSignerConfigured)}, err
	}
	capability := r.fetchCap(ctx, in.Alias, entry)
	if !in.Reveal && capability != nil && capability.Enforcement == "kernel" && capability.Pinned && capability.Net {
		return r.execNetwork(ctx, entry, sigwire.EnvelopeConfinedNet+in.Command, outputCap, RunOutput{Kind: "read"})
	}
	if entry.ReadOnly {
		return networkRefusal(VerdictNetworkNotPermitted)
	}
	if capability == nil || !capability.NetGrants {
		return networkRefusal(VerdictNetworkUnsupportedGate)
	}
	if capability.Enforcement != "kernel" {
		return networkRefusal(VerdictNetworkRequiresConfinement)
	}
	if r.Sign == nil {
		return networkRefusal(VerdictNetworkUnsupportedSigner)
	}
	ttl := r.WriteTTLSec
	if ttl <= 0 {
		ttl = DefaultWriteTTLSec
	}
	requestID, err := newRequestID()
	if err != nil {
		return RunOutput{}, fmt.Errorf("tools: request id: %w", err)
	}
	result, err := r.Sign.Sign(ctx, requestID, []signpkg.CmdReq{{Server: in.Alias, Host: entry.Fingerprint, Cmd: in.Command, TTLSec: ttl, Reveal: in.Reveal, Net: true, Reason: in.Reason}})
	if err != nil {
		if strings.Contains(err.Error(), sigwire.SignerNetUnsupported) || strings.Contains(err.Error(), sigwire.OldStrictDecodeNet) {
			out, _ := networkRefusal(VerdictNetworkUnsupportedSigner)
			return out, fmt.Errorf("tools: %s: %w", out.Denial.Summary, err)
		}
		return RunOutput{Kind: "write", Denial: r.denialForSignErr(err)}, r.remediateSignErr(err)
	}
	if len(result.Signed) != 1 {
		return RunOutput{}, fmt.Errorf("tools: expected 1 signature; got %d", len(result.Signed))
	}
	return r.execNetwork(ctx, entry, result.Signed[0].Sig+" "+in.Command, outputCap,
		RunOutput{Kind: "write", Approved: true, Revealed: in.Reveal, AuthMode: result.AuthMode})
}

func networkRefusal(class string) (RunOutput, error) {
	denial := newDenial(class)
	return RunOutput{Kind: "read", Denial: denial}, errors.New("tools: " + denial.Summary)
}

func (r *Runner) execNetwork(ctx context.Context, entry registry.Entry, command string, outputCap int, out RunOutput) (RunOutput, error) {
	stdout, stderr, exit, err := r.SSH.Run(ctx, entry.Host, entry.User, entry.Port, command)
	out.Stdout, _ = capOutput(string(stdout), outputCap)
	out.Stderr, _ = capOutput(string(stderr), outputCap)
	out.ExitCode = exit
	// Inspect the complete diagnostic before applying the output cap.
	out.Denial = networkGateDenial(exit, string(stderr))
	if out.Denial != nil {
		if err != nil {
			return out, fmt.Errorf("tools: %s: %w", out.Denial.Summary, err)
		}
		return out, errors.New("tools: " + out.Denial.Summary)
	}
	if err != nil {
		return out, fmt.Errorf("ssh exec: %w", err)
	}
	if out.Approved {
		out.Denial = denialForGateExit(exit)
		if out.Denial != nil {
			if exit == 65 && strings.Contains(string(stderr), "signature not yet valid") {
				out.Denial.HowTo = append(out.Denial.HowTo, "A human checks clock skew between signer and host; signatures allow at most 30 seconds ahead.")
			}
			return out, fmt.Errorf("tools: %s", gateDenyNote(exit))
		}
	}
	return out, nil
}

func networkGateDenial(exit int, stderr string) *Denial {
	if exit == 77 {
		switch {
		case strings.Contains(stderr, "gate: "+sigwire.GateDenyNetNotPermitted):
			return newDenial(VerdictNetworkNotPermitted)
		case strings.Contains(stderr, "gate: "+sigwire.GateDenyNetReadsOnly), strings.Contains(stderr, "gate: "+sigwire.GateDenyNetDaemonRead), strings.Contains(stderr, "gate: "+sigwire.GateDenyEnvelopeNotRead):
			return newDenial(VerdictNetworkGrantReadOnly)
		case strings.Contains(stderr, gateReadJailMarker):
			return newDenial(VerdictNetworkRequiresConfinement)
		case strings.Contains(stderr, "gate: "+sigwire.GateDenyBadEnvelope), strings.Contains(stderr, "write commands require a SSHGATE_SIG prefix"), strings.Contains(stderr, "no signing key configured"):
			return newDenial(VerdictNetworkUnsupportedGate)
		}
	}
	if exit == 65 && (strings.Contains(stderr, sigwire.OldStrictDecodeNet) || strings.Contains(stderr, sigwire.GateNetUnsupported)) {
		return newDenial(VerdictNetworkUnsupportedGate)
	}
	return nil
}

// Scan shell words, skipping assignments and env wrappers at each command head.
// Classification has already excluded opaque or writing shell constructs.
func networkDaemonRead(command string) bool {
	var word strings.Builder
	var quote byte
	atHead := true
	flush := func() bool {
		token := word.String()
		word.Reset()
		if !atHead || token == "" {
			return false
		}
		if strings.Contains(token, "=") || token == "env" {
			return false
		}
		atHead = false
		return path.Base(token) == "systemctl" || path.Base(token) == "docker"
	}
	for i := 0; i < len(command); i++ {
		c := command[i]
		if c == '\\' && quote != '\'' {
			if i+1 < len(command) {
				i++
				word.WriteByte(command[i])
			}
			continue
		}
		if quote != 0 {
			if c == quote {
				quote = 0
			} else {
				word.WriteByte(c)
			}
			continue
		}
		switch c {
		case '\'', '"':
			quote = c
		case ' ', '\t', '\r':
			if flush() {
				return true
			}
		case '|', '&', ';', '\n':
			if flush() {
				return true
			}
			atHead = true
		default:
			word.WriteByte(c)
		}
	}
	return flush()
}
