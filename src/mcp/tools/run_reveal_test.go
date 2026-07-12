package tools_test

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/karthikeyan5/sshgate/src/mcp/registry"
	signpkg "github.com/karthikeyan5/sshgate/src/mcp/sign"
	"github.com/karthikeyan5/sshgate/src/mcp/tools"
	"github.com/karthikeyan5/sshgate/src/sigwire"
)

// TestRun_RevealThreadsRevealAndReason pins that RunInput.Reveal=true threads
// BOTH the reveal flag and the mandatory reason into the sign request — and
// forces the SIGNING path even for a read-classified command (a reveal of
// `cat secret.env` would otherwise go direct/unsigned and the gate would never
// see the flag). Reveal is signed-only by construction.
func TestRun_RevealThreadsRevealAndReason(t *testing.T) {
	t.Parallel()
	const wantFP = "SHA256:prodHostKeyFingerprintAAAAAAAAAAAAAAAAAAAAAA"
	r := newRegistryWith(t, "h1", registry.Entry{
		Host: "1.2.3.4", Port: 22, User: "u", AddedAt: time.Now(), Fingerprint: wantFP,
	})
	// cat classifies as a READ; reveal must still route it through Sign.
	const cmd = "cat /etc/secret.env"
	payload := sigwire.SigPayload{Cmd: cmd, TS: 1, Exp: 60, Nonce: "abc", Host: wantFP, Reveal: true}
	wire, err := sigwire.EncodeSigned([]byte("0123456789012345678901234567890123456789012345678901234567890123"), payload)
	if err != nil {
		t.Fatal(err)
	}
	sign := &fakeSign{signed: []signpkg.Signed{{Cmd: cmd, Sig: wire}}}
	ssh := &fakeSSH{stdout: []byte("SECRET=hunter2\n"), exit: 0}
	runner := &tools.Runner{Servers: r, Sign: sign, SSH: ssh}

	out, err := runner.Run(context.Background(), tools.RunInput{
		Alias:   "h1",
		Command: cmd,
		Reveal:  true,
		Reason:  "need to confirm the DB password value",
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if !sign.signCalled {
		t.Fatal("reveal must go through the signing path (sign was not called)")
	}
	if len(sign.gotCmds) != 1 {
		t.Fatalf("got %d cmds; want 1 (reveal is single-command only)", len(sign.gotCmds))
	}
	if !sign.gotCmds[0].Reveal {
		t.Errorf("sign CmdReq.Reveal = false; want true")
	}
	if sign.gotCmds[0].Reason != "need to confirm the DB password value" {
		t.Errorf("sign CmdReq.Reason = %q; want the supplied reason", sign.gotCmds[0].Reason)
	}
	if sign.gotCmds[0].Host != wantFP {
		t.Errorf("sign CmdReq.Host = %q; want registry fingerprint %q", sign.gotCmds[0].Host, wantFP)
	}
	// The SSH side receives the signed wire prefix even though cmd is a read.
	if !strings.HasPrefix(ssh.gotCmd, "SSHGATE_SIG:") {
		t.Errorf("ssh got cmd %q; expected signed prefix for a reveal", ssh.gotCmd)
	}
	if out.Kind != "write" {
		t.Errorf("Kind = %q; want write (reveal forces the signed path)", out.Kind)
	}
	// The output MUST carry Revealed=true so downstream audit surfaces (the
	// live log) can blank the raw secret while still recording that a reveal
	// happened.
	if !out.Revealed {
		t.Errorf("RunOutput.Revealed = false; want true for a reveal command")
	}
}

// TestRun_NormalCommandRevealedFalse pins that an ordinary read leaves
// RunOutput.Revealed=false — the indicator is reveal-only, so the live log
// keeps logging normal output verbatim.
func TestRun_NormalCommandRevealedFalse(t *testing.T) {
	t.Parallel()
	r := newRegistryWith(t, "h1", registry.Entry{Host: "1.2.3.4", Port: 22, User: "u", AddedAt: time.Now()})
	sign := &fakeSign{}
	ssh := &fakeSSH{stdout: []byte("ok\n"), exit: 0}
	runner := &tools.Runner{Servers: r, Sign: sign, SSH: ssh}

	out, err := runner.Run(context.Background(), tools.RunInput{Alias: "h1", Command: "df -h"})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if out.Revealed {
		t.Errorf("RunOutput.Revealed = true for a normal read; want false")
	}
}

// TestRun_RevealRequiresReason pins the MCP-side validation: reveal=true with
// an empty (or whitespace) reason is rejected BEFORE any sign call — a reveal
// must always carry a human justification.
func TestRun_RevealRequiresReason(t *testing.T) {
	t.Parallel()
	r := newRegistryWith(t, "h1", registry.Entry{Host: "1.2.3.4", Port: 22, User: "u", AddedAt: time.Now()})
	sign := &fakeSign{}
	ssh := &fakeSSH{}
	runner := &tools.Runner{Servers: r, Sign: sign, SSH: ssh}

	for _, reason := range []string{"", "   ", "\t\n"} {
		out, err := runner.Run(context.Background(), tools.RunInput{
			Alias:   "h1",
			Command: "cat /etc/secret.env",
			Reveal:  true,
			Reason:  reason,
		})
		if err == nil {
			t.Fatalf("reveal with reason %q: expected an error, got nil", reason)
		}
		if !strings.Contains(strings.ToLower(err.Error()), "reason") {
			t.Errorf("reveal with reason %q: error %q should mention the missing reason", reason, err)
		}
		// #26-core: structured Denial → reveal_needs_reason / provide_reason.
		if out.Denial == nil || out.Denial.VerdictClass != tools.VerdictRevealNeedsReason ||
			out.Denial.RequiredAction != tools.ActionProvideReason {
			t.Errorf("reveal with reason %q: out.Denial=%+v; want reveal_needs_reason/provide_reason", reason, out.Denial)
		}
		if sign.signCalled {
			t.Errorf("reveal with reason %q: sign must NOT be called when validation fails", reason)
		}
	}
}

// TestRun_NoRevealLeavesFlagFalse pins that an ordinary write (no reveal) keeps
// CmdReq.Reveal=false and Reason empty — the common path is unchanged.
func TestRun_NoRevealLeavesFlagFalse(t *testing.T) {
	t.Parallel()
	const wantFP = "SHA256:prodHostKeyFingerprintAAAAAAAAAAAAAAAAAAAAAA"
	r := newRegistryWith(t, "h1", registry.Entry{
		Host: "1.2.3.4", Port: 22, User: "u", AddedAt: time.Now(), Fingerprint: wantFP,
	})
	payload := sigwire.SigPayload{Cmd: "rm /tmp/x", TS: 1, Exp: 60, Nonce: "abc", Host: wantFP}
	wire, _ := sigwire.EncodeSigned([]byte("0123456789012345678901234567890123456789012345678901234567890123"), payload)
	sign := &fakeSign{signed: []signpkg.Signed{{Cmd: "rm /tmp/x", Sig: wire}}}
	ssh := &fakeSSH{stdout: []byte("ok\n"), exit: 0}
	runner := &tools.Runner{Servers: r, Sign: sign, SSH: ssh}

	if _, err := runner.Run(context.Background(), tools.RunInput{Alias: "h1", Command: "rm /tmp/x"}); err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(sign.gotCmds) != 1 {
		t.Fatalf("got %d cmds; want 1", len(sign.gotCmds))
	}
	if sign.gotCmds[0].Reveal {
		t.Errorf("ordinary write CmdReq.Reveal = true; want false")
	}
	if sign.gotCmds[0].Reason != "" {
		t.Errorf("ordinary write CmdReq.Reason = %q; want empty", sign.gotCmds[0].Reason)
	}
}
