package signer_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/karthikeyan5/sshgate/pkg/signerkit"
	"github.com/karthikeyan5/sshgate/src/gate"
)

type netCountingBackend struct {
	*signerkit.MockBackend
	requests []signerkit.ApprovalRequest
}

func (b *netCountingBackend) Request(ctx context.Context, req signerkit.ApprovalRequest) (<-chan signerkit.Result, error) {
	b.requests = append(b.requests, req)
	return b.MockBackend.Request(ctx, req)
}

func networkCommand() map[string]any {
	return map[string]any{"server": "prod", "cmd": "curl https://example.com", "ttl_seconds": 60, "host": grantHost, "net": true, "reason": "check endpoint connectivity"}
}

func signNetwork(t *testing.T, d *signerkit.Daemon, id string, commands ...map[string]any) grantSignResp {
	t.Helper()
	raw, err := json.Marshal(map[string]any{"kind": "sign", "request_id": id, "commands": commands})
	if err != nil {
		t.Fatal(err)
	}
	conn := &memConn{in: bytes.NewReader(append(raw, '\n')), out: &bytes.Buffer{}}
	if err := d.HandleSignRequest(context.Background(), conn); err != nil {
		t.Fatal(err)
	}
	var resp grantSignResp
	if err := json.Unmarshal(conn.out.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	return resp
}

func rejectNetwork(t *testing.T, want string, commands ...map[string]any) {
	t.Helper()
	bk := &netCountingBackend{MockBackend: signerkit.NewMockBackend()}
	bk.Approve("net", "operator")
	d, _, audit, path := newDaemon(t, bk)
	defer audit.Close()
	resp := signNetwork(t, d, "net", commands...)
	if resp.Status != "error" || resp.Error != want || len(resp.Signatures) != 0 || len(bk.requests) != 0 {
		t.Fatalf("network admission: response=%+v prompts=%d; want error %q without prompt or signature", resp, len(bk.requests), want)
	}
	rows := readAudit(t, path)
	if len(rows) != 1 || rows[0].Status != "error" || rows[0].RequestID != "net" {
		t.Fatalf("audit=%+v", rows)
	}
}

func TestSignRejectsNetInBatch(t *testing.T) {
	for _, first := range []bool{true, false} {
		net, plain := networkCommand(), networkCommand()
		plain["net"] = false
		commands := []map[string]any{plain, net}
		if first {
			commands = []map[string]any{net, plain}
		}
		rejectNetwork(t, "network requires a single-command request", commands...)
	}
}
func TestSignRejectsNetWithoutReason(t *testing.T) {
	for _, reason := range []string{"", " \t\n"} {
		c := networkCommand()
		c["reason"] = reason
		rejectNetwork(t, "network requires a non-empty reason", c)
	}
}
func TestSignRejectsNetOnAdminVerb(t *testing.T) {
	for _, cmd := range []string{"SSHGATE_REVOKE", "SSHGATE_UPDATE abc", "SSHGATE_XFER_SEND abc", "SSHGATE_XFER_RECV abc", "SSHGATE_READ1 confined,net uptime", "SSHGATE_FUTURE"} {
		c := networkCommand()
		c["cmd"] = cmd
		rejectNetwork(t, "network is not available for admin verbs", c)
	}
}
func TestSignRejectsNetOnWrite(t *testing.T) {
	for _, cmd := range []string{"touch /tmp/example", "unrecognized-command", "curl -X POST https://example.com", "uptime; touch /tmp/example", "", " \t"} {
		c := networkCommand()
		c["cmd"] = cmd
		rejectNetwork(t, "network grants cover reads only", c)
	}
}

func TestMatchGrantNeverAutoSignsNet(t *testing.T) {
	// Keep both scopes in this leaf so srcmut judges one complete protection.
	for _, scope := range []string{"all", "commands"} {
		bk := &netCountingBackend{MockBackend: signerkit.NewMockBackend()}
		d, _, audit, _, _ := newGrantDaemon(t, bk, time.Unix(1000, 0))
		defer audit.Close()
		bk.Approve("grant", "operator")
		var commands []string
		if scope == "commands" {
			commands = []string{"curl https://example.com"}
		}
		grant := createGrant(t, d, "grant", "prod", scope, commands, 3600)
		if grant.Status != "approved" {
			t.Fatalf("grant=%+v", grant)
		}
		// Prove the live grant actually covers this command before asking for network.
		plain := networkCommand()
		plain["net"] = false
		if resp := signNetwork(t, d, "plain", plain); resp.Status != "approved" || resp.AuthMode != "grant:"+grant.GrantID || len(bk.requests) != 0 {
			t.Fatalf("grant control=%+v prompts=%d", resp, len(bk.requests))
		}
		bk.Deny("net")
		resp := signNetwork(t, d, "net", networkCommand())
		if len(bk.requests) == 0 && resp.Status == "approved" && len(resp.Signatures) == 1 {
			t.Fatal("MUTATION-EFFECT grant-autosigned-net")
		}
		if len(bk.requests) != 1 || !bk.requests[0].Commands[0].Net || resp.Status != "denied" || len(resp.Signatures) != 0 {
			t.Fatalf("scope=%s response=%+v prompts=%+v", scope, resp, bk.requests)
		}
	}
}

func TestDaemon_SignsNetFlag(t *testing.T) {
	for _, reveal := range []bool{false, true} {
		bk := &netCountingBackend{MockBackend: signerkit.NewMockBackend()}
		d, pub, audit, _ := newDaemon(t, bk)
		defer audit.Close()
		bk.Approve("net", "operator")
		c := networkCommand()
		c["reveal"] = reveal
		resp := signNetwork(t, d, "net", c)
		if resp.Status != "approved" || len(resp.Signatures) != 1 {
			t.Fatalf("response=%+v", resp)
		}
		if len(bk.requests) != 1 || !bk.requests[0].Commands[0].Net || bk.requests[0].Commands[0].Reason != c["reason"] {
			t.Fatalf("prompt=%+v", bk.requests)
		}
		verified, err := gate.Verify(resp.Signatures[0].Sig, pub, time.Unix(1000, 0), []string{grantHost})
		if err != nil || !verified.Net || verified.Reveal != reveal || verified.Cmd != c["cmd"] {
			t.Fatalf("verified=%+v err=%v", verified, err)
		}
		if _, _, err := gate.VerifySigned(resp.Signatures[0].Sig, pub, time.Unix(1000, 0), []string{grantHost}); !errors.Is(err, gate.ErrNetUnsupported) {
			t.Fatalf("legacy verifier=%v", err)
		}
	}
}
