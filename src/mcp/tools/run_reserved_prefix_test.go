package tools_test

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/karthikeyan5/sshgate/src/mcp/registry"
	"github.com/karthikeyan5/sshgate/src/mcp/tools"
)

func TestRunRejectsAgentEnvelope(t *testing.T) {
	for _, command := range []string{"SSHGATE_READ", "SSHGATE_READ1 confined,net cat /etc/hostname", "SSHGATE_READ2 confined cat /etc/hostname", "SSHGATE_READER", "SSHGATE_READ\tcat /etc/hostname"} {
		for _, reveal := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/reveal=%t", command, reveal), func(t *testing.T) {
				signer, ssh := &fakeSign{}, &fakeSSH{}
				runner := &tools.Runner{Servers: newRegistryWith(t, "host", registry.Entry{Host: "example.test", User: "user", Port: 22}), Sign: signer, SSH: ssh}
				out, err := runner.Run(context.Background(), tools.RunInput{Alias: "host", Command: command, Reveal: reveal, Reason: "inspect output"})
				if err == nil || !strings.Contains(err.Error(), "reserved") || !strings.Contains(err.Error(), "SSHGATE_READ") {
					t.Errorf("expected reserved-prefix error, got %v", err)
				}
				if out.Denial != nil || out.Approved || out.Revealed {
					t.Errorf("expected plain tool error, got %+v", out)
				}
				if signer.signCalled || len(ssh.callHistory) != 0 {
					t.Errorf("reserved input reached signer=%t or SSH=%v", signer.signCalled, ssh.callHistory)
				}
			})
		}
	}
}

func TestRunBatchRejectsAgentEnvelope(t *testing.T) {
	for _, command := range []string{"SSHGATE_READ", "SSHGATE_READ1 confined,net cat /etc/hostname", "SSHGATE_READ2 confined cat /etc/hostname", "SSHGATE_READER", "SSHGATE_READ\tcat /etc/hostname"} {
		for _, index := range []int{0, 1, 2} {
			t.Run(fmt.Sprintf("%s/index=%d", command, index), func(t *testing.T) {
				signer, ssh := &fakeSign{}, &fakeSSH{}
				runner := &tools.Runner{Servers: newRegistryWith(t, "host", registry.Entry{Host: "example.test", User: "user", Port: 22}), Sign: signer, SSH: ssh}
				commands := []string{"cat /etc/hostname", "touch /tmp/example", "df -h"}
				commands[index] = command
				out, err := runner.RunBatch(context.Background(), tools.RunBatchInput{Alias: "host", Commands: commands})
				if err == nil || !strings.Contains(err.Error(), fmt.Sprintf("commands[%d]", index)) || !strings.Contains(err.Error(), "reserved command prefix SSHGATE_READ") {
					t.Errorf("expected indexed reserved-prefix error, got %v", err)
				}
				if out.Denial != nil || out.Approved || len(out.Results) != 0 {
					t.Errorf("expected plain tool error with no results, got %+v", out)
				}
				if signer.signCalled || len(ssh.callHistory) != 0 {
					t.Errorf("reserved input reached signer=%t or SSH=%v", signer.signCalled, ssh.callHistory)
				}
			})
		}
	}
}
