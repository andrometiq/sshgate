//go:build journey

package journey

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

type journeyRig struct {
	project     string
	composeFile string
	controller  string
}

func commandOutput(ctx context.Context, name string, args ...string) (string, error) {
	command := exec.CommandContext(ctx, name, args...)
	output, err := command.CombinedOutput()
	return string(output), err
}

func (r *journeyRig) compose(ctx context.Context, args ...string) (string, error) {
	return commandOutput(ctx, "docker", append([]string{"compose", "-p", r.project, "-f", r.composeFile}, args...)...)
}

func (r *journeyRig) exec(t *testing.T, service string, args ...string) string {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	output, err := r.compose(ctx, append([]string{"exec", "-T", service}, args...)...)
	if err != nil {
		t.Fatalf("fixture %s command failed: %v\n%s", service, err, output)
	}
	return output
}

// Each invocation starts a fresh login, including supplementary groups added by install.sh.
func (r *journeyRig) operator(t *testing.T, script string) string {
	t.Helper()
	return r.exec(t, "controller", "runuser", "-l", "sgop", "-c", script)
}

func (r *journeyRig) wait(t *testing.T, service string, args ...string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	ticker := time.NewTicker(250 * time.Millisecond)
	defer ticker.Stop()
	var output string
	var err error
	for {
		output, err = r.compose(ctx, append([]string{"exec", "-T", service}, args...)...)
		if err == nil {
			return
		}
		select {
		case <-ctx.Done():
			t.Fatalf("%s readiness failed: %v\n%s", service, err, output)
		case <-ticker.C:
		}
	}
}

func newJourneyRig(t *testing.T) *journeyRig {
	t.Helper()
	r := &journeyRig{project: os.Getenv("JOURNEY_PROJECT"), composeFile: os.Getenv("JOURNEY_COMPOSE_FILE")}
	if r.project == "" || r.composeFile == "" {
		t.Fatal("run scripts/test-journey.sh; Docker/systemd are required")
	}
	// Cleanup is registered before up, including a partially failed start.
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
		defer cancel()
		if t.Failed() {
			// Status only: never dump service journals, credentials or remote output here.
			output, _ := r.compose(ctx, "ps", "--all")
			t.Log(output)
		}
		output, err := r.compose(ctx, "down", "--volumes", "--remove-orphans", "--timeout", "10")
		if err != nil {
			t.Errorf("fixture cleanup: %v\n%s", err, output)
		}
	})
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	if output, err := r.compose(ctx, "up", "-d", "--no-build", "--pull", "never"); err != nil {
		t.Fatalf("fixture startup: %v\n%s", err, output)
	}
	r.wait(t, "controller", "systemctl", "is-active", "multi-user.target")
	if pid1 := strings.TrimSpace(r.exec(t, "controller", "cat", "/proc/1/comm")); pid1 != "systemd" {
		t.Fatalf("PID 1 = %q", pid1)
	}
	id, err := r.compose(ctx, "ps", "-q", "controller")
	if err != nil {
		t.Fatal(err)
	}
	r.controller = strings.TrimSpace(id)
	output, err := commandOutput(ctx, "docker", "inspect", "--format", "{{.HostConfig.CgroupnsMode}}", r.controller)
	if err != nil || strings.TrimSpace(output) != "private" {
		t.Fatalf("private cgroup namespace: %q %v", output, err)
	}
	for _, host := range []string{"target-a", "target-b"} {
		r.wait(t, "controller", "bash", "-c", "ssh-keyscan -T 2 "+host+" 2>/dev/null | grep -q ssh-")
	}
	output, err = commandOutput(ctx, "docker", "network", "inspect", "--format", "{{.Internal}}", r.project+"_journey")
	if err != nil || strings.TrimSpace(output) != "true" {
		t.Fatalf("network is not internal: %q %v", output, err)
	}
	hostKeys := make(map[string]bool)
	for _, service := range []string{"controller", "target-a", "target-b"} {
		containerID, err := r.compose(ctx, "ps", "-q", service)
		if err != nil {
			t.Fatal(err)
		}
		topology, err := commandOutput(ctx, "docker", "inspect", "--format", "{{len .HostConfig.PortBindings}} {{len .NetworkSettings.Networks}}", strings.TrimSpace(containerID))
		if err != nil || strings.TrimSpace(topology) != "0 1" {
			t.Fatalf("%s has published ports or extra networks: %q %v", service, topology, err)
		}
		if service != "controller" {
			key := strings.TrimSpace(r.exec(t, service, "cat", "/etc/ssh/ssh_host_ed25519_key.pub"))
			fields := strings.Fields(key)
			if len(fields) < 2 || hostKeys[fields[1]] {
				t.Fatal("targets must have independent SSH host keys")
			}
			hostKeys[fields[1]] = true
		}
		r.exec(t, service, "bash", "-c", "! curl --noproxy '*' --connect-timeout 2 --max-time 3 -s http://1.1.1.1 >/dev/null")
		r.exec(t, service, "bash", "-c", "! timeout 3 getent ahostsv4 example.com >/dev/null")
	}
	r.exec(t, "controller", "bash", "-ec", `install -d -o sgop -g sgop /home/sgop/src
chmod a+r /opt/journey/source.bundle
runuser -u sgop -- git clone /opt/journey/source.bundle /home/sgop/src/SSHGate
cp -a /opt/journey/vendor /home/sgop/src/SSHGate/vendor
chown -R sgop:sgop /home/sgop/src/SSHGate/vendor
printf '%s\n' 'export PATH="$HOME/go/bin:/usr/local/go/bin:$PATH"' 'export GOPROXY=off GOSUMDB=off GOTOOLCHAIN=local' > /home/sgop/.bash_profile
chown sgop:sgop /home/sgop/.bash_profile`)
	commit := strings.TrimSpace(r.operator(t, "cd ~/src/SSHGate && git rev-parse HEAD"))
	if commit != os.Getenv("JOURNEY_COMMIT") {
		t.Fatalf("installed commit %q differs from tested commit", commit)
	}
	r.operator(t, "cd ~/src/SSHGate && make install-local")
	return r
}

func (r *journeyRig) addReadOnly(t *testing.T) {
	t.Helper()
	publicKey := strings.TrimSpace(r.operator(t, "sshgate pubkey 2>/dev/null"))
	if !strings.HasPrefix(publicKey, "ssh-ed25519 ") || strings.ContainsAny(publicKey, "\r\n'") {
		t.Fatal("unexpected public key format")
	}
	for _, host := range []string{"target-a", "target-b"} {
		r.exec(t, host, "bash", "-ec", "printf '%s\\n' '"+publicKey+"' > /home/user/.ssh/authorized_keys; chown user:user /home/user/.ssh/authorized_keys; chmod 600 /home/user/.ssh/authorized_keys")
	}
	r.operator(t, "sshgate add web1 user@target-a --read-only")
	r.exec(t, "target-a", "test", "!", "-e", "/home/user/.sshgate-gate/gate.pub")
	r.operator(t, `test "$(stat -c %a ~/.config/sshgate/ssh/sshgate_ed25519)" = 600`)
	r.exec(t, "target-a", "bash", "-ec", `grep -q 'command=.*gate' /home/user/.ssh/authorized_keys; grep -q 'no-pty' /home/user/.ssh/authorized_keys`)
	installed := strings.Fields(r.operator(t, "sha256sum ~/.config/sshgate/bin/sshgate-gate-linux-amd64"))[0]
	deployed := strings.Fields(r.exec(t, "target-a", "sha256sum", "/home/user/.sshgate-gate/gate"))[0]
	if installed != deployed {
		t.Fatal("published gate installation hash mismatch")
	}
	t.Logf("published gate SHA256 %s", installed)
	t.Log(r.operator(t, "cd ~/src/SSHGate && sha256sum bin/sshgate-gate-linux-amd64 && go version -m bin/sshgate-gate-linux-amd64 && go version -m dist/gate/sshgate-gate-linux-amd64"))
}

func (r *journeyRig) telegramAdmin(t *testing.T, route, body string) {
	t.Helper()
	output := r.exec(t, "controller", "curl", "--fail", "--silent", "--show-error", "--max-time", "5",
		"-H", "Content-Type: application/json", "--data", body, "http://127.0.0.1:18081"+route)
	var response struct {
		OK bool `json:"ok"`
	}
	if err := json.Unmarshal([]byte(output), &response); err != nil || !response.OK {
		t.Fatalf("fake Telegram %s failed: %s (%v)", route, output, err)
	}
}

func (r *journeyRig) installSigner(t *testing.T) {
	t.Helper()
	// The fixture process must listen on loopback :18080, with admin on :18081.
	r.exec(t, "controller", "bash", "-ec", `mkdir -p /etc/systemd/system/sshgate-signer-telegram.service.d
printf '%s\n' '[Service]' 'Environment=SSHGATE_TELEGRAM_API_URL=http://127.0.0.1:18080' > /etc/systemd/system/sshgate-signer-telegram.service.d/journey.conf
`)
	args := []string{"systemd-run", "--unit=journey-fake-telegram", "/opt/journey/fake-telegram",
		"--api", "127.0.0.1:18080", "--admin", "127.0.0.1:18081", "--user-id", "424242"}
	if raw := os.Getenv("JOURNEY_FAKE_TELEGRAM_ARGS_JSON"); raw != "" {
		var extra []string
		if err := json.Unmarshal([]byte(raw), &extra); err != nil {
			t.Fatal(err)
		}
		args = append(args, extra...)
	}
	r.exec(t, "controller", args...)
	r.wait(t, "controller", "curl", "--fail", "--silent", "http://127.0.0.1:18080/bot123456:journey_fixture_only/getMe")
	r.wait(t, "controller", "systemctl", "is-active", "journey-fake-telegram")
	r.wait(t, "controller", "curl", "--fail", "--silent", "--max-time", "5", "http://127.0.0.1:18081/events")
	r.telegramAdmin(t, "/start", `{"chat_id":424242}`)
	r.operator(t, "python3 /opt/journey/fixtures/install-pty.py")
	r.wait(t, "controller", "systemctl", "is-active", "sshgate-signer-telegram")
	r.exec(t, "controller", "bash", "-ec", `test "$(stat -c '%U:%a' /var/lib/sshgatesigner/keys/gate.key)" = sshgatesigner:600`)
	r.operator(t, "test ! -r /var/lib/sshgatesigner/keys/gate.key && test ! -r /var/lib/sshgatesigner/tokens/telegram.token && id -nG | tr ' ' '\n' | grep -qx sshgatesigner")
	r.wait(t, "controller", "python3", "-c", `import json
with open('/var/lib/sshgatesigner/config/peer.json') as peer:
    assert json.load(peer)['chat_id'] == 424242`)
	r.telegramAdmin(t, "/policy", `{"policy":"approve_now"}`)
	// A new login is also used for every subsequent MCP process.
	output := r.operator(t, "sshgate add web2 user@target-b")
	r.telegramAdmin(t, "/policy", `{"policy":"hold"}`)
	if !strings.Contains(output, `transfer:    registered (label "web2")`) {
		t.Fatal("web2 transfer enrollment did not succeed")
	}
	r.exec(t, "controller", "python3", "-c", `import json, urllib.request
with urllib.request.urlopen('http://127.0.0.1:18081/events', timeout=5) as response:
    transcript = json.load(response)
assert transcript['ok']
assert not transcript['result']['failures'], transcript['result']['failures']`)
}

func TestJourneyRig(t *testing.T) {
	rig := newJourneyRig(t)
	rig.operator(t, "test ! -e ~/.config/sshgate/ssh/sshgate_ed25519")
	client := rig.mcp(t)
	client.assertTools(t)
	client.call(t, "list_servers", map[string]any{}, nil)
	client.close(t)
	rig.operator(t, "test ! -e ~/.config/sshgate/ssh/sshgate_ed25519")
	rig.addReadOnly(t)
	rig.installSigner(t)
	client = rig.mcp(t)
	client.assertTools(t)
	for _, alias := range []string{"web1", "web2"} {
		var result map[string]any
		client.call(t, "ping", map[string]any{"alias": alias}, &result)
		if fmt.Sprint(result["reachable"]) != "true" {
			t.Fatalf("%s unreachable: %v", alias, result)
		}
	}
}
