//go:build linux

package main

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/karthikeyan5/sshgate/src/redact"
)

// withLane2Bins points lane2BinDirs at a temp dir holding symlinks named
// systemctl and docker to this test binary, whose TestMain then reports how it
// was exec'd (path, argv, env, stdin) instead of running tests.
func withLane2Bins(t *testing.T) string {
	t.Helper()
	self, err := os.Executable()
	if err != nil {
		t.Fatalf("os.Executable: %v", err)
	}
	dir := t.TempDir()
	for _, name := range []string{"systemctl", "docker"} {
		if err := os.Symlink(self, filepath.Join(dir, name)); err != nil {
			t.Fatalf("symlink %s: %v", name, err)
		}
	}
	prev, prevRules := lane2BinDirs, redactRules
	lane2BinDirs = []string{dir}
	// The child's report carries random temp paths the production redactor
	// would scrub as high-entropy; compare it raw.
	redactRules = []redact.Rule{}
	t.Cleanup(func() { lane2BinDirs, redactRules = prev, prevRules })
	return dir
}

func TestLane2Argv(t *testing.T) {
	bin := withLane2Bins(t)
	sc, dk := filepath.Join(bin, "systemctl"), filepath.Join(bin, "docker")

	match := map[string][]string{
		"systemctl status sshd":                           {sc, "--no-pager", "status", "sshd"},
		"systemctl status\t nginx.service  --no-pager":    {sc, "--no-pager", "status", "nginx.service", "--no-pager"},
		"systemctl status -l -n 50 getty@tty1.service":    {sc, "--no-pager", "status", "-l", "-n", "50", "getty@tty1.service"},
		"systemctl list-units --type=service,socket -a":   {sc, "--no-pager", "list-units", "--type=service,socket", "-a"},
		"systemctl show -p ActiveState sshd":              {sc, "--no-pager", "show", "-p", "ActiveState", "sshd"},
		"systemctl is-active -q sshd":                     {sc, "--no-pager", "is-active", "-q", "sshd"},
		"systemctl get-default":                           {sc, "--no-pager", "get-default"},
		"docker ps -a":                                    {dk, "ps", "-a"},
		"docker ps --filter status=running --format json": {dk, "ps", "--filter", "status=running", "--format", "json"},
		"docker logs --tail 100 --since 1h web":           {dk, "logs", "--tail", "100", "--since", "1h", "web"},
		"docker stats --no-stream":                        {dk, "stats", "--no-stream"},
		"docker inspect --format=json web":                {dk, "inspect", "--format=json", "web"},
		"docker top web":                                  {dk, "top", "web"},
		"docker version":                                  {dk, "version"},
	}
	for cmd, want := range match {
		got, ok := lane2Argv(cmd)
		if !ok || !reflect.DeepEqual(got, want) {
			t.Errorf("lane2Argv(%q) = %q, %v; want %q, true", cmd, got, ok, want)
		}
	}

	noMatch := map[string]string{
		// Shell syntax of any kind: never a Lane-2 candidate.
		"systemctl status sshd; id":             "semicolon",
		"systemctl status sshd | head":          "pipe",
		"systemctl status sshd && id":           "and-list",
		"systemctl status sshd &":               "background",
		"systemctl status sshd > /tmp/x":        "redirect out",
		"systemctl status < /etc/passwd":        "redirect in",
		"systemctl status `id`":                 "backtick",
		"systemctl status $(id)":                "command substitution",
		"systemctl status ${HOME}":              "parameter expansion",
		"systemctl status $HOME":                "variable",
		"systemctl status 'sshd'":               "single quote",
		`systemctl status "sshd"`:               "double quote",
		`systemctl status ss\hd`:                "backslash",
		"systemctl status ssh*":                 "glob star",
		"systemctl status ssh?":                 "glob question",
		"systemctl status [s]shd":               "glob class",
		"systemctl status ~/x":                  "tilde",
		"systemctl status sshd #c":              "comment",
		"systemctl status {a,b}":                "brace",
		"systemctl status sshd\nid":             "newline",
		"systemctl status (sshd)":               "subshell",
		"DOCKER_HOST=tcp://evil:2375 docker ps": "env assignment prefix",
		// Not on the allowlist.
		"systemctl restart sshd":          "write verb",
		"systemctl edit sshd":             "edit verb",
		"systemctl --no-pager":            "no verb",
		"systemctl":                       "bare binary",
		"journalctl -u sshd":              "other binary",
		"/usr/bin/systemctl status sshd":  "absolute argv0",
		"docker run alpine":               "docker write verb",
		"docker exec web id":              "docker exec",
		"docker logs -f web":              "follow flag",
		"docker stats":                    "stats without --no-stream",
		"docker ps -aq":                   "bundled short flags",
		"systemctl status -n":             "value flag without value",
		"systemctl status -n --all":       "value flag followed by a flag",
		"systemctl status --full=yes":     "inline value on a boolean flag",
		"systemctl status --root=/x sshd": "offline-root flag",
		"systemctl status --user":         "unlisted flag",
		// Daemon-redirecting flags, in every spelling.
		"systemctl -H root@evil status sshd": "-H before verb",
		"systemctl status -H root@evil sshd": "-H",
		"systemctl status --host=evil sshd":  "--host=",
		"systemctl status --host evil":       "--host",
		"systemctl status -M box sshd":       "-M",
		"systemctl status --machine=box":     "--machine",
		"docker ps -H tcp://evil:2375":       "docker -H",
		"docker ps --host=tcp://evil:2375":   "docker --host",
		"docker ps --context evil":           "docker --context",
		"docker ps -c evil":                  "docker -c",
		"docker -H tcp://evil:2375 ps":       "global -H before verb",
	}
	for cmd, why := range noMatch {
		if got, ok := lane2Argv(cmd); ok {
			t.Errorf("lane2Argv(%q) [%s] = %q, want no match", cmd, why, got)
		}
	}
}

// TestLane2DockerConfigCannotExist: the docker CLI's config dir is pinned to a
// path no one can create, so no config.json (context switch, CLI hooks) and no
// user cli-plugins/ dir can ever be read by a Lane-2 docker read.
func TestLane2DockerConfigCannotExist(t *testing.T) {
	if !slices.Contains(lane2Env, "DOCKER_CONFIG="+lane2NoDockerConfig) {
		t.Fatalf("lane2Env = %q does not pin DOCKER_CONFIG", lane2Env)
	}
	if _, err := os.Stat(lane2NoDockerConfig); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("stat %s: %v, want not-exist", lane2NoDockerConfig, err)
	}
	if err := os.Mkdir(lane2NoDockerConfig, 0o700); err == nil {
		_ = os.Remove(lane2NoDockerConfig)
		t.Fatalf("created %s; the pinned docker config dir must be uncreatable", lane2NoDockerConfig)
	}
}

// TestLane2BinaryAbsentFallsThrough: an allowlisted command whose binary is not
// in the fixed directories is not a Lane-2 match (it never falls back to $PATH).
func TestLane2BinaryAbsentFallsThrough(t *testing.T) {
	prev := lane2BinDirs
	lane2BinDirs = []string{t.TempDir()}
	t.Cleanup(func() { lane2BinDirs = prev })
	t.Setenv("PATH", "/usr/bin:/bin")
	if got, ok := lane2Argv("systemctl status sshd"); ok {
		t.Fatalf("matched %q with no binary in the fixed dirs", got)
	}
}

// TestRunLane2ExecShellFreeClosedEnv drives run() end to end: an exact Lane-2
// read execs the fixed binary directly (no /bin/sh), with the closed four-var
// environment — a planted DOCKER_HOST/DOCKER_TLS_VERIFY and every other
// inherited variable are absent — and /dev/null stdin, and is audited as lane2.
func TestRunLane2ExecShellFreeClosedEnv(t *testing.T) {
	bin := withLane2Bins(t)
	for _, kv := range [][2]string{
		{"DOCKER_HOST", "tcp://attacker.invalid:2375"},
		{"DOCKER_TLS_VERIFY", "0"},
		{"DOCKER_CONFIG", "/nonexistent"},
		{"SYSTEMD_PAGER", "sh -c id"},
		{"PAGER", "sh -c id"},
		{"LC_PLANTED", "x"},
	} {
		t.Setenv(kv[0], kv[1])
	}
	self, _ := os.Executable()
	self, _ = filepath.EvalSymlinks(self)

	for _, tc := range []struct {
		cmd      string
		approval string
		wantArgs []string
	}{
		{"docker ps -a", "unsigned", []string{filepath.Join(bin, "docker"), "ps", "-a"}},
		{"systemctl status sshd", "unsigned", []string{filepath.Join(bin, "systemctl"), "--no-pager", "status", "sshd"}},
	} {
		t.Run(tc.cmd, func(t *testing.T) {
			dir := t.TempDir() // no gate.pub: Tier-1 unsigned read
			withGateDir(t, dir)
			code, out, stderr := runWith(t, tc.cmd)
			if code != exitOK {
				t.Fatalf("exit = %d, stderr = %q", code, stderr)
			}
			var rep execReport
			if err := json.Unmarshal([]byte(out), &rep); err != nil {
				t.Fatalf("child report %q: %v", out, err)
			}
			if rep.Path != self {
				t.Errorf("exec'd %q, want the fixed binary (-> %q)", rep.Path, self)
			}
			if !reflect.DeepEqual(rep.Args, tc.wantArgs) {
				t.Errorf("argv = %q, want %q (exact, shell-free)", rep.Args, tc.wantArgs)
			}
			if !reflect.DeepEqual(rep.Env, lane2Env) {
				t.Errorf("child env = %q, want exactly %q", rep.Env, lane2Env)
			}
			for _, kv := range rep.Env {
				if strings.HasPrefix(kv, "DOCKER_") && kv != "DOCKER_CONFIG="+lane2NoDockerConfig {
					t.Errorf("planted %s reached the Lane-2 child", kv)
				}
			}
			if !rep.StdinIsNul {
				t.Errorf("Lane-2 child stdin is not /dev/null")
			}
			recs := auditRecords(t, dir)
			if len(recs) != 1 || recs[0]["rung"] != "lane2" || recs[0]["classification"] != "read" ||
				recs[0]["approval_status"] != tc.approval {
				t.Errorf("audit = %v, want one read/%s record with rung lane2", recs, tc.approval)
			}
		})
	}
}

// TestRunLane2SignedRead: Lane 2 is also consulted on the signed read path.
func TestRunLane2SignedRead(t *testing.T) {
	bin := withLane2Bins(t)
	dir := t.TempDir()
	pub, priv := genKey(t)
	seedPub(t, dir, pub, 0o644)
	withGateDir(t, dir)

	code, out, stderr := runWith(t, signedLine(t, priv, freshPayload("docker ps")))
	if code != exitOK {
		t.Fatalf("exit = %d, stderr = %q", code, stderr)
	}
	var rep execReport
	if err := json.Unmarshal([]byte(out), &rep); err != nil {
		t.Fatalf("child report %q: %v", out, err)
	}
	if want := []string{filepath.Join(bin, "docker"), "ps"}; !reflect.DeepEqual(rep.Args, want) {
		t.Errorf("argv = %q, want %q", rep.Args, want)
	}
	recs := auditRecords(t, dir)
	if len(recs) != 1 || recs[0]["rung"] != "lane2" || recs[0]["approval_status"] != "signed" {
		t.Errorf("audit = %v, want one signed record with rung lane2", recs)
	}
}

// TestRunLane2OutputRedacted: Lane 2 runs unjailed and its verbs (docker logs and
// inspect, systemctl show and cat) can print secrets, so its output must pass
// the gate's production redactor exactly like a jailed read's.
func TestRunLane2OutputRedacted(t *testing.T) {
	withLane2Bins(t)
	redactRules = nil // the production ruleset; withLane2Bins restores the seam
	dir := t.TempDir()
	withGateDir(t, dir)

	code, out, stderr := runWith(t, "docker logs "+lane2SecretArg)
	if code != exitOK {
		t.Fatalf("exit = %d, stderr = %q", code, stderr)
	}
	if strings.Contains(out, lane2PlantedSecret) || !strings.Contains(out, redact.MarkerPrefix) {
		t.Errorf("Lane-2 stdout = %q; want the planted secret replaced by a redaction marker", out)
	}
	recs := auditRecords(t, dir)
	if len(recs) != 1 || recs[0]["rung"] != "lane2" {
		t.Errorf("audit = %v, want one lane2 record", recs)
	}
}
