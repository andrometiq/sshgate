//go:build linux && jail_e2e

package main

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"slices"
	"strings"
	"testing"

	"github.com/karthikeyan5/sshgate/src/gate/confine"
	"github.com/karthikeyan5/sshgate/src/redact"
)

// TestFidelitySmokeDaemonRead: the installed systemctl and docker give the same
// answer in their jail as unjailed (the forced-Absent fallback), at the native
// Landlock ABI and at ABI 1. Rows whose raw output carries live state are
// compared through a projection of the fields that must agree: status's
// memory, CPU and task counters move between runs; docker's JSON is projected
// to fields every CLI since 20.10 prints.
func TestFidelitySmokeDaemonRead(t *testing.T) {
	requireJail(t)
	if _, err := os.Stat("/usr/bin/docker"); err != nil {
		t.Fatalf("SETUP: docker client missing: %v", err)
	}
	if output, err := exec.Command("/usr/bin/docker", "--host=unix:///run/docker.sock", "version").CombinedOutput(); err != nil {
		t.Fatalf("SETUP: docker server unreachable unjailed: %v: %s", err, output)
	}
	previous := redactRules
	redactRules = []redact.Rule{} // compare the clients' own bytes
	t.Cleanup(func() { redactRules = previous })
	for _, abi := range []string{"native", "abi1"} {
		for _, row := range []struct {
			line    string
			project func(string) string
		}{
			{"systemctl status --lines=0 systemd-journald.service", projectStatus},
			{"systemctl show --property=Id,LoadState,ActiveState,UnitFileState systemd-journald.service", func(out string) string { return out }},
			{"docker ps --no-trunc --format json", projectDockerPs},
			{"docker version --format json", projectDockerVersion},
		} {
			t.Run(abi+"/"+row.line, func(t *testing.T) {
				jailed := daemonReadRun(t, row.line, func(spec *confine.Spec) {
					if abi == "abi1" {
						spec.ForceABI = 1
					}
				}, "ro-v1")
				fallback := daemonReadRun(t, row.line, func(spec *confine.Spec) { spec.ForceABI = confine.ForceNoLandlock }, "")
				got, want := row.project(jailed.out)+jailed.exit, row.project(fallback.out)+fallback.exit
				if strings.Contains(got+want, "unparsed:") {
					t.Fatalf("output did not parse: jailed %q, unjailed %q", jailed.out, fallback.out)
				}
				if got != want {
					t.Errorf("jailed %q\nunjailed %q", got, want)
				}
			})
		}
	}
}

type daemonReadResult struct{ out, exit string }

// daemonReadRun runs line through the gate with the Spec change and requires
// the audit to say how it ran: in the jail (profile ro-v1) or as the fallback.
func daemonReadRun(t *testing.T, line string, change func(*confine.Spec), profile string) daemonReadResult {
	t.Helper()
	dir := t.TempDir()
	withGateDir(t, dir)
	previous := readSpecHook
	readSpecHook = change
	defer func() { readSpecHook = previous }()
	code, out, stderr := runWith(t, line)
	records := auditRecords(t, dir)
	if len(records) != 1 || records[0]["enforcement"] != "daemon-read" || (records[0]["profile"] == "ro-v1") != (profile == "ro-v1") {
		t.Fatalf("%q ran as %v (stderr %q), want profile %q", line, records, stderr, profile)
	}
	return daemonReadResult{out, fmt.Sprintf(" exit=%d", code)}
}

// projectStatus keeps status's first line, its Loaded: line and its Active:
// state word.
func projectStatus(out string) string {
	lines := strings.Split(out, "\n")
	projected := []string{lines[0]}
	for _, line := range lines {
		fields := strings.Fields(line)
		switch {
		case len(fields) > 0 && fields[0] == "Loaded:":
			projected = append(projected, strings.TrimSpace(line))
		case len(fields) > 1 && fields[0] == "Active:":
			projected = append(projected, "Active: "+fields[1])
		}
	}
	return strings.Join(projected, "\n")
}

// projectDockerPs keeps each container's ID, names and image, sorted.
func projectDockerPs(out string) string {
	var rows []string
	for _, line := range strings.Split(strings.TrimSpace(out), "\n") {
		var container struct{ ID, Names, Image string }
		if line == "" || json.Unmarshal([]byte(line), &container) != nil {
			rows = append(rows, "unparsed:"+line)
			continue
		}
		rows = append(rows, container.ID+" "+container.Names+" "+container.Image)
	}
	slices.Sort(rows)
	return strings.Join(rows, "\n")
}

// projectDockerVersion keeps the client and server versions and the API
// version.
func projectDockerVersion(out string) string {
	var version struct {
		Client struct{ Version string }
		Server struct {
			Version    string
			APIVersion string `json:"ApiVersion"`
		}
	}
	if json.Unmarshal([]byte(out), &version) != nil || version.Server.APIVersion == "" {
		return "unparsed:" + out
	}
	return version.Client.Version + " " + version.Server.Version + " " + version.Server.APIVersion
}
