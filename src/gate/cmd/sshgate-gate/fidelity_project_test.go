package main

import (
	"encoding/json"
	"slices"
	"strings"
	"testing"
)

// The daemon-read fidelity projections (TestFidelitySmokeDaemonRead, jail_e2e)
// live untagged so ordinary make test checks them.

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

// projectDockerPs keeps each container's ID, names and image, sorted. No
// output is no containers: an empty result set.
func projectDockerPs(out string) string {
	if strings.TrimSpace(out) == "" {
		return ""
	}
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

// TestProjectDockerPs: empty output is an empty result set; every nonempty
// record must parse.
func TestProjectDockerPs(t *testing.T) {
	for out, want := range map[string]string{
		"":   "",
		"\n": "",
		`{"ID":"b","Names":"n2","Image":"i"}` + "\n" + `{"ID":"a","Names":"n1","Image":"i"}` + "\n": "a n1 i\nb n2 i",
		`{"ID":"a","Names":"n1","Image":"i"}` + "\nnot json\n":                                      "a n1 i\nunparsed:not json",
		`{"ID":"a","Names":"n1","Image":"i"}` + "\n\n" + `{"ID":"b","Names":"n2","Image":"i"}`:      "a n1 i\nb n2 i\nunparsed:",
	} {
		if got := projectDockerPs(out); got != want {
			t.Errorf("projectDockerPs(%q) = %q, want %q", out, got, want)
		}
	}
}
