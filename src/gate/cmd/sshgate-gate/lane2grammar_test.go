package main

import (
	"reflect"
	"strings"
	"testing"
)

// lane2Golden maps accepted agent lines to their canonical argv after the
// name: the prefix, the verb, the flags in grammar order and the positionals.
var lane2Golden = map[string][]string{
	// The P3.0 matrix lines.
	"docker version":                           {"--host=unix:///run/docker.sock", "version"},
	"docker ps":                                {"--host=unix:///run/docker.sock", "ps"},
	"docker ps -a --no-trunc":                  {"--host=unix:///run/docker.sock", "ps", "--all", "--no-trunc"},
	"docker ps -s":                             {"--host=unix:///run/docker.sock", "ps", "--size"},
	"docker ps -q --filter name=p30":           {"--host=unix:///run/docker.sock", "ps", "--quiet", "--filter=name=p30"},
	"docker inspect p30":                       {"--host=unix:///run/docker.sock", "inspect", "p30"},
	"docker inspect -s p30":                    {"--host=unix:///run/docker.sock", "inspect", "--size", "p30"},
	"docker inspect --type image busybox:1.36": {"--host=unix:///run/docker.sock", "inspect", "--type=image", "busybox:1.36"},
	"docker logs p30":                          {"--host=unix:///run/docker.sock", "logs", "p30"},
	"docker logs -t --tail 2 p30":              {"--host=unix:///run/docker.sock", "logs", "--timestamps", "--tail=2", "p30"},
	"docker images":                            {"--host=unix:///run/docker.sock", "images"},
	"docker images -a --digests --no-trunc":    {"--host=unix:///run/docker.sock", "images", "--all", "--no-trunc", "--digests"},
	"docker stats --no-stream":                 {"--host=unix:///run/docker.sock", "stats", "--no-stream"},
	"docker stats --no-stream -a --no-trunc":   {"--host=unix:///run/docker.sock", "stats", "--no-stream", "--all", "--no-trunc"},
	"docker top p30":                           {"--host=unix:///run/docker.sock", "top", "p30"},
	"systemctl status docker.service":          {"--no-pager", "--no-ask-password", "status", "docker.service"},
	"systemctl status ssh.service -n 5":        {"--no-pager", "--no-ask-password", "status", "--lines=5", "ssh.service"},
	"systemctl status":                         {"--no-pager", "--no-ask-password", "status"},
	"systemctl is-active docker.service":       {"--no-pager", "--no-ask-password", "is-active", "docker.service"},
	"systemctl is-failed docker.service":       {"--no-pager", "--no-ask-password", "is-failed", "docker.service"},
	"systemctl list-units":                     {"--no-pager", "--no-ask-password", "list-units"},
	"systemctl list-units --type=service --all --plain --no-legend": {"--no-pager", "--no-ask-password", "list-units", "--all", "--no-legend", "--plain", "--type=service"},
	"systemctl list-unit-files":                                     {"--no-pager", "--no-ask-password", "list-unit-files"},
	"systemctl show docker.service":                                 {"--no-pager", "--no-ask-password", "show", "docker.service"},
	"systemctl show -p MainPID --value docker.service":              {"--no-pager", "--no-ask-password", "show", "--property=MainPID", "--value", "docker.service"},
	"systemctl cat docker.service":                                  {"--no-pager", "--no-ask-password", "cat", "docker.service"},
	"systemctl get-default":                                         {"--no-pager", "--no-ask-password", "get-default"},
	// Every other flag, spelling and verb.
	"systemctl status --no-pager --no-ask-password --system -q -l -a --no-legend --plain a b": {"--no-pager", "--no-ask-password", "status", "--full", "--all", "--no-legend", "--plain", "--quiet", "a", "b"},
	"systemctl list-unit-files -t timer --state enabled":                                      {"--no-pager", "--no-ask-password", "list-unit-files", "--type=timer", "--state=enabled"},
	"systemctl list-units --state=failed sshd.service":                                        {"--no-pager", "--no-ask-password", "list-units", "--state=failed", "sshd.service"},
	"systemctl show --property=A,B,C 1234":                                                    {"--no-pager", "--no-ask-password", "show", "--property=A,B,C", "1234"},
	"systemctl status --lines=0 /dev/sda":                                                     {"--no-pager", "--no-ask-password", "status", "--lines=0", "/dev/sda"},
	"systemctl cat getty@tty1.service":                                                        {"--no-pager", "--no-ask-password", "cat", "getty@tty1.service"},
	"docker ps -l -n 3 -f status=running --format table":                                      {"--host=unix:///run/docker.sock", "ps", "--latest", "--last=3", "--filter=status=running", "--format=table"},
	"docker ps --format=json":                                                                 {"--host=unix:///run/docker.sock", "ps", "--format={{json .}}"},
	"docker inspect -f json --type=volume a b":                                                {"--host=unix:///run/docker.sock", "inspect", "--format={{json .}}", "--type=volume", "a", "b"},
	"docker logs --details -n all --since 2026-10-15 --until 2026-10-15T00:00:00-05:00 web":   {"--host=unix:///run/docker.sock", "logs", "--details", "--tail=all", "--since=2026-10-15", "--until=2026-10-15T00:00:00-05:00", "web"},
	"docker logs --since 2026-10-15T00:00:00Z --until 2026-10-15T00:00:00+05:30 web":          {"--host=unix:///run/docker.sock", "logs", "--since=2026-10-15T00:00:00Z", "--until=2026-10-15T00:00:00+05:30", "web"},
	"docker logs --since=10m web":                                                             {"--host=unix:///run/docker.sock", "logs", "--since=10m", "web"},
	"docker images -q -f dangling=true --format json alpine":                                  {"--host=unix:///run/docker.sock", "images", "--quiet", "--filter=dangling=true", "--format={{json .}}", "alpine"},
	"docker version -f json":                                                                  {"--host=unix:///run/docker.sock", "version", "--format={{json .}}"},
	"docker stats --format json --no-stream web db":                                           {"--host=unix:///run/docker.sock", "stats", "--no-stream", "--format={{json .}}", "web", "db"},
	"docker inspect sha256:0123abcd":                                                          {"--host=unix:///run/docker.sock", "inspect", "sha256:0123abcd"},
}

// lane2Unlisted are lines refused only because a token is outside the
// grammar: the P-L2-GRAMMAR mutation admits each.
var lane2Unlisted = []string{
	"systemctl status --x", "systemctl status --x=v", "systemctl status --x v",
	"systemctl show --sg-unlisted unit", "systemctl status -aq", "systemctl status -n5",
	"systemctl status --", "systemctl status --type=service", "systemctl is-active --lines=5",
	"systemctl get-default --property=A", "docker ps -aq", "docker ps --follow",
	"docker top --all web", "docker logs --follow web", "docker version --size",
	"docker stats --no-stream --stream", "docker images --tree", "docker inspect --x=v web",
	"systemctl status -x", "systemctl status -",
}

// lane2Refused are lines refused whatever the grammar mutation does.
var lane2Refused = []string{
	"systemctl is-enabled sshd", "docker info", "docker info --format json", "systemctl restart sshd",
	"systemctl status -a --all", "systemctl status -q -q", "docker ps --format json --format table",
	"systemctl --no-pager --no-pager status", "docker logs web db", "docker logs", "docker top",
	"docker top web aux", "docker ps web", "systemctl cat", "systemctl get-default unit",
	"docker stats", "docker stats -a", "systemctl status -n", "systemctl status -n --all",
	"systemctl status --full=yes", "systemctl status -n=5", "systemctl status --lines=-5",
	"systemctl status --lines=05", "systemctl status --lines=10001", "systemctl status --lines=+5",
	"docker ps --last 1001", "docker logs --tail 1000001 web", "docker logs --tail -5 web",
	"docker logs --since -10m web", "docker logs --since now web", "docker logs --since=: web",
	"docker ps --format xml", "docker inspect --format table web", "docker ps --filter foo=bar",
	"docker ps --filter name", "docker images --filter name=x", "docker inspect --type=plugin web",
	"systemctl list-units --type=service,socket", "systemctl list-units --type=bogus",
	"systemctl list-units --state=a,b", "systemctl list-units --state=Failed", "systemctl show -p A,,B",
	"systemctl show -p A-B", "docker ps --filter name=a=b,c",
	"systemctl status " + strings.Repeat("u", lane2MaxValue+1), "systemctl status a=b", "systemctl status a,b",
	"systemctl status a+b", "docker logs --since " + strings.Repeat("1", lane2MaxValue+1) + " web",
}

// lane2RedirectSpellings are every spelling of every refused flag, with a
// value inline, as the next token, and attached to a short flag.
func lane2RedirectSpellings() []string {
	var spellings []string
	for _, flag := range lane2RedirectFlags {
		spellings = append(spellings, flag, flag+"=x")
		if !strings.HasPrefix(flag, "--") {
			spellings = append(spellings, flag+"x")
		}
	}
	return append(spellings, "--us", "--mach=box", "--ho", "--cont", "--glob", "--ro=/x", "--im")
}

// testLane2Grammar is U-Lane2Grammar: the parse admits exactly the grammar.
func testLane2Grammar(t *testing.T) {
	p := newProof(t, "U-Lane2Grammar")
	accepted := true
	for line, want := range lane2Golden {
		call, ok := lane2Parse(line)
		accepted = accepted && ok
		if !ok {
			t.Errorf("lane2Parse(%q) refused a grammar line", line)
			continue
		}
		if got := call.render("/fixed/"+call.client, "/run/docker.sock")[1:]; !reflect.DeepEqual(got, want) {
			t.Errorf("render(%q) = %q, want %q", line, got, want)
		}
		again, ok := lane2Parse(call.canonicalLine())
		if !ok || !reflect.DeepEqual(again, call) {
			t.Errorf("canonical line %q of %q does not parse back", call.canonicalLine(), line)
		}
	}
	for _, line := range lane2Refused {
		if _, ok := lane2Parse(line); ok {
			t.Errorf("lane2Parse(%q) admitted a line outside the grammar", line)
		}
	}
	for client, grammar := range lane2Grammar {
		for verb := range grammar.verbs {
			for _, spelling := range append(lane2RedirectSpellings(), "-H x", "--host x", "--user x", "-c x") {
				line := client + " " + verb + " " + spelling + " web"
				if _, ok := lane2Parse(line); ok {
					t.Errorf("lane2Parse(%q) admitted a redirect flag", line)
				}
			}
		}
	}
	admitted := false
	for _, line := range lane2Unlisted {
		_, ok := lane2Parse(line)
		admitted = admitted || ok
	}
	p.Effect("decision", admitted)
	p.Control("decision", accepted)
	p.Finish()
}

// testLane2RedirectList is U-Lane2RedirectList: the refusal list names every
// spelling of every redirect flag, and no grammar flag.
func testLane2RedirectList(t *testing.T) {
	p := newProof(t, "U-Lane2RedirectList")
	missed := false
	for _, spelling := range lane2RedirectSpellings() {
		missed = missed || !lane2Redirect(spelling)
	}
	clean := true
	for _, grammar := range lane2Grammar {
		for _, verb := range grammar.verbs {
			for _, flag := range verb.flags {
				for _, spelling := range append([]string{flag.long, flag.long + "=v"}, flag.aliases...) {
					clean = clean && !lane2Redirect(spelling)
				}
			}
		}
		for _, dropped := range grammar.dropped {
			clean = clean && !lane2Redirect(dropped)
		}
	}
	clean = clean && !lane2Redirect("--hostname") && !lane2Redirect("--users")
	p.Effect("decision", missed)
	p.Control("decision", clean)
	p.Finish()
}

// TestPhase3Tables holds the daemon-read decision tables, once per ABI name
// like the gate's other proof legs.
func TestPhase3Tables(t *testing.T) {
	for _, abi := range []string{"native", "abi1"} {
		t.Run(abi, func(t *testing.T) {
			t.Run("U-Lane2Grammar", testLane2Grammar)
			t.Run("U-Lane2RedirectList", testLane2RedirectList)
			t.Run("U-Lane2ELFSearchTags", testLane2ELFSearchTags)
		})
	}
}

// lane2LongLine pads prefix with positionals of at most lane2MaxValue bytes
// to exactly size bytes.
func lane2LongLine(t *testing.T, prefix string, size int) string {
	t.Helper()
	line := prefix
	for len(line) < size {
		n := min(size-len(line)-1, lane2MaxValue)
		if n < 1 {
			t.Fatalf("SETUP: cannot pad %q to %d bytes", prefix, size)
		}
		line += " " + strings.Repeat("u", n)
	}
	return line
}

func TestLane2LengthBounds(t *testing.T) {
	plain := lane2LongLine(t, "systemctl status --quiet", lane2MaxLine)
	expanding := lane2LongLine(t, "systemctl status -q -l -a -n 1", lane2MaxLine)
	short := "systemctl status -q"
	canonical1024 := lane2LongLine(t, short, lane2MaxLine-len("--quiet")+len("-q"))
	canonical1025 := lane2LongLine(t, short, lane2MaxLine+1-len("--quiet")+len("-q"))
	for _, tc := range []struct {
		name, line string
		want       bool
	}{
		{"1024-byte line", plain, true},
		{"1025-byte line", plain + "u", false},
		{"1024-byte line, 1041-byte canonical line", expanding, false},
		{"canonical line of exactly 1024 bytes", canonical1024, true},
		{"canonical line of 1025 bytes", canonical1025, false},
		{"33 tokens", "systemctl status" + strings.Repeat(" u", 31), false},
		{"128-byte value", "docker logs --since " + strings.Repeat("1", lane2MaxValue) + " web", true},
	} {
		call, ok := lane2Parse(tc.line)
		if ok != tc.want {
			t.Errorf("%s: lane2Parse ok = %v, want %v", tc.name, ok, tc.want)
		}
		if ok && len(call.canonicalLine()) > lane2MaxLine {
			t.Errorf("%s: canonical line is %d bytes", tc.name, len(call.canonicalLine()))
		}
	}
}

// FuzzLane2Parse: the parse is total; an accepted line's canonical line fits,
// parses back to the same call and renders the same argv; and every rendered
// token is a grammar token, never a refused flag.
func FuzzLane2Parse(f *testing.F) {
	for line := range lane2Golden {
		f.Add(line)
	}
	for _, line := range append(append(lane2Unlisted, lane2Refused...), lane2RedirectSpellings()...) {
		f.Add(line)
		f.Add("systemctl status " + line)
	}
	for b := 0; b < 256; b++ {
		f.Add("docker logs web" + string([]byte{byte(b)}))
		f.Add("systemctl status -q u" + string([]byte{byte(b)}))
	}
	f.Add("systemctl status" + strings.Repeat(" u", 30))
	f.Add("systemctl status" + strings.Repeat(" u", 31))
	f.Add("docker logs --since -10m web")
	f.Add("systemctl status -q -l -a -n 1 " + strings.Repeat("u", lane2MaxValue))
	f.Fuzz(func(t *testing.T, line string) {
		call, ok := lane2Parse(line)
		if !ok {
			return
		}
		canonical := call.canonicalLine()
		if len(canonical) > lane2MaxLine {
			t.Fatalf("canonical line of %q is %d bytes", line, len(canonical))
		}
		again, ok := lane2Parse(canonical)
		if !ok || !reflect.DeepEqual(again, call) || again.canonicalLine() != canonical {
			t.Fatalf("canonical line %q of %q does not parse back to the same call", canonical, line)
		}
		name := "/usr/bin/" + call.client
		argv := call.render(name, "/run/docker.sock")
		if !reflect.DeepEqual(again.render(name, "/run/docker.sock"), argv) {
			t.Fatalf("argv of %q is not idempotent", line)
		}
		grammar := lane2Grammar[call.client]
		tokens := argv[1+len(call.prefix("/run/docker.sock")):]
		if tokens[0] != call.verb {
			t.Fatalf("argv %q does not start with the verb", argv)
		}
		verb := grammar.verbs[call.verb]
		for _, token := range tokens[1:] {
			if lane2Redirect(token) || !lane2RenderedToken(verb, token) {
				t.Fatalf("argv %q of %q carries %q", argv, line, token)
			}
		}
	})
}

// lane2RenderedToken: token is a canonical flag spelling, with a value of its
// type or the gate's json template, or a positional of the verb's type.
func lane2RenderedToken(verb lane2Verb, token string) bool {
	if !strings.HasPrefix(token, "-") {
		return lane2ValueBounds(token) && verb.positional(token)
	}
	name, value, hasValue := strings.Cut(token, "=")
	flag := verb.flag(name)
	switch {
	case flag == nil || flag.long != name || hasValue != (flag.value != nil):
		return false
	case !hasValue:
		return true
	case name == "--format" && value == lane2JSONTemplate:
		return flag.value("json")
	case name == "--format" && value == "json":
		return false
	}
	return lane2ValueBounds(value) && flag.value(value)
}
