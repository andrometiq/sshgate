package main

import (
	"os"
	"path/filepath"
	"strings"
)

// Lane 2 is the exact daemon-read allowlist: a few systemctl and docker read
// verbs that must talk to a local daemon over AF_UNIX, which the read jail
// denies. A match runs SHELL-FREE and UNJAILED, so the door is deliberately
// narrow: an allowlisted binary from a fixed directory (never $PATH), an
// allowlisted verb, allowlisted flags, a closed environment built from scratch
// and /dev/null stdin. Anything that is not an exact match is not Lane 2 and
// takes the normal (jailed) read path. docker.sock is root-equivalent, so every
// new entry here is review-gated.

// lane2Flag describes one allowlisted flag spelling.
type lane2Flag struct {
	takesValue bool
}

// lane2Verb is one allowlisted verb with its flag allowlist. required lists
// flags that must be present (docker stats must not stream forever).
type lane2Verb struct {
	flags    map[string]lane2Flag
	required []string
}

var (
	noVal = lane2Flag{}
	val   = lane2Flag{takesValue: true}
)

// systemctlFlags are display-only options shared by every allowlisted
// systemctl verb.
var systemctlFlags = map[string]lane2Flag{
	"--no-pager": noVal, "-l": noVal, "--full": noVal, "-a": noVal, "--all": noVal,
	"--no-legend": noVal, "--plain": noVal, "--value": noVal, "-q": noVal, "--quiet": noVal,
	"-t": val, "--type": val, "--state": val, "-n": val, "--lines": val, "-p": val, "--property": val,
}

func systemctlVerb() lane2Verb { return lane2Verb{flags: systemctlFlags} }

// lane2Allow is the full allowlist: binary name -> verb -> flags.
var lane2Allow = map[string]map[string]lane2Verb{
	"systemctl": {
		"status": systemctlVerb(), "is-active": systemctlVerb(), "is-enabled": systemctlVerb(),
		"is-failed": systemctlVerb(), "list-units": systemctlVerb(), "list-unit-files": systemctlVerb(),
		"show": systemctlVerb(), "cat": systemctlVerb(), "get-default": systemctlVerb(),
	},
	"docker": {
		"ps": {flags: map[string]lane2Flag{
			"-a": noVal, "--all": noVal, "-q": noVal, "--quiet": noVal, "--no-trunc": noVal,
			"-l": noVal, "--latest": noVal, "-s": noVal, "--size": noVal,
			"-n": val, "--last": val, "-f": val, "--filter": val, "--format": val,
		}},
		"inspect": {flags: map[string]lane2Flag{
			"-s": noVal, "--size": noVal, "-f": val, "--format": val, "--type": val,
		}},
		"logs": {flags: map[string]lane2Flag{
			"-t": noVal, "--timestamps": noVal, "--details": noVal,
			"-n": val, "--tail": val, "--since": val, "--until": val,
		}},
		"images": {flags: map[string]lane2Flag{
			"-a": noVal, "--all": noVal, "-q": noVal, "--quiet": noVal, "--no-trunc": noVal,
			"--digests": noVal, "-f": val, "--filter": val, "--format": val,
		}},
		"version": {flags: map[string]lane2Flag{"-f": val, "--format": val}},
		"info":    {flags: map[string]lane2Flag{"-f": val, "--format": val}},
		"stats": {flags: map[string]lane2Flag{
			"--no-stream": noVal, "-a": noVal, "--all": noVal, "--no-trunc": noVal, "--format": val,
		}, required: []string{"--no-stream"}},
		"top": {flags: map[string]lane2Flag{}},
	},
}

// lane2DaemonRedirect are flags that point the client at a different daemon or
// machine. None is on any allowlist; they are named here so the refusal is
// explicit and does not hinge on a table never gaining them.
var lane2DaemonRedirect = map[string]bool{
	"-H": true, "--host": true, "-M": true, "--machine": true, "--context": true, "-c": true,
}

// lane2BinDirs is the fixed search list for an allowlisted binary. It is a var
// only so tests can point it at a fake binary; it is never derived from $PATH
// or any other environment.
var lane2BinDirs = []string{"/usr/bin", "/bin", "/usr/sbin"}

// lane2Env is the child's entire environment. It is built from nothing, so no
// inherited DOCKER_*, SYSTEMD_*, PAGER, LC_* or SSH-injected variable reaches a
// client that talks to a root-equivalent daemon.
//
// DOCKER_CONFIG is pinned to lane2NoDockerConfig so the docker CLI never reads
// the gate user's ~/.docker: a config.json there could switch the endpoint
// (currentContext), add CLI hooks, or put plugin binaries in cli-plugins/ that
// `docker info` would run.
var lane2Env = []string{"PATH=/usr/bin:/bin", "LANG=C", "SYSTEMD_COLORS=0", "TERM=dumb", "DOCKER_CONFIG=" + lane2NoDockerConfig}

// lane2NoDockerConfig is a directory that cannot exist: procfs refuses to
// create entries, even for root. The docker CLI treats a missing config dir as
// "defaults": the local daemon socket, no hooks, system plugin dirs only.
const lane2NoDockerConfig = "/proc/sshgate-no-docker-config"

// lane2Argv returns the exact argv to exec for cmd, or ok=false when cmd is not
// a Lane-2 match (it then takes the normal read path). argv[0] is the absolute
// binary path.
func lane2Argv(cmd string) (argv []string, ok bool) {
	toks, ok := lane2Tokens(cmd)
	if !ok || len(toks) < 2 {
		return nil, false
	}
	verbs, ok := lane2Allow[toks[0]]
	if !ok {
		return nil, false
	}
	verb, ok := verbs[toks[1]]
	if !ok || !lane2ArgsAllowed(verb, toks[2:]) {
		return nil, false
	}
	bin, ok := lane2Binary(toks[0])
	if !ok {
		return nil, false
	}
	argv = []string{bin}
	if toks[0] == "systemctl" {
		// Forced, even when the caller passed it: a pager would read the
		// gate's stdin-less terminal and the env has no PAGER to honour anyway.
		argv = append(argv, "--no-pager")
	}
	return append(argv, toks[1:]...), true
}

// lane2Tokens splits cmd on spaces and tabs. Every byte of every token must be
// in a small positive charset, so any shell syntax at all (quotes, $, `, ;, |,
// &, <, >, globs, ~, #, \, braces, newlines) makes cmd not a Lane-2 candidate:
// Lane 2 only ever runs commands whose meaning is the same with or without sh.
func lane2Tokens(cmd string) ([]string, bool) {
	for i := 0; i < len(cmd); i++ {
		b := cmd[i]
		if b == ' ' || b == '\t' || lane2TokenByte(b) {
			continue
		}
		return nil, false
	}
	return strings.FieldsFunc(cmd, func(r rune) bool { return r == ' ' || r == '\t' }), true
}

func lane2TokenByte(b byte) bool {
	switch {
	case b >= 'a' && b <= 'z', b >= 'A' && b <= 'Z', b >= '0' && b <= '9':
		return true
	}
	return strings.IndexByte("._-:@/=,+", b) >= 0
}

// lane2ArgsAllowed checks every argument after the verb: a token starting with
// '-' must be an allowlisted flag (as "--flag", "--flag=value" or "--flag
// value"); anything else is a positional (a unit or container name).
func lane2ArgsAllowed(verb lane2Verb, args []string) bool {
	seen := map[string]bool{}
	for i := 0; i < len(args); i++ {
		a := args[i]
		if !strings.HasPrefix(a, "-") {
			continue
		}
		name, _, hasInline := strings.Cut(a, "=")
		if lane2DaemonRedirect[name] {
			return false
		}
		f, ok := verb.flags[name]
		if !ok {
			return false
		}
		switch {
		case hasInline && !f.takesValue:
			return false
		case f.takesValue && !hasInline:
			// The value is the next token and must not itself look like a flag.
			if i+1 >= len(args) || strings.HasPrefix(args[i+1], "-") {
				return false
			}
			i++
		}
		seen[name] = true
	}
	for _, r := range verb.required {
		if !seen[r] {
			return false
		}
	}
	return true
}

// lane2Binary resolves name to an executable regular file in lane2BinDirs.
func lane2Binary(name string) (string, bool) {
	for _, dir := range lane2BinDirs {
		p := filepath.Join(dir, name)
		fi, err := os.Stat(p)
		if err == nil && fi.Mode().IsRegular() && fi.Mode().Perm()&0o111 != 0 {
			return p, true
		}
	}
	return "", false
}
