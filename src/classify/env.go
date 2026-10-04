package classify

import (
	"strings"
)

// dangerousEnvVars is the denylist of environment variable keys that
// known-allowlisted binaries will honor as shell-execution / loader /
// file-side-effect vectors. If any of these appears as a leading
// `KEY=VAL` prefix on a command, the whole command is classified WRITE
// regardless of head — the wrapped binary cannot be trusted to ignore
// the smuggled env. Cited in
// docs/security-readonly-bypass.md (BLOCKER-3).
var dangerousEnvVars = map[string]bool{
	"GIT_EXTERNAL_DIFF":   true,
	"GIT_SSH_COMMAND":     true,
	"GIT_SSH":             true,
	"GIT_PAGER":           true,
	"GIT_EDITOR":          true,
	"GIT_EXEC_PATH":       true,
	"GIT_TERMINAL_PROMPT": true,
	"LESSOPEN":            true,
	"LESSCLOSE":           true,
	"LESSEDIT":            true,
	"LD_PRELOAD":          true,
	"LD_LIBRARY_PATH":     true,
	"LD_AUDIT":            true,
	"IFS":                 true,
	"PATH":                true,
	"SHELL":               true,
	"BASH_ENV":            true,
	"ENV":                 true,
	"PYTHONSTARTUP":       true,
	"PYTHONPATH":          true,
	"PERL5OPT":            true,
	"PERL5LIB":            true,
	"RUBYOPT":             true,
	"RUBYLIB":             true,
	"MANPAGER":            true,
	"PAGER":               true, // many tools spawn this; safer to deny
	// HOME / XDG base-dir redirection: a leading `HOME=/attacker` (or any of
	// the XDG_*_HOME / XDG_CACHE/STATE/RUNTIME dirs) redirects a read-tool's
	// config/data/cache WRITE to an attacker-controlled path — e.g.
	// `HOME=/tmp/x top -bn1` makes top write its rc under /tmp/x, and the
	// same trick aims dotfile/history/cache writes of other allowlisted
	// tools at arbitrary locations. A leading assignment of any of these =>
	// WRITE (2026-06-15 rig hunt). Plain `top -bn1` (no prefix) stays READ.
	"HOME":            true,
	"XDG_CONFIG_HOME": true,
	"XDG_DATA_HOME":   true,
	"XDG_CACHE_HOME":  true,
	"XDG_STATE_HOME":  true,
	"XDG_RUNTIME_DIR": true,
	// Command-running hooks read from the environment by git and by the
	// pagers/editors read tools may spawn.
	"GIT_ASKPASS":       true,
	"SSH_ASKPASS":       true,
	"GIT_PROXY_COMMAND": true,
	"GIT_DIR":           true,
	"GIT_WORK_TREE":     true,
	"EDITOR":            true,
	"VISUAL":            true,
	"SYSTEMD_PAGER":     true,
	"SYSTEMD_EDITOR":    true,
}

// isDangerousEnvVar reports whether a leading KEY=VAL assignment makes the
// command a write. Every GIT_CONFIG* key is included: GIT_CONFIG_PARAMETERS
// and GIT_CONFIG_COUNT/KEY_n/VALUE_n inject arbitrary config (core.fsmonitor,
// diff.external, core.pager run commands), and GIT_CONFIG/_GLOBAL/_SYSTEM
// point git at another config file.
func isDangerousEnvVar(key string) bool {
	return dangerousEnvVars[key] || strings.HasPrefix(key, "GIT_CONFIG")
}

// envRule classifies `env` invocations. `env` is READ iff it is invoked
// with no args (prints the environment) or only with `KEY=VAL` assignments
// and no trailing wrapped command. The moment a non-assignment positional
// appears, `env` is acting as a wrapper — we recursively classify the
// wrapped command and apply the dangerous-env-var denylist to each
// assignment. Any `env` flag (`-i`, `-u`, `-S`, `--ignore-environment`,
// `--unset`, `--split-string`, `--chdir`, `--block-signal`, etc.) is
// treated as WRITE because each of them can smuggle execution or
// significantly change the wrapper's behavior. Cited as MAJOR-1 in
// docs/security-readonly-bypass.md.
func envRule(args []string) Kind {
	if len(args) == 0 {
		return KindRead
	}
	for i := 0; i < len(args); i++ {
		a := args[i]
		// Any env flag (short or long) is conservatively WRITE.
		if len(a) > 0 && a[0] == '-' && a != "--" {
			return KindWrite
		}
		// `--` end-of-options: everything after is the wrapped command.
		if a == "--" {
			rest := args[i+1:]
			if len(rest) == 0 {
				return KindRead
			}
			return classifyWrapped(rest)
		}
		// KEY=VAL assignment: deny dangerous keys, otherwise skip.
		if isAssignment(a) {
			key := a[:strings.IndexByte(a, '=')]
			if isDangerousEnvVar(key) {
				return KindWrite
			}
			continue
		}
		// First non-assignment positional: wrapped command + its args.
		return classifyWrapped(args[i:])
	}
	// All tokens were KEY=VAL assignments with no wrapped command.
	return KindRead
}

// classifyWrapped recursively classifies a wrapped command (the part of
// `env KEY=VAL cmd args...` after the assignments). It runs the same
// per-segment logic as `classifySegment`, but on an already-tokenized
// slice and without re-splitting on control operators (the tokens were
// pre-split by the outer tokenizer / segmenter).
func classifyWrapped(tokens []string) Kind {
	if len(tokens) == 0 {
		return KindUnknown
	}
	// Re-run the assignment-strip loop (the wrapper may be `env env FOO=bar cmd`).
	i := 0
	for i < len(tokens) && isAssignment(tokens[i]) {
		key := tokens[i][:strings.IndexByte(tokens[i], '=')]
		if isDangerousEnvVar(key) {
			return KindWrite
		}
		i++
	}
	if i >= len(tokens) {
		return KindUnknown
	}
	head := tokens[i]
	args := tokens[i+1:]
	if head == "sudo" {
		return KindWrite
	}
	rule, ok := readAllowlist[head]
	if !ok {
		return KindWrite
	}
	if rule == nil {
		return KindRead
	}
	return rule(args)
}
