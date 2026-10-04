package classify

import (
	"strings"
)

// Kind is the classification of a shell command for the SSHGate gate.
type Kind int

const (
	// KindUnknown means the input did not contain any executable command
	// (empty, whitespace, or non-printable). Callers should treat this as
	// an input error rather than routing it through the gate.
	KindUnknown Kind = iota

	// KindRead means the command only reads or observes state and may run
	// without an operator signature.
	KindRead

	// KindWrite means the command may mutate state and therefore requires
	// a valid SSHGATE_SIG signature from signer.
	KindWrite
)

// String reports the lowercase name of the Kind: "unknown", "read", or
// "write". Unknown values render as "unknown" so log lines stay readable.
func (k Kind) String() string {
	switch k {
	case KindRead:
		return "read"
	case KindWrite:
		return "write"
	default:
		return "unknown"
	}
}

// Classify reports whether cmd is a read or write command per the spec's
// "Command Classification" rules. The classifier is fail-safe: pipes,
// redirects, control operators (; && ||), sudo prefixes, command
// substitution, and unknown binaries all return KindWrite. Empty or
// whitespace-only input returns KindUnknown.
func Classify(cmd string) Kind {
	if !hasPrintable(cmd) {
		return KindUnknown
	}
	// Command substitution is opaque to us — route through the gate.
	if containsSubstitution(cmd) {
		return KindWrite
	}
	// A WRITING top-level redirect (a real path / &>file / >&file target) makes
	// the command a write regardless of head. Stderr-only fd-dup/close and the
	// discard/stream sinks are carved out (§5) and do NOT force a write.
	if hasWritingRedirect(cmd) {
		return KindWrite
	}
	// Split on top-level control operators / pipes; any write segment wins.
	segments := splitSegments(cmd)
	if len(segments) == 0 {
		return KindUnknown
	}
	sawRead := false
	for _, seg := range segments {
		switch classifySegment(seg) {
		case KindWrite:
			return KindWrite
		case KindUnknown:
			// A blank segment (e.g. trailing ';') is ignored; if every
			// segment is blank the outer hasPrintable check would have
			// caught it.
			continue
		case KindRead:
			sawRead = true
		}
	}
	if sawRead {
		return KindRead
	}
	return KindUnknown
}

// hasPrintable reports whether s contains at least one non-whitespace,
// non-null byte.
func hasPrintable(s string) bool {
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c == 0 || c == ' ' || c == '\t' || c == '\n' || c == '\r' {
			continue
		}
		return true
	}
	return false
}

// containsSubstitution reports whether s contains a command substitution
// (`$(...)` or backticks) or a process substitution (`<(...)`, `>(...)`)
// at top level (outside quotes). Any such construct is opaque to the
// classifier and routes the whole command through the gate.
func containsSubstitution(s string) bool {
	// Track single- and double-quote contexts SEPARATELY. In /bin/sh only
	// SINGLE quotes are fully literal; command substitution `$(...)` and
	// backticks STILL expand inside DOUBLE quotes. Suppressing detection
	// inside double quotes (the old behavior) let `cat "$(rm -rf x)"`
	// classify READ yet execute the rm — a read-only-gate bypass. A single
	// quote inside double quotes (e.g. `"it's $(rm)"`) is a literal byte,
	// not a quote opener, so the two states must be tracked independently.
	var inSingle, inDouble bool
	for i := 0; i < len(s); i++ {
		c := s[i]
		// A backslash escapes the next byte EVERYWHERE except inside single
		// quotes (in sh, inside '...' a backslash is literal). An escaped
		// quote/$/` is a literal data byte — it must NOT toggle quote state
		// or trigger substitution. Without this, `stat f \'$(rm)` hid its
		// `$(` behind a phantom single-quote and classified READ while
		// /bin/sh ran the substitution — an unsigned-exec bypass.
		if c == '\\' && !inSingle {
			i++ // skip the escaped byte
			continue
		}
		switch {
		case inSingle:
			if c == '\'' {
				inSingle = false
			}
		case inDouble:
			switch c {
			case '"':
				inDouble = false
			case '`':
				return true
			case '$':
				if i+1 < len(s) && s[i+1] == '(' {
					return true
				}
			}
		default: // unquoted
			switch c {
			case '\'':
				inSingle = true
			case '"':
				inDouble = true
			case '`':
				return true
			case '$':
				if i+1 < len(s) && s[i+1] == '(' {
					return true
				}
			case '<', '>':
				// Process substitution `<(cmd)` / `>(cmd)` only occurs
				// unquoted (it does not expand inside quotes). The output
				// redirect `>` is handled separately by hasWritingRedirect;
				// here we only flag the `<(` / `>(` pair.
				if i+1 < len(s) && s[i+1] == '(' {
					return true
				}
			}
		}
	}
	return false
}

// hasWritingRedirect reports whether s has a top-level (unquoted, unescaped)
// output redirect whose TARGET writes a file or host stream. NON-writing ONLY
// for: fd dup/close (>&N, N>&M, N>&-) and the discard/stream sinks /dev/null,
// /dev/stdout, /dev/stderr. Replaces the old hasTopLevelRedirect (which forced
// WRITE on ANY '>'); input redirects (<) stay ignored. The narrow carve-out is
// the whole point of W2-3d — keep it target-exact and fail closed on anything
// else. Preserves the same quote/backslash handling as before.
func hasWritingRedirect(s string) bool {
	var quote byte
	for i := 0; i < len(s); i++ {
		c := s[i]
		// Backslash escapes the next byte unless inside single quotes — an
		// escaped `>` is a literal, not a redirect (and `\"` must not open a
		// phantom quote that hides a real `>`).
		if c == '\\' && quote != '\'' {
			i++
			continue
		}
		if quote != 0 {
			if c == quote {
				quote = 0
			}
			continue
		}
		switch c {
		case '\'', '"':
			quote = c
		case '>':
			j := i + 1
			if j < len(s) && s[j] == '>' {
				j++ // append '>>'
			}
			// fd dup/close form: '>' immediately followed by '&'.
			if j < len(s) && s[j] == '&' {
				tgt := readRedirTarget(s, j+1)
				if isAllDigits(tgt) || tgt == "-" {
					continue // >&N dup or >&- close: non-writing
				}
				return true // >&file : both streams to a file
			}
			// ordinary target: skip spaces, read the target word.
			k := j
			for k < len(s) && (s[k] == ' ' || s[k] == '\t') {
				k++
			}
			switch readRedirTarget(s, k) {
			case "/dev/null", "/dev/stdout", "/dev/stderr":
				continue // sink: non-writing
			default:
				return true // real path (or dangling '>') : write
			}
		}
	}
	return false
}

// readRedirTarget reads the redirect target word starting at start, stopping
// at whitespace or any shell metachar. A quoted or empty target yields a token
// that will NOT match the digit/sink allowlists → fail closed to WRITE.
func readRedirTarget(s string, start int) string {
	i := start
	for i < len(s) {
		switch s[i] {
		case ' ', '\t', '\n', ';', '|', '&', '<', '>', '\'', '"', '(', ')':
			return s[start:i]
		}
		i++
	}
	return s[start:]
}

// isAllDigits reports whether t is a non-empty run of ASCII digits.
func isAllDigits(t string) bool {
	if t == "" {
		return false
	}
	for i := 0; i < len(t); i++ {
		if t[i] < '0' || t[i] > '9' {
			return false
		}
	}
	return true
}

// splitSegments splits s on top-level (unquoted) pipes and control
// operators: |, ||, &, &&, ;. Returns the segments with surrounding
// whitespace trimmed; empty segments are dropped.
func splitSegments(s string) []string {
	var out []string
	var quote byte
	start := 0
	flush := func(end int) {
		seg := strings.TrimSpace(s[start:end])
		if seg != "" {
			out = append(out, seg)
		}
	}
	i := 0
	for i < len(s) {
		c := s[i]
		// Backslash escapes the next byte unless inside single quotes — an
		// escaped separator (`\;`, `\&`, `\|`, escaped newline) is literal
		// and must NOT split, and an escaped quote must NOT open a phantom
		// quote that swallows a real separator (`ls \' && rm` => the `&&`
		// and the `rm` segment must still be seen).
		if c == '\\' && quote != '\'' {
			i += 2
			continue
		}
		if quote != 0 {
			if c == quote {
				quote = 0
			}
			i++
			continue
		}
		switch c {
		case '\'', '"':
			quote = c
			i++
		case ';', '\n':
			// ';' and an unquoted newline are both top-level command
			// separators for /bin/sh, and the gate execs via `sh -c`, so a
			// newline runs a second command. Splitting on it closes a
			// read-only-gate bypass: `ls\nrm -rf x` must NOT classify READ
			// just because the first line reads. (Newlines inside quotes are
			// skipped above, so only an unquoted newline splits.)
			flush(i)
			start = i + 1
			i++
		case '|':
			flush(i)
			if i+1 < len(s) && s[i+1] == '|' {
				i += 2
			} else {
				i++
			}
			start = i
		case '&':
			// A `&` that is part of a REDIRECTION operator is NOT a control
			// operator and must not split the segment — otherwise `2>&1` splits
			// into ["… 2>", "1"] and the non-writing-redirect carve-out (§5.1)
			// is undone. Detect it by the adjacent redirect char:
			//   - fd dup/close `>&`/`<&`  (2>&1, >&2, 2>&-, <&0): preceding `>`/`<`
			//   - bash redirect-all `&>` / `&>>` (&>/dev/null):    following `>`
			// Any WRITING redirect target was already caught by hasWritingRedirect
			// before this function runs, so a redirect `&` reaching here is always
			// non-writing. A bare `&` (background) or `&&` (and-list) still splits.
			if (i > 0 && (s[i-1] == '>' || s[i-1] == '<')) ||
				(i+1 < len(s) && s[i+1] == '>') {
				i++ // treat as an ordinary char; keep scanning this segment
				continue
			}
			// & or && — both are top-level separators. (Background `&`
			// alone is not in our corpus but is handled the same way.)
			flush(i)
			if i+1 < len(s) && s[i+1] == '&' {
				i += 2
			} else {
				i++
			}
			start = i
		default:
			i++
		}
	}
	flush(len(s))
	return out
}

// classifySegment classifies a single command segment (no top-level pipes
// or control operators). It strips any leading environment-variable
// assignments, returns KindWrite for sudo or unknown heads, and otherwise
// applies the per-command argument rules.
func classifySegment(seg string) Kind {
	tokens := tokenize(seg)
	if len(tokens) == 0 {
		return KindUnknown
	}
	// Strip leading FOO=bar VAR=baz assignments. Any of these env vars is a
	// known shell-execution vector (e.g. GIT_EXTERNAL_DIFF, LD_PRELOAD,
	// IFS, PATH); safer to classify the wrapping command as WRITE rather
	// than ignore the prefix and trust the wrapped binary not to honor it.
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

	// sudo always means write, regardless of what it wraps.
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

// tokenize splits a single-segment command into shell-style tokens,
// respecting single and double quotes. Escapes are passed through as-is;
// the classifier only needs to identify the head command and scan args.
func tokenize(s string) []string {
	var out []string
	var cur strings.Builder
	var quote byte
	flush := func() {
		if cur.Len() > 0 {
			out = append(out, cur.String())
			cur.Reset()
		}
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		// Backslash escapes the next byte unless inside single quotes; the
		// escaped char is literal token data, so `\ ` does not split the
		// token and `\'`/`\"` do not toggle quote state.
		if c == '\\' && quote != '\'' {
			if i+1 < len(s) {
				cur.WriteByte(s[i+1])
				i++
			}
			continue
		}
		if quote != 0 {
			if c == quote {
				quote = 0
				continue
			}
			cur.WriteByte(c)
			continue
		}
		switch c {
		case '\'', '"':
			quote = c
		case ' ', '\t', '\n', '\r':
			flush()
		default:
			cur.WriteByte(c)
		}
	}
	flush()
	return out
}

// isAssignment reports whether tok is a leading KEY=VALUE env assignment.
func isAssignment(tok string) bool {
	eq := strings.IndexByte(tok, '=')
	if eq <= 0 {
		return false
	}
	for i := 0; i < eq; i++ {
		c := tok[i]
		if !(c == '_' ||
			(c >= 'A' && c <= 'Z') ||
			(c >= 'a' && c <= 'z') ||
			(i > 0 && c >= '0' && c <= '9')) {
			return false
		}
	}
	return true
}

// argRule narrows a head command from "read by default" to KindWrite when
// specific argument patterns appear (e.g. `sed -i`, `find -delete`).
// A nil rule means "always read."
type argRule func(args []string) Kind

// readAllowlist maps a command's head to its argument rule (or nil if
// every invocation is read-only). Anything not in this map is KindWrite.
var readAllowlist = map[string]argRule{
	// File inspection.
	"cat":      nil,
	"less":     lessRule,
	"more":     nil,
	"head":     nil,
	"tail":     nil,
	"wc":       nil,
	"file":     fileRule, // -C/--compile writes a .mgc file (C1)
	"stat":     nil,
	"readlink": nil,

	// Directory + path lookup.
	"ls":      nil,
	"find":    findRule,
	"locate":  nil,
	"which":   nil,
	"whereis": nil,

	// Text processing.
	"grep":  nil,
	"egrep": nil,
	"fgrep": nil,
	"awk":   awkRule,
	"sed":   sedRule,
	"sort":  sortRule,
	"uniq":  uniqRule,
	"diff":  nil,
	"comm":  nil,
	// Text filters (print to stdout; no write flag).
	"jq": nil, "cut": nil, "tr": nil, "column": nil, "zcat": nil, "zgrep": nil,
	"zdiff": nil, "nl": nil, "tac": nil, "rev": nil,
	// Hashes (print digests; no write-to-file flag).
	"md5sum": nil, "sha1sum": nil, "sha256sum": nil, "sha512sum": nil, "cksum": nil, "b2sum": nil,
	// Path lookup (print; no write).
	"realpath": nil, "basename": nil, "dirname": nil,

	// System status.
	"df":     nil,
	"du":     nil,
	"free":   nil,
	"uptime": nil,
	"uname":  nil,
	// System probes (print; no write).
	"lscpu": nil, "lsblk": nil, "nproc": nil, "vmstat": nil, "iostat": nil, "mpstat": nil, "getent": nil,
	// Shell predicates (evaluate only; no side effect).
	"type": nil, "test": nil, "[": nil,
	// Probe utilities with a write form (arg-gated; see rules_probe.go).
	"tree": treeRule, "crontab": crontabRule, "sysctl": sysctlRule, "mount": mountRule,
	"command": commandRule, "ulimit": ulimitRule, "history": historyRule,
	// "watch": wired in init() (recursive wrapper, like env).
	// Interpreter version probe ONLY (razor-narrow; everything else WRITE).
	"python":      interpreterVersionRule("-V", "--version"),
	"python2":     interpreterVersionRule("-V", "--version"),
	"python3":     interpreterVersionRule("-V", "--version"),
	"node":        interpreterVersionRule("-v", "--version"),
	"nodejs":      interpreterVersionRule("-v", "--version"),
	"perl":        interpreterVersionRule("-v", "-V", "--version"),
	"ruby":        interpreterVersionRule("--version"),
	"hostname":    hostnameRule,
	"whoami":      nil,
	"id":          nil,
	"groups":      nil,
	"date":        dateRule,
	"timedatectl": timedatectlRule,
	// `env` is special: it is allowed as a read-only print-the-environment
	// command, but with any positional argument it acts as a wrapper for
	// another command. envRule recursively classifies the wrapped command
	// against this same map, so we wire it up in init() below to avoid
	// an initialization cycle.
	"env":      nil,
	"printenv": nil,
	// Pure-output builtins: spec lists `echo/cat/tee with redirects` under
	// write. Top-level redirect detection runs before head lookup, so a
	// bare `echo done` reaches this map and is correctly a read.
	"echo":   nil,
	"printf": nil,
	"true":   nil,
	"false":  nil,

	// Process + network introspection.
	"ps":         nil,
	"top":        nil,
	"htop":       nil,
	"pgrep":      nil,
	"lsof":       nil,
	"ss":         ssRule,
	"netstat":    nil,
	"ip":         ipRule,
	"ifconfig":   ifconfigRule,
	"ping":       nil,
	"dig":        nil,
	"nslookup":   nil,
	"traceroute": nil,
	"curl":       curlRule,
	"wget":       wgetRule,

	// Logs / who.
	"journalctl": journalctlRule,
	"dmesg":      dmesgRule,
	"last":       nil,
	"lastlog":    lastlogRule,
	"w":          nil,
	"who":        nil,

	// Subcommand-gated heads.
	"systemctl": systemctlRule,
	"service":   serviceRule,
	"docker":    dockerRule,
	"git":       gitRule,
	"kubectl":   kubectlRule,

	// Package managers default to write; only their query subcommands are read.
	// (Spec lists them under write; corpus has no read-side example for them.)
}

func init() {
	// Wire envRule into the allowlist after the map literal is initialized.
	// envRule recursively reads readAllowlist, which would be an
	// initialization cycle if expressed directly in the literal.
	readAllowlist["env"] = envRule
	// watchRule recurses into readAllowlist too (it classifies the wrapped
	// command), so wire it here for the same reason.
	readAllowlist["watch"] = watchRule
}

// firstNonFlag returns the first arg that doesn't start with '-', or "".
func firstNonFlag(args []string) string {
	for _, a := range args {
		if a == "" || strings.HasPrefix(a, "-") {
			continue
		}
		return a
	}
	return ""
}

// hasEqValue reports whether arg is a `--flag=VALUE` long option (contains an
// `=` after the `--`).
func hasEqValue(arg string) bool {
	if !strings.HasPrefix(arg, "--") {
		return false
	}
	return strings.IndexByte(arg[2:], '=') >= 0
}

// eqValue returns the VALUE part of a `--flag=VALUE` long option (everything
// after the first `=`), or "" if there is no `=`.
func eqValue(arg string) string {
	if eq := strings.IndexByte(arg, '='); eq >= 0 {
		return arg[eq+1:]
	}
	return ""
}

// matchesAbbrev reports whether arg is a GNU `--long` option that abbreviates
// (or fully names) one of the dangerous long-option stems in opts. GNU
// getopt_long accepts ANY non-empty unambiguous prefix of a long option, so a
// rule that matched a dangerous flag only by its exact spelling let the
// abbreviated form fall through to KindRead and run unsigned. This helper
// closes that gap by treating arg as a WRITE marker if its option name is a
// prefix of any dangerous stem.
//
// Rules:
//   - arg must begin with `--` (a GNU long option). Single-dash and bundled
//     short flags are handled by each rule's own short-flag logic.
//   - any `=VALUE` suffix is stripped first; only the option NAME is matched.
//   - the option name must be non-empty (bare `--` / `--=x` never match).
//   - a match is: the option name is a prefix of a dangerous stem (so `--clea`
//     matches `clear`, `--output` matches `output`). Fail-safe: a name that is
//     a prefix of EITHER a dangerous or a benign option is still classified
//     WRITE here when it matches a dangerous stem — getopt would reject a
//     genuinely ambiguous prefix anyway, and routing it through the gate is the
//     safe default. Callers pass ONLY the known-dangerous stems so benign reads
//     are not over-classified.
func matchesAbbrev(arg string, opts ...string) bool {
	if !strings.HasPrefix(arg, "--") {
		return false
	}
	body := arg[2:]
	if eq := strings.IndexByte(body, '='); eq >= 0 {
		body = body[:eq]
	}
	if body == "" {
		return false
	}
	for _, stem := range opts {
		if strings.HasPrefix(stem, body) {
			return true
		}
	}
	return false
}
