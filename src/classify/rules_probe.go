package classify

import (
	"strings"
)

// This file holds the W2-3a "probe" arg-rules: read utilities that have a
// write form gated behind a specific flag/positional, plus the razor-narrow
// interpreter version-probe rule. Every rule fails closed — any form not
// explicitly recognized as a read is WRITE.

// treeRule: `tree` prints a directory listing (READ) but `-o FILE` /
// `--output FILE` writes the listing to a file. READ unless an output flag
// is present.
func treeRule(args []string) Kind {
	for _, a := range args {
		if a == "-o" || matchesAbbrev(a, "output") {
			return KindWrite // -o FILE / --output FILE / --output=FILE
		}
		if strings.HasPrefix(a, "-o") && len(a) > 2 && a[1] != '-' {
			return KindWrite // bundled -o<file>
		}
	}
	return KindRead
}

// crontabRule: READ only for the list form (`crontab -l`). `crontab -e`
// (edit), `crontab -r` (remove), `crontab -i` (remove w/ prompt), a bare FILE
// positional (install), and bare `crontab` (reads stdin and REPLACES the
// crontab) are all WRITE. Keeps classifier-corpus.txt `crontab -e` WRITE.
func crontabRule(args []string) Kind {
	hasList := false
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch {
		case a == "-l" || matchesAbbrev(a, "list"):
			hasList = true
		case a == "-e" || a == "-r" || a == "-i" || matchesAbbrev(a, "edit", "remove"):
			return KindWrite
		case a == "-u" || matchesAbbrev(a, "user"):
			i++ // -u USER consumes its value; the value is not a positional
		case len(a) > 0 && a[0] != '-':
			return KindWrite // a bare FILE positional installs a new crontab
		}
	}
	if hasList {
		return KindRead
	}
	return KindWrite // bare `crontab` reads stdin and replaces the table
}

// sysctlRule: READ for queries (`sysctl -a`, `sysctl -n key`, `sysctl key`).
// WRITE for `-w`, `-p`/`--load`, or any `key=value` positional (a bare
// assignment writes too).
func sysctlRule(args []string) Kind {
	for _, a := range args {
		if a == "-w" || matchesAbbrev(a, "write") {
			return KindWrite
		}
		if a == "-p" || matchesAbbrev(a, "load") {
			return KindWrite
		}
		if len(a) > 0 && a[0] != '-' && strings.IndexByte(a, '=') >= 0 {
			return KindWrite
		}
	}
	return KindRead
}

// mountRule: bare `mount` and flag-only forms (`-l`, `-t TYPE`) list mounts =
// READ. ANY bare positional (a device, a target, or an fstab entry) mounts
// something = WRITE; `-a` (mount all) = WRITE. Stricter than an
// ifconfig-clone (>=2 positionals): `mount /mnt` (a single positional,
// mount-by-fstab) IS a write, so the any-positional rule is the correct
// fail-closed shape. Keeps classifier-corpus.txt `mount /dev/sda1 /mnt` WRITE.
func mountRule(args []string) Kind {
	for i := 0; i < len(args); i++ {
		a := args[i]
		if a == "-a" || matchesAbbrev(a, "all") {
			return KindWrite
		}
		if a == "-t" || a == "-o" || a == "-O" || matchesAbbrev(a, "types", "options") {
			i++ // value belongs to the flag, not a positional
			continue
		}
		if len(a) > 0 && a[0] != '-' {
			return KindWrite // any device/target/fstab entry mounts
		}
	}
	return KindRead
}

// commandRule: the `command` builtin. READ only for the describe probes
// `-v`/`-V`. Any other form RUNS the wrapped command → WRITE (fail-closed; do
// NOT recurse — `command` bypasses functions/aliases and `-p` still executes).
func commandRule(args []string) Kind {
	for _, a := range args {
		if a == "-v" || a == "-V" {
			return KindRead
		}
	}
	return KindWrite
}

// ulimitRule: READ for query forms (`ulimit -a`, `ulimit -n`); a bare non-flag
// positional is the new limit value = WRITE (`ulimit -n 4096`).
func ulimitRule(args []string) Kind {
	for _, a := range args {
		if len(a) > 0 && a[0] == '-' {
			continue
		}
		return KindWrite // a bare value sets the limit
	}
	return KindRead
}

// historyRule: bare `history` or `history N` prints (READ). Any flag (`-c`
// clear, `-w FILE` write, `-d`, `-a`, `-r`, `-n`) is WRITE.
func historyRule(args []string) Kind {
	for _, a := range args {
		if len(a) > 0 && a[0] == '-' {
			return KindWrite
		}
	}
	return KindRead
}

// watchRule: recursive wrapper (like `env`). Strip `watch`'s own options, then
// classify the wrapped command via classifyWrapped. Because watch's wrapped
// command is a single segment, any unquoted operator (`;`, `&&`, `|`) in the
// caller string is already split by the outer splitSegments, so a hidden write
// (`watch ls; rm x`) is caught by the OTHER segment. A quoted compound
// (`watch 'df; rm x'`) tokenizes to a single head `df;` → not in the allowlist
// → WRITE (fail-closed). Wired in init() (recursive), like env.
//
// Mi2 (documented risk, no code change): `-n`/`--interval` are treated as the
// only separate-value options; no other watch option takes a separate value
// today, and an unknown wrapped head fails closed → WRITE, bounding the blast
// radius. If a future watch adds a value-taking option, revisit (prefer an
// explicit allowlist of watch flags if touched again).
func watchRule(args []string) Kind {
	i := 0
	for i < len(args) {
		a := args[i]
		if a == "--" {
			i++
			break
		}
		if len(a) == 0 || a[0] != '-' {
			break // wrapped command starts
		}
		if a == "-n" || a == "--interval" {
			i += 2 // bare form consumes the interval value
			continue
		}
		i++ // -n5 / --interval=5 / no-arg flags (-d,-t,-b,-g,-e,-p,-c,-x,...)
	}
	rest := args[i:]
	if len(rest) == 0 {
		return KindWrite // `watch -n 5` with no command — fail-closed
	}
	return classifyWrapped(rest)
}

// interpreterVersionRule returns an argRule that classifies READ ONLY when
// args is exactly one allowed version flag; everything else (bare REPL, -c,
// -e, a script path, extra args) stays WRITE. Interpreters exec arbitrary
// code, so this is intentionally the narrowest possible carve-out — never a
// blanket allowlist. Per-head allowed sets differ deliberately (e.g.
// `python -v` is verbose-REPL, not a version print; `ruby -v` enters program
// mode and reads stdin — both excluded).
//
// Mi3 (documented, not exploitable): `python3 --version ""` tokenizes to
// ["--version"] (empty token dropped) → len(args)==1 → READ. There is no
// code-exec surface (the extra empty arg cannot run code), so this is accepted.
func interpreterVersionRule(allowed ...string) argRule {
	set := make(map[string]bool, len(allowed))
	for _, f := range allowed {
		set[f] = true
	}
	return func(args []string) Kind {
		if len(args) == 1 && set[args[0]] {
			return KindRead
		}
		return KindWrite
	}
}
