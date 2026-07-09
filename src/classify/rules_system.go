package classify

import (
	"strings"
)

// journalctlRule: `journalctl` is read iff none of its mutating flags are
// present. The dangerous flags rotate, vacuum (delete), flush, sync,
// release var-log, update the catalog, or generate FSS keys. GNU long
// options accept unambiguous prefixes, so we use prefix-match against
// each dangerous flag stem. Cited as MAJOR-2 in
// docs/security-readonly-bypass.md.
func journalctlRule(args []string) Kind {
	for _, a := range args {
		if journalctlFlagIsDangerous(a) {
			return KindWrite
		}
	}
	return KindRead
}

// journalctlDangerousLong is the list of journalctl long-option stems
// that mutate state. We match any arg whose `--` prefix is a prefix of
// one of these stems (GNU getopt prefix-abbreviation), with one safety
// constraint: the matched arg must have at least 3 chars after `--`
// (e.g. `--rot`) to avoid colliding with unrelated short prefixes like
// `--no-pager`. The bound was chosen empirically from journalctl(1).
var journalctlDangerousLong = []string{
	"rotate",
	"vacuum-size",
	"vacuum-time",
	"vacuum-files",
	"flush",
	"sync",
	"relinquish-var",
	"smart-relinquish-var",
	"update-catalog",
	"setup-keys",
}

func journalctlFlagIsDangerous(a string) bool {
	if !strings.HasPrefix(a, "--") {
		return false
	}
	body := a[2:]
	// Strip `=VALUE` suffix; we only care about the option name.
	if eq := strings.IndexByte(body, '='); eq >= 0 {
		body = body[:eq]
	}
	if len(body) < 3 {
		return false
	}
	for _, stem := range journalctlDangerousLong {
		if strings.HasPrefix(stem, body) {
			return true
		}
	}
	return false
}

// dateRule: `date` is read for display (`date`, `date +FMT`, `-u`, `-d STR`,
// `-r FILE`, `-f FILE`) but WRITES the system clock with `-s`/`--set` or a
// bare MMDDhhmm-style positional. `date` was a nil (always-READ) entry, so
// `date -s ...` / `date 010100002020` set the clock unsigned on a read-only
// server. Display flags that consume a value (-d/--date, -r/--reference,
// -f/--file) are skipped so their argument is not mistaken for a set spec.
func dateRule(args []string) Kind {
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch {
		case a == "-s" || matchesAbbrev(a, "set") ||
			(strings.HasPrefix(a, "-s") && !strings.HasPrefix(a, "--") && len(a) > 2):
			// `--set`/`--set=SPEC` and its unambiguous abbreviations (`--se`,
			// `--s` — `set` is the ONLY date long option starting with `s`)
			// SET the system clock. matchesAbbrev handles both the bare and
			// `=VALUE` forms.
			return KindWrite
		case a == "-d" || a == "--date" || a == "-r" || a == "--reference" ||
			a == "-f" || a == "--file":
			i++ // value belongs to a display flag, not a set positional
		case len(a) > 0 && (a[0] == '-' || a[0] == '+'):
			// other flags (-u, --utc, -I[FMT], --rfc-3339=, ...) and the
			// `+FORMAT` output spec are display-only.
			continue
		default:
			// a bare positional that is not `+FORMAT` is the MMDDhhmm[[CC]YY]
			// clock-set form.
			return KindWrite
		}
	}
	return KindRead
}

// ipRule: iproute2 `ip [OPTIONS] OBJECT [ACTION ...]` is read ONLY for the
// inspection actions (show/list/get/monitor/save + help) or when no action
// token is present (object-only, e.g. `ip a`, `ip link`). Any other action
// token reconfigures the host and is a WRITE.
//
// The previous rule matched a fixed denylist of full-word write verbs, so
// iproute2's unambiguous ABBREVIATIONS slipped through and ran unsigned:
// `ip a a 10.0.0.1/24 dev eth0` (addr add), `ip r a default via X` (route
// add), `ip l s eth0 up` (link set), `ip n a ...` (neigh add). It was also a
// nil-style allowlist for `ip -batch FILE`, which runs an opaque command
// file. We now FAIL SAFE: only a recognized READ action keeps READ.
//
// Action classification is prefix-based to honor iproute2's abbreviation
// matching, but a prefix that matches BOTH a read verb and a write verb is
// AMBIGUOUS and falls to WRITE — so `s` (show/save vs set/restore family)
// makes `ip l s eth0 up` a WRITE. Use the unambiguous `sh` for addr-show.
// Cited by the 2026-06-14 adversarial review.
func ipRule(args []string) Kind {
	// Any batch/force option runs an opaque command file or bypasses safety
	// prompts — always WRITE. iproute2 uses single-dash long options.
	for _, a := range args {
		switch a {
		case "-b", "-batch", "--batch", "-force", "--force":
			return KindWrite
		}
	}
	// The first non-flag token is the OBJECT; the second is the ACTION.
	var object, action string
	have := 0
	for _, a := range args {
		if a == "" || a[0] == '-' {
			continue
		}
		have++
		switch have {
		case 1:
			object = a
		case 2:
			action = a
		}
		if have == 2 {
			break
		}
	}
	_ = object // object identity is irrelevant; we classify on the action
	if action == "" {
		// Object-only (or bare `ip`): a status query, e.g. `ip a`, `ip link`.
		return KindRead
	}
	if ipActionIsRead(action) {
		return KindRead
	}
	return KindWrite
}

// ipReadVerbs are the iproute2 actions that only observe state.
var ipReadVerbs = []string{"show", "list", "get", "monitor", "save", "help"}

// ipWriteVerbs are the common iproute2 actions that mutate state. The list is
// only used for AMBIGUITY detection (a token that prefix-matches both a read
// and a write verb is treated as WRITE); any unrecognized action is WRITE
// anyway, so the list does not need to be exhaustive.
var ipWriteVerbs = []string{
	"add", "del", "delete", "set", "change", "chg", "replace", "append",
	"prepend", "flush", "modify", "remove", "restore", "reset", "enslave",
}

// ipActionIsRead reports whether action unambiguously names a read-only
// iproute2 verb: it is a prefix of some read verb and a prefix of NO write
// verb. A prefix that matches both is ambiguous and reported false (WRITE).
func ipActionIsRead(action string) bool {
	matchesRead := false
	for _, v := range ipReadVerbs {
		if strings.HasPrefix(v, action) {
			matchesRead = true
			break
		}
	}
	if !matchesRead {
		return false
	}
	for _, v := range ipWriteVerbs {
		if strings.HasPrefix(v, action) {
			return false // ambiguous read/write prefix => fail safe to WRITE
		}
	}
	return true
}

// ifconfigRule: `ifconfig` with no interface, only flags (-a/-s/-v), or a
// single interface name is a read (status query). A second positional means
// it is configuring the interface (`ifconfig eth0 192.168.1.5`,
// `ifconfig eth0 up`, `ifconfig eth0 netmask ...`) — a WRITE. `ifconfig` was
// a nil (always-READ) entry, so every such reconfiguration ran unsigned.
func ifconfigRule(args []string) Kind {
	positionals := 0
	for _, a := range args {
		if len(a) > 0 && a[0] == '-' {
			continue
		}
		positionals++
	}
	if positionals >= 2 {
		return KindWrite
	}
	return KindRead
}

// timedatectlRule: `timedatectl` is read for its status/inspection
// subcommands (status/show/show-timesync/timesync-status/list-timezones) and
// the bare no-subcommand form (which prints status). Every other subcommand
// — set-time, set-timezone, set-ntp, set-local-rtc — MUTATES the system clock
// or timezone (the same write class as the already-fixed `date -s`), so it is
// a WRITE. `timedatectl` was a nil (always-READ) entry, so every set-* ran
// unsigned on a read-only server. Cited by the 2026-06-14 adversarial review.
func timedatectlRule(args []string) Kind {
	sub := firstNonFlag(args)
	switch sub {
	case "", "status", "show", "show-timesync", "timesync-status",
		"list-timezones":
		return KindRead
	}
	return KindWrite
}

// dmesgRule: `dmesg` is read for printing the kernel ring buffer, but several
// flags clear or change it: --clear/-C (clear), -c/--read-clear (print then
// clear), -D/-E (disable/enable console logging), -n/--console-level (set the
// console log level). `dmesg` was a nil (always-READ) entry, so these ran
// unsigned. Cited by the 2026-06-14 adversarial review.
func dmesgRule(args []string) Kind {
	for _, a := range args {
		switch a {
		case "-C", "-c", "-D", "-E", "-n":
			return KindWrite
		}
		// Long-option abbreviations: GNU getopt accepts any unambiguous prefix,
		// so `--clea`/`--read-c`/`--console-of`/`--console-l` all fire the
		// dangerous flag. Match the dangerous stems by abbreviation. The benign
		// reads (`--color`, `--ctime`, `--decode`, ...) are NOT prefixes of any
		// stem here, so they stay READ. `--console-level` takes the new level
		// (e.g. `--console-l 1`); the flag alone marks WRITE.
		if matchesAbbrev(a, "clear", "read-clear", "console-off", "console-on",
			"console-level") {
			return KindWrite
		}
	}
	return KindRead
}

// hostnameRule: `hostname` with no positional only DISPLAYS the name and its
// variants (`hostname`, `-f`/`--fqdn`, `-i`/`-I`/`--all-ip-addresses`,
// `-s`/`--short`, `-d`/`--domain`, `-A`/`--all-fqdns`, `-y`/`--yp`) — READ.
// A single non-flag positional is the NEW name and SETS the system hostname:
// `hostname pwned` is a WRITE. `hostname` was a nil (always-READ) allowlist
// entry, so the set form ran unsigned (2026-06-15 rig hunt). We classify WRITE
// if any non-flag positional is present, else READ. (`-F`/`--file` takes a
// file VALUE that also sets the name, but it begins with `-`; to stay safe we
// also treat the value-taking `-F`/`-b`/`-i`-style separate operands narrowly:
// only a BARE positional — not a flag and not a flag's consumed value — counts.
// `-F FILE` itself reads the name from a file and sets it, so the leading `-F`
// flag is enough to mark WRITE.)
func hostnameRule(args []string) Kind {
	for i := 0; i < len(args); i++ {
		a := args[i]
		if a == "" {
			continue
		}
		if a[0] == '-' && a != "-" {
			// `-F`/`--file` reads the new name from a file and SETS it — a
			// write. Match `--file` by abbreviation (GNU getopt prefix): `--fi`
			// is unambiguous for `--file` (`--fqdn` needs `--fq`), so `--fi`/
			// `--fil`/`--file`/`--file=FILE` all SET. The display flags
			// (`--fqdn`, `--short`, `--domain`, ...) are not prefixes of
			// `file`, so they stay READ.
			if a == "-F" || matchesAbbrev(a, "file") {
				return KindWrite
			}
			continue
		}
		// A bare positional (incl. `-` for stdin) is the NEW hostname.
		return KindWrite
	}
	return KindRead
}

// ssRule: `ss` is read for socket inspection, but `-K`/`--kill` forcibly
// closes matching sockets — a state mutation. `ss` was a nil (always-READ)
// entry, so `ss -K ...` ran unsigned. Cited by the 2026-06-14 review.
func ssRule(args []string) Kind {
	for _, a := range args {
		if a == "-K" {
			return KindWrite
		}
		// `--kill` and its unambiguous abbreviations (`--kil`, `--ki`, `--k`)
		// forcibly close matching sockets. No other ss long option starts with
		// `k`, so any `--k...` prefix is `--kill`.
		if matchesAbbrev(a, "kill") {
			return KindWrite
		}
	}
	return KindRead
}

// lastlogRule: `lastlog` is read for reporting last-login times, but
// `-C`/--clear and `-S`/--set WRITE the lastlog database. `lastlog` was a nil
// (always-READ) entry, so these ran unsigned. Cited by the 2026-06-14 review.
func lastlogRule(args []string) Kind {
	for _, a := range args {
		switch a {
		case "-C", "-S":
			return KindWrite
		}
		// `--clear`/`--set` and their unambiguous abbreviations (`--cl`,
		// `--se`) WRITE the lastlog database. The benign long options
		// (`--user`, `--before`, `--time`) do not start with `c`/`s`, so no
		// READ form is over-classified.
		if matchesAbbrev(a, "clear", "set") {
			return KindWrite
		}
	}
	return KindRead
}

// lessRule: `less` is read for paging files, but its log-file options write a
// copy of the input to a named file: `-o FILE`/`-O FILE` (the `-O` form
// overwrites without prompting) and `--log-file FILE`/`--LOG-FILE FILE`.
// `less` was a nil (always-READ) entry, so `less -o /tmp/x file` wrote a file
// unsigned. The output file may be bundled (`-o/tmp/x`) or the next arg.
// `--log-file=FILE` / `--LOG-FILE=FILE` are also handled. Cited by the
// 2026-06-14 adversarial review.
func lessRule(args []string) Kind {
	for _, a := range args {
		switch a {
		case "-o", "-O":
			return KindWrite
		}
		// `--log-file FILE` / `--LOG-FILE FILE` (and `=FILE`) write a copy of
		// the input to FILE. GNU getopt accepts abbreviations: `--log` is
		// unambiguous for `--log-file` (the only other `--log*`/`--lo*` is
		// `--long-prompt`, which `--log` is NOT a prefix of), so match by
		// abbreviation. The case-distinct `--LOG-FILE` overwrites without
		// prompting; match it too. (less is case-sensitive on these.)
		if matchesAbbrev(a, "log-file") || matchesAbbrev(a, "LOG-FILE") {
			return KindWrite
		}
		// Bundled short form: -o<file> / -O<file>.
		if len(a) > 2 && a[0] == '-' && (a[1] == 'o' || a[1] == 'O') {
			return KindWrite
		}
	}
	return KindRead
}

// systemctlRule: only inspection subcommands are read. Anything that can
// change unit state is write.
func systemctlRule(args []string) Kind {
	sub := firstNonFlag(args)
	switch sub {
	case "status", "is-active", "is-enabled", "is-failed",
		"list-units", "list-unit-files", "list-sockets", "list-timers",
		"show", "cat", "get-default",
		// NEW readers. set-environment / unset-environment / import-environment
		// are NOT added → they stay WRITE.
		"show-environment", "list-dependencies", "list-jobs", "is-system-running":
		return KindRead
	}
	return KindWrite
}

// kubectlRule: only inspection subcommands read; anything that can mutate
// cluster state writes. FAIL-CLOSED: any unrecognized subcommand → WRITE.
// Two verbs need second-token guards: `cluster-info dump` writes files, and
// `config` has write subcommands. `-o go-template`/`jsonpath`/`--format` are
// Go text/template (sandboxed, no shell exec) — not a hole.
func kubectlRule(args []string) Kind {
	sub := firstNonFlag(args)
	switch sub {
	case "get", "describe", "logs", "events", "top", "explain",
		"api-resources", "api-versions", "version":
		return KindRead
	case "cluster-info":
		// bare `cluster-info` prints endpoints (READ); `cluster-info dump`
		// writes files (WRITE).
		if secondNonFlag(args) == "" {
			return KindRead
		}
		return KindWrite
	case "config":
		switch secondNonFlag(args) {
		case "view", "current-context", "get-contexts", "get-clusters", "get-users":
			return KindRead
		}
		return KindWrite // set / set-context / use-context / set-credentials / ...
	}
	// apply/delete/edit/scale/rollout/exec/cp/patch/create/replace/label/
	// annotate/drain/cordon/uncordon/taint/run/port-forward/proxy/attach/set/...
	return KindWrite
}

// secondNonFlag returns the SECOND non-flag token in args, or "".
func secondNonFlag(args []string) string {
	seen := 0
	for _, a := range args {
		if a == "" || strings.HasPrefix(a, "-") {
			continue
		}
		seen++
		if seen == 2 {
			return a
		}
	}
	return ""
}

// serviceRule: `service <name> status` is read; everything else is write.
func serviceRule(args []string) Kind {
	// service <unit> <verb>
	if len(args) >= 2 {
		verb := args[len(args)-1]
		if verb == "status" {
			return KindRead
		}
	}
	return KindWrite
}

// dockerRule: introspection subcommands are read; lifecycle ones are write.
// Keeps the top-level read verbs and adds two-level parsing for the namespaced
// management commands. FAIL-CLOSED: any (namespace, verb) pair not explicitly
// listed READ → WRITE, so a write verb one token deeper (`network rm`,
// `system prune`, `compose up`) is denied.
func dockerRule(args []string) Kind {
	sub := firstNonFlag(args)
	switch sub {
	case "ps", "logs", "inspect", "images", "stats",
		"version", "info", "top", "diff", "history",
		"port", "events", "search":
		return KindRead
	case "system", "network", "volume", "image", "container",
		"node", "service", "compose", "context":
		// `compose config` renders the merged config to stdout (READ) but
		// `-o`/`--output FILE` writes a file (M1) — route it through the
		// flag-check BEFORE the namespaced-read table.
		if sub == "compose" && secondNonFlag(args) == "config" {
			return dockerComposeConfigKind(args)
		}
		if dockerNamespacedRead(sub, secondNonFlag(args)) {
			return KindRead
		}
		return KindWrite
	}
	return KindWrite
}

// dockerComposeConfigKind: `docker compose config` renders the merged config
// to stdout (READ) UNLESS -o/--output names a file (WRITE). GNU-style:
// -o FILE, -o<file>, --output FILE, --output=FILE all write.
func dockerComposeConfigKind(args []string) Kind {
	for _, a := range args {
		if a == "-o" || a == "--output" || matchesAbbrev(a, "output") {
			return KindWrite
		}
		if strings.HasPrefix(a, "-o") && len(a) > 2 && a[1] != '-' { // -o<file>
			return KindWrite
		}
	}
	return KindRead
}

// dockerNamespacedRead reports whether `docker <ns> <verb>` only reads.
func dockerNamespacedRead(ns, verb string) bool {
	switch ns {
	case "system":
		return verb == "df" || verb == "info" || verb == "events"
	case "network":
		return verb == "ls" || verb == "inspect"
	case "volume":
		return verb == "ls" || verb == "inspect"
	case "image":
		return verb == "ls" || verb == "inspect" || verb == "history"
	case "container":
		return verb == "ls" || verb == "inspect" || verb == "logs" ||
			verb == "stats" || verb == "top" || verb == "diff" || verb == "port"
	case "node":
		return verb == "ls" || verb == "inspect"
	case "service":
		return verb == "ls" || verb == "ps" || verb == "inspect" || verb == "logs"
	case "compose":
		// `config` is handled by dockerComposeConfigKind before this table is
		// consulted (removed here to avoid confusion; leaving it in would be
		// dead but harmless).
		return verb == "ps" || verb == "logs" ||
			verb == "ls" || verb == "top" || verb == "images" || verb == "version"
	case "context":
		return verb == "ls" || verb == "inspect" || verb == "show"
	}
	return false
}

// gitRule: read-only porcelain only. Anything that updates refs, the
// index, or the working tree is write. Per code-review Mi3 we treat
// `git stash` (and its mutating subcommands) as write; only the
// inspection subcommands `stash list` / `stash show` are read.
// `git config --set` (and write-side variants like --unset/--add) are
// write; `git config --get` and bare `git config <name>` are read.
func gitRule(args []string) Kind {
	// `git -c KEY=VAL` injects ad-hoc config. Many config keys execute
	// shell commands when git invokes them: `core.pager`, `core.editor`,
	// `core.sshCommand`, `core.hooksPath`, `gpg.program`, `diff.external`,
	// `credential.helper`, any `alias.*` (a `!`-prefixed alias is an
	// arbitrary shell command), and so on. Rather than maintain a
	// denylist (which inevitably misses a key), classify ANY `git -c ...`
	// invocation as WRITE. Cited as MAJOR-3 in
	// docs/security-readonly-bypass.md.
	for i := 0; i < len(args); i++ {
		a := args[i]
		if a == "-c" || a == "--config-env" ||
			strings.HasPrefix(a, "--config-env=") {
			return KindWrite
		}
	}
	sub := firstNonFlag(args)
	switch sub {
	case "status", "log", "diff", "show",
		"blame", "describe", "remote",
		"rev-parse", "ls-files", "ls-remote", "shortlog",
		// cat-file --textconv (and pre-existing `git log --ext-diff`) can exec
		// a REPO-CONFIGURED filter/differ. That requires a pre-existing
		// malicious repo config on the host (inline `-c` is guarded above; env
		// vectors are denied by dangerousEnvVars), so it is repo-trust, not
		// inline command injection — an accepted residual, out of scope for W2
		// (Mi4). NOTE that `grep` is deliberately NOT in this plain-reader list.
		"cat-file", "show-ref", "for-each-ref", "count-objects":
		return KindRead
	case "grep":
		return gitGrepKind(args) // C2 — pager/-O exec guard
	case "tag":
		return gitTagKind(args)
	case "worktree":
		return gitWorktreeKind(args)
	case "reflog":
		return gitReflogKind(args)
	case "branch":
		return gitBranchKind(args)
	case "stash":
		return gitStashKind(args)
	case "config":
		return gitConfigKind(args)
	}
	return KindWrite
}

// gitGrepKind: `git grep <pattern>` reads, but -O / --open-files-in-pager
// opens the matching files in a pager/command, executing arbitrary shell
// (`git grep -O'touch x'`, `--open-files-in-pager='sh -c "…"'`). Even bare -O
// runs $GIT_PAGER/$PAGER/core.pager. Route ANY -O / --open-files-in-pager form
// to WRITE; plain git grep stays READ. The existing `git -c`/env guards do NOT
// cover -O (it is an explicit git-grep flag, not -c/env).
func gitGrepKind(args []string) Kind {
	for _, a := range args {
		if a == "--open-files-in-pager" ||
			strings.HasPrefix(a, "--open-files-in-pager=") {
			return KindWrite
		}
		// Short-flag bundle: scan for `O` up to the first value-consuming
		// short flag, whose remainder is that flag's argument, not flags.
		// git-grep value-taking short flags: -f FILE, -e PATTERN, -m NUM,
		// -A/-B/-C NUM. An `O` reached before any of those is the pager flag
		// (bare `-O`, bundled `-nO`, or glued `-O<cmd>`).
		if len(a) >= 2 && a[0] == '-' && a[1] != '-' {
			for j := 1; j < len(a); j++ {
				c := a[j]
				if c == 'O' {
					return KindWrite
				}
				if c == 'f' || c == 'e' || c == 'm' ||
					c == 'A' || c == 'B' || c == 'C' {
					break
				}
			}
		}
	}
	return KindRead
}

// gitTagKind: listing forms READ; create/delete/force WRITE.
func gitTagKind(args []string) Kind {
	hasList := false
	sawTag := false
	for _, a := range args {
		if !sawTag {
			if a == "tag" {
				sawTag = true
			}
			continue
		}
		switch a {
		case "-d", "-D":
			return KindWrite
		}
		if matchesAbbrev(a, "delete", "annotate", "sign", "message", "force", "create-reflog") {
			return KindWrite // -a/-s/-m create; -f force; --delete
		}
		if a == "-l" || (strings.HasPrefix(a, "-n") && a != "--") ||
			matchesAbbrev(a, "list", "contains", "no-contains", "points-at",
				"merged", "no-merged", "sort", "format", "column", "omit-empty") {
			hasList = true
			continue
		}
		if len(a) > 0 && a[0] != '-' {
			// a bare positional with a list flag present is a PATTERN (READ);
			// without one it is a NEW TAG NAME (create → WRITE).
			if !hasList {
				return KindWrite
			}
		}
	}
	return KindRead
}

// gitWorktreeKind: only `worktree list` reads.
func gitWorktreeKind(args []string) Kind {
	if secondNonFlag(args) == "list" { // args[0]=="worktree", args[1]=="list"
		return KindRead
	}
	return KindWrite // add/remove/move/prune/lock/unlock/repair, or bare
}

// gitReflogKind: bare `reflog` and `reflog show` read; expire/delete write.
func gitReflogKind(args []string) Kind {
	switch secondNonFlag(args) {
	case "", "show":
		return KindRead
	}
	return KindWrite // expire / delete
}

// gitBranchKind classifies `git branch ...`. Listing forms (`git branch`,
// `-a`, `-v`, `--list`, `-r`, ...) are READ, but `-d`/`-D`/`--delete`,
// `-m`/`-M`/`--move`, and `-c`/`-C`/`--copy` delete/rename/copy a ref — a
// state mutation that ran unsigned before (2026-06-15 rig hunt). Any of those
// ref-mutating flags => WRITE; otherwise READ.
func gitBranchKind(args []string) Kind {
	for _, a := range args {
		switch a {
		case "-d", "-D", "-m", "-M", "-c", "-C":
			return KindWrite
		}
		// `--delete`/`--move`/`--copy` and their GNU abbreviations (`--del`,
		// `--mov`, `--cop`) delete/rename/copy a ref. The listing flags
		// (`--list`, `--all`, `--verbose`, `--color`, `--column`,
		// `--contains`, `--merged`, `--remotes`, ...) are NOT prefixes of any
		// of these stems, so they stay READ.
		if matchesAbbrev(a, "delete", "move", "copy") {
			return KindWrite
		}
	}
	return KindRead
}

// gitStashKind classifies `git stash <sub>`. Bare `git stash` is
// shorthand for `git stash push` (mutating). Only `list` and `show`
// are read-only inspection.
func gitStashKind(args []string) Kind {
	// Find the subcommand after "stash" (skipping flags).
	seen := false
	for _, a := range args {
		if a == "" || strings.HasPrefix(a, "-") {
			continue
		}
		if !seen {
			// This is "stash" itself.
			seen = true
			continue
		}
		switch a {
		case "list", "show":
			return KindRead
		}
		return KindWrite
	}
	// Bare `git stash` (no sub) — defaults to `stash push`, which is write.
	return KindWrite
}

// gitConfigKind classifies `git config …` by OPERATION FORM, failing closed.
//
// READ is granted ONLY to an explicit query form: --get / --get-all /
// --get-regexp / --get-urlmatch / --get-color / --get-colorbool, --list / -l,
// or a bare `git config` with no key or value (prints usage). Those forms only
// print; their arguments are key names / regexes / files to read, never a set.
//
// EVERYTHING ELSE is WRITE:
//   - an explicit mutating flag: --add / --unset / --unset-all / --replace-all /
//     --rename-section / --remove-section / --edit / -e (and GNU abbreviations);
//   - the POSITIONAL set forms `KEY` and `KEY VALUE` — this was a confirmed
//     Tier-1 read-only bypass (2026-07-09): `git config user.name evil` and
//     `git config --global alias.x '!touch /tmp/pwned'` both mutate ~/.gitconfig
//     (the `!`-alias persists a shell-exec vector), yet the old rule saw no
//     write *flag* and fell through to READ, so they ran UNSIGNED;
//   - any unrecognized / ambiguous form (default-deny).
//
// Scope/file selectors (--global/--system/--local/--worktree/-f/--file) and
// output modifiers (--show-origin/--show-scope/--name-only/--type/--default)
// are NOT reads by themselves — they modify whichever operation follows, so
// they never flip the class in either direction. A VALUE that itself looks like
// a flag (`git config alias.x '!touch x'`) also cannot flip it: the positional
// KEY already forces WRITE, and no value can introduce a query flag.
func gitConfigKind(args []string) Kind {
	seenConfig := false
	hasRead := false       // an explicit query flag was seen
	hasPositional := false // a non-flag KEY/VALUE (positional set form)
	for _, a := range args {
		if !seenConfig {
			// Skip any leading git-level flags (e.g. --no-pager) up to the
			// "config" subcommand token itself.
			if a == "config" {
				seenConfig = true
			}
			continue
		}
		// Explicit mutating operation → WRITE immediately, fail-closed even if
		// a query flag is also present in a malformed command.
		if a == "-e" {
			return KindWrite
		}
		// Write subflags and their GNU abbreviations (`--rep`→replace-all,
		// `--uns`→unset, `--unset-a`→unset-all, `--rem`→remove-section,
		// `--ren`→rename-section, `--ed`→edit, ...). None of the query flags
		// below are prefixes of any dangerous stem, so they are disjoint.
		if matchesAbbrev(a, "set", "unset", "unset-all", "add", "replace-all",
			"remove-section", "rename-section", "edit") {
			return KindWrite
		}
		// Explicit query flag → this is a read.
		switch a {
		case "--get", "--get-all", "--get-regexp", "--get-urlmatch",
			"--get-color", "--get-colorbool", "--list", "-l":
			hasRead = true
			continue
		}
		// A non-flag token after "config", with no query flag governing it, is
		// a KEY (or VALUE) of a set — the positional-set WRITE form.
		if a != "" && !strings.HasPrefix(a, "-") {
			hasPositional = true
		}
	}
	if hasRead {
		return KindRead
	}
	if hasPositional {
		return KindWrite // positional KEY / KEY VALUE set — fail closed
	}
	// Bare `git config` (usage) or a query-modifier-only form with no key.
	return KindRead
}
