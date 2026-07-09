package classify

import "testing"

// classifier_abbrev_test.go pins the GNU long-option ABBREVIATION bypasses.
//
// GNU getopt_long accepts ANY unambiguous prefix of a long option, so a rule
// that matched a dangerous `--flag` only by EXACT token let the abbreviated
// form (`--clea` for `--clear`, `--rep` for `--replace-all`, ...) fall through
// to KindRead and run unsigned on a read-only server. Every WRITE row below was
// a CONFIRMED bypass verified against the real binaries; every READ row is a
// non-regression guard that the prefix-matching must NOT over-classify.
//
// Cited as roadmap #21 stopgap (the structural cure is argv-exec, #22).
func TestClassify_LongOptionAbbreviationBypasses(t *testing.T) {
	cases := []struct {
		name string
		cmd  string
		want Kind
	}{
		// --- sort --output / --compress-program abbreviations ---
		{"sort --o= abbrev clobbers", "sort --o=/tmp/evil in", KindWrite},
		{"sort --out= abbrev clobbers", "sort --out=/tmp/evil in", KindWrite},
		{"sort --outp= abbrev clobbers", "sort --outp=/tmp/evil in", KindWrite},
		{"sort --output= full", "sort --output=/tmp/evil in", KindWrite},
		{"sort --o separate-value clobbers", "sort --o /tmp/evil in", KindWrite},
		{"sort --out separate-value clobbers", "sort --out /tmp/evil in", KindWrite},
		{"sort --compr= abbrev exec", "sort --compr=/tmp/evil in", KindWrite},
		{"sort --compress= abbrev exec", "sort --compress=/bin/sh in", KindWrite},
		{"sort --compress-program full", "sort --compress-program /bin/sh in", KindWrite},
		// sort READ non-regressions: benign long options must NOT match.
		{"sort plain read", "sort f", KindRead},
		{"sort -k2 read", "sort -k2 f", KindRead},
		{"sort --numeric-sort read", "sort --numeric-sort f", KindRead},
		{"sort --reverse read", "sort --reverse f", KindRead},
		{"sort --check read", "sort --check f", KindRead},
		{"sort --ignore-case read", "sort --ignore-case f", KindRead},
		{"sort --key read", "sort --key=2 f", KindRead},
		{"sort --field-separator read", "sort --field-separator=: f", KindRead},
		{"sort --unique read", "sort --unique f", KindRead},
		{"sort --merge read", "sort --merge f", KindRead},

		// --- awk -i inplace / --in-place / -f - / -f /dev/stdin ---
		{"awk -i inplace overwrite", "awk -i inplace '{print}' file", KindWrite},
		{"awk --in-place overwrite", "awk --in-place '{print}' file", KindWrite},
		{"awk --in= abbrev overwrite", "awk --in=inplace '{print}' file", KindWrite},
		{"awk -f - program from stdin", "awk -f - file", KindWrite},
		{"awk -f /dev/stdin program from stdin", "awk -f /dev/stdin file", KindWrite},
		{"awk --file - program from stdin", "awk --file - file", KindWrite},
		{"awk --file=/dev/stdin program from stdin", "awk --file=/dev/stdin file", KindWrite},
		{"awk --fil= abbrev file", "awk --fil=/tmp/prog.awk file", KindWrite},
		// awk READ non-regressions.
		{"awk plain print read", "awk '{print}' f", KindRead},
		{"awk -F field-sep read", "awk -F: '{print $1}' f", KindRead},
		{"awk --field-separator read", "awk --field-separator=: '{print $1}' f", KindRead},
		{"awk comparison read", `awk '$3>100' /etc/passwd`, KindRead},

		// --- dmesg clear / console abbreviations ---
		{"dmesg --clea abbrev clear", "dmesg --clea", KindWrite},
		{"dmesg --clear full", "dmesg --clear", KindWrite},
		{"dmesg --read-c abbrev read-clear", "dmesg --read-c", KindWrite},
		{"dmesg --console-l abbrev level", "dmesg --console-l 1", KindWrite},
		{"dmesg --console-of abbrev off", "dmesg --console-of", KindWrite},
		{"dmesg --console-on abbrev on", "dmesg --console-on", KindWrite},
		// dmesg READ non-regressions: color/ctime/decode/etc are NOT dangerous.
		{"dmesg plain read", "dmesg", KindRead},
		{"dmesg --color read", "dmesg --color", KindRead},
		{"dmesg --ctime read", "dmesg --ctime", KindRead},
		{"dmesg --decode read", "dmesg --decode", KindRead},
		{"dmesg --human read", "dmesg --human", KindRead},
		{"dmesg --kernel read", "dmesg --kernel", KindRead},
		{"dmesg --facility read", "dmesg --facility=kern", KindRead},

		// --- ss --kill abbreviation ---
		{"ss --kil abbrev kill", "ss --kil", KindWrite},
		{"ss --kill full", "ss --kill", KindWrite},
		{"ss --ki abbrev kill", "ss --ki", KindWrite},
		// ss READ non-regressions.
		{"ss -tlnp read", "ss -tlnp", KindRead},
		{"ss --listening read", "ss --listening", KindRead},
		{"ss --tcp read", "ss --tcp", KindRead},
		{"ss --info read", "ss --info", KindRead},

		// --- lastlog --clear / --set abbreviations ---
		{"lastlog --cl abbrev clear", "lastlog --cl", KindWrite},
		{"lastlog --clear full", "lastlog --clear", KindWrite},
		{"lastlog --se abbrev set", "lastlog --se", KindWrite},
		{"lastlog --set full", "lastlog --set", KindWrite},
		// lastlog READ non-regressions.
		{"lastlog plain read", "lastlog", KindRead},
		{"lastlog -u read", "lastlog -u root", KindRead},

		// --- date --set abbreviation ---
		{"date --se= abbrev set clock", "date --se=010100002020", KindWrite},
		{"date --set= full", "date --set=010100002020", KindWrite},
		{"date --set separate value", "date --set 010100002020", KindWrite},
		// date READ non-regressions: display flags must stay read.
		{"date plain read", "date", KindRead},
		{"date -u read", "date -u", KindRead},
		{"date --utc read", "date --utc", KindRead},
		{"date -d read", "date -d yesterday", KindRead},
		{"date --date read", "date --date=yesterday", KindRead},
		{"date -R read", "date -R", KindRead},

		// --- hostname --file abbreviation (reads new name from FILE and SETS) ---
		{"hostname --fi= abbrev file", "hostname --fi=/tmp/name", KindWrite},
		{"hostname --file= full", "hostname --file=/tmp/name", KindWrite},
		{"hostname --file separate value", "hostname --file /tmp/name", KindWrite},
		// hostname READ non-regressions.
		{"hostname plain read", "hostname", KindRead},
		{"hostname --fqdn read", "hostname --fqdn", KindRead},
		{"hostname -f read", "hostname -f", KindRead},
		{"hostname --short read", "hostname --short", KindRead},
		{"hostname --all-ip read", "hostname -I", KindRead},

		// --- git config write-flag abbreviations ---
		{"git config --rep abbrev replace-all", "git config --rep core.x y", KindWrite},
		{"git config --replace-all full", "git config --replace-all core.x y", KindWrite},
		{"git config --unset-a abbrev unset-all", "git config --unset-a core.x", KindWrite},
		{"git config --uns abbrev unset", "git config --uns core.x", KindWrite},
		{"git config --add full", "git config --add core.x y", KindWrite},
		{"git config --rem abbrev remove-section", "git config --rem core", KindWrite},
		{"git config --ren abbrev rename-section", "git config --ren old new", KindWrite},
		{"git config --ed abbrev edit", "git config --ed", KindWrite},
		// git config READ non-regressions.
		{"git config --get read", "git config --get core.x", KindRead},
		{"git config --get-all read", "git config --get-all core.x", KindRead},
		{"git config --list read", "git config --list", KindRead},
		{"git config -l read", "git config -l", KindRead},
		{"git config --global --get read", "git config --global --get user.name", KindRead},
		// C3 (2026-07-10): the single-KEY get grammar `git config <key>` PRINTS
		// the value — a read. `<key> <value>` sets and bare mutating verbs stay
		// WRITE (see classifier_gitconfig_test.go for the full matrix).
		{"git config single-KEY get read", "git config user.name", KindRead},
		{"git config KEY VALUE set stays write", "git config user.name evil", KindWrite},
		{"git config new-grammar edit stays write", "git config edit", KindWrite},

		// --- git branch ref-mutation abbreviations ---
		{"git branch --del abbrev delete", "git branch --del foo", KindWrite},
		{"git branch --delete full", "git branch --delete foo", KindWrite},
		{"git branch --mov abbrev move", "git branch --mov a b", KindWrite},
		{"git branch --cop abbrev copy", "git branch --cop a b", KindWrite},
		// git branch READ non-regressions.
		{"git branch plain read", "git branch", KindRead},
		{"git branch -a read", "git branch -a", KindRead},
		{"git branch --list read", "git branch --list", KindRead},
		{"git branch --color read", "git branch --color", KindRead},
		{"git branch --contains read", "git branch --contains HEAD", KindRead},
		{"git branch --merged read", "git branch --merged", KindRead},
		{"git branch --remotes read", "git branch --remotes", KindRead},
		{"git branch --verbose read", "git branch --verbose", KindRead},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := Classify(tc.cmd); got != tc.want {
				t.Errorf("Classify(%q) = %s; want %s", tc.cmd, got, tc.want)
			}
		})
	}
}

// TestMatchesAbbrev unit-tests the abbreviation helper directly.
func TestMatchesAbbrev(t *testing.T) {
	cases := []struct {
		name string
		arg  string
		opts []string
		want bool
	}{
		{"exact match", "--clear", []string{"clear"}, true},
		{"prefix abbrev", "--clea", []string{"clear"}, true},
		{"shortest 1-char prefix", "--c", []string{"clear"}, true},
		{"strips =value", "--out=/tmp/x", []string{"output"}, true},
		{"strips =value abbrev", "--o=/tmp/x", []string{"output"}, true},
		{"no match different stem", "--color", []string{"clear"}, false},
		{"not a long option", "-o", []string{"output"}, false},
		{"single dash long opt ignored", "-output", []string{"output"}, false},
		{"empty body after dashes", "--", []string{"output"}, false},
		{"empty =value strips to nothing", "--=x", []string{"output"}, false},
		{"longer than option not a prefix", "--outputs", []string{"output"}, false},
		{"matches one of several", "--ren", []string{"replace-all", "rename-section"}, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := matchesAbbrev(tc.arg, tc.opts...); got != tc.want {
				t.Errorf("matchesAbbrev(%q, %v) = %v; want %v", tc.arg, tc.opts, got, tc.want)
			}
		})
	}
}
