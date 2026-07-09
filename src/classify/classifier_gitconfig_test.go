package classify

import "testing"

// classifier_gitconfig_test.go pins the `git config` operation-FORM classifier.
//
// CONFIRMED bypass (2026-07-09): `git config user.name evil` and
// `git config --global alias.x '!touch /tmp/pwned'` are WRITES — they mutate
// ~/.gitconfig, and the `!`-prefixed alias persists a shell-exec vector that a
// later `git <alias>` runs. The old gitConfigKind detected only write *flags*
// (--unset/--add/…), so the positional-set form fell through to READ and ran
// UNSIGNED on a Tier-1 read-only server. The fix classifies by form and fails
// closed: WRITE for every set/mutate/unknown/exec form. READ is granted to
// explicit query forms AND (C3, 2026-07-10) the single-KEY get grammar
// `git config <key>`, which only prints a value — but `<key> <value>` sets,
// mutating flags, and the new-grammar bare verbs (`edit`/`set`/`unset`/…) all
// stay WRITE. Every WRITE row below is a set/mutation/exec that MUST require an
// approval tap; every READ row is a non-regression guard that queries stay
// tap-free.
func TestClassify_GitConfigForms(t *testing.T) {
	cases := []struct {
		name string
		cmd  string
		want Kind
	}{
		// --- WRITE: the reported bypass + every mutating/positional form ---
		{"positional KEY VALUE set (reported bypass)", "git config user.name evil", KindWrite},
		{"global alias shell-exec set (reported bypass)", "git config --global alias.x '!touch /tmp/x'", KindWrite},
		{"add", "git config --add core.x y", KindWrite},
		{"unset", "git config --unset core.x", KindWrite},
		{"replace-all", "git config --replace-all k v", KindWrite},
		{"-e edit", "git config -e", KindWrite},
		{"--edit", "git config --edit", KindWrite},
		{"remove-section", "git config --remove-section foo", KindWrite},
		{"global positional set", "git config --global user.email a@b.c", KindWrite},
		{"file positional set", "git config -f /tmp/cfg k v", KindWrite},
		// Extra fail-closed guards.
		{"unset-all", "git config --unset-all core.x", KindWrite},
		{"rename-section", "git config --rename-section old new", KindWrite},
		{"value that looks like a flag stays write", "git config alias.x '!touch x'", KindWrite},
		{"--file long form positional set", "git config --file /tmp/cfg k v", KindWrite},
		{"system positional set", "git config --system user.name evil", KindWrite},
		// C3 (2026-07-10): the single-KEY get form is now READ, but every WRITE
		// must stay WRITE. New-grammar bare subcommand verbs are the sharp edge:
		{"new-grammar edit opens editor (exec)", "git config edit", KindWrite},
		{"new-grammar bare set verb", "git config set user.name evil", KindWrite},
		{"new-grammar bare unset verb", "git config unset user.name", KindWrite},
		{"new-grammar get KEY (2 positionals) fail-closed", "git config get user.name", KindWrite},
		{"scoped edit still write", "git config --global edit", KindWrite},

		// --- READ: explicit query forms only ---
		{"--get", "git config --get user.name", KindRead},
		{"--list", "git config --list", KindRead},
		{"-l", "git config -l", KindRead},
		{"--get-regexp", "git config --get-regexp '^alias'", KindRead},
		{"--global --get", "git config --global --get user.name", KindRead},
		{"--get-all", "git config --get-all remote.origin.url", KindRead},
		{"bare git config", "git config", KindRead},
		// C3: single-KEY get grammar prints the value — a common daily read.
		{"single-KEY get user.name", "git config user.name", KindRead},
		{"single-KEY get user.email", "git config user.email", KindRead},
		{"scoped single-KEY get", "git config --global user.name", KindRead},
		{"new-grammar bare list verb read", "git config list", KindRead},
		// Modifiers on a query stay read.
		{"--show-origin --get read", "git config --show-origin --get user.name", KindRead},
		{"--get-urlmatch read", "git config --get-urlmatch http.https://x.y", KindRead},
		{"-f FILE --list read", "git config -f /tmp/cfg --list", KindRead},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := Classify(tc.cmd); got != tc.want {
				t.Errorf("Classify(%q) = %s; want %s", tc.cmd, got, tc.want)
			}
		})
	}
}
