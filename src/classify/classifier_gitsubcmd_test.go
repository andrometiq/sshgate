package classify

import "testing"

// TestClassify_GitSubcommandForm pins the FORM-based classification of git
// subcommands that are read-only ONLY in their bare/list/query form and become
// WRITES the moment a positional name or a mutating subverb is supplied.
//
// Two of these were CONFIRMED live Tier-1 read-only bypasses (2026-07-09):
//   - `git branch newfeature` creates a ref (writes .git/refs/heads/…)
//   - `git remote add o url`   writes a remote to .git/config
//
// Both classified READ under the old rule and would have run UNSIGNED on a
// read-only server. A regression on any WRITE row here re-opens that hole.
func TestClassify_GitSubcommandForm(t *testing.T) {
	cases := []struct {
		name string
		cmd  string
		want Kind
	}{
		// --- CONFIRMED exploits: now WRITE ---
		{"branch create positional", "git branch newfeature", KindWrite},
		{"branch create + start-point", "git branch feature main", KindWrite},
		{"remote add", "git remote add o url", KindWrite},

		// --- git branch: WRITE forms ---
		{"branch -d delete", "git branch -d old", KindWrite},
		{"branch -D force delete", "git branch -D old", KindWrite},
		{"branch -m rename", "git branch -m old new", KindWrite},
		{"branch -M force rename", "git branch -M old new", KindWrite},
		{"branch -c copy", "git branch -c old new", KindWrite},
		{"branch -C force copy", "git branch -C old new", KindWrite},
		{"branch --delete", "git branch --delete old", KindWrite},
		{"branch --move", "git branch --move old new", KindWrite},
		{"branch --copy", "git branch --copy old new", KindWrite},
		{"branch --set-upstream-to=", "git branch --set-upstream-to=origin/x", KindWrite},
		{"branch --set-upstream-to value", "git branch --set-upstream-to origin/x", KindWrite},
		{"branch -u upstream", "git branch -u origin/x", KindWrite},
		{"branch --unset-upstream", "git branch --unset-upstream feat", KindWrite},
		{"branch --edit-description", "git branch --edit-description", KindWrite},
		{"branch -f force create", "git branch -f newfeature main", KindWrite},
		{"branch --force create", "git branch --force newfeature main", KindWrite},

		// --- git branch: READ forms ---
		{"branch bare", "git branch", KindRead},
		{"branch -a", "git branch -a", KindRead},
		{"branch -r", "git branch -r", KindRead},
		{"branch -v", "git branch -v", KindRead},
		{"branch -vv", "git branch -vv", KindRead},
		{"branch --list", "git branch --list", KindRead},
		{"branch --list pattern", "git branch --list feat/*", KindRead},
		{"branch -l pattern", "git branch -l feat/*", KindRead},
		{"branch --show-current", "git branch --show-current", KindRead},
		{"branch --all --verbose", "git branch --all --verbose", KindRead},
		{"branch --merged", "git branch --merged", KindRead},
		{"branch --no-merged", "git branch --no-merged", KindRead},
		{"branch --color", "git branch --color", KindRead},
		// Regression guard: --contains HEAD is a QUERY (its operand is a commit,
		// not a new branch name) and MUST stay READ.
		{"branch --contains HEAD", "git branch --contains HEAD", KindRead},
		{"branch --no-contains HEAD", "git branch --no-contains HEAD", KindRead},
		{"branch --points-at HEAD", "git branch --points-at HEAD", KindRead},

		// --- git remote: WRITE forms ---
		{"remote remove", "git remote remove o", KindWrite},
		{"remote rm", "git remote rm o", KindWrite},
		{"remote rename", "git remote rename a b", KindWrite},
		{"remote set-url", "git remote set-url o url2", KindWrite},
		{"remote set-head", "git remote set-head o main", KindWrite},
		{"remote set-branches", "git remote set-branches o main", KindWrite},
		{"remote prune", "git remote prune o", KindWrite},
		{"remote update", "git remote update", KindWrite},

		// --- git remote: READ forms ---
		{"remote bare", "git remote", KindRead},
		{"remote -v", "git remote -v", KindRead},
		{"remote --verbose", "git remote --verbose", KindRead},
		{"remote show", "git remote show o", KindRead},
		{"remote get-url", "git remote get-url o", KindRead},

		// --- audited siblings (fail-closed / already-correct) ---
		{"notes add", "git notes add", KindWrite},
		{"submodule add", "git submodule add url path", KindWrite},
		{"worktree add", "git worktree add ../x", KindWrite},
		{"worktree list", "git worktree list", KindRead},
		{"tag create", "git tag v1.0", KindWrite},
		{"tag -d", "git tag -d v1", KindWrite},
		{"tag -f", "git tag -f v1", KindWrite},
		{"tag bare", "git tag", KindRead},
		{"tag -l", "git tag -l", KindRead},
		{"stash bare (push)", "git stash", KindWrite},
		{"checkout", "git checkout main", KindWrite},
		{"switch", "git switch main", KindWrite},
		{"restore", "git restore f", KindWrite},
	}
	for _, c := range cases {
		if got := Classify(c.cmd); got != c.want {
			t.Errorf("%s: Classify(%q) = %v, want %v", c.name, c.cmd, got, c.want)
		}
	}
}
