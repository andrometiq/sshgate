package classify

import (
	"strings"
	"testing"

	"github.com/karthikeyan5/sshgate/internal/redteam"
)

// TestClassify_W2 pins every W2 addition with a positive (now-READ) case AND an
// adversarial (still-WRITE) case, at the classifier level so `make test` proves
// fail-closed WITHOUT Docker (classification precedes exec, so these hold
// whether or not the tool is installed). It is the unit-level counterpart to
// the Dockerized gate-redteam campaign. The four M5 CRITICAL/CRIT/MAJOR
// exploits (git grep -O, sed '/./e', sed '\|.|e', docker compose config -o) are
// asserted WRITE explicitly — a regression here is a build blocker.
func TestClassify_W2(t *testing.T) {
	cases := []struct {
		name string
		cmd  string
		want Kind
	}{
		// --- W2-3a nil read tools (READ) ---
		{"jq", "jq -r .x f", KindRead},
		{"cut", "cut -d: -f1 /etc/passwd", KindRead},
		{"tr", "tr -d x", KindRead},
		{"column", "column -t f", KindRead},
		{"zgrep", "zgrep e f.gz", KindRead},
		{"zcat", "zcat f.gz", KindRead},
		{"nl", "nl f", KindRead},
		{"tac", "tac f", KindRead},
		{"rev", "rev f", KindRead},
		{"md5sum", "md5sum f", KindRead},
		{"sha256sum", "sha256sum f", KindRead},
		{"cksum", "cksum f", KindRead},
		{"b2sum", "b2sum f", KindRead},
		{"realpath", "realpath f", KindRead},
		{"basename", "basename f", KindRead},
		{"dirname", "dirname f", KindRead},
		{"lscpu", "lscpu", KindRead},
		{"lsblk", "lsblk", KindRead},
		{"nproc", "nproc", KindRead},
		{"vmstat", "vmstat 1 1", KindRead},
		{"iostat", "iostat", KindRead},
		{"mpstat", "mpstat", KindRead},
		{"getent", "getent passwd root", KindRead},
		{"type", "type ls", KindRead},
		{"test", "test -f /etc/hosts", KindRead},
		{"bracket", "[ -d /var ]", KindRead},

		// --- W2-3a arg-rules (READ / WRITE) ---
		{"tree read", "tree /etc", KindRead},
		{"tree -o write", "tree -o /tmp/x", KindWrite},
		{"tree -o<file> write", "tree -o/tmp/x", KindWrite},
		{"crontab -l read", "crontab -l", KindRead},
		{"crontab -e write", "crontab -e", KindWrite},
		{"crontab -r write", "crontab -r", KindWrite},
		{"crontab FILE write", "crontab /tmp/newtab", KindWrite},
		{"crontab bare write", "crontab", KindWrite},
		{"sysctl -a read", "sysctl -a", KindRead},
		{"sysctl key read", "sysctl kernel.hostname", KindRead},
		{"sysctl -w write", "sysctl -w vm.swappiness=1", KindWrite},
		{"sysctl -p write", "sysctl -p", KindWrite},
		{"sysctl assign write", "sysctl vm.swappiness=1", KindWrite},
		{"mount bare read", "mount", KindRead},
		{"mount -l read", "mount -l", KindRead},
		{"mount -t read", "mount -t ext4", KindRead},
		{"mount dev+target write", "mount /dev/sda1 /mnt", KindWrite},
		{"mount by-fstab write", "mount /mnt", KindWrite},
		{"mount -a write", "mount -a", KindWrite},
		{"command -v read", "command -v docker", KindRead},
		{"command -V read", "command -V ls", KindRead},
		{"command wrap write", "command ls", KindWrite},
		{"command -p write", "command -p env", KindWrite},
		{"ulimit -a read", "ulimit -a", KindRead},
		{"ulimit -n read", "ulimit -n", KindRead},
		{"ulimit set write", "ulimit -n 4096", KindWrite},
		{"history read", "history", KindRead},
		{"history N read", "history 20", KindRead},
		{"history -c write", "history -c", KindWrite},
		{"history -w write", "history -w /tmp/x", KindWrite},
		{"watch read", "watch -n 5 df -h", KindRead},
		{"watch bare wrap read", "watch df", KindRead},
		{"watch wrap write", "watch rm x", KindWrite},
		{"watch interval wrap write", "watch -n 5 rm x", KindWrite},
		{"watch quoted compound write", "watch 'df; rm x'", KindWrite},
		{"watch no command write", "watch -n 5", KindWrite},

		// --- W2-3a interpreter version probe (READ / WRITE) ---
		{"node --version read", "node --version", KindRead},
		{"node -v read", "node -v", KindRead},
		{"python3 -V read", "python3 -V", KindRead},
		{"python3 --version read", "python3 --version", KindRead},
		{"perl -v read", "perl -v", KindRead},
		{"ruby --version read", "ruby --version", KindRead},
		{"python3 -c write", "python3 -c 'print(1)'", KindWrite},
		{"ruby -v write (program mode)", "ruby -v", KindWrite},
		{"python -v write (verbose repl)", "python -v", KindWrite},
		{"python3 bare repl write", "python3", KindWrite},
		{"python3 --version foo write", "python3 --version foo", KindWrite},
		{"node -e write", "node -e 'x'", KindWrite},

		// --- W2-3b kubectl (READ / WRITE) ---
		{"kubectl get read", "kubectl get pods", KindRead},
		{"kubectl config view read", "kubectl config view", KindRead},
		{"kubectl cluster-info read", "kubectl cluster-info", KindRead},
		{"kubectl exec write", "kubectl exec x -- sh", KindWrite},
		{"kubectl config set-context write", "kubectl config set-context c", KindWrite},
		{"kubectl cluster-info dump write", "kubectl cluster-info dump", KindWrite},
		{"kubectl apply write", "kubectl apply -f x", KindWrite},
		{"kubectl delete write", "kubectl delete pod x", KindWrite},

		// --- W2-3b docker (READ / WRITE) — with M1 ---
		{"docker system df read", "docker system df", KindRead},
		{"docker network ls read", "docker network ls", KindRead},
		{"docker volume ls read", "docker volume ls", KindRead},
		{"docker compose ps read", "docker compose ps", KindRead},
		{"docker compose logs read", "docker compose logs", KindRead},
		{"docker container ls read", "docker container ls", KindRead},
		{"docker compose config read", "docker compose config", KindRead},
		{"M1: compose config -o write", "docker compose config -o /tmp/x", KindWrite},
		{"M1: compose config --output= write", "docker compose config --output=/tmp/x", KindWrite},
		{"M1: compose config -o<file> write", "docker compose config -o/tmp/x", KindWrite},
		{"docker compose up write", "docker compose up", KindWrite},
		{"docker network rm write", "docker network rm n", KindWrite},
		{"docker system prune write", "docker system prune", KindWrite},

		// --- W2-3b git (READ / WRITE) — with C2 ---
		{"git tag read", "git tag", KindRead},
		{"git tag -l read", "git tag -l", KindRead},
		{"git grep read", "git grep TODO", KindRead},
		{"git worktree list read", "git worktree list", KindRead},
		{"git cat-file read", "git cat-file -p HEAD", KindRead},
		{"git show-ref read", "git show-ref", KindRead},
		{"git for-each-ref read", "git for-each-ref", KindRead},
		{"git reflog read", "git reflog", KindRead},
		{"C2: git grep -O write", "git grep -O'touch /tmp/x' TODO", KindWrite},
		{"C2: git grep --open-files-in-pager write", "git grep --open-files-in-pager='sh -c id' p", KindWrite},
		{"C2: git grep -nO write", "git grep -nO'cmd' p", KindWrite},
		{"git tag -d write", "git tag -d v1", KindWrite},
		{"git tag create write", "git tag v2", KindWrite},
		{"git worktree add write", "git worktree add ../x", KindWrite},
		{"git reflog expire write", "git reflog expire --all", KindWrite},
		{"git fetch --dry-run write", "git fetch --dry-run", KindWrite},
		{"git -c core.pager grep write", "git -c core.pager='!x' grep p", KindWrite},

		// --- W2-3b systemctl (READ / WRITE) ---
		{"systemctl show-environment read", "systemctl show-environment", KindRead},
		{"systemctl list-dependencies read", "systemctl list-dependencies nginx", KindRead},
		{"systemctl set-environment write", "systemctl set-environment X=1", KindWrite},

		// --- W2-3b wget (READ / WRITE) — M3 ---
		{"M3: wget -qO- read", "wget -qO- https://x", KindRead},
		{"M3: wget -nvO- read", "wget -nvO- https://x", KindRead},
		{"wget -O- read", "wget -O- https://x", KindRead},
		{"M3: wget -qOfile write", "wget -qOfile https://x", KindWrite},
		{"M3: wget -t3O- write (t consumes)", "wget -t3O- https://x", KindWrite},
		{"M3: wget -qo- write (lowercase log)", "wget -qo- https://x", KindWrite},
		{"M3: wget -qO- -o log write", "wget -qO- -o /tmp/log https://x", KindWrite},
		{"wget bare URL write", "wget https://x", KindWrite},

		// --- W2-3c sed (READ / WRITE) — C1 + M2 ---
		{"sed s/warn/err/ read", "sed 's/warn/err/' f", KindRead},
		{"sed s/error/warn/ read", "sed 's/error/warn/' f", KindRead},
		{"sed -n /error/p read", "sed -n '/error/p' f", KindRead},
		{"sed /error/d read", "sed '/error/d' f", KindRead},
		{"sed s/end$// read", "sed 's/end$//' f", KindRead},
		{"sed s|/etc|/opt| read", "sed 's|/etc|/opt|' f", KindRead},
		{"sed s/a\\/e/b/ read", "sed 's/a\\/e/b/' f", KindRead},
		{"sed \\#/etc/#d read (custom-delim, cmd d)", "sed '\\#/etc/#d' f", KindRead},
		{"sed s///e write", "sed 's/.*/id/e'", KindWrite},
		{"sed -e s///e write", "sed -e 's/X/Y/e' f", KindWrite},
		{"sed s///w write", "sed 's/X/Y/w /tmp/log' f", KindWrite},
		{"sed 1r write", "sed '1r /etc/passwd' f", KindWrite},
		{"sed e cmd write", "sed 'e touch /tmp/x' f", KindWrite},
		{"sed s|a|b|e write", "sed 's|a|b|e' f", KindWrite},
		{"sed $w write", "sed '$w /tmp/x' f", KindWrite},
		{"sed spaced /re/ w write", "sed '/re/ w /tmp/x' f", KindWrite},
		{"sed -i write", "sed -i 's/a/b/' f", KindWrite},
		{"C1: sed /./e touch write", "sed '/./e touch /tmp/x' f", KindWrite},
		{"C1: sed /pat/e write", "sed '/pat/e' f", KindWrite},
		{"C1: sed 1,/pat/e write", "sed '1,/pat/e' f", KindWrite},
		{"C1: sed /x/e wall write", "sed '/x/e wall pwned' f", KindWrite},
		{"M2: sed \\|.|e write", "sed '\\|.|e echo pwned' f", KindWrite},
		{"M2: sed \\#/etc/#w write", "sed '\\#/etc/#w /tmp/x' f", KindWrite},

		// --- W2-3d redirects (READ / WRITE) — B1 ---
		{"ls 2>&1 read", "ls x 2>&1", KindRead},
		{"find 2>/dev/null read", "find / -name '*.pid' 2>/dev/null", KindRead},
		{"docker logs 2>&1 read", "docker logs app 2>&1", KindRead},
		{"cat 2>&- read", "cat /etc/hosts 2>&-", KindRead},
		{"journalctl 2>/dev/null read", "journalctl -u nginx 2>/dev/null", KindRead},
		{"df -h 2>&1 read", "df -h 2>&1", KindRead},
		{"df >/dev/null 2>&1 read", "df -h >/dev/null 2>&1", KindRead},
		{"ls &>/dev/null read", "ls &>/dev/null", KindRead},
		{"echo >&2 read", "echo hi >&2", KindRead},
		{"journalctl 1>&2 read", "journalctl -u nginx 1>&2", KindRead},
		{"echo > file write", "echo x > /tmp/y", KindWrite},
		{"echo 2>file write", "echo x 2>/tmp/log", KindWrite},
		{"echo 1>file write", "echo x 1>/tmp/o", KindWrite},
		{"echo &>file write", "echo x &>/tmp/all", KindWrite},
		{"echo 2>>file write", "echo x 2>>/tmp/log", KindWrite},
		{"echo >&file write", "echo x >&file", KindWrite},
		{"echo data 2> file write", "echo data 2> /tmp/x", KindWrite},
		{"B1: 2>&1 >file still write", "ls 2>&1 >file", KindWrite},
		{"B1: bare & splits to write", "ls & rm x", KindWrite},
		{"B1: background & write", "touch x &", KindWrite},
		{"B1: 2>&1 && rm x splits", "ls 2>&1 && rm x", KindWrite},
		{"B1: 2>&1 & rm x splits", "ls 2>&1 & rm x", KindWrite},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			if got := Classify(tc.cmd); got != tc.want {
				t.Errorf("Classify(%q) = %s; want %s", tc.cmd, got, tc.want)
			}
		})
	}
}

// TestClassify_W2_M5Exploits isolates the four exploits the v1 spec + red-team
// corpus were MISSING (M5). Each MUST classify WRITE regardless of whether the
// tool is installed — classification precedes exec, so a Tier-1 gate denies
// them before any unsigned run. A regression here is a build blocker.
func TestClassify_W2_M5Exploits(t *testing.T) {
	for _, cmd := range []string{
		"git grep -O'touch /tmp/x' TODO",
		"git grep --open-files-in-pager='sh -c id' p",
		"sed '/./e touch /tmp/x' f",
		"sed '/pat/e' f",
		"sed '\\|.|e echo pwned' f",
		"sed '\\#/etc/#w /tmp/x' f",
		"docker compose config -o /tmp/x",
	} {
		if got := Classify(cmd); got != KindWrite {
			t.Errorf("M5 exploit Classify(%q) = %s; want write", cmd, got)
		}
	}
}

// TestClassify_RedteamWriteToolsAreWrite proves — WITHOUT Docker — that the
// W2-relevant write-attack rows in the gate-redteam corpus classify WRITE, so a
// Tier-1 gate DENIES each before exec. It covers the whole classifier-write-tools
// category plus the four M5 rows that v1 was missing (git grep -O, sed '/./e',
// sed '\|.|e', docker compose config -o), explicitly confirming they are among
// the denied. This is the classifier-level guarantee behind the campaign's
// "0 bypasses" bar. The campaign templates real canary/beacon paths; here we
// use placeholders (classification is path-independent).
//
// NOTE: the whole git-write category is not exhaustively asserted here. It once
// contained a PRE-EXISTING (not W2) gap — `git config --global alias.x '!touch'`
// classified READ because gitConfigKind only detected write-*flags*, missing the
// modern `git config KEY VALUE` positional-set form (a real Tier-1 read-only
// bypass). That gap is now CLOSED: gitConfigKind classifies by operation form
// and fails closed on any positional set. The adversarial matrix lives in
// classifier_gitconfig_test.go (TestClassify_GitConfigForms).
func TestClassify_RedteamWriteToolsAreWrite(t *testing.T) {
	atk := redteam.Corpus("/canary", "/secret")
	sawGitGrepO, sawSedSlashE, sawSedCustomDelim, sawComposeO := false, false, false, false
	for _, a := range atk {
		if a.Category == "classifier-write-tools" {
			if got := Classify(a.Cmd); got != KindWrite {
				t.Errorf("redteam classifier-write-tools row Classify(%q) = %s; want write (BYPASS)", a.Cmd, got)
			}
		}
		switch {
		case strings.HasPrefix(a.Cmd, "git grep -O"):
			sawGitGrepO = true
			if Classify(a.Cmd) != KindWrite {
				t.Errorf("M5 git grep -O row is not WRITE: %q", a.Cmd)
			}
		case strings.HasPrefix(a.Cmd, "sed '/./e"):
			sawSedSlashE = true
		case strings.HasPrefix(a.Cmd, `sed '\|.|e`):
			sawSedCustomDelim = true
		case strings.HasPrefix(a.Cmd, "docker compose config -o"):
			sawComposeO = true
		}
	}
	if !sawGitGrepO || !sawSedSlashE || !sawSedCustomDelim || !sawComposeO {
		t.Errorf("missing an M5 row in the redteam corpus: gitGrepO=%v sedSlashE=%v sedCustomDelim=%v composeO=%v",
			sawGitGrepO, sawSedSlashE, sawSedCustomDelim, sawComposeO)
	}
}
