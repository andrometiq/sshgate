package classify

import "testing"

// classifier_reviewfix_test.go pins the five read-only-gate bypasses closed by
// the 2026-07-10 adversarial triple review on feat/v1-release-polish. Each WRITE
// row is a confirmed unsigned-exec / arbitrary-write primitive reproduced against
// the real classifier; each READ row is a non-regression guard so the fix does
// not over-tax a legitimate diagnostic. All fixes fail closed.
func TestClassify_ReviewFixes(t *testing.T) {
	cases := []struct {
		name string
		cmd  string
		want Kind
	}{
		// --- SEC-1: `command` wraps + RUNS the named binary; a -v/-V buried in
		// the WRAPPED command's args must NOT be read as command's describe flag. ---
		{"SEC-1 command rm -v exploit", "command rm -v -rf /srv/data", KindWrite},
		{"SEC-1 command sh -v -c exploit", "command sh -v -c 'rm -rf /'", KindWrite},
		{"SEC-1 command umount -v exploit", "command umount -v /mnt", KindWrite},
		{"SEC-1 command -v docker describe read", "command -v docker", KindRead},
		{"SEC-1 command ls wrapped write", "command ls", KindWrite},
		{"SEC-1 command -p env still executes", "command -p env", KindWrite},

		// --- SEC-2: git diff/show/log --output=FILE writes/clobbers a file. ---
		{"SEC-2 git diff --output= glued", "git diff --output=/home/u/.ssh/authorized_keys", KindWrite},
		{"SEC-2 git diff --output space", "git diff --output /tmp/x", KindWrite},
		{"SEC-2 git show --output= glued", "git show --output=/tmp/x HEAD", KindWrite},
		{"SEC-2 git show --output space", "git show --output /tmp/x HEAD", KindWrite},
		{"SEC-2 git log -p --output=", "git log -p --output=/tmp/x", KindWrite},
		{"SEC-2 git log --output=", "git log --output=/tmp/x", KindWrite},
		{"SEC-2 plain git diff read", "git diff", KindRead},
		{"SEC-2 plain git show HEAD read", "git show HEAD", KindRead},
		{"SEC-2 plain git log --oneline read", "git log --oneline", KindRead},
		{"SEC-2 git diff -O orderfile read", "git diff -O/tmp/order", KindRead},

		// --- C1: `file -C`/`--compile` compiles a .mgc file to disk. ---
		{"C1 file -C write", "file -C", KindWrite},
		{"C1 file -C -m write", "file -C -m /etc/magic", KindWrite},
		{"C1 file --compile write", "file --compile -m foo", KindWrite},
		{"C1 file PATH read", "file /etc/hosts", KindRead},
		{"C1 file -i read", "file -i x", KindRead},
		{"C1 file --mime read", "file --mime x", KindRead},

		// --- SEC-3: sysctl --system / -f FILE / -S re-apply config to the kernel. ---
		{"SEC-3 sysctl --system write", "sysctl --system", KindWrite},
		{"SEC-3 sysctl -f FILE write", "sysctl -f /etc/sysctl.conf", KindWrite},
		{"SEC-3 sysctl -S write", "sysctl -S", KindWrite},
		{"SEC-3 sysctl -a read", "sysctl -a", KindRead},
		{"SEC-3 sysctl read a key", "sysctl vm.swappiness", KindRead},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := Classify(tc.cmd); got != tc.want {
				t.Errorf("Classify(%q) = %s; want %s", tc.cmd, got, tc.want)
			}
		})
	}
}
