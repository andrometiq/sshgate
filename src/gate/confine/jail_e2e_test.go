//go:build linux && jail_e2e

// Package confine's jail acceptance matrix. Tagged jail_e2e and run by
// `make test-jail`, NOT by `make test`: these legs build a helper and run real
// confined commands. Each leg skips with a clear reason when the host lacks the
// probed feature, so the suite is never "green by skip" silently.
//
// The matrix runs native and forced ABI 1, plus mandatory-Landlock refusal.
// Every destructive leg retains its unjailed control.
//
// Scope (Phase 0/1, honest): these legs prove the file-write, metadata (incl.
// chattr/xattr), AF_UNIX, FIFO, IPC, tty and fail-closed classes with the
// suite's OWN seeded targets and probes. Replaying the BYPASS-CATALOGUE.md
// corpus (sinks rewritten to seeded targets) is a separate run and is
// deliberately not here.
package confine

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
)

// jailCfg is one matrix configuration: a rung, an optional forced ABI, and
// whether it runs the heavy native-only legs (fill, read corpus).
type jailCfg struct {
	name     string
	forceABI int  // 0 = host ABI; ForceNoLandlock = none; >0 = capped
	native   bool // run the heavy legs (fill, corpus) only on the native rungs
}

func (c jailCfg) spec(t *testing.T) Spec {
	t.Helper()
	return Spec{Profile: ProfileROv1, Net: true, ForceABI: c.forceABI}
}

func TestJailMatrix(t *testing.T) {
	rep := Detect()
	t.Logf("host: rung=%s landlock_abi=%d userns=%v seccomp=%v probeErr=%v",
		rep.Rung, rep.LandlockABI, rep.Userns, rep.Seccomp, rep.ProbeErr)

	probe := buildProbe(t) // built ONCE; every leg reuses the same binary

	cfgs := []jailCfg{{name: "native", native: true}, {name: "abi1", forceABI: 1}}

	for _, cfg := range cfgs {
		cfg := cfg
		t.Run(cfg.name, func(t *testing.T) { runLegs(t, cfg, probe) })
	}

	// Landlock is mandatory: without it, nothing may run.
	{
		t.Run("no_landlock_fails_closed", func(t *testing.T) {
			spec := Spec{Profile: ProfileROv1, Net: true, ForceABI: ForceNoLandlock}
			r := runLegacyJailed(t, spec, "echo SHOULD_NOT_RUN")
			var se *SetupError
			if !errors.As(r.setupErr, &se) {
				unexpected(t, "expected *SetupError, got %v", r.setupErr)
				t.FailNow()
			}
			if se.Stage != "landlock" {
				unexpected(t, "SetupError stage=%q want landlock", se.Stage)
			}
			if strings.Contains(r.stdout, "SHOULD_NOT_RUN") {
				unexpected(t, "command ran despite required Landlock being unavailable")
			}
		})
	}
}

func runLegs(t *testing.T, cfg jailCfg, probe string) {
	spec := cfg.spec(t)
	t.Run("reads_work", func(t *testing.T) { legReadsWork(t, spec) })
	t.Run("bypass_corpus", func(t *testing.T) { legBypassCorpus(t, spec) })
	t.Run("file_write_neutralised", func(t *testing.T) { legFileWrite(t, spec) })
	t.Run("metadata_blocked", func(t *testing.T) { legMetadata(t, spec) })
	t.Run("chattr_blocked", func(t *testing.T) { legChattr(t, spec, probe) })
	t.Run("xattr_blocked", func(t *testing.T) { legXattr(t, spec, probe) })
	t.Run("af_unix_denied", func(t *testing.T) { legAFUnix(t, spec, probe) })
	t.Run("proc_mem_unreadable", func(t *testing.T) { legProcMem(t, spec, probe) })
	t.Run("rlimits_applied", func(t *testing.T) { legRlimits(t, spec) })
	t.Run("ipc", func(t *testing.T) { legIPC(t, spec, probe) })
	t.Run("posix_mqueue_isolated", func(t *testing.T) { legMQueue(t, spec, probe) })
	t.Run("fail_closed_before_execve", func(t *testing.T) { legFailClosed(t, spec) })

	t.Run("reaper_no_hang", func(t *testing.T) { legReaper(t, spec) })
	t.Run("procfs_control_readonly", func(t *testing.T) { legProcfsReadOnly(t, spec) })
	t.Run("proc_state_isolated", func(t *testing.T) { legProcState(t, spec, probe) })
	t.Run("tty_isolated", func(t *testing.T) { legTtyIsolated(t, spec) })
	t.Run("truncate_scratch", func(t *testing.T) { legTruncateScratch(t, spec) })
	if cfg.native {
		t.Run("fill_bounded", func(t *testing.T) { legFill(t, spec) })
		t.Run("read_corpus_clean", func(t *testing.T) { legReadCorpus(t, spec) })
	}
}

// --- legs ---------------------------------------------------------------------

func legReadsWork(t *testing.T, spec Spec) {
	for _, cmd := range []string{"cat /etc/hostname", "id", "ls /", "echo RAN"} {
		r := runLegacyJailed(t, spec, cmd)
		if r.setupErr != nil {
			unexpected(t, "%q: unexpected setup failure: %v (stderr=%q)", cmd, r.setupErr, r.stderr)
			t.FailNow()
		}
		if r.exit != 0 {
			unexpected(t, "%q: exit=%d want 0 (stderr=%q)", cmd, r.exit, r.stderr)
		}
	}
	if r := runLegacyJailed(t, spec, "echo RAN"); !strings.Contains(r.stdout, "RAN") {
		unexpected(t, "echo RAN produced no stdout (%q)", r.stdout)
	}
}

// bypassRow is one BYPASS-CATALOGUE.md entry rewritten as a jail regression test:
// a command our old read/write classifier misjudged, with its write/compile/
// download sink pointed at a seeded file + marker under $HOME. build seeds any
// per-row fixtures under dir and returns the shell command plus the marker path
// the exploit should create ("" when the exploit writes only the seeded target).
// A non-empty skip means the entry has NO file sink (a network-side POST, or a
// host/kernel-state change needing root): it is logged and listed, never asserted
// — the honest Phase-1 carve-out (spec §0.12 leg 1).
type bypassRow struct {
	name  string
	tool  string // LookPath gate ("" = always available)
	skip  string // non-empty => logged, not asserted (no file sink)
	build func(t *testing.T, dir, target string) (cmd, marker string)
}

// legBypassCorpus replays the BYPASS-CATALOGUE.md regression corpus (spec §0.12
// leg 1). For each row: run the exploit UNJAILED as a control — it MUST change the
// seeded target or create the marker, or the row is vacuous (tool hardened away,
// fixture wrong, exploit not reproducible on this host's tool version) and is
// logged, not asserted. Then run it jailed on THIS config and require the seeded
// target's sha256 unchanged and the marker absent: the jail neutralises the write
// whatever the classifier decided. Per-row skips are t.Logf (not t.Skip) so the
// Makefile's no-SKIP gate still trips only on a real regression.
func legBypassCorpus(t *testing.T, spec Spec) {
	for _, row := range bypassCorpus() {
		if row.skip != "" {
			t.Logf("corpus %q: not asserted (%s)", row.name, row.skip)
			continue
		}
		if row.tool != "" {
			if _, err := exec.LookPath(row.tool); err != nil {
				t.Logf("corpus %q: not asserted (tool %q not installed)", row.name, row.tool)
				continue
			}
		}
		dir, err := os.MkdirTemp(homeDir(t), ".sshgate-bypass-")
		if err != nil {
			unexpected(t, "corpus %q: mkdir under home: %v", row.name, err)
			t.FailNow()
		}
		func() {
			defer os.RemoveAll(dir)
			target := filepath.Join(dir, "target")
			seed := []byte("original-content\n")
			if err := os.WriteFile(target, seed, 0o644); err != nil {
				unexpected(t, "corpus %q: seed target: %v", row.name, err)
				t.FailNow()
			}
			cmd, marker := row.build(t, dir, target)

			// Control: unjailed, the exploit must land a real file effect, else the
			// jailed assertion below would pass vacuously.
			before := hashFile(t, target)
			runHostUnjailed(t, cmd)
			targetHit := hashFile(t, target) != before
			markerHit := marker != "" && pathExists(marker)
			if !targetHit && !markerHit {
				t.Logf("corpus %q: not asserted (control produced no file effect on this host; exploit not reproducible)", row.name)
				return
			}

			// Reset the fixtures, then run the SAME command jailed on this config.
			if err := os.WriteFile(target, seed, 0o644); err != nil {
				unexpected(t, "corpus %q: reset target: %v", row.name, err)
				t.FailNow()
			}
			if marker != "" {
				_ = os.Remove(marker)
			}
			jBefore := hashFile(t, target)
			// runJailedRan proves the shell execve'd (canary), so a setup abort can
			// never let a "contained" assertion pass without the exploit running.
			_ = runJailedRan(t, spec, cmd)
			if hashFile(t, target) != jBefore {
				unexpected(t, "corpus %q: jailed exploit MODIFIED the seeded target %s; the jail did not contain the write", row.name, target)
			}
			if marker != "" && pathExists(marker) {
				unexpected(t, "corpus %q: jailed exploit created marker %s; the jail did not contain the write", row.name, marker)
			}
		}()
	}
}

// bypassCorpus is the BYPASS-CATALOGUE.md Wave-4 regression corpus as test data:
// every classifier read/write-misjudgement, each rewritten so its sink lands on a
// seeded file or marker under $HOME (where the jail is read-only on every rung).
// Network-side and host/kernel-state entries carry a skip reason instead.
func bypassCorpus() []bypassRow {
	return []bypassRow{
		// --- CRITICAL: /bin/sh-wrapper env-program injection. On hardened gzip
		// (>=1.12) zgrep/zdiff exec $GREP/$DIFF directly with no shell eval, so the
		// documented RCE no longer fires and the control gates the row off.
		{
			name: "zgrep_GREP_injection", tool: "zgrep",
			build: func(t *testing.T, dir, target string) (string, string) {
				marker := filepath.Join(dir, "marker")
				return fmt.Sprintf(`GREP='sh -c "touch %s" #' zgrep x %s`, marker, target), marker
			},
		},
		{
			name: "zdiff_DIFF_injection", tool: "zdiff",
			build: func(t *testing.T, dir, target string) (string, string) {
				marker := filepath.Join(dir, "marker")
				return fmt.Sprintf(`DIFF='sh -c "touch %s"' zdiff %s %s`, marker, target, target), marker
			},
		},
		// --- CRITICAL: git grep --open-files-in-pager (abbreviates to --op=) runs
		// the flag value as a shell command on each matched file.
		{
			name: "git_grep_open_files_in_pager", tool: "git",
			build: func(t *testing.T, dir, target string) (string, string) {
				repo := filepath.Join(dir, "repo")
				mustGitRepo(t, repo)
				marker := filepath.Join(dir, "marker")
				return fmt.Sprintf(`git -C %s grep --open-files-in-pager='sh -c "touch %s"' hello`, repo, marker), marker
			},
		},
		// --- CRITICAL: curl -o bundled behind no-arg short flags writes an
		// arbitrary file (file:// source, so no network is involved).
		{
			name: "curl_bundled_output", tool: "curl",
			build: func(t *testing.T, dir, target string) (string, string) {
				src := seedPayload(t, dir)
				return fmt.Sprintf("curl -so %s file://%s", target, src), ""
			},
		},
		// --- CRITICAL: sed --i (unambiguous abbreviation of --in-place) edits the
		// file in place.
		{
			name: "sed_inplace_abbrev", tool: "sed",
			build: func(t *testing.T, dir, target string) (string, string) {
				return fmt.Sprintf(`sed --i 's/.*/pwned/' %s`, target), ""
			},
		},
		// --- MAJOR: file -rC bundles -C (compile); `file -C -m <name>` writes
		// basename(name).mgc into the cwd, so the row pins cwd with cd.
		{
			name: "file_compile_bundle", tool: "file",
			build: func(t *testing.T, dir, target string) (string, string) {
				if err := os.WriteFile(filepath.Join(dir, "m"), []byte("0 string MAGIC testfile\n"), 0o644); err != nil {
					unexpected(t, "seed magic: %v", err)
					t.FailNow()
				}
				return fmt.Sprintf("cd %s && file -rC -m m", dir), filepath.Join(dir, "m.mgc")
			},
		},
		// --- MAJOR: tree -no bundles -o to write the directory listing to a file.
		{
			name: "tree_bundled_output", tool: "tree",
			build: func(t *testing.T, dir, target string) (string, string) {
				return fmt.Sprintf("tree -no %s /etc", target), ""
			},
		},
		// --- MAJOR: curl -O (remote-name) writes basename(url) into the cwd. cwd is
		// a subdir so the written basename cannot collide with the source payload.
		{
			name: "curl_remote_name", tool: "curl",
			build: func(t *testing.T, dir, target string) (string, string) {
				out := filepath.Join(dir, "out")
				if err := os.Mkdir(out, 0o755); err != nil {
					unexpected(t, "mkdir out: %v", err)
					t.FailNow()
				}
				src := seedPayload(t, dir) // dir/payload, outside the cwd subdir
				return fmt.Sprintf("cd %s && curl -sO file://%s", out, src), filepath.Join(out, filepath.Base(src))
			},
		},
		// --- MAJOR: curl -D (dump-header) bundled writes the headers to a file.
		{
			name: "curl_dump_header", tool: "curl",
			build: func(t *testing.T, dir, target string) (string, string) {
				src := seedPayload(t, dir)
				return fmt.Sprintf("curl -sD %s file://%s", target, src), ""
			},
		},
		// --- MAJOR: curl -c (cookie-jar) bundled writes the jar to a file. A file://
		// transfer sets no cookies, so on many hosts the jar is not written; the
		// control gates the row.
		{
			name: "curl_cookie_jar", tool: "curl",
			build: func(t *testing.T, dir, target string) (string, string) {
				src := seedPayload(t, dir)
				return fmt.Sprintf("curl -sc %s file://%s", target, src), ""
			},
		},
		// --- MAJOR: gawk @include pulls in opaque source (the program-text analogue
		// of -i/--include) which here writes a file.
		{
			name: "awk_include_directive", tool: "gawk",
			build: func(t *testing.T, dir, target string) (string, string) {
				marker := filepath.Join(dir, "marker")
				inc := filepath.Join(dir, "inc.awk")
				if err := os.WriteFile(inc, []byte(fmt.Sprintf("BEGIN { print \"pwned\" > \"%s\" }\n", marker)), 0o644); err != nil {
					unexpected(t, "seed inc.awk: %v", err)
					t.FailNow()
				}
				return fmt.Sprintf(`gawk '@include "%s"'`, inc), marker
			},
		},
		// --- No file sink: a network-side HTTP POST. Phase 1 keeps inet in front of
		// the classifier (denying inet is a later step), so the jail
		// does not contain it — carved out, not asserted.
		{name: "curl_json_post", skip: "network-side HTTP POST (curl --json); no file sink, contained once inet is denied, not Phase 1"},
		// --- No file sink: host/kernel-state changes needing CAP_SYS_ADMIN. There
		// is nothing to seed and the unjailed control cannot run unprivileged, so
		// these are listed, not asserted.
		{name: "mount_inline_options", skip: "mount(2) host-state change (needs CAP_SYS_ADMIN); no file sink, unprivileged control cannot demonstrate it"},
		{name: "mount_source_target", skip: "mount(2) host-state change (needs CAP_SYS_ADMIN); no file sink, unprivileged control cannot demonstrate it"},
		{name: "sysctl_reload_bundle", skip: "sysctl -p re-applies kernel params (needs CAP_SYS_ADMIN); no file sink, unprivileged control cannot demonstrate it"},
	}
}

// seedPayload writes a distinctive payload file under dir (a curl file:// source)
// and returns its path.
func seedPayload(t *testing.T, dir string) string {
	t.Helper()
	p := filepath.Join(dir, "payload")
	if err := os.WriteFile(p, []byte("EXFILTRATED\n"), 0o644); err != nil {
		unexpected(t, "seed payload: %v", err)
		t.FailNow()
	}
	return p
}

// mustGitRepo makes a one-commit git repo at repo with a file matching "hello"
// (the git-grep corpus row needs a real working tree). Global/system gitconfig is
// neutralised so the operator's settings cannot perturb the fixture.
func mustGitRepo(t *testing.T, repo string) {
	t.Helper()
	if err := os.MkdirAll(repo, 0o755); err != nil {
		unexpected(t, "mkdir repo: %v", err)
		t.FailNow()
	}
	if err := os.WriteFile(filepath.Join(repo, "f"), []byte("hello\n"), 0o644); err != nil {
		unexpected(t, "seed repo file: %v", err)
		t.FailNow()
	}
	ident := []string{"-c", "user.email=t@example.invalid", "-c", "user.name=t"}
	for _, args := range [][]string{
		{"init", "-q"},
		append(ident, "add", "f"),
		append(ident, "commit", "-qm", "seed"),
	} {
		c := exec.Command("git", append([]string{"-C", repo}, args...)...)
		c.Env = append(os.Environ(), "GIT_CONFIG_GLOBAL=/dev/null", "GIT_CONFIG_SYSTEM=/dev/null")
		if out, err := c.CombinedOutput(); err != nil {
			unexpected(t, "git %v: %v\n%s", args, err, out)
			t.FailNow()
		}
	}
}

// runHostUnjailed runs a corpus command on the host (no jail) with a timeout,
// ignoring its exit status — an exploit may exit non-zero yet still write.
func runHostUnjailed(t *testing.T, cmd string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	c := exec.CommandContext(ctx, "/bin/sh", "-c", cmd)
	c.Stdin = nil
	_ = c.Run()
}

// pathExists reports whether a path exists (a marker check).
func pathExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

func legFileWrite(t *testing.T, spec Spec) {
	target := seedTarget(t) // under $HOME: read-only inside the jail on every rung
	marker := filepath.Join(filepath.Dir(target), "marker")
	before := hashFile(t, target)
	// One command that both appends to the seeded target AND drops a marker; the
	// jail must stop BOTH side effects. runJailedRan proves the shell actually ran
	// (canary), so a setup failure cannot pass this leg vacuously.
	r := runJailedRan(t, spec, "echo pwned >> "+target+" ; echo m > "+marker)
	if r.exit == 0 {
		unexpected(t, "jailed write exited 0; expected failure")
	}
	if after := hashFile(t, target); after != before {
		unexpected(t, "seeded target was modified by the jailed write (%s)", target)
	}
	if _, err := os.Stat(marker); !errors.Is(err, os.ErrNotExist) {
		unexpected(t, "marker %s exists (err=%v); the jailed write was not contained", marker, err)
	}
}

func legMetadata(t *testing.T, spec Spec) {
	target := seedTarget(t)
	ctl := filepath.Join(filepath.Dir(target), "ctl")
	if err := os.WriteFile(ctl, []byte("x"), 0o644); err != nil {
		unexpected(t, "%v", err)
		t.FailNow()
	}
	ops := []string{"chmod 0777 %s", "touch -d 2000-01-01 %s", "truncate -s 0 %s"}
	// Control: each op must work UNJAILED on the ctl file, or a missing tool
	// (exit 127) would make the jailed assertions pass vacuously.
	for _, op := range ops {
		if out, err := exec.Command("sh", "-c", fmt.Sprintf(op, ctl)).CombinedOutput(); err != nil {
			t.Skipf("control %q failed on this host (%v: %s)", op, err, out)
		}
	}

	before := statMode(t, target)
	hashBefore := hashFile(t, target)
	for _, op := range ops {
		cmd := fmt.Sprintf(op, target)
		if r := runJailedRan(t, spec, cmd); r.exit == 0 {
			unexpected(t, "%q exited 0; expected failure", cmd)
		}
	}
	if statMode(t, target) != before {
		unexpected(t, "seeded target metadata changed")
	}
	if hashFile(t, target) != hashBefore {
		unexpected(t, "seeded target content changed (truncate got through)")
	}
}

// legChattr checks generic fileattr setters cannot alter host inode flags.
func legChattr(t *testing.T, spec Spec, probe string) {
	if !haveTool(t, "chattr") || !haveTool(t, "lsattr") {
		t.Skip("chattr/lsattr not installed")
	}
	target := seedTarget(t)
	ctl := filepath.Join(filepath.Dir(target), "ctl")
	if err := os.WriteFile(ctl, []byte("x"), 0o644); err != nil {
		unexpected(t, "%v", err)
		t.FailNow()
	}
	// Control: chattr +d must work unjailed, or the filesystem cannot carry the
	// flag and the leg is meaningless here.
	if out, err := exec.Command("chattr", "+d", ctl).CombinedOutput(); err != nil {
		t.Skipf("chattr +d unsupported on this fs (%v: %s)", err, out)
	}
	_ = exec.Command("chattr", "-d", ctl).Run()

	before := lsattr(t, target)
	if r := runJailedRan(t, spec, "chattr +d "+target); r.exit == 0 {
		unexpected(t, "jailed `chattr +d` exited 0; expected failure")
	}
	if after := lsattr(t, target); after != before {
		unexpected(t, "lsattr changed by the jailed chattr: %q -> %q", before, after)
	}

	// Tool-independent: the probe exercises FS_IOC_SETFLAGS, FS_IOC_FSSETXATTR and
	// file_setattr directly (chattr only drives FS_IOC_SETFLAGS). An unjailed
	// control on a separate file must show every ioctl/syscall succeeds, then the
	// jailed run must have every one fail and leave lsattr unchanged.
	pctl := filepath.Join(filepath.Dir(target), "setflags-ctl")
	if err := os.WriteFile(pctl, []byte("x"), 0o644); err != nil {
		unexpected(t, "%v", err)
		t.FailNow()
	}
	// file_setattr exists only from Linux 6.17; ENOSYS there means "not
	// applicable on this kernel", not a broken control. The two ioctl paths stay
	// mandatory.
	out, _ := exec.Command(probe, "setflags", pctl).CombinedOutput()
	ctlOut := string(out)
	if na := "file_setattr=" + strconv.Itoa(int(unix.ENOSYS)); strings.Contains(ctlOut, na) {
		t.Logf("file_setattr not on this kernel (ENOSYS); asserting the ioctl paths only")
		ctlOut = strings.Replace(ctlOut, na, "", 1)
	}
	if !allProbeOK(ctlOut) || !strings.Contains(ctlOut, "setflags=ok") || !strings.Contains(ctlOut, "fssetxattr=ok") {
		t.Skipf("control `probe setflags` did not succeed on this fs: %s", out)
	}
	pbefore := lsattr(t, target)
	r := runLegacyJailed(t, spec, probe+" setflags "+target+" ; echo "+ranCanary)
	if r.setupErr != nil {
		unexpected(t, "probe setflags: jail setup failed: %v", r.setupErr)
		t.FailNow()
	}
	if !strings.Contains(r.stdout, ranCanary) {
		unexpected(t, "probe setflags never ran; stdout=%q stderr=%q", r.stdout, r.stderr)
		t.FailNow()
	}
	for _, op := range []string{"setflags=ok", "fssetxattr=ok", "file_setattr=ok"} {
		if strings.Contains(r.stdout, op) {
			unexpected(t, "jailed probe setflags reported %q; the metadata-ioctl path is open (stdout=%q)", op, r.stdout)
		}
	}
	if after := lsattr(t, target); after != pbefore {
		unexpected(t, "lsattr changed by the jailed probe setflags: %q -> %q", pbefore, after)
	}
}

// allProbeOK reports whether every "<name>=<result>" line in a probe's output is
// "=ok" (used by an unjailed control to prove the attack works on the host).
func allProbeOK(out string) bool {
	seen := false
	for _, ln := range strings.Split(strings.TrimSpace(out), "\n") {
		ln = strings.TrimSpace(ln)
		if ln == "" {
			continue
		}
		seen = true
		if !strings.HasSuffix(ln, "=ok") {
			return false
		}
	}
	return seen
}

// legXattr checks setting and removing host xattrs are blocked.
func legXattr(t *testing.T, spec Spec, probe string) {
	if !haveTool(t, "setfattr") || !haveTool(t, "getfattr") {
		t.Skip("setfattr/getfattr not installed")
	}
	target := seedTarget(t)
	if out, err := exec.Command("setfattr", "-n", "user.seed", "-v", "seedval", target).CombinedOutput(); err != nil {
		t.Skipf("user xattrs unsupported on this fs (%v: %s)", err, out)
	}
	ctl := filepath.Join(filepath.Dir(target), "ctl")
	if err := os.WriteFile(ctl, []byte("x"), 0o644); err != nil {
		unexpected(t, "%v", err)
		t.FailNow()
	}
	if out, err := exec.Command("setfattr", "-n", "user.ctl", "-v", "1", ctl).CombinedOutput(); err != nil {
		t.Skipf("control setfattr failed (%v: %s)", err, out)
	}

	before := getfattr(t, target)
	for _, cmd := range []string{
		"setfattr -n user.pwn -v 1 " + target,
		"setfattr -x user.seed " + target,
	} {
		if r := runJailedRan(t, spec, cmd); r.exit == 0 {
			unexpected(t, "jailed %q exited 0; expected failure", cmd)
		}
	}
	if after := getfattr(t, target); after != before {
		unexpected(t, "xattr list changed by the jailed setfattr:\n before=%q\n after =%q", before, after)
	}
	// Belt-and-braces via raw syscalls (tool-independent): every setxattr AND
	// removexattr variant must fail inside the jail. An unjailed control on a
	// separate file proves both probe ops work on this fs first.
	if out, err := exec.Command(probe, "xattr-set", ctl, "user.ctlset", "v").CombinedOutput(); err != nil || !allProbeOK(string(out)) {
		t.Skipf("control `probe xattr-set` did not succeed (%v: %s)", err, out)
	}
	// xattr-rm removes the SAME name three ways, so only the first call finds the
	// attr present (the later two get ENODATA, making the probe exit non-zero,
	// which is expected — we do NOT gate on its exit). The control just proves the
	// removexattr path works on this fs.
	if out, _ := exec.Command(probe, "xattr-rm", ctl, "user.ctl").CombinedOutput(); !strings.Contains(string(out), "removexattr=ok") {
		t.Skipf("control `probe xattr-rm` did not remove a user xattr: %s", out)
	}
	// The read-only open the probe does (open=ok) is legitimate; it is the WRITE
	// ops that must every one fail inside the jail.
	for _, op := range []struct {
		name, cmd string
		writes    []string
	}{
		{"xattr-set", probe + " xattr-set " + target + " user.raw rawval",
			[]string{"setxattr=ok", "lsetxattr=ok", "fsetxattr=ok"}},
		{"xattr-rm", probe + " xattr-rm " + target + " user.seed",
			[]string{"removexattr=ok", "lremovexattr=ok", "fremovexattr=ok"}},
	} {
		r := runLegacyJailed(t, spec, op.cmd+" ; echo "+ranCanary)
		if r.setupErr != nil {
			unexpected(t, "probe %s: jail setup failed: %v", op.name, r.setupErr)
			t.FailNow()
		}
		if !strings.Contains(r.stdout, ranCanary) {
			unexpected(t, "probe %s never ran; stdout=%q stderr=%q", op.name, r.stdout, r.stderr)
			t.FailNow()
		}
		for _, w := range op.writes {
			if strings.Contains(r.stdout, w) {
				unexpected(t, "jailed probe %s reported %q; the xattr-write path is open (stdout=%q)", op.name, w, r.stdout)
			}
		}
	}
	if after := getfattr(t, target); after != before {
		unexpected(t, "xattr list changed by the jailed probe ops:\n before=%q\n after =%q", before, after)
	}
}

func legAFUnix(t *testing.T, spec Spec, probe string) {
	// A real listener under $HOME (visible on every rung — /tmp is overmounted on
	// the jail), with an unjailed control
	// dial proving the socket actually accepts connections.
	home := homeDir(t)
	dir, err := os.MkdirTemp(home, ".sshgate-jailsock-")
	if err != nil {
		unexpected(t, "mkdir sock dir: %v", err)
		t.FailNow()
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	sock := filepath.Join(dir, "s.sock")

	ln, err := net.Listen("unix", sock)
	if err != nil {
		unexpected(t, "listen unix: %v", err)
		t.FailNow()
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			_ = c.Close()
		}
	}()

	// Control: the probe dials the socket successfully OUTSIDE the jail.
	if out, err := exec.Command(probe, "dial-unix", sock).CombinedOutput(); err != nil {
		unexpected(t, "unjailed control dial failed (%v): %s", err, out)
		t.FailNow()
	} else if !strings.Contains(string(out), "socket=ok") || !strings.Contains(string(out), "connect=ok") {
		unexpected(t, "unjailed control dial did not connect: %s", out)
		t.FailNow()
	}

	// Jailed: socket(AF_UNIX) is denied at creation (EPERM==1), before any connect.
	r := runLegacyJailed(t, spec, probe+" dial-unix "+sock)
	if r.exit == 0 {
		unexpected(t, "jailed AF_UNIX dial succeeded; expected EPERM")
		t.FailNow()
	}
	if !strings.Contains(r.stdout, "socket="+strconv.Itoa(int(unix.EPERM))) {
		unexpected(t, "jailed probe did not report socket=EPERM(%d); stdout=%q stderr=%q",
			int(unix.EPERM), r.stdout, r.stderr)
	}
}

func legProcMem(t *testing.T, spec Spec, probe string) {
	// Make this test process ptrace-able by ANY process, so Yama ptrace_scope is
	// NOT what blocks the read — the jail is. Without this the leg is vacuous:
	// under ptrace_scope=1 an unjailed sibling also gets EACCES, so the jailed
	// failure proves nothing. PR_SET_PTRACER is a harmless no-op where Yama is
	// absent (then an unjailed open just succeeds and the jail is still the wall).
	_ = unix.Prctl(unix.PR_SET_PTRACER, uintptr(unix.PR_SET_PTRACER_ANY), 0, 0, 0)
	pid := strconv.Itoa(os.Getpid())

	// Control: an UNJAILED probe can now open /proc/<testpid>/mem.
	out, _ := exec.Command(probe, "read-mem", pid).CombinedOutput()
	if !strings.Contains(string(out), "open=ok") {
		unexpected(t, "unjailed control could not open /proc/<testpid>/mem (PR_SET_PTRACER ineffective?): %s", out)
		t.FailNow()
	}

	// The host /proc stays visible; cross-userns ptrace and Landlock deny memory access.
	r := runJailedRan(t, spec, probe+" read-mem "+pid)
	if strings.Contains(r.stdout, "open=ok") {
		unexpected(t, "jailed probe opened /proc/<testpid>/mem (stdout=%q); the read should be blocked", r.stdout)
	}
	if r.exit == 0 {
		unexpected(t, "jailed read-mem exited 0; expected failure")
	}
}

func legRlimits(t *testing.T, spec Spec) {
	var core unix.Rlimit
	mutationSetup(t, unix.Getrlimit(unix.RLIMIT_CORE, &core))
	r := runJailedRan(t, spec, "cat /proc/self/limits")
	for name, want := range map[string]string{"Max processes": "256", "Max file size": "1073741824", "Max core file size": strconv.FormatUint(min(uint64(1), core.Max), 10)} {
		found := false
		for _, line := range strings.Split(r.stdout, "\n") {
			if strings.HasPrefix(line, name) {
				found = true
				values := strings.Fields(strings.TrimPrefix(line, name))
				if len(values) < 2 || values[0] != want || values[1] != want {
					unexpected(t, "%s: %q", name, line)
				}
			}
		}
		if !found {
			unexpected(t, "missing limit %s", name)
		}
	}
}

// legFifo proves mandatory Landlock blocks writes to existing host FIFOs.
func legFifo(t *testing.T, spec Spec) {
	p := newProof(t, "L-FIFO-WRITE")
	probe := buildProbe(t)
	dir, err := os.MkdirTemp(homeDir(t), ".sshgate-jailfifo-")
	mutationSetup(t, err)
	t.Cleanup(func() { os.RemoveAll(dir) })
	path := filepath.Join(dir, "probe.fifo")
	mutationSetup(t, unix.Mkfifo(path, 0600))
	reader, err := unix.Open(path, unix.O_RDONLY|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	mutationSetup(t, err)
	observer := &mountFIFOObserver{fd: reader}
	p.ObserveWith("fifo", observer)
	control := mountControl(t, exec.Command(probe, "device-write", path), 0)
	if string(control) != "open=ok\nwrite=ok\n" {
		t.Fatalf("SETUP: FIFO control: %s", control)
	}
	mark := observer.Mark()
	mutationSetup(t, observer.Seal(ProducerSync{Complete: true, Kind: "process-exited"}))
	if got := observer.Since(mark); !got.Conclusive || len(got.Records) != 1 || got.Records[0] != "x" {
		t.Fatalf("SETUP: FIFO control delivery: %+v", got)
	}
	p.Control("fifo", ControlResult{Valid: true})
	mark = observer.Mark()
	result := runJailed(t, p, spec, RunPlan{Mode: Execute, Ops: []ProofOp{{Name: "fifo", Command: probe + " device-write " + path, Outcomes: []OpOutcome{{Stdout: "open=13\n", Exit: 1}, {Stdout: "open=ok\nwrite=ok\n"}}}}})
	p.Jailed("fifo", result)
	mutationSetup(t, observer.Seal(ProducerSync{Complete: true, Kind: "framed-op-ended"}))
	records := observer.Since(mark)
	got := strings.Join(records.Records, "")
	valid := (got == "" && result.stdout == "open=13\n") || (got == "x" && result.stdout == "open=ok\nwrite=ok\n")
	p.Observed("fifo", Observation{Conclusive: records.Conclusive, Sealed: records.Sealed, Valid: valid, Detail: fmt.Sprintf("bytes=%q report=%q", got, result.stdout)})
	mutationEffect(t, "L-FIFO-WRITE", "delivered", len(got) != 0)
	p.Finish()
}

// legIPC proves the IPC namespace protects host SysV segments.
func legIPC(t *testing.T, spec Spec, probe string) {
	// Control: removing a throwaway segment works outside the jail.
	ctlID := shmCreate(t)
	if out, err := exec.Command(probe, "shm-rmid", strconv.Itoa(ctlID)).CombinedOutput(); err != nil {
		shmRemove(ctlID)
		unexpected(t, "unjailed control shm-rmid failed (%v): %s", err, out)
		t.FailNow()
	}
	if shmExists(ctlID) {
		shmRemove(ctlID)
		unexpected(t, "control: segment %d still exists after an unjailed ipcrm", ctlID)
		t.FailNow()
	}

	id := shmCreate(t)
	defer shmRemove(id)
	// runJailedRan prepends the canary, so r.exit stays the probe's own exit code.
	r := runJailedRan(t, spec, probe+" shm-rmid "+strconv.Itoa(id))

	if !shmExists(id) {
		unexpected(t, "rung 1: host shm segment %d was deleted from inside the jail; CLONE_NEWIPC should isolate it", id)
	}
	if r.exit == 0 {
		unexpected(t, "rung 1: jailed shm-rmid exited 0; the host id should be invalid in the new IPC namespace")
	}
}

// legMQueue proves host queue creation and removal are refused.
func legMQueue(t *testing.T, spec Spec, probe string) {
	name := fmt.Sprintf("sshgate-jailtest-%d-%d", os.Getpid(), time.Now().UnixNano())
	t.Cleanup(func() { mqUnlink(t, name) })
	unjailed := func(op string) {
		t.Helper()
		if out, err := exec.Command(probe, op, name).CombinedOutput(); err != nil {
			unexpected(t, "unjailed control %s failed (%v): %s", op, err, out)
			t.FailNow()
		}
	}

	unjailed("mq-create")
	if !mqExists(t, name) {
		unexpected(t, "control: the unjailed probe did not create a host queue")
		t.FailNow()
	}
	unjailed("mq-unlink")
	if mqExists(t, name) {
		unexpected(t, "control: the unjailed probe did not remove the host queue")
		t.FailNow()
	}

	unjailed("mq-create")
	r := runJailedRan(t, spec, probe+" mq-unlink "+name)
	if !mqExists(t, name) {
		unexpected(t, "jailed mq_unlink deleted the host queue %q (stdout=%q)", name, r.stdout)
	}
	if r.exit == 0 {
		unexpected(t, "jailed mq_unlink exited 0; want it refused (stdout=%q)", r.stdout)
	}
	mqUnlink(t, name)

	r = runJailedRan(t, spec, probe+" mq-create "+name)
	if mqExists(t, name) {
		unexpected(t, "jailed mq_open(O_CREAT) left a queue %q on the host (stdout=%q)", name, r.stdout)
	}
}

// mqExists reports whether the host IPC namespace holds the POSIX queue name.
func mqExists(t *testing.T, name string) bool {
	t.Helper()
	fd, _, e := unix.Syscall6(unix.SYS_MQ_OPEN, uintptr(unsafe.Pointer(cstr(t, name))), uintptr(unix.O_RDONLY|unix.O_CLOEXEC), 0, 0, 0, 0)
	switch e {
	case 0:
		_ = unix.Close(int(fd))
		return true
	case unix.ENOENT:
		return false
	default:
		unexpected(t, "mq_open(%q) on the host: %v", name, e)
		t.FailNow()
		return false
	}
}

// mqUnlink removes the host queue name, if it exists.
func mqUnlink(t *testing.T, name string) {
	_, _, _ = unix.Syscall(unix.SYS_MQ_UNLINK, uintptr(unsafe.Pointer(cstr(t, name))), 0, 0)
}

func cstr(t *testing.T, s string) *byte {
	t.Helper()
	p, err := unix.BytePtrFromString(s)
	if err != nil {
		unexpected(t, "%v", err)
		t.FailNow()
	}
	return p
}

func legFailClosed(t *testing.T, spec Spec) {
	stages := []string{"cmdread", "mounts", "nnp", "caps", "rlimits", "landlock", "seccomp"}
	for _, stage := range stages {
		target := seedTarget(t)
		marker := filepath.Join(filepath.Dir(target), "marker")
		before := hashFile(t, target)

		s := spec
		s.InjectFailAt = stage
		r := runLegacyJailed(t, s, "echo pwned >> "+target+" ; echo m > "+marker+" ; echo SHOULD_NOT_RUN")

		var se *SetupError
		if !errors.As(r.setupErr, &se) {
			unexpected(t, "stage %q: expected *SetupError, got %v", stage, r.setupErr)
			continue
		}
		if se.Stage != stage {
			unexpected(t, "stage %q: SetupError names stage %q", stage, se.Stage)
		}
		if strings.Contains(r.stdout, "SHOULD_NOT_RUN") {
			unexpected(t, "stage %q: command executed despite injected setup failure", stage)
		}
		if hashFile(t, target) != before {
			unexpected(t, "stage %q: seeded target changed; the command ran", stage)
		}
		if _, err := os.Stat(marker); !errors.Is(err, os.ErrNotExist) {
			unexpected(t, "stage %q: marker exists; the command ran", stage)
		}
	}
}

// Scratch truncation is allowed; host truncation remains covered by legMetadata.
func legTruncateScratch(t *testing.T, spec Spec) {
	r := runJailedRan(t, spec, "printf data > /dev/shm/truncate-test && printf x >> /dev/shm/truncate-test && truncate -s 0 /dev/shm/truncate-test && test ! -s /dev/shm/truncate-test")
	if r.exit != 0 {
		unexpected(t, "scratch append/truncate failed: %+v", r)
		t.FailNow()
	}
}

// legFill proves private tmpfs writes stop at the mount size bound.
func legFill(t *testing.T, spec Spec) {
	{
		// /dev/shm is a bounded tmpfs inside the jail; a fill stops at its size and
		// the host is untouched. Fill and measure in the SAME jail (a new jail
		// gets a fresh, empty tmpfs). RLIMIT_FSIZE (1 GiB) is far above the
		// tmpfs bound, so a size at or below it is the tmpfs size= at work.
		r := runJailedRan(t, spec, "cat /dev/zero > /dev/shm/fill 2>/dev/null; echo fillexit=$?; stat -c size=%s /dev/shm/fill")
		var fillExit, size string
		for _, ln := range strings.Split(r.stdout, "\n") {
			if v, ok := strings.CutPrefix(ln, "fillexit="); ok {
				fillExit = strings.TrimSpace(v)
			}
			if v, ok := strings.CutPrefix(ln, "size="); ok {
				size = strings.TrimSpace(v)
			}
		}
		if fillExit == "" || fillExit == "0" {
			unexpected(t, "rung 1: tmpfs fill exit=%q; expected non-zero (ENOSPC at the tmpfs bound); stdout=%q", fillExit, r.stdout)
		}
		n, err := strconv.ParseInt(size, 10, 64)
		if err != nil {
			unexpected(t, "rung 1: fill size %q not a number (stdout=%q stderr=%q): %v", size, r.stdout, r.stderr, err)
			t.FailNow()
		}
		if n <= 0 || n > tmpfsSizeBytes {
			unexpected(t, "rung 1: tmpfs fill reached %d bytes; want 0 < n <= %d", n, tmpfsSizeBytes)
		}
		return
	}
}

// legProcfsReadOnly proves the rung-1 jail mounts its /proc read-only. The kernel
// control files (/proc/sys, /proc/sysrq-trigger, /proc/irq, ...) check only DAC
// on write, so a root SSH user on a host without Landlock would pass that check;
// the read-only mount is what stops it. The suite runs unprivileged, so the
// write it attempts is to /proc/self/comm, a file every process may write on the
// host (the unjailed control) and whose write meets the same mount-level wall as
// the root-only ones. The jail's mountinfo must show /proc ro, the control files
// must still exist inside (blocked, not missing), and the fd magic links that
// /dev/stdout resolves through must keep working.
func legProcfsReadOnly(t *testing.T, spec Spec) {
	const write = "echo sshgate-ctl > /proc/self/comm"
	if out, err := exec.Command("/bin/sh", "-c", write).CombinedOutput(); err != nil {
		unexpected(t, "unjailed control could not write /proc/self/comm: %v: %s", err, out)
		t.FailNow()
	}
	ctl := []string{"/proc/sysrq-trigger", "/proc/sys/kernel/sysrq", "/proc/irq", "/proc/bus", "/proc/fs"}
	for _, p := range ctl {
		if _, err := os.Stat(p); err != nil {
			unexpected(t, "unjailed control: %s missing on this host: %v", p, err)
			t.FailNow()
		}
	}

	if r := runJailedRan(t, spec, write); r.exit == 0 || !strings.Contains(r.stderr, "Read-only file system") {
		unexpected(t, "jailed write to /proc/self/comm: exit=%d stderr=%q; want an EROFS failure", r.exit, r.stderr)
	}
	if r := runJailedRan(t, spec, "ls -d "+strings.Join(ctl, " ")); r.exit != 0 {
		unexpected(t, "control files not visible in the jail (exit=%d stderr=%q); the leg would be vacuous", r.exit, r.stderr)
	}
	r := runJailedRan(t, spec, "cat /proc/self/mountinfo")
	entries, err := parseMountInfo(strings.NewReader(strings.TrimPrefix(r.stdout, ranCanary+"\n")))
	if err != nil {
		unexpected(t, "parse jailed mountinfo: %v", err)
		t.FailNow()
	}
	var procOpts []string
	for _, e := range entries {
		if e.point == "/proc" {
			procOpts = e.opts // the last /proc entry is the one a lookup reaches
		}
	}
	if len(procOpts) == 0 || procOpts[0] != "ro" {
		unexpected(t, "jail /proc mount options = %v; want ro", procOpts)
	}
	if r := runJailedRan(t, spec, "echo VIA_FD > /dev/stdout"); r.exit != 0 || !strings.Contains(r.stdout, "VIA_FD") {
		unexpected(t, "write through /dev/stdout broke in the jail: exit=%d stdout=%q stderr=%q", r.exit, r.stdout, r.stderr)
	}
}

// legReaper proves the rung-1 pid-1 reaper returns as soon as the WORKER exits
// and does not block on a backgrounded child (the spec's named proof point
// "backgrounded cmd & does not hang"). A hang would be caught by the timeout
// (exit != 0) and by the elapsed-time bound.
func legReaper(t *testing.T, spec Spec) {
	start := time.Now()
	r := runJailedTimeout(t, spec, "sleep 30 & echo BG", 25*time.Second)
	elapsed := time.Since(start)
	if r.setupErr != nil {
		unexpected(t, "reaper leg: jail setup failed: %v", r.setupErr)
		t.FailNow()
	}
	if r.exit != 0 {
		unexpected(t, "reaper leg: exit=%d want 0 (a hang would be killed at the timeout; stderr=%q)", r.exit, r.stderr)
	}
	if !strings.Contains(r.stdout, "BG") {
		unexpected(t, "reaper leg: no BG output (%q); the command did not run", r.stdout)
	}
	if elapsed > 20*time.Second {
		unexpected(t, "reaper leg: returned in %v; the backgrounded sleep held the gate (subreaper cleanup should free it immediately)", elapsed)
	}
}

// legProcState proves outside process state is protected by the retune argument filters.
func legProcState(t *testing.T, spec Spec, probe string) {
	// Control target: prove prlimit/setpriority/setaffinity WORK unjailed.
	ctl := startSleeper(t)
	if out, err := exec.Command(probe, "proc-state", strconv.Itoa(ctl.Process.Pid)).CombinedOutput(); err != nil || !allProbeOK(string(out)) {
		unexpected(t, "unjailed control could not retune an outside process (%v: %s)", err, out)
		t.FailNow()
	}

	// Victim target: snapshot its state, run the JAILED attempt, assert NOTHING
	// changed and every op was refused.
	victim := startSleeper(t)
	vpid := victim.Process.Pid
	niceBefore := readNice(t, vpid)
	nofileBefore := readNofile(t, vpid)
	affBefore := readAffinity(t, vpid)

	r := runLegacyJailed(t, spec, probe+" proc-state "+strconv.Itoa(vpid)+" ; echo "+ranCanary)
	if r.setupErr != nil {
		unexpected(t, "proc-state leg: jail setup failed (nothing ran): %v", r.setupErr)
		t.FailNow()
	}
	if !strings.Contains(r.stdout, ranCanary) {
		unexpected(t, "proc-state leg: probe never ran; stdout=%q stderr=%q", r.stdout, r.stderr)
		t.FailNow()
	}
	if strings.Contains(r.stdout, "=ok") {
		unexpected(t, "a jailed proc-state op succeeded against an outside process; every op must be refused (stdout=%q)", r.stdout)
	}
	if n := readNice(t, vpid); n != niceBefore {
		unexpected(t, "victim nice changed %d -> %d through the jail", niceBefore, n)
	}
	if n := readNofile(t, vpid); n != nofileBefore {
		unexpected(t, "victim RLIMIT_NOFILE changed %d -> %d through the jail", nofileBefore, n)
	}
	if a := readAffinity(t, vpid); a != affBefore {
		unexpected(t, "victim affinity changed %d -> %d cpus through the jail", affBefore, a)
	}
}

// legTtyIsolated checks host pty termios and window size remain unchanged.
func legTtyIsolated(t *testing.T, spec Spec) {
	if !haveTool(t, "stty") {
		t.Skip("stty not installed")
	}
	const set = "-echo rows 7 cols 9"

	ctlPath, ctlFd := openPty(t)
	if out, err := exec.Command("stty", append([]string{"-F", ctlPath}, strings.Fields(set)...)...).CombinedOutput(); err != nil {
		unexpected(t, "unjailed control stty failed (%v): %s", err, out)
		t.FailNow()
	}
	if tio, ws := ttyState(t, ctlFd); tio.Lflag&unix.ECHO != 0 || ws.Row != 7 || ws.Col != 9 {
		unexpected(t, "control: stty did not change the pty (echo=%v rows=%d cols=%d)", tio.Lflag&unix.ECHO != 0, ws.Row, ws.Col)
		t.FailNow()
	}

	vPath, vFd := openPty(t)
	tioBefore, wsBefore := ttyState(t, vFd)
	if tioBefore.Lflag&unix.ECHO == 0 {
		unexpected(t, "victim pty starts with ECHO off; the leg cannot observe a change")
		t.FailNow()
	}
	if r := runJailedRan(t, spec, "stty -F "+vPath+" "+set); r.exit == 0 {
		unexpected(t, "jailed stty -F on an outside pty exited 0; expected failure")
	}
	tioAfter, wsAfter := ttyState(t, vFd)
	if tioAfter != tioBefore {
		unexpected(t, "victim termios changed through the jail: %+v -> %+v", tioBefore, tioAfter)
	}
	if wsAfter != wsBefore {
		unexpected(t, "victim winsize changed through the jail: %+v -> %+v", wsBefore, wsAfter)
	}
}

// openPty opens a throwaway pty pair outside the jail and returns the slave
// path plus an fd on the slave for observing its state; both fds close at
// cleanup.
func openPty(t *testing.T) (string, int) {
	t.Helper()
	m, err := unix.Open("/dev/ptmx", unix.O_RDWR|unix.O_NOCTTY|unix.O_CLOEXEC, 0)
	if err != nil {
		unexpected(t, "open /dev/ptmx: %v", err)
		t.FailNow()
	}
	t.Cleanup(func() { _ = unix.Close(m) })
	if err := unix.IoctlSetPointerInt(m, unix.TIOCSPTLCK, 0); err != nil {
		unexpected(t, "unlockpt: %v", err)
		t.FailNow()
	}
	n, err := unix.IoctlGetUint32(m, unix.TIOCGPTN)
	if err != nil {
		unexpected(t, "ptsname: %v", err)
		t.FailNow()
	}
	path := "/dev/pts/" + strconv.Itoa(int(n))
	s, err := unix.Open(path, unix.O_RDWR|unix.O_NOCTTY|unix.O_CLOEXEC, 0)
	if err != nil {
		unexpected(t, "open %s: %v", path, err)
		t.FailNow()
	}
	t.Cleanup(func() { _ = unix.Close(s) })
	return path, s
}

func ttyState(t *testing.T, fd int) (unix.Termios, unix.Winsize) {
	t.Helper()
	tio, err := unix.IoctlGetTermios(fd, unix.TCGETS)
	if err != nil {
		unexpected(t, "TCGETS: %v", err)
		t.FailNow()
	}
	ws, err := unix.IoctlGetWinsize(fd, unix.TIOCGWINSZ)
	if err != nil {
		unexpected(t, "TIOCGWINSZ: %v", err)
		t.FailNow()
	}
	return *tio, *ws
}

// legReadCorpus replays the classifier's READ corpus inside the jail: a read that
// works on the host must still work in the jail (so the seccomp ENOSYS ceiling is
// not silently breaking a legitimate read), while the
// daemon rows (systemctl/docker/timedatectl — the Lane-2 inventory) are logged,
// not required. Network/follow rows are skipped: they are not about the fs/
// syscall wall and would hang or need connectivity.
func legReadCorpus(t *testing.T, spec Spec) {
	rows := readCorpusRows(t)
	for _, row := range rows {
		if row == "ps aux" {
			for i := 1; i < 20; i++ {
				rows = append(rows, row)
			}
			break
		}
	}
	if len(rows) == 0 {
		unexpected(t, "no READ rows parsed from the classifier corpus")
		t.FailNow()
	}
	const perCmd = 5 * time.Second
	var broke, logged, ran int
	for _, cmd := range rows {
		// Control: does this read work on the host at all? If not (missing file,
		// absent tool, no connectivity), it is environmental, not the jail.
		if !hostReadOK(cmd, perCmd) {
			continue
		}
		ran++
		r := runJailedTimeout(t, spec, cmd, perCmd)
		if r.setupErr != nil {
			unexpected(t, "read %q: jail setup failed: %v", cmd, r.setupErr)
			continue
		}
		if isSeccompKill(r.exit) {
			unexpected(t, "read %q: killed by seccomp (exit=%d); the jail broke a legitimate read", cmd, r.exit)
			continue
		}
		if r.exit == 0 {
			continue
		}
		if os.Geteuid() == 0 && cmd == "dmesg" && strings.Contains(strings.ToLower(r.stderr), "operation not permitted") {
			t.Log("dmesg denied after dropping CAP_SYSLOG")
			continue
		}
		if isDaemonRow(cmd) {
			logged++
			t.Logf("Lane-2 inventory: %q breaks in the jail (exit=%d) — daemon/AF_UNIX read", cmd, r.exit)
			continue
		}
		broke++
		unexpected(t, "read %q works on the host but exits %d in the jail (stderr=%q)", cmd, r.exit, strings.TrimSpace(r.stderr))
	}
	t.Logf("read corpus: %d rows executed in the jail, %d non-daemon breaks, %d daemon rows logged", ran, broke, logged)
	// A near-empty run (corpus truncated, or no host control passed) would look
	// green; require a floor of real reads so this leg cannot pass vacuously.
	if ran < 20 {
		unexpected(t, "only %d corpus rows actually ran in the jail; expected at least 20 (corpus/host-control problem)", ran)
	}
}

// --- helpers ------------------------------------------------------------------

func runLegacyJailed(t *testing.T, spec Spec, cmd string) jailResult {
	return runJailedTimeout(t, spec, cmd, 30*time.Second)
}

// ranCanary is appended to a destructive command so a leg can prove the shell
// actually reached and ran it (vs a setup failure that never execs).
const ranCanary = "JAILRAN"

// runJailedRan runs a destructive command and FAILS the leg (not asserts) when
// the jail aborted in setup or the shell never ran — so a setup failure (exit 70,
// nothing ran) or a missing tool can never let a "blocked" assertion pass
// vacuously. The canary is PREPENDED ("echo <canary> ; <cmd>"): proving the shell
// execve'd while leaving r.exit equal to the destructive command's own exit code
// (an appended canary would mask it with echo's 0).
func runJailedRan(t *testing.T, spec Spec, cmd string) jailResult {
	t.Helper()
	r := runLegacyJailed(t, spec, "echo "+ranCanary+" ; "+cmd)
	if r.setupErr != nil {
		unexpected(t, "jail setup failed (nothing ran) for %q: %v (stderr=%q)", cmd, r.setupErr, r.stderr)
		t.FailNow()
	}
	if !strings.Contains(r.stdout, ranCanary) {
		unexpected(t, "command %q never reached the shell (no canary); stdout=%q stderr=%q", cmd, r.stdout, r.stderr)
		t.FailNow()
	}
	return r
}

// startSleeper launches a throwaway `sleep` OUTSIDE the jail and returns it; the
// proc-state legs target only this process (never -u / a whole uid), so a jailed
// attempt can do no host-wide damage even before the fix lands.
func startSleeper(t *testing.T) *exec.Cmd {
	t.Helper()
	if !haveTool(t, "sleep") {
		t.Skip("sleep not installed")
	}
	c := exec.Command("sleep", "3600")
	if err := c.Start(); err != nil {
		unexpected(t, "start sleeper: %v", err)
		t.FailNow()
	}
	t.Cleanup(func() {
		_ = c.Process.Kill()
		_, _ = c.Process.Wait()
	})
	return c
}

// readNice returns a process's nice value from /proc/<pid>/stat (field 19, after
// the parenthesised comm which may itself contain spaces/parens).
func readNice(t *testing.T, pid int) int {
	t.Helper()
	b, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/stat")
	if err != nil {
		unexpected(t, "read stat %d: %v", pid, err)
		t.FailNow()
	}
	s := string(b)
	i := strings.LastIndexByte(s, ')')
	if i < 0 {
		unexpected(t, "malformed stat for %d: %q", pid, s)
		t.FailNow()
	}
	fields := strings.Fields(s[i+1:]) // fields[0]=state, so nice is index 16
	if len(fields) < 17 {
		unexpected(t, "stat for %d has too few fields: %q", pid, s)
		t.FailNow()
	}
	n, err := strconv.Atoi(fields[16])
	if err != nil {
		unexpected(t, "parse nice for %d (%q): %v", pid, fields[16], err)
		t.FailNow()
	}
	return n
}

// readNofile returns a process's RLIMIT_NOFILE soft limit (same-uid read, no
// change).
func readNofile(t *testing.T, pid int) uint64 {
	t.Helper()
	var lim unix.Rlimit
	if err := unix.Prlimit(pid, unix.RLIMIT_NOFILE, nil, &lim); err != nil {
		unexpected(t, "read nofile for %d: %v", pid, err)
		t.FailNow()
	}
	return lim.Cur
}

// readAffinity returns the number of CPUs in a process's affinity mask.
func readAffinity(t *testing.T, pid int) int {
	t.Helper()
	var set unix.CPUSet
	if err := unix.SchedGetaffinity(pid, &set); err != nil {
		unexpected(t, "read affinity for %d: %v", pid, err)
		t.FailNow()
	}
	return set.Count()
}

func runJailedTimeout(t *testing.T, spec Spec, cmd string, d time.Duration) jailResult {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), d)
	defer cancel()
	j, err := spec.Command(ctx, cmd)
	if err != nil {
		unexpected(t, "Command(%q): %v", cmd, err)
		t.FailNow()
	}
	var out, errb bytes.Buffer
	j.Cmd.Stdout = &out
	j.Cmd.Stderr = &errb
	j.Cmd.Stdin = nil
	if err := j.Cmd.Start(); err != nil {
		j.Abort()
		unexpected(t, "start jail for %q: %v", cmd, err)
		t.FailNow()
	}
	_ = j.Started()
	waitErr := j.Cmd.Wait()
	_, setupErr := j.Status()
	return jailResult{exit: exitCodeOf(waitErr), stdout: out.String(), stderr: errb.String(), setupErr: setupErr}
}

func exitCodeOf(err error) int {
	if err == nil {
		return 0
	}
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		if ws, ok := ee.Sys().(syscall.WaitStatus); ok {
			if ws.Signaled() {
				return 128 + int(ws.Signal())
			}
			return ws.ExitStatus()
		}
	}
	return -1
}

// isSeccompKill reports whether an exit code is a SIGSYS kill (128+31), the
// signature of a syscall the seccomp filter refused with KILL.
func isSeccompKill(exit int) bool { return exit == 128+int(unix.SIGSYS) }

// seedTarget creates a temp file under $HOME (read-only in the jail on every
// rung — it is not /tmp, /var/tmp, /dev/shm or the scratch dir) and returns its
// path, cleaned up after the test.
func seedTarget(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp(homeDir(t), ".sshgate-jailtest-")
	if err != nil {
		unexpected(t, "mkdir temp in home: %v", err)
		t.FailNow()
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	target := filepath.Join(dir, "target")
	if err := os.WriteFile(target, []byte("original-content"), 0644); err != nil {
		unexpected(t, "seed target: %v", err)
		t.FailNow()
	}
	return target
}

func homeDir(t *testing.T) string {
	t.Helper()
	home, err := os.UserHomeDir()
	if err != nil {
		unexpected(t, "home dir: %v", err)
		t.FailNow()
	}
	return home
}

func haveTool(t *testing.T, name string) bool {
	t.Helper()
	_, err := exec.LookPath(name)
	return err == nil
}

func hashFile(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		unexpected(t, "read %s: %v", path, err)
		t.FailNow()
	}
	return fmt.Sprintf("%x", sha256.Sum256(b))
}

func statMode(t *testing.T, path string) string {
	t.Helper()
	fi, err := os.Stat(path)
	if err != nil {
		unexpected(t, "stat %s: %v", path, err)
		t.FailNow()
	}
	return fmt.Sprintf("%v|%d|%d", fi.Mode(), fi.Size(), fi.ModTime().UnixNano())
}

func lsattr(t *testing.T, path string) string {
	t.Helper()
	out, err := exec.Command("lsattr", path).Output()
	if err != nil {
		unexpected(t, "lsattr %s: %v", path, err)
		t.FailNow()
	}
	// lsattr prints "<flags> <path>"; keep only the flags.
	return strings.Fields(string(out))[0]
}

func getfattr(t *testing.T, path string) string {
	t.Helper()
	out, err := exec.Command("getfattr", "-d", "-m", "-", path).CombinedOutput()
	if err != nil {
		unexpected(t, "getfattr %s: %v\n%s", path, err, out)
		t.FailNow()
	}
	return string(out)
}

// fifoRoundTrip makes a FIFO named <name> under dir, opens the read end
// (non-blocking, so it needs no live writer), runs write(fifo), and returns
// whatever reached the reader within a short window.
func fifoRoundTrip(t *testing.T, dir, name string, write func(fifo string)) string {
	t.Helper()
	fifo := filepath.Join(dir, name+".fifo")
	if err := unix.Mkfifo(fifo, 0o644); err != nil {
		unexpected(t, "mkfifo: %v", err)
		t.FailNow()
	}
	defer os.Remove(fifo)
	rf, err := os.OpenFile(fifo, os.O_RDONLY|unix.O_NONBLOCK, 0)
	if err != nil {
		unexpected(t, "open fifo read end: %v", err)
		t.FailNow()
	}
	defer rf.Close()

	write(fifo)

	deadline := time.Now().Add(2 * time.Second)
	var got bytes.Buffer
	buf := make([]byte, 64)
	for time.Now().Before(deadline) {
		if err := rf.SetReadDeadline(time.Now().Add(100 * time.Millisecond)); err != nil {
			t.Fatalf("SETUP: FIFO reader deadline: %v", err)
		}
		n, err := rf.Read(buf)
		if err != nil && !errors.Is(err, io.EOF) && !errors.Is(err, unix.EAGAIN) && !errors.Is(err, unix.EWOULDBLOCK) && !errors.Is(err, os.ErrDeadlineExceeded) {
			t.Fatalf("SETUP: FIFO reader: %v", err)
		}
		if n > 0 {
			got.Write(buf[:n])
			break
		}
		if errors.Is(err, os.ErrDeadlineExceeded) {
			continue
		}
		// EOF/EAGAIN with no writer: keep polling until the deadline.
	}
	return got.String()
}

// shmCreate makes a throwaway SysV shm segment owned by this uid and returns its
// id. shmExists/shmRemove query and delete it.
func shmCreate(t *testing.T) int {
	t.Helper()
	id, err := unix.SysvShmGet(unix.IPC_PRIVATE, 4096, unix.IPC_CREAT|unix.IPC_EXCL|0o600)
	if err != nil {
		t.Skipf("cannot create a SysV shm segment (%v); IPC leg skipped", err)
	}
	return id
}

func shmExists(id int) bool {
	var ds unix.SysvShmDesc
	_, err := unix.SysvShmCtl(id, unix.IPC_STAT, &ds)
	return err == nil
}

func shmRemove(id int) { _, _ = unix.SysvShmCtl(id, unix.IPC_RMID, nil) }

// hostReadOK runs a corpus command UNJAILED with a timeout and reports whether it
// exits 0 — i.e. whether this read works on the host at all.
func hostReadOK(cmd string, d time.Duration) bool {
	ctx, cancel := context.WithTimeout(context.Background(), d)
	defer cancel()
	c := exec.CommandContext(ctx, "/bin/sh", "-c", cmd)
	c.Stdin = nil
	return c.Run() == nil
}

// daemonRowPrefixes are the corpus command heads that talk to a local daemon over
// a unix socket / D-Bus, which the jail's AF_UNIX denial breaks by design (the
// Lane-2 inventory).
var daemonRowPrefixes = map[string]bool{
	"systemctl": true, "docker": true, "timedatectl": true,
	"loginctl": true, "hostnamectl": true, "machinectl": true, "busctl": true,
}

func isDaemonRow(cmd string) bool {
	f := strings.Fields(cmd)
	return len(f) > 0 && daemonRowPrefixes[f[0]]
}

// corpusSkipHeads are command heads that need network or follow a stream: not
// about the fs/syscall wall, and they would hang or require connectivity.
var corpusSkipHeads = map[string]bool{
	"ping": true, "dig": true, "nslookup": true, "traceroute": true,
	"curl": true, "wget": true, "nc": true, "telnet": true, "ssh": true,
}

func readCorpusRows(t *testing.T) []string {
	t.Helper()
	// confine is src/gate/confine; the corpus lives at <repo>/tests/testdata.
	path := filepath.Join("..", "..", "..", "tests", "testdata", "classifier-corpus.txt")
	f, err := os.Open(path)
	if err != nil {
		unexpected(t, "open corpus: %v", err)
		t.FailNow()
	}
	defer f.Close()
	var rows []string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := sc.Text()
		if strings.HasPrefix(line, "#") || strings.TrimSpace(line) == "" {
			continue
		}
		parts := strings.SplitN(line, "\t", 2)
		if len(parts) != 2 || parts[0] != "READ" {
			continue
		}
		cmd := strings.TrimSpace(parts[1])
		fields := strings.Fields(cmd)
		if len(fields) == 0 || corpusSkipHeads[fields[0]] {
			continue
		}
		if fields[0] == "tail" && strings.Contains(cmd, "-f") {
			continue // follow: would hang
		}
		rows = append(rows, cmd)
	}
	if err := sc.Err(); err != nil {
		unexpected(t, "scan corpus: %v", err)
		t.FailNow()
	}
	return rows
}

func buildProbe(t *testing.T) string {
	t.Helper()
	// Build under $HOME so the helper shares the persistent fixture filesystem. $HOME is part of
	// the read-only bind, so the helper is visible and executable there.
	dir, err := os.MkdirTemp(homeDir(t), ".sshgate-jailprobe-")
	if err != nil {
		t.Fatalf("SETUP: mkdir probe dir: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	bin := filepath.Join(dir, "probe")
	// CGO_ENABLED=0 so the helper is self-contained inside the jail (no reliance
	// on the dynamic loader/libc layout under the read-only bind).
	cmd := exec.Command("go", "build", "-o", bin, "./testdata/probe")
	cmd.Env = append(os.Environ(), "CGO_ENABLED=0")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("SETUP: build probe helper: %v\n%s", err, out)
	}
	return bin
}
