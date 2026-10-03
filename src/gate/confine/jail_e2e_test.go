//go:build linux && jail_e2e

// Package confine's jail acceptance matrix. Tagged jail_e2e and run by
// `make test-jail`, NOT by `make test`: these legs build a helper and run real
// confined commands. Each leg skips with a clear reason when the host lacks the
// probed feature, so the suite is never "green by skip" silently.
//
// The matrix runs the full leg set across eight configurations — rung 1, rung 1
// with Landlock forced off, rung 2, and rung 2 forced to ABI 1/2/3/4/5 (each an
// ABI where a rung-2 wall moves between Landlock and seccomp) — plus a
// dedicated check that rung 2 with no Landlock FAILS CLOSED at the landlock
// stage (Landlock is rung 2's only fs wall). Every destructive leg carries an
// UNJAILED control proving the attack works on the host, so a leg that "passes"
// because the tool was missing or the fs could not support it is impossible.
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
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// jailCfg is one matrix configuration: a rung, an optional forced ABI, and
// whether it runs the heavy native-only legs (fill, read corpus).
type jailCfg struct {
	name     string
	rung     Rung
	forceABI int  // 0 = host ABI; ForceNoLandlock = none; >0 = capped
	native   bool // run the heavy legs (fill, corpus) only on the native rungs
}

// noLandlock reports whether this config emulates a host with no Landlock.
func (c jailCfg) noLandlock() bool { return c.forceABI == ForceNoLandlock }

// effABI is the Landlock ABI this config actually enforces with, given the host
// ABI, mirroring effectiveABI in the worker.
func (c jailCfg) effABI(hostABI int) int { return effectiveABI(hostABI, c.forceABI) }

// spec builds the Spec for this config, with a fresh scratch dir for rung 2.
func (c jailCfg) spec(t *testing.T) Spec {
	t.Helper()
	s := Spec{Rung: c.rung, AllowInet: true, ForceABI: c.forceABI}
	if c.rung == Rung2Landlock {
		s.ScratchDir = t.TempDir()
	}
	return s
}

func TestJailMatrix(t *testing.T) {
	rep := Detect()
	t.Logf("host: rung=%s landlock_abi=%d userns=%v seccomp=%v probeErr=%v",
		rep.Rung, rep.LandlockABI, rep.Userns, rep.Seccomp, rep.ProbeErr)

	probe := buildProbe(t) // built ONCE; every leg reuses the same binary

	cfgs := []jailCfg{
		{name: "rung1", rung: Rung1Full, forceABI: 0, native: true},
		{name: "rung1_no_landlock", rung: Rung1Full, forceABI: ForceNoLandlock},
		{name: "rung2", rung: Rung2Landlock, forceABI: 0, native: true},
		{name: "rung2_abi1", rung: Rung2Landlock, forceABI: 1},
		{name: "rung2_abi2", rung: Rung2Landlock, forceABI: 2},
		{name: "rung2_abi3", rung: Rung2Landlock, forceABI: 3},
		{name: "rung2_abi4", rung: Rung2Landlock, forceABI: 4},
		{name: "rung2_abi5", rung: Rung2Landlock, forceABI: 5},
	}

	for _, cfg := range cfgs {
		cfg := cfg
		switch cfg.rung {
		case Rung1Full:
			if !rep.Userns {
				t.Logf("SKIP %s: no unprivileged userns (%v)", cfg.name, rep.ProbeErr)
				continue
			}
		case Rung2Landlock:
			if rep.LandlockABI < 1 {
				t.Logf("SKIP %s: Landlock unavailable (abi=%d)", cfg.name, rep.LandlockABI)
				continue
			}
			if cfg.forceABI > 0 && rep.LandlockABI < cfg.forceABI {
				t.Logf("SKIP %s: host Landlock ABI %d < forced %d", cfg.name, rep.LandlockABI, cfg.forceABI)
				continue
			}
		}
		t.Run(cfg.name, func(t *testing.T) { runLegs(t, cfg, rep.LandlockABI, probe) })
	}

	// rung 2 with Landlock forced off must FAIL CLOSED: Landlock is rung 2's only
	// fs wall, so the worker aborts at the landlock stage and NOTHING runs.
	if rep.LandlockABI >= 1 {
		t.Run("rung2_no_landlock_fails_closed", func(t *testing.T) {
			spec := Spec{Rung: Rung2Landlock, AllowInet: true, ForceABI: ForceNoLandlock, ScratchDir: t.TempDir()}
			r := runJailed(t, spec, "echo SHOULD_NOT_RUN")
			var se *SetupError
			if !errors.As(r.setupErr, &se) {
				t.Fatalf("expected *SetupError, got %v", r.setupErr)
			}
			if se.Stage != "landlock" {
				t.Errorf("SetupError stage=%q want landlock", se.Stage)
			}
			if strings.Contains(r.stdout, "SHOULD_NOT_RUN") {
				t.Errorf("command ran despite rung-2 Landlock being unavailable")
			}
		})
	}
}

func runLegs(t *testing.T, cfg jailCfg, hostABI int, probe string) {
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
	t.Run("fifo", func(t *testing.T) { legFifo(t, cfg, spec) })
	t.Run("ipc", func(t *testing.T) { legIPC(t, cfg, spec, probe) })
	t.Run("fail_closed_before_execve", func(t *testing.T) { legFailClosed(t, spec) })

	if spec.Rung == Rung1Full {
		// The pid-1 reaper must not hang on a backgrounded child (pid-ns teardown).
		t.Run("reaper_no_hang", func(t *testing.T) { legReaper(t, spec) })
	}
	if spec.Rung == Rung2Landlock {
		// Rung 2 shares /proc with the host: seccomp must stop a jailed command
		// retuning another same-uid process. (Rung 1's pid namespace hides them.)
		t.Run("proc_state_isolated", func(t *testing.T) { legProcState(t, spec, probe) })
		// Rung 2 shares /dev/pts: a jailed command must not retune another
		// same-uid session's terminal (Landlock IOCTL_DEV at ABI ≥5, seccomp below).
		t.Run("tty_isolated", func(t *testing.T) { legTtyIsolated(t, spec) })
		if abi := cfg.effABI(hostABI); abi >= 1 && abi < 3 {
			t.Run("truncate_seccomp_below_abi3", func(t *testing.T) { legTruncateSeccompBelowABI3(t, spec) })
		}
	}
	if cfg.native {
		t.Run("fill_bounded", func(t *testing.T) { legFill(t, cfg, spec) })
		t.Run("read_corpus_clean", func(t *testing.T) { legReadCorpus(t, spec) })
	}
}

// --- legs ---------------------------------------------------------------------

func legReadsWork(t *testing.T, spec Spec) {
	for _, cmd := range []string{"cat /etc/hostname", "id", "ls /", "echo RAN"} {
		r := runJailed(t, spec, cmd)
		if r.setupErr != nil {
			t.Fatalf("%q: unexpected setup failure: %v (stderr=%q)", cmd, r.setupErr, r.stderr)
		}
		if r.exit != 0 {
			t.Errorf("%q: exit=%d want 0 (stderr=%q)", cmd, r.exit, r.stderr)
		}
	}
	if r := runJailed(t, spec, "echo RAN"); !strings.Contains(r.stdout, "RAN") {
		t.Errorf("echo RAN produced no stdout (%q)", r.stdout)
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
			t.Fatalf("corpus %q: mkdir under home: %v", row.name, err)
		}
		func() {
			defer os.RemoveAll(dir)
			target := filepath.Join(dir, "target")
			seed := []byte("original-content\n")
			if err := os.WriteFile(target, seed, 0o644); err != nil {
				t.Fatalf("corpus %q: seed target: %v", row.name, err)
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
				t.Fatalf("corpus %q: reset target: %v", row.name, err)
			}
			if marker != "" {
				_ = os.Remove(marker)
			}
			jBefore := hashFile(t, target)
			// runJailedRan proves the shell execve'd (canary), so a setup abort can
			// never let a "contained" assertion pass without the exploit running.
			_ = runJailedRan(t, spec, cmd)
			if hashFile(t, target) != jBefore {
				t.Errorf("corpus %q: jailed exploit MODIFIED the seeded target %s; the jail did not contain the write", row.name, target)
			}
			if marker != "" && pathExists(marker) {
				t.Errorf("corpus %q: jailed exploit created marker %s; the jail did not contain the write", row.name, marker)
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
					t.Fatalf("seed magic: %v", err)
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
					t.Fatalf("mkdir out: %v", err)
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
					t.Fatalf("seed inc.awk: %v", err)
				}
				return fmt.Sprintf(`gawk '@include "%s"'`, inc), marker
			},
		},
		// --- No file sink: a network-side HTTP POST. Phase 1 keeps inet in front of
		// the classifier (STEPBACK step 2 "deny inet" is a later step), so the jail
		// does not contain it — carved out, not asserted.
		{name: "curl_json_post", skip: "network-side HTTP POST (curl --json); no file sink, contained by STEPBACK step 2 'deny inet', not Phase 1"},
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
		t.Fatalf("seed payload: %v", err)
	}
	return p
}

// mustGitRepo makes a one-commit git repo at repo with a file matching "hello"
// (the git-grep corpus row needs a real working tree). Global/system gitconfig is
// neutralised so the operator's settings cannot perturb the fixture.
func mustGitRepo(t *testing.T, repo string) {
	t.Helper()
	if err := os.MkdirAll(repo, 0o755); err != nil {
		t.Fatalf("mkdir repo: %v", err)
	}
	if err := os.WriteFile(filepath.Join(repo, "f"), []byte("hello\n"), 0o644); err != nil {
		t.Fatalf("seed repo file: %v", err)
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
			t.Fatalf("git %v: %v\n%s", args, err, out)
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
		t.Errorf("jailed write exited 0; expected failure")
	}
	if after := hashFile(t, target); after != before {
		t.Errorf("seeded target was modified by the jailed write (%s)", target)
	}
	if _, err := os.Stat(marker); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("marker %s exists (err=%v); the jailed write was not contained", marker, err)
	}
}

func legMetadata(t *testing.T, spec Spec) {
	target := seedTarget(t)
	ctl := filepath.Join(filepath.Dir(target), "ctl")
	if err := os.WriteFile(ctl, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
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
			t.Errorf("%q exited 0; expected failure", cmd)
		}
	}
	if statMode(t, target) != before {
		t.Errorf("seeded target metadata changed")
	}
	if hashFile(t, target) != hashBefore {
		t.Errorf("seeded target content changed (truncate got through)")
	}
}

// legChattr proves the chattr/FS_IOC_SETFLAGS metadata-ioctl path is closed: an
// unjailed control shows `chattr +d` succeeds on this filesystem, then the jailed
// run must fail and leave lsattr unchanged (rung 1: EROFS; rung 2: seccomp denies
// the FS_IOC_SETFLAGS/FS_IOC_FSSETXATTR ioctls and SYS_FILE_SETATTR).
func legChattr(t *testing.T, spec Spec, probe string) {
	if !haveTool(t, "chattr") || !haveTool(t, "lsattr") {
		t.Skip("chattr/lsattr not installed")
	}
	target := seedTarget(t)
	ctl := filepath.Join(filepath.Dir(target), "ctl")
	if err := os.WriteFile(ctl, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	// Control: chattr +d must work unjailed, or the filesystem cannot carry the
	// flag and the leg is meaningless here.
	if out, err := exec.Command("chattr", "+d", ctl).CombinedOutput(); err != nil {
		t.Skipf("chattr +d unsupported on this fs (%v: %s)", err, out)
	}
	_ = exec.Command("chattr", "-d", ctl).Run()

	before := lsattr(t, target)
	if r := runJailedRan(t, spec, "chattr +d "+target); r.exit == 0 {
		t.Errorf("jailed `chattr +d` exited 0; expected failure")
	}
	if after := lsattr(t, target); after != before {
		t.Errorf("lsattr changed by the jailed chattr: %q -> %q", before, after)
	}

	// Tool-independent: the probe exercises FS_IOC_SETFLAGS, FS_IOC_FSSETXATTR and
	// file_setattr directly (chattr only drives FS_IOC_SETFLAGS). An unjailed
	// control on a separate file must show every ioctl/syscall succeeds, then the
	// jailed run must have every one fail and leave lsattr unchanged.
	pctl := filepath.Join(filepath.Dir(target), "setflags-ctl")
	if err := os.WriteFile(pctl, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
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
	r := runJailed(t, spec, probe+" setflags "+target+" ; echo "+ranCanary)
	if r.setupErr != nil {
		t.Fatalf("probe setflags: jail setup failed: %v", r.setupErr)
	}
	if !strings.Contains(r.stdout, ranCanary) {
		t.Fatalf("probe setflags never ran; stdout=%q stderr=%q", r.stdout, r.stderr)
	}
	for _, op := range []string{"setflags=ok", "fssetxattr=ok", "file_setattr=ok"} {
		if strings.Contains(r.stdout, op) {
			t.Errorf("jailed probe setflags reported %q; the metadata-ioctl path is open (stdout=%q)", op, r.stdout)
		}
	}
	if after := lsattr(t, target); after != pbefore {
		t.Errorf("lsattr changed by the jailed probe setflags: %q -> %q", pbefore, after)
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

// legXattr proves the user-xattr path is closed: an unjailed control sets a
// user.* xattr, then the jailed setfattr -n (add) and -x (remove) against a
// pre-seeded target must fail and leave the getfattr dump unchanged (rung 1:
// EROFS; rung 2: Landlock read-only + seccomp SETXATTR/REMOVEXATTR deny).
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
		t.Fatal(err)
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
			t.Errorf("jailed %q exited 0; expected failure", cmd)
		}
	}
	if after := getfattr(t, target); after != before {
		t.Errorf("xattr list changed by the jailed setfattr:\n before=%q\n after =%q", before, after)
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
		r := runJailed(t, spec, op.cmd+" ; echo "+ranCanary)
		if r.setupErr != nil {
			t.Fatalf("probe %s: jail setup failed: %v", op.name, r.setupErr)
		}
		if !strings.Contains(r.stdout, ranCanary) {
			t.Fatalf("probe %s never ran; stdout=%q stderr=%q", op.name, r.stdout, r.stderr)
		}
		for _, w := range op.writes {
			if strings.Contains(r.stdout, w) {
				t.Errorf("jailed probe %s reported %q; the xattr-write path is open (stdout=%q)", op.name, w, r.stdout)
			}
		}
	}
	if after := getfattr(t, target); after != before {
		t.Errorf("xattr list changed by the jailed probe ops:\n before=%q\n after =%q", before, after)
	}
}

func legAFUnix(t *testing.T, spec Spec, probe string) {
	// A real listener under $HOME (visible on every rung — /tmp is overmounted on
	// rung 1 and Landlock-hidden-from-writes on rung 2), with an unjailed control
	// dial proving the socket actually accepts connections.
	home := homeDir(t)
	dir, err := os.MkdirTemp(home, ".sshgate-jailsock-")
	if err != nil {
		t.Fatalf("mkdir sock dir: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	sock := filepath.Join(dir, "s.sock")

	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatalf("listen unix: %v", err)
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
		t.Fatalf("unjailed control dial failed (%v): %s", err, out)
	} else if !strings.Contains(string(out), "socket=ok") || !strings.Contains(string(out), "connect=ok") {
		t.Fatalf("unjailed control dial did not connect: %s", out)
	}

	// Jailed: socket(AF_UNIX) is denied at creation (EPERM==1), before any connect.
	r := runJailed(t, spec, probe+" dial-unix "+sock)
	if r.exit == 0 {
		t.Fatalf("jailed AF_UNIX dial succeeded; expected EPERM")
	}
	if !strings.Contains(r.stdout, "socket="+strconv.Itoa(int(unix.EPERM))) {
		t.Errorf("jailed probe did not report socket=EPERM(%d); stdout=%q stderr=%q",
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
		t.Fatalf("unjailed control could not open /proc/<testpid>/mem (PR_SET_PTRACER ineffective?): %s", out)
	}

	// Jailed: the open must FAIL — rung 1 cannot even see the host pid (fresh
	// /proc), rung 2 is blocked by Landlock's ptrace restriction on a target
	// outside the jail's domain.
	r := runJailedRan(t, spec, probe+" read-mem "+pid)
	if strings.Contains(r.stdout, "open=ok") {
		t.Errorf("jailed probe opened /proc/<testpid>/mem (stdout=%q); the read should be blocked", r.stdout)
	}
	if r.exit == 0 {
		t.Errorf("jailed read-mem exited 0; expected failure")
	}
}

func legRlimits(t *testing.T, spec Spec) {
	rf := runJailed(t, spec, "ulimit -f")
	if rf.setupErr != nil {
		t.Fatalf("ulimit -f setup failure: %v", rf.setupErr)
	}
	if strings.TrimSpace(rf.stdout) == "unlimited" {
		t.Errorf("RLIMIT_FSIZE not applied: ulimit -f = unlimited")
	}
	// RLIMIT_NPROC is a rung-1-only bound (namespace-local); rung 2 defers it to
	// the cgroup harden phase, so only assert it on rung 1.
	if spec.Rung == Rung1Full {
		ru := runJailed(t, spec, "ulimit -u")
		if ru.setupErr != nil {
			t.Fatalf("ulimit -u setup failure: %v", ru.setupErr)
		}
		n, err := strconv.Atoi(strings.TrimSpace(ru.stdout))
		if err != nil {
			t.Fatalf("ulimit -u output %q not a number: %v", ru.stdout, err)
		}
		if n > defaultRlimitNproc {
			t.Errorf("RLIMIT_NPROC not applied: ulimit -u = %d > %d", n, defaultRlimitNproc)
		}
	}
}

// legFifo covers the special-file write that a read-only MOUNT does not stop
// (opening a FIFO for write skips the ro check). On rung 1 WITHOUT Landlock this
// is a recorded residual: the write reaches a reader
// outside the jail. Every Landlock configuration (and rung 1 with Landlock) must
// deny the write. An unjailed control proves the FIFO mechanism works.
func legFifo(t *testing.T, cfg jailCfg, spec Spec) {
	if !haveTool(t, "mkfifo") {
		t.Skip("mkfifo not installed")
	}
	home := homeDir(t)
	dir, err := os.MkdirTemp(home, ".sshgate-jailfifo-")
	if err != nil {
		t.Fatalf("mkdir fifo dir: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })

	// Control: an unjailed write reaches the reader.
	if got := fifoRoundTrip(t, dir, "ctl", func(fifo string) {
		if out, err := exec.Command("sh", "-c", "printf FIFOWRITE > "+fifo).CombinedOutput(); err != nil {
			t.Fatalf("unjailed control fifo write failed (%v): %s", err, out)
		}
	}); !strings.Contains(got, "FIFOWRITE") {
		t.Fatalf("control: FIFO write did not reach the reader (got %q)", got)
	}

	// Jailed write (runJailedRan proves the shell ran, so a setup failure cannot
	// masquerade as a contained write).
	got := fifoRoundTrip(t, dir, "jail", func(fifo string) {
		runJailedRan(t, spec, "printf FIFOWRITE > "+fifo)
	})
	reached := strings.Contains(got, "FIFOWRITE")

	if cfg.rung == Rung1Full && cfg.noLandlock() {
		// Recorded residual: rung 1 with no Landlock cannot stop a FIFO write.
		if !reached {
			t.Logf("note: rung-1-no-Landlock FIFO write did NOT reach the reader (got %q); "+
				"residual not reproduced here but still documented", got)
		} else {
			t.Logf("recorded residual: rung-1-no-Landlock FIFO write reached the reader")
		}
		return
	}
	if reached {
		t.Errorf("jailed FIFO write reached the reader (got %q); expected it to be denied", got)
	}
}

// legIPC covers SysV shared memory. Rung 1 adds CLONE_NEWIPC, so a host shm id is
// invalid inside the jail and the segment survives a jailed ipcrm (isolated).
// Rung 2 has no IPC namespace: a jailed ipcrm of a same-uid segment deletes it —
// a recorded residual. An unjailed control proves the removal mechanism works.
func legIPC(t *testing.T, cfg jailCfg, spec Spec, probe string) {
	// Control: removing a throwaway segment works outside the jail.
	ctlID := shmCreate(t)
	if out, err := exec.Command(probe, "shm-rmid", strconv.Itoa(ctlID)).CombinedOutput(); err != nil {
		shmRemove(ctlID)
		t.Fatalf("unjailed control shm-rmid failed (%v): %s", err, out)
	}
	if shmExists(ctlID) {
		shmRemove(ctlID)
		t.Fatalf("control: segment %d still exists after an unjailed ipcrm", ctlID)
	}

	id := shmCreate(t)
	defer shmRemove(id)
	// runJailedRan prepends the canary, so r.exit stays the probe's own exit code.
	r := runJailedRan(t, spec, probe+" shm-rmid "+strconv.Itoa(id))

	if cfg.rung == Rung1Full {
		if !shmExists(id) {
			t.Errorf("rung 1: host shm segment %d was deleted from inside the jail; CLONE_NEWIPC should isolate it", id)
		}
		if r.exit == 0 {
			t.Errorf("rung 1: jailed shm-rmid exited 0; the host id should be invalid in the new IPC namespace")
		}
		return
	}
	// Rung 2: no IPC namespace — the recorded residual.
	if shmExists(id) {
		t.Logf("note: rung-2 jailed shm-rmid did NOT delete host segment %d; residual not reproduced here", id)
	} else {
		t.Logf("recorded residual (rung 2 has no IPC namespace): jailed ipcrm deleted host shm segment %d", id)
	}
}

func legFailClosed(t *testing.T, spec Spec) {
	stages := []string{"cmdread", "nnp", "caps", "rlimits", "landlock", "seccomp"}
	if spec.Rung == Rung1Full {
		stages = []string{"cmdread", "mounts", "nnp", "caps", "rlimits", "landlock", "seccomp"}
	}
	for _, stage := range stages {
		target := seedTarget(t)
		marker := filepath.Join(filepath.Dir(target), "marker")
		before := hashFile(t, target)

		s := spec
		s.InjectFailAt = stage
		r := runJailed(t, s, "echo pwned >> "+target+" ; echo m > "+marker+" ; echo SHOULD_NOT_RUN")

		var se *SetupError
		if !errors.As(r.setupErr, &se) {
			t.Errorf("stage %q: expected *SetupError, got %v", stage, r.setupErr)
			continue
		}
		if se.Stage != stage {
			t.Errorf("stage %q: SetupError names stage %q", stage, se.Stage)
		}
		if strings.Contains(r.stdout, "SHOULD_NOT_RUN") {
			t.Errorf("stage %q: command executed despite injected setup failure", stage)
		}
		if hashFile(t, target) != before {
			t.Errorf("stage %q: seeded target changed; the command ran", stage)
		}
		if _, err := os.Stat(marker); !errors.Is(err, os.ErrNotExist) {
			t.Errorf("stage %q: marker exists; the command ran", stage)
		}
	}
}

// legTruncateSeccompBelowABI3 proves the seccomp truncate fallback: on rung 2
// below Landlock ABI 3, truncate/ftruncate are denied by seccomp even for a file
// inside the writable scratch dir (where the write itself would be allowed).
func legTruncateSeccompBelowABI3(t *testing.T, spec Spec) {
	scratch := spec.ScratchDir
	f := filepath.Join(scratch, "f")
	if err := os.WriteFile(f, []byte("data"), 0o644); err != nil {
		t.Fatal(err)
	}
	// A plain append must SUCCEED (writable area)...
	if r := runJailedRan(t, spec, "printf x >> "+f); r.exit != 0 {
		t.Fatalf("append to scratch file failed (exit=%d stderr=%q); scratch should be writable", r.exit, r.stderr)
	}
	// ...but truncate of a scratch file must FAIL (seccomp EPERM) and NOT shrink it.
	g := filepath.Join(scratch, "g")
	if err := os.WriteFile(g, []byte("keepme"), 0o644); err != nil {
		t.Fatal(err)
	}
	gBefore := hashFile(t, g)
	if r := runJailedRan(t, spec, "truncate -s 0 "+g); r.exit == 0 {
		t.Errorf("truncate of a writable scratch file succeeded below ABI 3; seccomp should deny it")
	}
	if hashFile(t, g) != gBefore {
		t.Errorf("truncate changed the scratch file despite the seccomp deny")
	}
}

// legFill proves a jailed writable-area fill is bounded and cannot exhaust the
// host: rung 1 stops at the tmpfs size, rung 2 at RLIMIT_FSIZE per file.
func legFill(t *testing.T, cfg jailCfg, spec Spec) {
	if spec.Rung == Rung1Full {
		// /tmp is a bounded tmpfs inside the jail; a fill stops at its size and
		// the host is untouched. Fill and measure in the SAME jail (a new jail
		// gets a fresh, empty tmpfs). RLIMIT_FSIZE (1 GiB) is far above the
		// tmpfs bound, so a size at or below it is the tmpfs size= at work.
		r := runJailedRan(t, spec, "cat /dev/zero > /tmp/fill 2>/dev/null; echo fillexit=$?; stat -c size=%s /tmp/fill")
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
			t.Errorf("rung 1: tmpfs fill exit=%q; expected non-zero (ENOSPC at the tmpfs bound); stdout=%q", fillExit, r.stdout)
		}
		n, err := strconv.ParseInt(size, 10, 64)
		if err != nil {
			t.Fatalf("rung 1: fill size %q not a number (stdout=%q stderr=%q): %v", size, r.stdout, r.stderr, err)
		}
		if n <= 0 || n > tmpfsSizeBytes {
			t.Errorf("rung 1: tmpfs fill reached %d bytes; want 0 < n <= %d", n, tmpfsSizeBytes)
		}
		return
	}
	// Rung 2: the scratch dir is on host disk, bounded per file by RLIMIT_FSIZE.
	// The write dies with SIGXFSZ at the limit and the file is capped there.
	fill := filepath.Join(spec.ScratchDir, "fill")
	r := runJailedRan(t, spec, "cat /dev/zero > "+fill+" 2>/dev/null")
	if r.exit == 0 {
		t.Errorf("rung 2: scratch fill exited 0; expected SIGXFSZ at RLIMIT_FSIZE")
	}
	fi, err := os.Stat(fill)
	if err != nil {
		t.Fatalf("stat scratch fill: %v", err)
	}
	if fi.Size() > defaultRlimitFsize {
		t.Errorf("rung 2: scratch fill reached %d bytes > RLIMIT_FSIZE %d", fi.Size(), defaultRlimitFsize)
	}
	_ = os.Remove(fill)
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
		t.Fatalf("reaper leg: jail setup failed: %v", r.setupErr)
	}
	if r.exit != 0 {
		t.Errorf("reaper leg: exit=%d want 0 (a hang would be killed at the timeout; stderr=%q)", r.exit, r.stderr)
	}
	if !strings.Contains(r.stdout, "BG") {
		t.Errorf("reaper leg: no BG output (%q); the command did not run", r.stdout)
	}
	if elapsed > 20*time.Second {
		t.Errorf("reaper leg: returned in %v; the backgrounded sleep held the gate (pid-ns teardown should free it immediately)", elapsed)
	}
}

// legProcState proves rung 2's seccomp wall against a jailed command retuning
// ANOTHER same-uid host process (rung 1's pid namespace hides host pids, so this
// is a rung-2-only concern). The targets are throwaway `sleep` processes the test
// owns — never a whole uid — so a jailed attempt can do no host-wide harm even if
// the wall regressed. An unjailed control proves the operations work on the host.
func legProcState(t *testing.T, spec Spec, probe string) {
	// Control target: prove prlimit/setpriority/setaffinity WORK unjailed.
	ctl := startSleeper(t)
	if out, err := exec.Command(probe, "proc-state", strconv.Itoa(ctl.Process.Pid)).CombinedOutput(); err != nil || !allProbeOK(string(out)) {
		t.Fatalf("unjailed control could not retune an outside process (%v: %s)", err, out)
	}

	// Victim target: snapshot its state, run the JAILED attempt, assert NOTHING
	// changed and every op was refused.
	victim := startSleeper(t)
	vpid := victim.Process.Pid
	niceBefore := readNice(t, vpid)
	nofileBefore := readNofile(t, vpid)
	affBefore := readAffinity(t, vpid)

	r := runJailed(t, spec, probe+" proc-state "+strconv.Itoa(vpid)+" ; echo "+ranCanary)
	if r.setupErr != nil {
		t.Fatalf("proc-state leg: jail setup failed (nothing ran): %v", r.setupErr)
	}
	if !strings.Contains(r.stdout, ranCanary) {
		t.Fatalf("proc-state leg: probe never ran; stdout=%q stderr=%q", r.stdout, r.stderr)
	}
	if strings.Contains(r.stdout, "=ok") {
		t.Errorf("a jailed proc-state op succeeded against an outside process; every op must be refused (stdout=%q)", r.stdout)
	}
	if n := readNice(t, vpid); n != niceBefore {
		t.Errorf("victim nice changed %d -> %d through the jail", niceBefore, n)
	}
	if n := readNofile(t, vpid); n != nofileBefore {
		t.Errorf("victim RLIMIT_NOFILE changed %d -> %d through the jail", nofileBefore, n)
	}
	if a := readAffinity(t, vpid); a != affBefore {
		t.Errorf("victim affinity changed %d -> %d cpus through the jail", affBefore, a)
	}
}

// legTtyIsolated proves a rung-2 jailed command cannot change the terminal
// state of a pty it did not inherit. The test opens throwaway ptys OUTSIDE the
// jail; an unjailed `stty -F` control proves the change works on the host, then
// the jailed attempt must fail and leave termios and winsize unchanged.
func legTtyIsolated(t *testing.T, spec Spec) {
	if !haveTool(t, "stty") {
		t.Skip("stty not installed")
	}
	const set = "-echo rows 7 cols 9"

	ctlPath, ctlFd := openPty(t)
	if out, err := exec.Command("stty", append([]string{"-F", ctlPath}, strings.Fields(set)...)...).CombinedOutput(); err != nil {
		t.Fatalf("unjailed control stty failed (%v): %s", err, out)
	}
	if tio, ws := ttyState(t, ctlFd); tio.Lflag&unix.ECHO != 0 || ws.Row != 7 || ws.Col != 9 {
		t.Fatalf("control: stty did not change the pty (echo=%v rows=%d cols=%d)", tio.Lflag&unix.ECHO != 0, ws.Row, ws.Col)
	}

	vPath, vFd := openPty(t)
	tioBefore, wsBefore := ttyState(t, vFd)
	if tioBefore.Lflag&unix.ECHO == 0 {
		t.Fatalf("victim pty starts with ECHO off; the leg cannot observe a change")
	}
	if r := runJailedRan(t, spec, "stty -F "+vPath+" "+set); r.exit == 0 {
		t.Errorf("jailed stty -F on an outside pty exited 0; expected failure")
	}
	tioAfter, wsAfter := ttyState(t, vFd)
	if tioAfter != tioBefore {
		t.Errorf("victim termios changed through the jail: %+v -> %+v", tioBefore, tioAfter)
	}
	if wsAfter != wsBefore {
		t.Errorf("victim winsize changed through the jail: %+v -> %+v", wsBefore, wsAfter)
	}
}

// openPty opens a throwaway pty pair outside the jail and returns the slave
// path plus an fd on the slave for observing its state; both fds close at
// cleanup.
func openPty(t *testing.T) (string, int) {
	t.Helper()
	m, err := unix.Open("/dev/ptmx", unix.O_RDWR|unix.O_NOCTTY|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatalf("open /dev/ptmx: %v", err)
	}
	t.Cleanup(func() { _ = unix.Close(m) })
	if err := unix.IoctlSetPointerInt(m, unix.TIOCSPTLCK, 0); err != nil {
		t.Fatalf("unlockpt: %v", err)
	}
	n, err := unix.IoctlGetUint32(m, unix.TIOCGPTN)
	if err != nil {
		t.Fatalf("ptsname: %v", err)
	}
	path := "/dev/pts/" + strconv.Itoa(int(n))
	s, err := unix.Open(path, unix.O_RDWR|unix.O_NOCTTY|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatalf("open %s: %v", path, err)
	}
	t.Cleanup(func() { _ = unix.Close(s) })
	return path, s
}

func ttyState(t *testing.T, fd int) (unix.Termios, unix.Winsize) {
	t.Helper()
	tio, err := unix.IoctlGetTermios(fd, unix.TCGETS)
	if err != nil {
		t.Fatalf("TCGETS: %v", err)
	}
	ws, err := unix.IoctlGetWinsize(fd, unix.TIOCGWINSZ)
	if err != nil {
		t.Fatalf("TIOCGWINSZ: %v", err)
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
	if len(rows) == 0 {
		t.Fatal("no READ rows parsed from the classifier corpus")
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
			t.Errorf("read %q: jail setup failed: %v", cmd, r.setupErr)
			continue
		}
		if isSeccompKill(r.exit) {
			t.Errorf("read %q: killed by seccomp (exit=%d); the jail broke a legitimate read", cmd, r.exit)
			continue
		}
		if r.exit == 0 {
			continue
		}
		if isDaemonRow(cmd) {
			logged++
			t.Logf("Lane-2 inventory: %q breaks in the jail (exit=%d) — daemon/AF_UNIX read", cmd, r.exit)
			continue
		}
		broke++
		t.Errorf("read %q works on the host but exits %d in the jail (stderr=%q)", cmd, r.exit, strings.TrimSpace(r.stderr))
	}
	t.Logf("read corpus: %d rows executed in the jail, %d non-daemon breaks, %d daemon rows logged", ran, broke, logged)
	// A near-empty run (corpus truncated, or no host control passed) would look
	// green; require a floor of real reads so this leg cannot pass vacuously.
	if ran < 20 {
		t.Errorf("only %d corpus rows actually ran in the jail; expected at least 20 (corpus/host-control problem)", ran)
	}
}

// TestROFallbackParent runs the pre-5.12 read-only remount fallback inside a real
// rung-1 clone (the live helper is otherwise dead code). It proves the fallback
// remounts every mount read-only, preserves the kernel-locked per-mount flags,
// handles an escaped mount point, and mounts /proc after pivot_root.
func TestROFallbackParent(t *testing.T) {
	if !Detect().Userns {
		t.Skip("host has no unprivileged userns; the RO-fallback parent test needs a rung-1 clone")
	}
	home := homeDir(t)
	dir, err := os.MkdirTemp(home, ".sshgate-rofb-")
	if err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })

	c := exec.Command("/proc/self/exe", sentinelROFallbackTest, dir, "marker")
	c.SysProcAttr = cloneSysProcAttr()
	out, err := c.CombinedOutput()
	if err != nil {
		t.Fatalf("RO-fallback child failed: %v\n%s", err, out)
	}
}

// --- helpers ------------------------------------------------------------------

type jailResult struct {
	exit     int
	stdout   string
	stderr   string
	setupErr error
}

func runJailed(t *testing.T, spec Spec, cmd string) jailResult {
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
	r := runJailed(t, spec, "echo "+ranCanary+" ; "+cmd)
	if r.setupErr != nil {
		t.Fatalf("jail setup failed (nothing ran) for %q: %v (stderr=%q)", cmd, r.setupErr, r.stderr)
	}
	if !strings.Contains(r.stdout, ranCanary) {
		t.Fatalf("command %q never reached the shell (no canary); stdout=%q stderr=%q", cmd, r.stdout, r.stderr)
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
		t.Fatalf("start sleeper: %v", err)
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
		t.Fatalf("read stat %d: %v", pid, err)
	}
	s := string(b)
	i := strings.LastIndexByte(s, ')')
	if i < 0 {
		t.Fatalf("malformed stat for %d: %q", pid, s)
	}
	fields := strings.Fields(s[i+1:]) // fields[0]=state, so nice is index 16
	if len(fields) < 17 {
		t.Fatalf("stat for %d has too few fields: %q", pid, s)
	}
	n, err := strconv.Atoi(fields[16])
	if err != nil {
		t.Fatalf("parse nice for %d (%q): %v", pid, fields[16], err)
	}
	return n
}

// readNofile returns a process's RLIMIT_NOFILE soft limit (same-uid read, no
// change).
func readNofile(t *testing.T, pid int) uint64 {
	t.Helper()
	var lim unix.Rlimit
	if err := unix.Prlimit(pid, unix.RLIMIT_NOFILE, nil, &lim); err != nil {
		t.Fatalf("read nofile for %d: %v", pid, err)
	}
	return lim.Cur
}

// readAffinity returns the number of CPUs in a process's affinity mask.
func readAffinity(t *testing.T, pid int) int {
	t.Helper()
	var set unix.CPUSet
	if err := unix.SchedGetaffinity(pid, &set); err != nil {
		t.Fatalf("read affinity for %d: %v", pid, err)
	}
	return set.Count()
}

func runJailedTimeout(t *testing.T, spec Spec, cmd string, d time.Duration) jailResult {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), d)
	defer cancel()
	j, err := spec.Command(ctx, cmd)
	if err != nil {
		t.Fatalf("Command(%q): %v", cmd, err)
	}
	var out, errb bytes.Buffer
	j.Cmd.Stdout = &out
	j.Cmd.Stderr = &errb
	j.Cmd.Stdin = nil
	if err := j.Cmd.Start(); err != nil {
		j.Abort()
		t.Fatalf("start jail for %q: %v", cmd, err)
	}
	_ = j.Started()
	waitErr := j.Cmd.Wait()
	setupErr := j.Status()
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
		t.Fatalf("mkdir temp in home: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	target := filepath.Join(dir, "target")
	if err := os.WriteFile(target, []byte("original-content"), 0644); err != nil {
		t.Fatalf("seed target: %v", err)
	}
	return target
}

func homeDir(t *testing.T) string {
	t.Helper()
	home, err := os.UserHomeDir()
	if err != nil {
		t.Fatalf("home dir: %v", err)
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
		t.Fatalf("read %s: %v", path, err)
	}
	return fmt.Sprintf("%x", sha256.Sum256(b))
}

func statMode(t *testing.T, path string) string {
	t.Helper()
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat %s: %v", path, err)
	}
	return fmt.Sprintf("%v|%d|%d", fi.Mode(), fi.Size(), fi.ModTime().UnixNano())
}

func lsattr(t *testing.T, path string) string {
	t.Helper()
	out, err := exec.Command("lsattr", path).Output()
	if err != nil {
		t.Fatalf("lsattr %s: %v", path, err)
	}
	// lsattr prints "<flags> <path>"; keep only the flags.
	return strings.Fields(string(out))[0]
}

func getfattr(t *testing.T, path string) string {
	t.Helper()
	out, err := exec.Command("getfattr", "-d", "-m", "-", path).CombinedOutput()
	if err != nil {
		t.Fatalf("getfattr %s: %v\n%s", path, err, out)
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
		t.Fatalf("mkfifo: %v", err)
	}
	defer os.Remove(fifo)
	rf, err := os.OpenFile(fifo, os.O_RDONLY|unix.O_NONBLOCK, 0)
	if err != nil {
		t.Fatalf("open fifo read end: %v", err)
	}
	defer rf.Close()

	write(fifo)

	deadline := time.Now().Add(2 * time.Second)
	var got bytes.Buffer
	buf := make([]byte, 64)
	for time.Now().Before(deadline) {
		_ = rf.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
		n, err := rf.Read(buf)
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
		t.Fatalf("open corpus: %v", err)
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
		t.Fatalf("scan corpus: %v", err)
	}
	return rows
}

func buildProbe(t *testing.T) string {
	t.Helper()
	// Build under $HOME, not /tmp: on rung 1 the jail overmounts /tmp with a fresh
	// tmpfs, so a /tmp binary would be invisible inside the jail. $HOME is part of
	// the read-only bind, so the helper is visible and executable there.
	dir, err := os.MkdirTemp(homeDir(t), ".sshgate-jailprobe-")
	if err != nil {
		t.Fatalf("mkdir probe dir: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	bin := filepath.Join(dir, "probe")
	// CGO_ENABLED=0 so the helper is self-contained inside the jail (no reliance
	// on the dynamic loader/libc layout under the read-only bind).
	cmd := exec.Command("go", "build", "-o", bin, "./testdata/probe")
	cmd.Env = append(os.Environ(), "CGO_ENABLED=0")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("build probe helper: %v\n%s", err, out)
	}
	return bin
}
