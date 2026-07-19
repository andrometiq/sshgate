package redteam

import (
	"context"
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// The in-container write tripwire.
//
// The before/after canary snapshot (Snapshot in container.go) only sees
// writes under CanaryRoot + SecretPath. A write to an UNPREDICTED
// location (e.g. `sort -o /tmp/pwned`, `touch /etc/cron.d/x`) is
// invisible to it. The tripwire closes that gap: a mechanism-agnostic,
// in-container monitor that fires on ANY create/modify/move/delete under
// a curated CLEAN ZONE — directories a legitimate forced-command read
// never writes to. It is an INDEPENDENT, broader signal than the
// canary-scoped fs_changed.
//
// Primary mechanism: a background `inotifywait -m -r` appending events to
// /redteam-watch/events.log. Fallback (if inotify-tools is unavailable):
// a periodic broad snapshot of the same roots. Either way the operator
// gets a deterministic, function-call-away API: WriteMark before a run,
// WriteEventsSince after.

const (
	// watchDir is the tripwire's working dir inside the container.
	watchDir = "/redteam-watch"
	// watchLog is the append-only event log inotifywait writes to.
	watchLog = watchDir + "/events.log"
	// BeaconDir is a world-writable dir nothing but attacks write to.
	// The classifier-write-tools corpus aims here so a let-through write
	// lands somewhere the tripwire is guaranteed to be watching. Exported
	// so the command can print it at `up` time.
	BeaconDir = watchDir + "/beacon"
	beaconDir = BeaconDir
	// watchPID is where the monitor records its inotifywait PID so
	// status/teardown can check liveness.
	watchPID = watchDir + "/inotify.pid"
	// watchMode records whether the live inotify monitor ("inotify") or
	// the snapshot fallback ("snapshot") is active, so status + the
	// marker primitive can behave correctly without re-probing.
	watchModeFile = watchDir + "/mode"
)

// watchRoots is the CURATED CLEAN ZONE the tripwire monitors. These are
// directories a legitimate forced-command `sh -c <read>` never writes to,
// so ANY event under them while the gate said "executed" is a strong
// independent bypass signal — even if the write landed outside the
// canary tree the corpus aimed at.
//
// CRITICAL: the SSH user (testuser) HOME is /config, NOT /home — so
// /config is the real persistence surface and MUST be watched. In
// particular /config/.ssh/authorized_keys (the gate's own forced-command
// entry) is the prime self-escalation / persistence target: a bypass that
// appends a second key, or drops the forced command, owns the box. /tmp
// is the classic stage-and-pivot landing pad. Both are now watched.
// /home is kept too (a future image, or a second user, may live there).
//
// Roots are deliberately broad (system + the real user home + a world-
// writable scratch + cron + a beacon), EXCLUDING a few empirically-
// confirmed RUNTIME-noisy paths (see watchExcludes). Verified empirically
// by TestTripwire_SilentOnRead: plain reads (`cat /etc/hostname`,
// `ls -la /etc`, `df -h`, `id`, `sort`) through the gate produce ZERO
// events under the watched zone.
var watchRoots = []string{
	CanaryRoot,        // the seeded canary tree (overlaps Snapshot, intentional belt-and-braces)
	beaconDir,         // the attack landing pad
	containerHome,     // /config — the SSH user's REAL home; covers /config/.ssh/authorized_keys (persistence) and any drop elsewhere in the home
	"/tmp",            // classic stage/pivot landing pad (e.g. `sort -o /tmp/pwned`, a planted script)
	"/etc",            // cron.d, passwd, shadow, init configs, ssh drop-ins
	"/root",           // root's home
	"/home",           // other/future user homes (testuser lives in /config, but cover /home too)
	"/usr/local/bin",  // a classic drop-target for a planted binary
	"/var/spool/cron", // crontab spool
}

// watchExcludes are POSIX extended-regex fragments passed to
// inotifywait --exclude. They suppress events from paths that churn during
// NORMAL operation (the rig's own event log, the sshd session log, tool
// caches, TOFU known_hosts churn, and GNU sort's /tmp temp spills) so the
// tripwire stays SPECIFIC — zero false positives on a read.
//
// Every exclude is a path empirically confirmed to be written at BOOT or
// by a LEGITIMATE read — never a guess. Boot-time-only writers (s6 init,
// host-key generation, the empty /etc/ssh/sshd_config.d dir) do NOT need
// an exclude on their own account, because startTripwire launches the
// monitor from NewTarget AFTER the container has booted, been deployed-to,
// and seeded: every boot write is already in the past before the first
// WriteMark. The s6/host-key excludes are kept only as cheap defence
// against a mid-run supervision tick.
//
// IMPORTANT — what is deliberately NOT excluded:
//   - /etc/ssh/sshd_config.d: empty on this image and never written at
//     runtime, so a RUNTIME drop-in there (e.g.
//     /etc/ssh/sshd_config.d/99-evil.conf — sshd persistence) MUST fire.
//     It was a BLANKET exclude before, which silently hid exactly that.
//   - /config/.ssh: only the known_hosts churn within it is excluded;
//     authorized_keys is the prime persistence target and stays watched.
//   - the bulk of /tmp: only GNU sort's temp template is excluded; any
//     other /tmp write (planted script, sort -o output) still fires.
//
// Each entry is OR-ed by inotifywait into one regex. Anchor loosely
// (substring match is fine) and keep them conservative: excluding too
// much would blind the tripwire.
var watchExcludes = []string{
	watchDir + "/events\\.log",  // never alert on our own append-only log
	watchDir + "/inotify\\.pid", // the monitor's own pidfile
	// The gate's OWN authoritative audit log (Tier-6a). The gate appends one
	// JSON line to gateDir/audit.log for EVERY command it processes — reads
	// INCLUDED — by design (src/gate/audit.go: AuditPath default =
	// gateDir/defaultAuditFile "audit.log"; DefaultAuditLevel == AuditAllMeta
	// logs reads too). In this rig the gate is installed at
	// /config/.sshgate-gate/gate (deployGate in container.go), so the gate
	// dir resolves (os.Executable → filepath.Dir) to /config/.sshgate-gate and
	// the log lands at /config/.sshgate-gate/audit.log — under the watched
	// /config home root. That write is a LEGITIMATE, expected gate-internal
	// accountability record, NOT a read-only bypass, so it must not trip the
	// wire. The exclude is pinned to this EXACT file (anchored to the gate
	// dir + the literal "audit.log" name); any OTHER write under the gate dir
	// or elsewhere in /config still fires, so a real bypass (e.g. an attacker
	// dropping a key in /config/.ssh/authorized_keys, or any other file under
	// .sshgate-gate) is NOT masked.
	containerHome + "/\\.sshgate-gate/audit\\.log",
	"/etc/s6-overlay",            // linuxserver s6 supervision runtime (mid-run tick guard)
	"/etc/services\\.d",          // s6 service dir (mid-run tick guard)
	"/etc/cont-init\\.d",         // s6 init scripts (mid-run tick guard)
	"/etc/ssh/ssh_host_",         // host keys (boot-regenerated; guard)
	"/config/\\.cache",           // tool caches under the user home
	"/config/logs",               // sshd session log (/config/logs/openssh/current) — written on every connection; CONFIRMED runtime-noisy
	"/config/\\.ssh/known_hosts", // TOFU churn within .ssh (authorized_keys is NOT excluded)
	"/tmp/sort",                  // GNU sort 9.8 temp spills (/tmp/sortXXXXXX) from legitimate large `sort` reads — CONFIRMED; the rest of /tmp stays watched
}

// WriteEvent is one tripwire observation: a filesystem mutation under the
// clean zone, as reported by inotifywait (or synthesised by the snapshot
// fallback). It is intentionally minimal — the path is the load-bearing
// field; the agent contract surfaces just the paths.
type WriteEvent struct {
	// UnixTime is the event time in whole seconds (inotifywait %T with a
	// %s timefmt). Zero if the source did not carry a time.
	UnixTime int64 `json:"unix_time,omitempty"`
	// Events is the comma-joined inotify event mask (e.g. "CREATE",
	// "MODIFY", "MOVED_TO", "DELETE"). "SNAPSHOT" for fallback-detected
	// changes.
	Events string `json:"events"`
	// Path is the absolute path that changed.
	Path string `json:"path"`
}

// Marker is an opaque cursor into the append-only event log: the number
// of log lines present at the moment WriteMark was called. WriteEventsSince
// reads only the lines AFTER this offset, so each Detector.Test sees
// exactly the events its own command produced — deterministic, no
// cross-contamination between candidates.
type Marker struct {
	// LineOffset is how many event-log lines existed at mark time.
	LineOffset int
}

// parseWatchLog parses the raw inotifywait event log (the tab-separated
// `%T\t%e\t%w%f` format this rig configures) into WriteEvents, starting
// AFTER the given line offset. It is a PURE function — no I/O — so it is
// unit-tested with a fake log and no Docker (see tripwire_test.go).
//
// Lines pointing at the rig's own watch dir (the event log / pidfile) are
// dropped defensively: even if inotifywait's --exclude misses one, the
// tripwire must never alert on its own bookkeeping.
//
// It returns the parsed events and the NEW total line count, so the
// caller can advance its cursor.
func parseWatchLog(raw string, sinceLine int) (events []WriteEvent, totalLines int) {
	lines := splitLogLines(raw)
	totalLines = len(lines)
	if sinceLine < 0 {
		sinceLine = 0
	}
	for i := sinceLine; i < len(lines); i++ {
		line := lines[i]
		if line == "" {
			continue
		}
		ev, ok := parseWatchLine(line)
		if !ok {
			continue
		}
		// Defensive: never surface the rig's own bookkeeping paths.
		if strings.HasPrefix(ev.Path, watchLog) || strings.HasPrefix(ev.Path, watchPID) ||
			strings.HasPrefix(ev.Path, watchModeFile) {
			continue
		}
		events = append(events, ev)
	}
	return events, totalLines
}

// splitLogLines splits a log blob into lines, trimming a trailing newline
// so a well-formed N-line log yields exactly N entries (not N+1). Used by
// both the parser and WriteMark's line-count.
func splitLogLines(raw string) []string {
	raw = strings.TrimRight(raw, "\n")
	if raw == "" {
		return nil
	}
	out := strings.Split(raw, "\n")
	for i := range out {
		out[i] = strings.TrimRight(out[i], "\r")
	}
	return out
}

// parseWatchLine parses one `<unixtime>\t<events>\t<path>` line. The path
// may itself contain tabs in pathological cases, so we split on the FIRST
// two tabs only and treat the remainder as the path. A line that does not
// match this shape is rejected (ok=false) rather than guessed at.
func parseWatchLine(line string) (WriteEvent, bool) {
	parts := strings.SplitN(line, "\t", 3)
	if len(parts) != 3 {
		return WriteEvent{}, false
	}
	ts, err := strconv.ParseInt(strings.TrimSpace(parts[0]), 10, 64)
	if err != nil {
		// Tolerate a non-numeric time field (e.g. a fallback line) by
		// treating it as time 0 rather than dropping the event — a
		// possible write must never be silently discarded.
		ts = 0
	}
	ev := strings.TrimSpace(parts[1])
	path := parts[2]
	if path == "" {
		return WriteEvent{}, false
	}
	return WriteEvent{UnixTime: ts, Events: ev, Path: path}, true
}

// WriteMark captures the current end of the event log as an opaque cursor.
// Call it immediately BEFORE running a candidate; pass the returned Marker
// to WriteEventsSince afterwards to read exactly that candidate's events.
//
// It is a single cheap `docker exec wc -l` (or a snapshot capture in
// fallback mode). Deterministic and side-effect-free with respect to the
// watched roots.
func (t *Target) WriteMark(ctx context.Context) (Marker, error) {
	if t.tripwireFallback {
		return t.snapshotMark(ctx)
	}
	// Count current lines in the event log. `wc -l` on a missing file is
	// an error, so tolerate absence as zero (the monitor may not have
	// flushed its first line yet).
	script := fmt.Sprintf("[ -f %[1]s ] && wc -l < %[1]s || echo 0", watchLog)
	out, err := dockerExec(ctx, t.composeFile, nil, script)
	if err != nil {
		return Marker{}, fmt.Errorf("write-mark: %w\n%s", err, out)
	}
	n, perr := strconv.Atoi(strings.TrimSpace(string(out)))
	if perr != nil {
		return Marker{}, fmt.Errorf("write-mark: parse line count %q: %w", strings.TrimSpace(string(out)), perr)
	}
	return Marker{LineOffset: n}, nil
}

// WriteEventsSince returns every tripwire event recorded AFTER the given
// marker — i.e. every write under the clean zone since WriteMark was
// called. An empty slice means the watched roots were untouched.
//
// In inotify mode it reads the event-log delta; in fallback mode it
// diffs a fresh broad snapshot against the one captured at mark time.
func (t *Target) WriteEventsSince(ctx context.Context, m Marker) ([]WriteEvent, error) {
	if t.tripwireFallback {
		return t.snapshotEventsSince(ctx, m)
	}
	script := fmt.Sprintf("[ -f %[1]s ] && cat %[1]s || true", watchLog)
	out, err := dockerExec(ctx, t.composeFile, nil, script)
	if err != nil {
		return nil, fmt.Errorf("write-events: %w\n%s", err, out)
	}
	events, _ := parseWatchLog(string(out), m.LineOffset)
	return events, nil
}

// ---- snapshot fallback (no inotify-tools) --------------------------

// snapshotMark captures a broad snapshot of the watch roots and stores it
// on the Target keyed by the next marker id, returning that id. Coarser
// than inotify (no mid-run transient files, mtime granularity is seconds)
// but still deterministic.
func (t *Target) snapshotMark(ctx context.Context) (Marker, error) {
	snap, err := t.watchSnapshot(ctx)
	if err != nil {
		return Marker{}, err
	}
	t.fallbackMu.Lock()
	defer t.fallbackMu.Unlock()
	id := t.fallbackNextID
	t.fallbackNextID++
	if t.fallbackSnaps == nil {
		t.fallbackSnaps = map[int]Snapshot{}
	}
	t.fallbackSnaps[id] = snap
	return Marker{LineOffset: id}, nil
}

// snapshotEventsSince diffs a fresh watch-root snapshot against the one
// captured at mark time and reports each changed path as a WriteEvent
// tagged "SNAPSHOT".
func (t *Target) snapshotEventsSince(ctx context.Context, m Marker) ([]WriteEvent, error) {
	t.fallbackMu.Lock()
	before, ok := t.fallbackSnaps[m.LineOffset]
	t.fallbackMu.Unlock()
	if !ok {
		return nil, fmt.Errorf("write-events: unknown fallback marker %d", m.LineOffset)
	}
	after, err := t.watchSnapshot(ctx)
	if err != nil {
		return nil, err
	}
	changed := Diff(before, after)
	var events []WriteEvent
	for _, p := range changed {
		events = append(events, WriteEvent{Events: "SNAPSHOT", Path: p})
	}
	t.fallbackMu.Lock()
	delete(t.fallbackSnaps, m.LineOffset)
	t.fallbackMu.Unlock()
	return events, nil
}

// watchSnapshot enumerates every regular file under the watch roots
// (path -> sha256 + mtime), the same shape as Snapshot but over the
// broad clean zone. Used only by the snapshot fallback.
func (t *Target) watchSnapshot(ctx context.Context) (Snapshot, error) {
	script := fmt.Sprintf(`
set -e
roots="%s"
for r in $roots; do
  if [ -e "$r" ]; then
    find "$r" -type f 2>/dev/null | while IFS= read -r f; do
      case "$f" in %s/*) continue ;; esac
      mt=$(stat -c %%Y "$f" 2>/dev/null || echo 0)
      sz=$(stat -c %%s "$f" 2>/dev/null || echo 0)
      h=$(sha256sum "$f" 2>/dev/null | cut -d' ' -f1)
      printf '%%s\t%%s\t%%s\t%%s\n' "$mt" "$sz" "$h" "$f"
    done
  fi
done
`, strings.Join(watchRoots, " "), watchDir)
	out, err := dockerExec(ctx, t.composeFile, nil, script)
	if err != nil {
		return nil, fmt.Errorf("watch snapshot: %w\n%s", err, out)
	}
	snap := Snapshot{}
	for _, line := range splitLogLines(string(out)) {
		parts := strings.SplitN(line, "\t", 4)
		if len(parts) != 4 {
			continue
		}
		// Apply the SAME exclusion set inotify uses, so the snapshot
		// fallback stays as quiet on a read as the live monitor. Without
		// this the fallback would re-introduce the very noise (the sshd
		// session log, GNU sort temp spills) the --exclude list suppresses
		// in inotify mode — a false positive that inotify mode would not
		// have. Parity matters: the fallback must never be MORE noisy.
		if excludedPath(parts[3]) {
			continue
		}
		var mt, sz int64
		fmt.Sscanf(parts[0], "%d", &mt)
		fmt.Sscanf(parts[1], "%d", &sz)
		snap[parts[3]] = FileState{Path: parts[3], Exists: true, MtimeNs: mt, Size: sz, Sha256: parts[2]}
	}
	return snap, nil
}

// excludeMatchers compiles each watchExcludes fragment once as a Go regexp
// (the fragments are POSIX-ERE substrings — the same shape inotifywait's
// --exclude consumes) so the snapshot fallback can honour the exact same
// exclusion set. A fragment that fails to compile is dropped loudly-safe:
// it simply never matches, so the fallback errs toward FLAGGING (never
// toward hiding a write).
var excludeMatchers = func() []*regexp.Regexp {
	ms := make([]*regexp.Regexp, 0, len(watchExcludes))
	for _, frag := range watchExcludes {
		if re, err := regexp.Compile(frag); err == nil {
			ms = append(ms, re)
		}
	}
	return ms
}()

// excludedPath reports whether p matches any watchExcludes fragment (the
// rig's own bookkeeping is dropped separately by parseWatchLog and the
// inotify --exclude; this is the snapshot-fallback equivalent).
func excludedPath(p string) bool {
	for _, re := range excludeMatchers {
		if re.MatchString(p) {
			return true
		}
	}
	return false
}

// ---- install / start (called from NewTarget) -----------------------

// startTripwire installs inotify-tools and launches the background
// recursive monitor inside the container, or — if that is unavailable —
// arms the snapshot fallback. It sets t.tripwireFallback accordingly and
// is loud (writes a mode marker + returns the mode) so the rig never
// SILENTLY disables write detection.
//
// Returns the active mode ("inotify" or "snapshot").
func startTripwire(ctx context.Context, composeFile string) (mode string, err error) {
	// 1. Create the watch dir + beacon (world-writable, owned by the SSH
	//    user so an attack running as that user can land a write there).
	mkdir := fmt.Sprintf(`
set -e
mkdir -p %[1]s %[2]s
chown %[3]s:%[3]s %[2]s
chmod 1777 %[2]s
: > %[4]s
chmod 666 %[4]s
`, watchDir, beaconDir, remoteUser, watchLog)
	if out, err := dockerExec(ctx, composeFile, nil, mkdir); err != nil {
		return "", fmt.Errorf("tripwire mkdir: %w\n%s", err, out)
	}

	// 2. Try to install inotify-tools, but never let an offline package
	//    mirror stall the integration gate. Images without `timeout` skip
	//    the network attempt and use the documented snapshot fallback.
	haveInotify := false
	if out, ierr := dockerExec(ctx, composeFile, nil,
		"if command -v inotifywait >/dev/null 2>&1; then echo yes; elif command -v timeout >/dev/null 2>&1 && timeout 15 apk add --no-cache inotify-tools >/dev/null 2>&1 && command -v inotifywait >/dev/null 2>&1; then echo yes; else echo no; fi",
	); ierr == nil && strings.Contains(string(out), "yes") {
		haveInotify = true
	}

	if !haveInotify {
		// Fallback: record the mode and return. WriteMark/EventsSince will
		// use the snapshot path. This is LOUD by contract — the caller
		// logs it.
		_, _ = dockerExec(ctx, composeFile, nil, fmt.Sprintf("printf snapshot > %s", watchModeFile))
		return "snapshot", nil
	}

	// 3. Launch the recursive monitor in the background. It runs detached
	//    (setsid + nohup) so it survives the docker exec returning, writes
	//    its PID, and appends `<unixtime>\t<events>\t<path>` lines.
	excludeRE := strings.Join(watchExcludes, "|")
	roots := strings.Join(watchRoots, " ")
	// Only watch roots that exist (inotifywait errors out on a missing
	// path and would refuse to start), so filter at launch time.
	launch := fmt.Sprintf(`
set -e
existing=""
for r in %[1]s; do
  [ -e "$r" ] && existing="$existing $r"
done
setsid sh -c '
  echo $$ > %[2]s
  exec inotifywait -m -r -q \
    --timefmt %%s --format "%%T	%%e	%%w%%f" \
    -e create -e modify -e moved_to -e moved_from -e move -e delete -e attrib \
    --exclude "%[3]s" \
    '"$existing"' >> %[4]s 2>%[5]s/inotify.err
' </dev/null >/dev/null 2>&1 &
printf inotify > %[6]s
`, roots, watchPID, excludeRE, watchLog, watchDir, watchModeFile)
	if out, err := dockerExec(ctx, composeFile, nil, launch); err != nil {
		return "", fmt.Errorf("tripwire launch: %w\n%s", err, out)
	}

	// 4. Wait briefly for inotifywait to be watching. `inotifywait -m`
	//    prints "Watches established." to stderr once ready; poll for the
	//    process so the first marked run can't race it.
	if err := waitTripwireReady(ctx, composeFile, 10); err != nil {
		return "", err
	}
	return "inotify", nil
}

// waitTripwireReady polls (up to attempts ~half-seconds) until the
// inotifywait monitor process is alive, so the rig does not take its
// first WriteMark before the watch is established.
func waitTripwireReady(ctx context.Context, composeFile string, attempts int) error {
	check := fmt.Sprintf(
		`p=$(cat %s 2>/dev/null); [ -n "$p" ] && [ -d /proc/"$p" ] && grep -q . %s/inotify.err 2>/dev/null && echo ready || echo waiting`,
		watchPID, watchDir)
	for i := 0; i < attempts; i++ {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		out, _ := dockerExec(ctx, composeFile, nil, check)
		if strings.Contains(string(out), "ready") {
			return nil
		}
		// Cheap sleep inside the container avoids host-side timing flakiness.
		_, _ = dockerExec(ctx, composeFile, nil, "sleep 0.5")
	}
	// Process-alive is the hard requirement; the "Watches established"
	// stderr line is best-effort. If the PID is alive, proceed.
	out, _ := dockerExec(ctx, composeFile, nil,
		fmt.Sprintf(`p=$(cat %s 2>/dev/null); [ -n "$p" ] && [ -d /proc/"$p" ] && echo alive || echo dead`, watchPID))
	if strings.Contains(string(out), "alive") {
		return nil
	}
	return fmt.Errorf("tripwire monitor did not come up within %d attempts", attempts)
}

// tripwireAlive reports whether the inotify monitor process is still
// running (always true in snapshot-fallback mode, which has no process).
func tripwireAlive(ctx context.Context, composeFile string, fallback bool) bool {
	if fallback {
		return true
	}
	out, err := dockerExec(ctx, composeFile, nil,
		fmt.Sprintf(`p=$(cat %s 2>/dev/null); [ -n "$p" ] && [ -d /proc/"$p" ] && echo alive || echo dead`, watchPID))
	if err != nil {
		return false
	}
	return strings.Contains(string(out), "alive")
}

// sortedPaths returns the unique sorted set of paths from a list of
// events, the form surfaced on the verdict's write_events field.
func sortedPaths(events []WriteEvent) []string {
	seen := map[string]struct{}{}
	for _, e := range events {
		seen[e.Path] = struct{}{}
	}
	out := make([]string, 0, len(seen))
	for p := range seen {
		out = append(out, p)
	}
	sort.Strings(out)
	return out
}
