//go:build linux

package confine

import (
	"fmt"
	"os"
	"slices"
	"sort"
	"strconv"
	"strings"

	"github.com/karthikeyan5/sshgate/src/gate/confine/jailmut"
	"golang.org/x/sys/unix"
)

func pathMountID(path string) (int, error) {
	fd, err := unix.Open(path, unix.O_PATH|unix.O_CLOEXEC, 0)
	if err != nil {
		return 0, err
	}
	defer unix.Close(fd)
	return mountID(fd)
}

func selfcheck(spec Spec, abi int, facts *Facts) error {
	if !jailmut.On("P-SELFCHECK-MOUNTS") {
		if err := selfcheckMounts(spec, facts); err != nil {
			return err
		}
	}
	data, err := os.ReadFile("/proc/thread-self/status")
	if err != nil {
		return err
	}
	if err := selfcheckCredentials(string(data), os.Getuid() == 0); !jailmut.On("P-SELFCHECK-CREDS") && err != nil {
		return err
	}
	if !jailmut.On("P-SELFCHECK-LL") && abi < 1 {
		return fmt.Errorf("Landlock was not installed")
	}
	return nil
}

func selfcheckCredentials(status string, root bool) error {
	expected := map[string]uint64{"CapInh": 0, "CapPrm": 0, "CapEff": 0, "CapBnd": 0, "CapAmb": 0, "NoNewPrivs": 1, "Seccomp": 2}
	if root {
		for _, key := range []string{"CapPrm", "CapEff", "CapBnd"} {
			expected[key] = 1 << unix.CAP_DAC_READ_SEARCH
		}
	}
	seen := map[string]bool{}
	for _, line := range strings.Split(status, "\n") {
		key, raw, ok := strings.Cut(line, ":")
		want, required := expected[key]
		if !ok || (!required && key != "Seccomp_filters") {
			continue
		}
		if seen[key] {
			return fmt.Errorf("duplicate credential field %s", key)
		}
		seen[key] = true
		base := 10
		if strings.HasPrefix(key, "Cap") {
			base = 16
		}
		value, err := strconv.ParseUint(strings.TrimSpace(raw), base, 64)
		if err != nil || (required && value != want) || (key == "Seccomp_filters" && value < 1) {
			return fmt.Errorf("unexpected credential field %s", key)
		}
	}
	for key := range expected {
		if !seen[key] {
			return fmt.Errorf("missing credential field %s", key)
		}
	}
	if !seen["Seccomp_filters"] {
		return fmt.Errorf("missing Seccomp_filters")
	}
	return nil
}

func selfcheckMountFlags(entries []mountEntry, scratch int, devices map[int]bool) error {
	writable := 0
	for _, entry := range entries {
		has := func(option string) bool { return slices.Contains(entry.opts, option) }
		if has("rw") {
			writable++
			if entry.id != scratch || entry.fstype != "tmpfs" || !has("noexec") || !has("nodev") || has("ro") {
				return fmt.Errorf("unexpected writable mount %d", entry.id)
			}
		} else if !has("ro") {
			return fmt.Errorf("mount %d lacks ro", entry.id)
		}
		if !has("nosuid") || (!has("nodev") && !devices[entry.id]) {
			return fmt.Errorf("unsafe mount flags %d", entry.id)
		}
		for _, tag := range entry.optional {
			if strings.HasPrefix(tag, "shared:") || strings.HasPrefix(tag, "master:") {
				return fmt.Errorf("propagating mount %d", entry.id)
			}
		}
	}
	if writable != 1 {
		return fmt.Errorf("writable mount count %d", writable)
	}
	return nil
}

func selfcheckMounts(spec Spec, facts *Facts) error {
	entries, err := readMountInfo()
	if err != nil {
		return err
	}
	scratch, err := pathMountID("/dev/shm")
	if err != nil {
		return err
	}
	devices := map[int]bool{}
	for _, node := range devNodes {
		path := "/dev/" + node
		var st unix.Stat_t
		err := unix.Lstat(path, &st)
		if err == unix.ENOENT {
			continue
		}
		if err != nil {
			return err
		}
		if st.Mode&unix.S_IFMT != unix.S_IFCHR {
			return fmt.Errorf("invalid device %s", path)
		}
		id, err := pathMountID(path)
		if err != nil {
			return err
		}
		devices[id] = true
	}
	if err := selfcheckMountFlags(entries, scratch, devices); err != nil {
		return err
	}
	root, err := pathMountID("/")
	if err != nil {
		return err
	}
	view := reachableMounts(entries, root)
	// Setup observations are not evidence: derive unmet again from the final view.
	facts.Unmet = append([]string(nil), view.unmet...)
	accepted, covers := map[int]bool{}, map[int]bool{}
	var blocked []string
	for _, entry := range view.entries {
		accepted[entry.id] = mountAccepted(entry, spec.AcceptFS, backingInspector{sys: "/sys"})
		if !accepted[entry.id] {
			facts.Unmet = append(facts.Unmet, "fs-view:"+entry.fstype+"@"+entry.point)
			blocked = append(blocked, entry.point)
		}
		// Recheck each recorded cover against the final mount and the lookup ID.
		covers[entry.id] = facts.coverIDs[entry.id] && entry.fstype == "tmpfs" && entry.root == "/" && slices.Contains(entry.opts, "ro") && slices.Contains(entry.opts, "noexec")
	}
	if !jailmut.On("P-SELFCHECK-REACH") {
		points := make([]string, 0, len(entries))
		for _, entry := range entries {
			points = append(points, entry.point)
		}
		sort.Slice(points, func(i, j int) bool { return len(points[i]) < len(points[j]) })
		seen := map[string]bool{}
		for _, point := range points {
			if seen[point] {
				continue
			}
			seen[point] = true
			skip := false
			for _, parent := range blocked {
				if point != parent && pathWithin(point, parent) {
					skip = true
					break
				}
			}
			if skip {
				continue
			}
			walk := walkTo(point, view, accepted, covers)
			valid := walk.err == nil || walk.err == unix.ENOENT && walk.covered ||
				walk.err == unix.EACCES && deniedSubtreeSafe(entries, walk.denied, spec.AcceptFS, backingInspector{sys: "/sys"})
			walk.close()
			if !valid {
				facts.Unmet = append(facts.Unmet, "fs-view:lookup-mismatch@"+point)
				blocked = append(blocked, point)
			}
		}
	}
	cwd, err := pathMountID(".")
	if err != nil {
		return err
	}
	if !accepted[cwd] {
		facts.Unmet = append(facts.Unmet, fmt.Sprintf("fs-view:cwd@%d", cwd))
	}
	sort.Strings(facts.Unmet)
	facts.Unmet = slices.Compact(facts.Unmet)
	if spec.Strict && len(facts.Unmet) > 0 {
		return fmt.Errorf("unmet mount clauses: %s", strings.Join(facts.Unmet, ", "))
	}
	return nil
}

// deniedSubtreeSafe reports whether every mount at or below a component the
// worker cannot search is confirmed, so what hides there needs no cover.
func deniedSubtreeSafe(entries []mountEntry, denied string, acceptFS []string, inspector backingInspector) bool {
	if denied == "" {
		return false
	}
	for _, entry := range entries {
		if pathWithin(entry.point, denied) && !mountAccepted(entry, acceptFS, inspector) {
			return false
		}
	}
	return true
}
