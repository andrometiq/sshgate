//go:build linux

package confine

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
)

type mountEntry struct {
	id, parent       int
	dev, root, point string
	opts, optional   []string
	fstype, source   string
	superOpts        []string
}

func readMountInfo() ([]mountEntry, error) {
	f, err := os.Open("/proc/self/mountinfo")
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return parseMountInfo(f)
}

func parseMountInfo(r io.Reader) ([]mountEntry, error) {
	var result []mountEntry
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 64<<10), 1<<20)
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		separator := -1
		for i, field := range fields {
			if field == "-" {
				separator = i
				break
			}
		}
		if separator < 6 || len(fields) != separator+4 {
			return nil, fmt.Errorf("malformed mountinfo line %q", scanner.Text())
		}
		id, err := strconv.Atoi(fields[0])
		if err != nil || id <= 0 {
			return nil, fmt.Errorf("invalid mount ID")
		}
		parent, err := strconv.Atoi(fields[1])
		if err != nil || parent < 0 {
			return nil, fmt.Errorf("invalid mount parent")
		}
		major, minor, ok := strings.Cut(fields[2], ":")
		if !ok {
			return nil, fmt.Errorf("invalid mount device")
		}
		for _, part := range []string{major, minor} {
			if _, err := strconv.ParseUint(part, 10, 32); err != nil {
				return nil, err
			}
		}
		root, err := unescapeMountField(fields[3])
		if err != nil {
			return nil, err
		}
		point, err := unescapeMountField(fields[4])
		if err != nil {
			return nil, err
		}
		source, err := unescapeMountField(fields[separator+2])
		if err != nil {
			return nil, err
		}
		if !filepath.IsAbs(point) {
			return nil, fmt.Errorf("nonabsolute mount path")
		}
		result = append(result, mountEntry{id: id, parent: parent, dev: fields[2], root: root, point: point, opts: strings.Split(fields[5], ","), optional: fields[6:separator], fstype: fields[separator+1], source: source, superOpts: strings.Split(fields[separator+3], ",")})
	}
	return result, scanner.Err()
}

func unescapeMountField(value string) (string, error) {
	var out strings.Builder
	for i := 0; i < len(value); i++ {
		if value[i] != '\\' {
			out.WriteByte(value[i])
			continue
		}
		if i+4 > len(value) {
			return "", fmt.Errorf("truncated mount escape")
		}
		octal := value[i+1 : i+4]
		switch octal {
		case "040", "011", "012", "134":
		default:
			return "", fmt.Errorf("invalid mount escape %q", octal)
		}
		number, _ := strconv.ParseUint(octal, 8, 8)
		out.WriteByte(byte(number))
		i += 3
	}
	return out.String(), nil
}

func pathWithin(path, base string) bool {
	return path == base || base == "/" || strings.HasPrefix(path, base+"/")
}

type mountView struct {
	entries []mountEntry
	unmet   []string
}

// reachableMounts follows mount parentage and same-point stacks, not file order.
func reachableMounts(entries []mountEntry, rootID int) mountView {
	view := mountView{}
	byID := map[int]mountEntry{}
	children := map[int][]mountEntry{}
	bad := map[int]bool{}
	mark := func(entry mountEntry) {
		bad[entry.id] = true
		view.unmet = append(view.unmet, "fs-view:unplaceable@"+entry.point)
	}
	pairs := map[string]int{}
	for _, entry := range entries {
		if _, ok := byID[entry.id]; ok {
			mark(entry)
		}
		byID[entry.id] = entry
		children[entry.parent] = append(children[entry.parent], entry)
		pair := fmt.Sprintf("%d:%s", entry.parent, entry.point)
		if previous, ok := pairs[pair]; ok {
			mark(entry)
			mark(byID[previous])
		}
		pairs[pair] = entry.id
	}
	for _, entry := range entries {
		if parent, ok := byID[entry.parent]; ok && !pathWithin(entry.point, parent.point) {
			mark(entry)
		}
		seen := map[int]bool{}
		cursor := entry
		for {
			if seen[cursor.id] {
				mark(entry)
				break
			}
			seen[cursor.id] = true
			parent, ok := byID[cursor.parent]
			if !ok {
				break
			}
			cursor = parent
		}
	}
	root, ok := byID[rootID]
	if !ok {
		view.unmet = append(view.unmet, "fs-view:unplaceable@/")
		return view
	}
	visited := map[int]bool{}
	var walk func(mountEntry)
	walk = func(entry mountEntry) {
		if visited[entry.id] || bad[entry.id] {
			return
		}
		visited[entry.id] = true
		if strings.HasSuffix(entry.point, " (deleted)") {
			mark(entry)
			return
		}
		view.entries = append(view.entries, entry)
		for _, child := range children[entry.id] {
			if child.point == entry.point {
				continue
			} // root stacks and already-resolved stack links
			top := child
			seen := map[int]bool{}
			for !bad[top.id] && !seen[top.id] {
				seen[top.id] = true
				found := false
				for _, stack := range children[top.id] {
					if stack.point == top.point {
						top = stack
						found = true
						break
					}
				}
				if !found {
					break
				}
			}
			walk(top)
		}
	}
	walk(root)
	sort.SliceStable(view.entries, func(i, j int) bool { return len(view.entries[i].point) < len(view.entries[j].point) })
	return view
}

func (view mountView) expectedAt(path string) (mountEntry, bool) {
	var result mountEntry
	found := false
	for _, entry := range view.entries {
		if pathWithin(path, entry.point) && (!found || len(entry.point) > len(result.point)) {
			result = entry
			found = true
		}
	}
	return result, found
}

func mountID(fd int) (int, error) {
	var stat unix.Statx_t
	if err := unix.Statx(fd, "", unix.AT_EMPTY_PATH|unix.AT_STATX_DONT_SYNC, unix.STATX_MNT_ID, &stat); err != nil {
		return 0, err
	}
	if stat.Mask&unix.STATX_MNT_ID == 0 {
		return 0, unix.EOPNOTSUPP
	}
	return int(stat.Mnt_id), nil
}
