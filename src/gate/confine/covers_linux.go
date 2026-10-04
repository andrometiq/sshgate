//go:build linux

package confine

import (
	"github.com/karthikeyan5/sshgate/src/gate/confine/jailmut"
	"path/filepath"
	"strings"

	"golang.org/x/sys/unix"
)

type mountFacts = Facts

// walkResult owns fd and parent. Even on EACCES they identify the first denied
// component, without resolving a name inside an unconfirmed filesystem.
type walkResult struct {
	fd, parent   int
	path, denied string
	covered      bool
	err          error
}

func (result *walkResult) close() {
	if result.fd >= 0 {
		_ = unix.Close(result.fd)
	}
	if result.parent >= 0 {
		_ = unix.Close(result.parent)
	}
}
func walkTo(path string, view mountView, accepted map[int]bool, covers map[int]bool) walkResult {
	result := walkResult{fd: -1, parent: -1, path: "/"}
	result.fd, result.err = unix.Open("/", unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if result.err != nil {
		return result
	}
	check := func() bool {
		id, err := mountID(result.fd)
		expected, ok := view.expectedAt(result.path)
		if err != nil || !ok || id != expected.id {
			result.err = unix.ESTALE
			return false
		}
		result.covered = result.covered || covers[id]
		return true
	}
	if !check() {
		return result
	}
	for _, component := range strings.Split(strings.TrimPrefix(path, "/"), "/") {
		if component == "" {
			continue
		}
		expected, _ := view.expectedAt(result.path)
		if !accepted[expected.id] {
			result.err = unix.ESTALE
			return result
		}
		next := filepath.Join(result.path, component)
		fd, err := unix.Openat(result.fd, component, unix.O_PATH|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		if err != nil {
			result.err = err
			if err == unix.EACCES {
				// A successfully opened directory may itself deny search. Keep its parent.
				if unix.Faccessat(result.fd, ".", unix.X_OK, unix.AT_EACCESS) == unix.EACCES && result.path != "/" {
					result.denied = result.path
				} else {
					result.denied = next
					if result.parent >= 0 {
						_ = unix.Close(result.parent)
					}
					result.parent = result.fd
					result.fd = -1
				}
			}
			return result
		}
		if result.parent >= 0 {
			_ = unix.Close(result.parent)
		}
		result.parent = result.fd
		result.fd = fd
		result.path = next
		if !check() {
			return result
		}
	}
	return result
}

func uncoverable(point string) bool {
	if pathWithin("/dev/shm", point) {
		return true
	}
	for _, node := range devNodes {
		if pathWithin("/dev/"+node, point) {
			return true
		}
	}
	return false
}

func mountCover(parent int, name string) error {
	context, err := unix.Fsopen("tmpfs", unix.FSOPEN_CLOEXEC)
	if err != nil {
		return err
	}
	defer unix.Close(context)
	if err := unix.FsconfigSetString(context, "mode", "0555"); err != nil {
		return err
	}
	if err := unix.FsconfigCreate(context); err != nil {
		return err
	}
	mount, err := unix.Fsmount(context, unix.FSMOUNT_CLOEXEC, unix.MOUNT_ATTR_RDONLY|unix.MOUNT_ATTR_NOSUID|unix.MOUNT_ATTR_NODEV|unix.MOUNT_ATTR_NOEXEC)
	if err != nil {
		return err
	}
	defer unix.Close(mount)
	// Deliberately omit MOVE_MOUNT_T_AUTOMOUNTS: never trigger the covered mount.
	return unix.MoveMount(mount, "", parent, name, unix.MOVE_MOUNT_F_EMPTY_PATH)
}

func coverMounts(spec Spec) (mountFacts, error) {
	var facts mountFacts
	if jailmut.On("P-COVERS") {
		return facts, nil
	}
	entries, err := readMountInfo()
	if err != nil {
		return facts, err
	}
	root, err := unix.Open("/", unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return facts, err
	}
	rootID, err := mountID(root)
	_ = unix.Close(root)
	if err != nil {
		return facts, err
	}
	view := reachableMounts(entries, rootID)
	facts.Unmet = append(facts.Unmet, view.unmet...)
	inspector := backingInspector{sys: "/sys"}
	accepted := map[int]bool{}
	covers := map[int]bool{}
	facts.coverIDs = covers
	for _, entry := range view.entries {
		accepted[entry.id] = mountAccepted(entry, spec.AcceptFS, inspector)
	}
	original := append([]mountEntry(nil), view.entries...)
	var hidden, unmet []string
	for _, entry := range original {
		shadowed := false
		for _, point := range hidden {
			if pathWithin(entry.point, point) {
				shadowed = true
				break
			}
		}
		if shadowed {
			continue
		}
		blocked := false
		for _, point := range unmet {
			if pathWithin(entry.point, point) {
				blocked = true
				break
			}
		}
		if blocked {
			facts.Unmet = append(facts.Unmet, "fs-view:"+entry.fstype+"@"+entry.point)
			continue
		}
		if accepted[entry.id] {
			continue
		}
		if uncoverable(entry.point) {
			facts.Unmet = append(facts.Unmet, "fs-view:"+entry.fstype+"@"+entry.point)
			unmet = append(unmet, entry.point)
			continue
		}
		walk := walkTo(filepath.Dir(entry.point), view, accepted, covers)
		if walk.err == nil {
			id, idErr := mountID(walk.fd)
			if idErr != nil || !accepted[id] {
				walk.err = unix.ESTALE
			} else if searchErr := unix.Faccessat(walk.fd, ".", unix.X_OK, unix.AT_EACCESS); searchErr != nil {
				walk.err = searchErr
				if searchErr == unix.EACCES {
					walk.denied = walk.path
				}
			}
		}
		target := entry.point
		parent := walk.fd
		ancestor := false
		if walk.err != nil {
			if walk.err == unix.ENOENT && walk.covered {
				walk.close()
				continue
			}
			if walk.err == unix.EACCES && walk.denied != "" {
				target = walk.denied
				parent = walk.parent
				ancestor = true
			} else {
				facts.Unmet = append(facts.Unmet, "fs-view:lookup-mismatch@"+entry.point)
				unmet = append(unmet, entry.point)
				walk.close()
				continue
			}
		}
		if uncoverable(target) || parent < 0 {
			facts.Unmet = append(facts.Unmet, "fs-view:cover-at-ancestor@"+target)
			unmet = append(unmet, target)
			walk.close()
			continue
		}
		parentID, parentErr := mountID(parent)
		if parentErr != nil || !accepted[parentID] {
			facts.Unmet = append(facts.Unmet, "fs-view:lookup-mismatch@"+entry.point)
			unmet = append(unmet, entry.point)
			walk.close()
			continue
		}
		err = mountCover(parent, filepath.Base(target))
		walk.close()
		if err != nil {
			if !ancestor {
				return facts, err
			}
			facts.Unmet = append(facts.Unmet, "fs-view:cover-at-ancestor@"+target)
			unmet = append(unmet, target)
			continue
		}
		if ancestor {
			facts.CoverAtAncestor = append(facts.CoverAtAncestor, "cover_at_ancestor@"+target)
		}
		hidden = append(hidden, target)
		// Recompute the actual stack after each cover; later walks must verify its ID.
		entries, err = readMountInfo()
		if err != nil {
			return facts, err
		}
		view = reachableMounts(entries, rootID)
		facts.Unmet = append(facts.Unmet, view.unmet...)
		for _, current := range view.entries {
			if current.point == target {
				covers[current.id] = true
				accepted[current.id] = true
			}
		}
	}
	return facts, nil
}
