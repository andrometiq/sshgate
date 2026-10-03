//go:build linux

package confine

import (
	"encoding/json"
	"io"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/karthikeyan5/sshgate/src/gate/confine/jailmut"
	"golang.org/x/sys/unix"
)

func decodeSpec(raw string, spec *Spec) error {
	decoder := json.NewDecoder(strings.NewReader(raw))
	if !jailmut.On("P-SPEC") {
		decoder.DisallowUnknownFields()
	}
	if err := decoder.Decode(spec); err != nil {
		return unix.EINVAL
	}
	if !jailmut.On("P-SPEC") {
		var tail any
		if decoder.Decode(&tail) != io.EOF {
			return unix.EINVAL
		}
		return spec.validate(true)
	}
	return nil
}

func (s Spec) validate(worker bool) error {
	if s.Profile != ProfileROv1 || s.ForceABI < ForceNoLandlock {
		return unix.EINVAL
	}
	if (worker || s.Cwd != "") && (!filepath.IsAbs(s.Cwd) || filepath.Clean(s.Cwd) != s.Cwd || strings.ContainsRune(s.Cwd, 0) || len(s.Cwd) > 4096) {
		return unix.EINVAL
	}
	seen := map[string]bool{}
	for _, class := range s.AcceptFS {
		if (class != "network" && class != "autofs") || seen[class] {
			return unix.EINVAL
		}
		seen[class] = true
	}
	if s.InjectFailAt != "" {
		stage, errno := s.inject()
		switch stage {
		case "spec", "cmdread", "nsverify", "mounts", "private", "setattr", "devnodes", "covers", "scratch", "fds", "cwd", "nnp", "caps", "rlimits", "landlock", "seccomp", "tsync", "exec":
		default:
			return unix.EINVAL
		}
		if errno == 0 {
			return unix.EINVAL
		}
	}
	if worker && (s.ParentNS.User == 0 || s.ParentNS.Mnt == 0 || s.ParentNS.Pid == 0 || s.ParentNS.IPC == 0) {
		return unix.EINVAL
	}
	return nil
}

func (s Spec) inject() (string, syscall.Errno) {
	stage, name, hasErrno := strings.Cut(s.InjectFailAt, ":")
	if !hasErrno {
		return stage, unix.EIO
	}
	switch name {
	case "EIO":
		return stage, unix.EIO
	case "EACCES":
		return stage, unix.EACCES
	case "EPERM":
		return stage, unix.EPERM
	case "ENOSYS":
		return stage, unix.ENOSYS
	case "ENOSPC":
		return stage, unix.ENOSPC
	case "EOPNOTSUPP":
		return stage, unix.EOPNOTSUPP
	case "EINVAL":
		return stage, unix.EINVAL
	case "ENOENT":
		return stage, unix.ENOENT
	case "ENOTDIR":
		return stage, unix.ENOTDIR
	}
	return stage, 0
}

func namespaceIDs() (NSIDs, error) {
	var ids NSIDs
	for _, item := range []struct {
		name  string
		inode *uint64
	}{
		{"user", &ids.User}, {"mnt", &ids.Mnt}, {"pid", &ids.Pid}, {"ipc", &ids.IPC},
	} {
		var stat unix.Stat_t
		if err := unix.Stat("/proc/self/ns/"+item.name, &stat); err != nil {
			return NSIDs{}, err
		}
		*item.inode = stat.Ino
	}
	return ids, nil
}

func verifyNamespaces(parent NSIDs) error {
	current, err := namespaceIDs()
	if err != nil {
		return err
	}
	if unix.Getppid() != 1 || parent.User == 0 || parent.Mnt == 0 || parent.Pid == 0 || parent.IPC == 0 || current.User == parent.User || current.Mnt == parent.Mnt || current.Pid == parent.Pid || current.IPC == parent.IPC {
		return unix.EPERM
	}
	return nil
}
