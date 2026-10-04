//go:build linux

package confine

import (
	"fmt"
	"github.com/karthikeyan5/sshgate/src/gate/confine/jailmut"
	"golang.org/x/sys/unix"
)

const tmpfsSizeBytes = 64 << 20

var devNodes = []string{"null", "zero", "full", "random", "urandom", "tty"}

func setupMounts(spec Spec) (mountFacts, error) {
	var facts mountFacts
	stages := []struct {
		name string
		run  func() error
	}{
		{"private", func() error {
			if jailmut.On("P-PRIVATE") {
				return nil
			}
			return unix.Mount("", "/", "", unix.MS_REC|unix.MS_PRIVATE, "")
		}},
		{"setattr", remountRootReadOnly},
		{"devnodes", bindDevNodes},
		{"covers", func() (err error) { facts, err = coverMounts(spec); return err }},
		{"scratch", func() error { return mountTmpfs("/dev/shm") }},
	}
	for _, stage := range stages {
		err := stage.run()
		if name, errno := spec.inject(); name == stage.name {
			err = errno
		}
		if err != nil && !ignoreMountStageFailure(stage.name) {
			return facts, &SetupError{Stage: stage.name, Errno: errnoOf(err)}
		}
	}
	return facts, nil
}

func remountRootReadOnly() error {
	flags := uint64(unix.MOUNT_ATTR_RDONLY | unix.MOUNT_ATTR_NODEV | unix.MOUNT_ATTR_NOSUID)
	if jailmut.On("P-RO") {
		flags &^= unix.MOUNT_ATTR_RDONLY
	}
	if jailmut.On("P-NODEV") {
		flags &^= unix.MOUNT_ATTR_NODEV
	}
	if jailmut.On("P-NOSUID") {
		flags &^= unix.MOUNT_ATTR_NOSUID
	}
	return unix.MountSetattr(unix.AT_FDCWD, "/", unix.AT_RECURSIVE, &unix.MountAttr{Attr_set: flags})
}

func bindDevNodes() error {
	if jailmut.On("P-DEV-SIX") {
		return nil
	}
	for _, node := range devNodes {
		path := "/dev/" + node
		var stat unix.Stat_t
		err := unix.Lstat(path, &stat)
		if err == unix.ENOENT {
			continue
		}
		if err != nil {
			return err
		}
		if stat.Mode&unix.S_IFMT != unix.S_IFCHR {
			return unix.EINVAL
		}
		if err := unix.Mount(path, path, "", unix.MS_BIND, ""); err != nil {
			return err
		}
		if err := unix.MountSetattr(unix.AT_FDCWD, path, 0, &unix.MountAttr{Attr_clr: unix.MOUNT_ATTR_NODEV}); err != nil {
			return err
		}
	}
	return nil
}

func mountTmpfs(dir string) error {
	size := tmpfsSizeBytes
	if jailmut.On("P-SCRATCH-SIZE") {
		size *= 2
	}
	flags := uintptr(unix.MS_NOSUID | unix.MS_NODEV | unix.MS_NOEXEC)
	if jailmut.On("P-SCRATCH-FLAGS") {
		flags = 0
	}
	return unix.Mount("tmpfs", dir, "tmpfs", flags, fmt.Sprintf("mode=1777,size=%d", size))
}

func ignoreMountStageFailure(stage string) bool {
	switch stage {
	case "private":
		return jailmut.On("P-FAULT-private")
	case "setattr":
		return jailmut.On("P-FAULT-setattr")
	case "devnodes":
		return jailmut.On("P-FAULT-devnodes")
	case "covers":
		return jailmut.On("P-FAULT-covers")
	case "scratch":
		return jailmut.On("P-FAULT-scratch")
	}
	return false
}
