//go:build linux

package policyarchive

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/unix"
)

type nodeSpec struct {
	kind       uint32
	mode       uint32
	singleLink bool
	device     *uint64
}

func openParentNoSymlinks(path string) (int, string, string, error) {
	absolute, err := filepath.Abs(path)
	if err != nil {
		return -1, "", "", fmt.Errorf("policy archive: resolve absolute path: %w", err)
	}
	absolute = filepath.Clean(absolute)
	base := filepath.Base(absolute)
	if absolute == string(filepath.Separator) || base == "." || base == ".." || strings.ContainsRune(base, filepath.Separator) {
		return -1, "", "", errors.New("policy archive: path must name an entry below the filesystem root")
	}

	fd, err := unix.Open(string(filepath.Separator), unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return -1, "", "", fmt.Errorf("policy archive: open filesystem root: %w", err)
	}
	parent := filepath.Dir(absolute)
	components := strings.Split(strings.TrimPrefix(parent, string(filepath.Separator)), string(filepath.Separator))
	for _, component := range components {
		if component == "" || component == "." {
			continue
		}
		next, openErr := unix.Openat(fd, component, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		if openErr != nil {
			_ = unix.Close(fd)
			return -1, "", "", fmt.Errorf("policy archive: open path component %q: %w", component, openErr)
		}
		_ = unix.Close(fd)
		fd = next
	}
	return fd, base, absolute, nil
}

func validateOwnedFD(fd int, specification nodeSpec) (unix.Stat_t, error) {
	var status unix.Stat_t
	if err := unix.Fstat(fd, &status); err != nil {
		return unix.Stat_t{}, err
	}
	if err := validateOwnedStat(status, specification); err != nil {
		return unix.Stat_t{}, err
	}
	return status, nil
}

func validateOwnedStat(status unix.Stat_t, specification nodeSpec) error {
	if status.Mode&unix.S_IFMT != specification.kind {
		return errors.New("unexpected inode type")
	}
	if status.Uid != uint32(os.Geteuid()) {
		return errors.New("inode is not owned by process uid")
	}
	if status.Mode&0o7777 != specification.mode {
		return fmt.Errorf("inode mode is %#o; want %#o", status.Mode&0o7777, specification.mode)
	}
	if specification.singleLink {
		if status.Nlink != 1 {
			return errors.New("inode must have exactly one link")
		}
	} else if status.Nlink < 1 {
		return errors.New("inode is unlinked")
	}
	if specification.device != nil && uint64(status.Dev) != *specification.device {
		return errors.New("inode is on a different device")
	}
	return nil
}

func validateNamedIdentity(parentFD int, name string, heldFD int, specification nodeSpec) (unix.Stat_t, error) {
	held, err := validateOwnedFD(heldFD, specification)
	if err != nil {
		return unix.Stat_t{}, err
	}
	var named unix.Stat_t
	if err := unix.Fstatat(parentFD, name, &named, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		return unix.Stat_t{}, err
	}
	if err := validateOwnedStat(named, specification); err != nil {
		return unix.Stat_t{}, err
	}
	if uint64(named.Dev) != uint64(held.Dev) || named.Ino != held.Ino {
		return unix.Stat_t{}, errors.New("pathname inode identity changed")
	}
	return held, nil
}

func randomLowerHexName(prefix string) (string, error) {
	var random [16]byte
	if _, err := io.ReadFull(cryptographicRandom, random[:]); err != nil {
		return "", fmt.Errorf("policy archive: generate temporary name: %w", err)
	}
	const hexadecimal = "0123456789abcdef"
	name := make([]byte, len(prefix)+len(random)*2)
	copy(name, prefix)
	for index, value := range random {
		name[len(prefix)+index*2] = hexadecimal[value>>4]
		name[len(prefix)+index*2+1] = hexadecimal[value&0x0f]
	}
	return string(name), nil
}

func writeAll(fd int, body []byte) error {
	for len(body) > 0 {
		written, err := unix.Write(fd, body)
		if errors.Is(err, unix.EINTR) {
			continue
		}
		if err != nil {
			return err
		}
		if written == 0 {
			return io.ErrShortWrite
		}
		body = body[written:]
	}
	return nil
}

func readOwnedFileAt(parentFD int, name string, expectedBytes int64) ([]byte, error) {
	if expectedBytes <= 0 || expectedBytes > maxObjectBytes {
		return nil, fmt.Errorf("policy archive: expected file length %d is outside 1..%d", expectedBytes, maxObjectBytes)
	}
	fd, err := unix.Openat(parentFD, name, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(fd), name)
	if file == nil {
		_ = unix.Close(fd)
		return nil, errors.New("policy archive: create file handle")
	}
	defer file.Close()

	specification := nodeSpec{kind: unix.S_IFREG, mode: 0o600, singleLink: true}
	status, err := validateNamedIdentity(parentFD, name, fd, specification)
	if err != nil {
		return nil, err
	}
	if status.Size != expectedBytes {
		return nil, fmt.Errorf("policy archive: file length is %d; want %d", status.Size, expectedBytes)
	}
	body, err := io.ReadAll(io.LimitReader(file, expectedBytes+1))
	if err != nil {
		return nil, err
	}
	if int64(len(body)) != expectedBytes {
		return nil, fmt.Errorf("policy archive: read %d bytes; want %d", len(body), expectedBytes)
	}
	if _, err := validateNamedIdentity(parentFD, name, fd, specification); err != nil {
		return nil, err
	}
	return body, nil
}
