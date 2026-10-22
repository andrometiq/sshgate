package main

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"reflect"
	"strings"

	"github.com/karthikeyan5/sshgate/src/gate/confine"
	"golang.org/x/sys/unix"
)

// pinTempPrefix names the temporary file the pin is written through.
const pinTempPrefix = ".jail.tmp-"

// pinPrecondition is why `doctor --pin` cannot write here; code is its exit.
type pinPrecondition struct {
	code   int
	reason string
}

// lockGateDir checks that this process may pin the gate directory and locks
// it: the effective uid is the gate's uid and owns the directory, which is a
// real directory (not a symlink) that only its owner can write. The returned
// directory is flock'ed until it is closed.
func lockGateDir(gateDir string) (*os.File, *pinPrecondition) {
	uid := os.Geteuid()
	if uid != pinUIDFn() {
		return nil, &pinPrecondition{exitNoPermVal, fmt.Sprintf("run as the gate's user (uid %d), not uid %d", pinUIDFn(), uid)}
	}
	var before unix.Stat_t
	if err := unix.Lstat(gateDir, &before); err != nil {
		return nil, &pinPrecondition{exitNoPermVal, "gate directory: " + err.Error()}
	}
	if before.Mode&unix.S_IFMT != unix.S_IFDIR || before.Uid != uint32(uid) || before.Mode&0o022 != 0 {
		return nil, &pinPrecondition{exitNoPermVal, "the gate directory must be a directory owned by the gate's user and writable only by it"}
	}
	fd, err := unix.Open(gateDir, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, &pinPrecondition{exitNoPermVal, "gate directory: " + err.Error()}
	}
	var opened unix.Stat_t
	if err := unix.Fstat(fd, &opened); err != nil || opened.Dev != before.Dev || opened.Ino != before.Ino {
		_ = unix.Close(fd)
		return nil, &pinPrecondition{exitNoPermVal, "the gate directory changed while it was opened"}
	}
	if err := unix.Flock(fd, unix.LOCK_EX|unix.LOCK_NB); err != nil {
		_ = unix.Close(fd)
		if errors.Is(err, unix.EWOULDBLOCK) {
			return nil, &pinPrecondition{exitTempFail, "another doctor --pin holds the gate directory"}
		}
		return nil, &pinPrecondition{exitSoftware, "lock the gate directory: " + err.Error()}
	}
	return os.NewFile(uintptr(fd), gateDir), nil
}

// readPinAt reads the pin file name in dir without following a symlink.
func readPinAt(dirfd int, name string) ([]byte, unix.Stat_t, error) {
	var stat unix.Stat_t
	fd, err := unix.Openat(dirfd, name, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, stat, err
	}
	file := os.NewFile(uintptr(fd), name)
	defer file.Close()
	if err := unix.Fstat(fd, &stat); err != nil {
		return nil, stat, err
	}
	data, err := io.ReadAll(io.LimitReader(file, confine.MaxPinBytes+1))
	return data, stat, err
}

// pinMatches reports whether a pin file already is the candidate: a regular
// file of the gate's uid, mode 0600, one link, holding candBytes or a pin
// equal to cand.
func pinMatches(dirfd int, candBytes []byte, cand confine.Pin) bool {
	data, stat, err := readPinAt(dirfd, confine.PinFile)
	if err != nil || stat.Mode&unix.S_IFMT != unix.S_IFREG || stat.Uid != uint32(pinUIDFn()) || stat.Mode&0o7777 != 0o600 || stat.Nlink != 1 {
		return false
	}
	if bytes.Equal(data, candBytes) {
		return true
	}
	parsed, err := confine.ParsePin(data)
	return err == nil && reflect.DeepEqual(parsed, cand)
}

// writePin writes candBytes, the pin the rehearsal ran, as the gate's jail
// pin: "unchanged" if it already is, else through an exclusive 0600 temporary
// file that is synced, read back and renamed over the pin, and the directory
// synced. The pin the read path then reads must be cand. dir is the locked
// gate directory.
func writePin(dir *os.File, candBytes []byte, cand confine.Pin) (string, error) {
	dirfd := int(dir.Fd())
	if pinMatches(dirfd, candBytes, cand) {
		return "unchanged", nil
	}
	temp := pinTempPrefix + randomToken(8)
	fd, err := unix.Openat(dirfd, temp, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0o600)
	if err != nil {
		return "", fmt.Errorf("create %s: %w", temp, err)
	}
	renamed := false
	defer func() {
		if !renamed {
			_ = unix.Unlinkat(dirfd, temp, 0)
		}
	}()
	file := os.NewFile(uintptr(fd), temp)
	err = writeTempPin(file, candBytes)
	if closeErr := file.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		return "", err
	}
	data, _, err := readPinAt(dirfd, temp)
	parsed, parseErr := confine.ParsePin(data)
	if err != nil || parseErr != nil || !bytes.Equal(data, candBytes) || !reflect.DeepEqual(parsed, cand) {
		return "", errors.New("the written pin does not read back as the rehearsed one")
	}
	if err := unix.Renameat(dirfd, temp, dirfd, confine.PinFile); err != nil {
		return "", fmt.Errorf("replace the pin: %w", err)
	}
	renamed = true
	if err := unix.Fsync(dirfd); err != nil {
		return "", fmt.Errorf("sync the gate directory: %w", err)
	}
	if pin := readJailPin(); !pin.valid || !reflect.DeepEqual(pin.pin, cand) {
		return "", errors.New("the read path does not see the written pin")
	}
	return "written", nil
}

// writeTempPin sets the temporary file's mode, checks it is a fresh regular
// file of the gate's uid, and writes and syncs the pin.
func writeTempPin(file *os.File, candBytes []byte) error {
	fd := int(file.Fd())
	if err := unix.Fchmod(fd, 0o600); err != nil {
		return err
	}
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil {
		return err
	}
	if stat.Mode&unix.S_IFMT != unix.S_IFREG || stat.Uid != uint32(pinUIDFn()) || stat.Nlink != 1 {
		return errors.New("the temporary pin is not a fresh regular file")
	}
	if _, err := file.Write(candBytes); err != nil {
		return err
	}
	return file.Sync()
}

// staleTempPins lists temporary pin files a failed write left behind. They
// are never read.
func staleTempPins(gateDir string) []string {
	entries, _ := os.ReadDir(gateDir)
	var stale []string
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), pinTempPrefix) {
			stale = append(stale, entry.Name())
		}
	}
	return stale
}
