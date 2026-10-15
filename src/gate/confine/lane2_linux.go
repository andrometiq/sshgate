//go:build linux

package confine

import (
	"os"

	"golang.org/x/sys/unix"
)

// lane2Opened are a daemon read's admitted objects, opened by path inside the
// jail's final view after their identity was checked. They are closed before
// the client runs.
type lane2Opened struct {
	binary, interp *os.File
	sockets        []*os.File
}

func (o lane2Opened) close() {
	for _, file := range append([]*os.File{o.binary, o.interp}, o.sockets...) {
		if file != nil {
			_ = file.Close()
		}
	}
}

// openLane2 opens the binary, the interpreter and each socket O_PATH by the
// path the gate admitted and requires each to be the admitted inode, on that
// fd and on the reference the gate still holds. The held reference keeps the
// inode alive, so its number cannot have been reused by a replacement.
func openLane2(l *Lane2) (lane2Opened, error) {
	var opened lane2Opened
	open := func(path string, want FileID, held int, socket bool) (*os.File, error) {
		fd, err := unix.Open(path, unix.O_PATH|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		if err != nil {
			return nil, err
		}
		file := os.NewFile(uintptr(fd), path)
		var atPath, atHeld unix.Stat_t
		if err = unix.Fstat(fd, &atPath); err == nil {
			err = unix.Fstat(held, &atHeld)
		}
		if err == nil {
			err = lane2Identity(atPath, atHeld, want, socket)
		}
		if err != nil {
			_ = file.Close()
			return nil, err
		}
		return file, nil
	}
	var err error
	if opened.binary, err = open(l.Binary, l.BinaryID, l.BinaryFD, false); err != nil {
		return opened, err
	}
	if l.Interp != "" {
		if opened.interp, err = open(l.Interp, l.InterpID, l.InterpFD, false); err != nil {
			opened.close()
			return lane2Opened{}, err
		}
	}
	for _, socket := range l.Sockets {
		file, err := open(socket.Path, socket.ID, socket.FD, true)
		if err != nil {
			opened.close()
			return lane2Opened{}, err
		}
		opened.sockets = append(opened.sockets, file)
	}
	return opened, nil
}

// lane2Identity requires the admitted file type, and the admitted inode both
// where the jail's view resolves the path and on the held reference.
func lane2Identity(atPath, atHeld unix.Stat_t, want FileID, socket bool) error {
	kind := uint32(unix.S_IFREG)
	if socket {
		kind = unix.S_IFSOCK
	}
	if atPath.Mode&unix.S_IFMT != kind {
		return unix.ESTALE
	}
	for _, st := range []unix.Stat_t{atPath, atHeld} {
		if (FileID{Dev: uint64(st.Dev), Ino: st.Ino}) != want {
			return unix.ESTALE
		}
	}
	return nil
}
