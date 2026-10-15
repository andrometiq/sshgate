//go:build linux

// Package executor owns the local asynchronous execution service.
package executor

import (
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sync"

	"github.com/karthikeyan5/sshgate/internal/securestate"
	"golang.org/x/sys/unix"
)

// Local holds the process locks and same-user listener. Close it only after
// handlers and stores have closed; store descriptors share its ownership lock.
type Local struct {
	listener  *net.UnixListener
	singleton *os.File
	directory *os.File
	peerUID   func(*net.UnixConn) (uint32, error)
	once      sync.Once
	closeErr  error
}

// OpenLocal requires existing runtime and config roots. It acquires both locks
// before binding the socket. Callers must treat any failure as fatal at startup.
func OpenLocal(runtimeRoot, configRoot string) (_ *Local, err error) {
	if !filepath.IsAbs(runtimeRoot) || !filepath.IsAbs(configRoot) {
		return nil, errors.New("executor: runtime and config roots must be absolute")
	}
	local := &Local{peerUID: socketPeerUID}
	defer func() {
		if err != nil {
			_ = local.Close()
		}
	}()
	runtimeDir, err := openPrivateDirectory(runtimeRoot, "sshgate")
	if err != nil {
		return nil, err
	}
	defer runtimeDir.Close()
	fd, err := unix.Openat(int(runtimeDir.Fd()), "executor.lock", unix.O_RDWR|unix.O_CREAT|unix.O_NOFOLLOW|unix.O_CLOEXEC|unix.O_NONBLOCK, 0600)
	if err != nil {
		return nil, fmt.Errorf("executor: open singleton: %w", err)
	}
	local.singleton = os.NewFile(uintptr(fd), "executor.lock")
	var stat unix.Stat_t
	if err = unix.Fstat(fd, &stat); err != nil {
		return nil, err
	}
	if stat.Mode != unix.S_IFREG|0600 || stat.Uid != uint32(os.Getuid()) || stat.Nlink != 1 {
		return nil, errors.New("executor: unsafe singleton lock")
	}
	if err = lock(fd, "singleton"); err != nil {
		return nil, err
	}
	local.directory, err = openPrivateDirectory(configRoot, "executor")
	if err != nil {
		return nil, err
	}
	if err = lock(int(local.directory.Fd()), filepath.Join(configRoot, "executor")); err != nil {
		return nil, err
	}
	socketPath := filepath.Join(runtimeRoot, "sshgate", "executor.sock")
	// Only a stale socket may be removed, and only while holding the singleton.
	if err = unix.Fstatat(int(runtimeDir.Fd()), "executor.sock", &stat, unix.AT_SYMLINK_NOFOLLOW); err == nil {
		if stat.Mode&unix.S_IFMT != unix.S_IFSOCK || stat.Uid != uint32(os.Getuid()) {
			return nil, errors.New("executor: unsafe socket")
		}
		if err = unix.Unlinkat(int(runtimeDir.Fd()), "executor.sock", 0); err != nil {
			return nil, err
		}
	} else if !errors.Is(err, unix.ENOENT) {
		return nil, err
	}
	local.listener, err = net.ListenUnix("unix", &net.UnixAddr{Name: socketPath, Net: "unix"})
	if err != nil {
		return nil, err
	}
	if err = os.Chmod(socketPath, 0600); err != nil {
		return nil, err
	}
	return local, nil
}

func openPrivateDirectory(root, name string) (*os.File, error) {
	parent, err := unix.Open(root, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	defer unix.Close(parent)
	if err = unix.Mkdirat(parent, name, 0700); err == nil {
		if err = unix.Fsync(parent); err != nil {
			return nil, err
		}
	} else if !errors.Is(err, unix.EEXIST) {
		return nil, err
	}
	fd, err := unix.Openat(parent, name, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	var stat unix.Stat_t
	err = unix.Fstat(fd, &stat)
	if err == nil && (stat.Mode != unix.S_IFDIR|0700 || stat.Uid != uint32(os.Getuid())) {
		err = fmt.Errorf("executor: unsafe directory %s", filepath.Join(root, name))
	}
	if err != nil {
		unix.Close(fd)
		return nil, err
	}
	return os.NewFile(uintptr(fd), filepath.Join(root, name)), nil
}

func lock(fd int, name string) error {
	err := unix.Flock(fd, unix.LOCK_EX|unix.LOCK_NB)
	if errors.Is(err, unix.EWOULDBLOCK) {
		return fmt.Errorf("executor: %s is held by another executor process: %w", name, err)
	}
	if err != nil {
		return fmt.Errorf("executor: lock %s: stores require a local filesystem: %w", name, err)
	}
	return nil
}

// OpenStore opens the locked inode, even if its pathname has been replaced.
// The caller must close the store before closing Local.
func (l *Local) OpenStore() (*securestate.Store, error) {
	return securestate.OpenDirectory(int(l.directory.Fd()), uint32(os.Getuid()), true)
}

// AcceptUnix returns only authenticated connections. A rejected peer is closed
// without reading a request; the serving loop may continue accepting afterward.
func (l *Local) AcceptUnix() (*net.UnixConn, error) {
	conn, err := l.listener.AcceptUnix()
	if err != nil {
		return nil, err
	}
	uid, err := l.peerUID(conn)
	if err != nil || uid != uint32(os.Getuid()) {
		conn.Close()
		return nil, errors.New("executor: peer credentials refused")
	}
	return conn, nil
}

func socketPeerUID(conn *net.UnixConn) (uint32, error) {
	raw, err := conn.SyscallConn()
	if err != nil {
		return 0, err
	}
	var cred *unix.Ucred
	var credentialErr error
	err = raw.Control(func(fd uintptr) {
		cred, credentialErr = unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED)
	})
	if err != nil {
		return 0, err
	}
	if credentialErr != nil {
		return 0, credentialErr
	}
	return cred.Uid, nil
}

// Close stops acceptance before releasing ownership. It is idempotent.
func (l *Local) Close() error {
	l.once.Do(func() {
		var errs []error
		if l.listener != nil {
			errs = append(errs, l.listener.Close())
		}
		if l.directory != nil {
			errs = append(errs, l.directory.Close())
		}
		if l.singleton != nil {
			errs = append(errs, l.singleton.Close())
		}
		l.closeErr = errors.Join(errs...)
	})
	return l.closeErr
}
