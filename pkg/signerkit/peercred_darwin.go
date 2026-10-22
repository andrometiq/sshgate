package signerkit

import (
	"errors"
	"net"

	"golang.org/x/sys/unix"
)

func socketPeerUID(conn *net.UnixConn) (uint32, error) {
	raw, err := conn.SyscallConn()
	if err != nil {
		return 0, err
	}
	var uid uint32
	var credentialErr error
	if err := raw.Control(func(fd uintptr) {
		credentials, err := unix.GetsockoptXucred(int(fd), unix.SOL_LOCAL, unix.LOCAL_PEERCRED)
		if err != nil {
			credentialErr = err
			return
		}
		if credentials.Version != 0 { // XUCRED_VERSION
			credentialErr = errors.New("unsupported peer credential version")
			return
		}
		uid = credentials.Uid
	}); err != nil {
		return 0, err
	}
	return uid, credentialErr
}
