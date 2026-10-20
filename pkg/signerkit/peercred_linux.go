package signerkit

import (
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
		credentials, err := unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED)
		if err != nil {
			credentialErr = err
			return
		}
		uid = credentials.Uid
	}); err != nil {
		return 0, err
	}
	return uid, credentialErr
}
