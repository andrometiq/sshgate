//go:build !linux && !darwin

package signerkit

import (
	"errors"
	"net"
)

func socketPeerUID(*net.UnixConn) (uint32, error) {
	return 0, errors.New("peer credentials unavailable on this platform")
}
