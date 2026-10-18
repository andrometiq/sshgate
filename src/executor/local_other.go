//go:build !linux

package executor

import (
	"errors"
	"net"
)

type Local struct{}

func OpenLocal(runtimeRoot, configRoot string) (*Local, error) {
	return nil, errors.New("executor: unsupported platform")
}

func (*Local) AcceptUnix() (*net.UnixConn, error) {
	return nil, errors.New("executor: unsupported platform")
}

func (*Local) Close() error { return nil }
