//go:build linux

package main

import (
	"errors"
	"fmt"
	"os"

	"github.com/karthikeyan5/sshgate/pkg/signerkit/lifecycle"
	ap "github.com/karthikeyan5/sshgate/src/approvalplan"
	"golang.org/x/sys/unix"
)

func main() {
	if err := commit(os.Args[1], os.Args[2]); err != nil {
		fmt.Fprintln(os.Stderr, err)
		if errors.Is(err, lifecycle.ErrStoreFatal) && errors.Is(err, unix.EBADF) {
			os.Exit(87)
		}
		os.Exit(1)
	}
	fmt.Println("committed")
}

func commit(directory, fixture string) error {
	data, err := os.ReadFile(fixture)
	if err != nil {
		return err
	}
	record, err := ap.DecodeR1(data)
	if err != nil {
		return err
	}
	store, err := lifecycle.OpenFileStore(directory, uint32(os.Getuid()))
	if store != nil {
		defer store.Close()
	}
	if err != nil {
		return err
	}
	return store.Commit(ap.RecordKey(record.Header.Principal, record.Header.RequestID), record)
}
