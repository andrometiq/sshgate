package main

import (
	"fmt"
	"io"

	"golang.org/x/sys/unix"
)

func metadataSnapshot(path, prefix string, output io.Writer) error {
	var stat unix.Stat_t
	if err := unix.Stat(path, &stat); err != nil {
		return err
	}
	buffer := make([]byte, 4096)
	n, err := unix.Getxattr(path, "user.sshgate", buffer)
	value := ""
	switch err {
	case nil:
		value = string(buffer[:n])
	case unix.ENODATA:
		value = "absent"
	case unix.EOPNOTSUPP:
		value = "unsupported"
	default:
		return err
	}
	_, err = fmt.Fprintf(output, "%s-mode=%o\n%s-mtime=%d:%d\n%s-xattr=%s\n", prefix, stat.Mode&0777, prefix, stat.Mtim.Sec, stat.Mtim.Nsec, prefix, value)
	return err
}
