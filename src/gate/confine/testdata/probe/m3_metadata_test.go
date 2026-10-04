package main

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

func TestMetadataSnapshot(t *testing.T) {
	path := t.TempDir() + "/metadata"
	if err := os.WriteFile(path, []byte("canary"), 0600); err != nil {
		t.Fatal(err)
	}
	var before bytes.Buffer
	if err := metadataSnapshot(path, "before", &before); err != nil {
		t.Fatal(err)
	}
	var stat unix.Stat_t
	if err := unix.Stat(path, &stat); err != nil {
		t.Fatal(err)
	}
	prefix := fmt.Sprintf("before-mode=600\nbefore-mtime=%d:%d\nbefore-xattr=", stat.Mtim.Sec, stat.Mtim.Nsec)
	if before.String() != prefix+"absent\n" && before.String() != prefix+"unsupported\n" {
		t.Fatalf("unexpected baseline %q", before.String())
	}
	if err := unix.Setxattr(path, "user.sshgate", []byte("test"), 0); err == nil {
		var after bytes.Buffer
		if err := metadataSnapshot(path, "after", &after); err != nil {
			t.Fatal(err)
		}
		if !strings.HasSuffix(after.String(), "after-xattr=test\n") {
			t.Fatalf("xattr effect not reported: %q", after.String())
		}
	} else if err != unix.EOPNOTSUPP {
		t.Fatal(err)
	}
	if err := metadataSnapshot(path+"-missing", "after", &bytes.Buffer{}); !errors.Is(err, unix.ENOENT) {
		t.Fatalf("missing file yielded %v", err)
	}
	if err := metadataSnapshot(path, "after", metadataErrorWriter{}); !errors.Is(err, unix.EIO) {
		t.Fatalf("output error yielded %v", err)
	}
}

type metadataErrorWriter struct{}

func (metadataErrorWriter) Write([]byte) (int, error) { return 0, unix.EIO }
