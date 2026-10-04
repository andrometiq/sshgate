package main

import (
	"encoding/binary"
	"testing"

	"golang.org/x/sys/unix"
)

func TestUringCompletionWaitsForPublishedResult(t *testing.T) {
	for _, head := range []uint32{0, 3, ^uint32(0)} {
		var cq [48]byte
		binary.LittleEndian.PutUint32(cq[0:], head)
		binary.LittleEndian.PutUint32(cq[4:], head)
		binary.LittleEndian.PutUint32(cq[8:], 1)
		calls := 0
		result, errno := uringCompletion(cq[:], 0, 4, 8, 16, func() unix.Errno {
			calls++
			if got := binary.LittleEndian.Uint32(cq[0:]); got != head {
				t.Fatalf("consumed unpublished CQE: head=%d, want %d", got, head)
			}
			switch calls {
			case 1:
				return 0 // A successful enter need not publish a completion.
			case 2:
				return unix.EINTR
			case 3:
				failure := -int32(unix.ENODATA)
				binary.LittleEndian.PutUint32(cq[16+(head&1)*16+8:], uint32(failure))
				binary.LittleEndian.PutUint32(cq[4:], head+1)
				return 0
			default:
				t.Fatal("waited after completion was published")
				return unix.EIO
			}
		})
		if errno != 0 || result != -int32(unix.ENODATA) || calls != 3 {
			t.Fatalf("result=%d errno=%v waits=%d", result, errno, calls)
		}
		if got := binary.LittleEndian.Uint32(cq[0:]); got != head+1 {
			t.Fatalf("head=%d, want %d", got, head+1)
		}
	}
}

func TestUringCompletionWaitErrorDoesNotConsume(t *testing.T) {
	var cq [32]byte
	_, errno := uringCompletion(cq[:], 0, 4, 8, 16, func() unix.Errno { return unix.EPERM })
	if errno != unix.EPERM || binary.LittleEndian.Uint32(cq[0:]) != 0 {
		t.Fatalf("errno=%v head=%d", errno, binary.LittleEndian.Uint32(cq[0:]))
	}
}
