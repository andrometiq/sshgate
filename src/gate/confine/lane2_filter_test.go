//go:build linux

package confine

import (
	"reflect"
	"testing"

	"golang.org/x/sys/unix"
)

// TestLane2LandlockRules: the plain read's Landlock plan is unchanged, and a
// daemon read's grants EXECUTE only on its client and interpreter inodes and,
// from ABI 9, Unix-socket connects only on its socket inodes.
func TestLane2LandlockRules(t *testing.T) {
	const execute = uint64(unix.LANDLOCK_ACCESS_FS_EXECUTE)
	for _, abi := range []int{1, 4, 6, 9, 10} {
		writable := writableSet()
		want := []landlockRule{{path: "/", fd: -1, rights: readRights()}}
		for _, path := range writable {
			want = append(want, landlockRule{path: path, fd: -1, rights: writeRights(abi), optional: true})
		}
		if got := landlockPlan(abi, writable, nil); !reflect.DeepEqual(got, want) {
			t.Errorf("ABI %d plain plan = %+v, want %+v", abi, got, want)
		}
		for _, interp := range []int{11, -1} {
			got := landlockPlan(abi, writable, &lane2FDs{binary: 10, interp: interp, sockets: []int{12, 13}})
			want := []landlockRule{{path: "/", fd: -1, rights: readRights() &^ execute}}
			for _, path := range writable {
				want = append(want, landlockRule{path: path, fd: -1, rights: writeRights(abi) &^ execute, optional: true})
			}
			want = append(want, landlockRule{fd: 10, rights: execute | unix.LANDLOCK_ACCESS_FS_READ_FILE})
			if interp >= 0 {
				want = append(want, landlockRule{fd: interp, rights: execute | unix.LANDLOCK_ACCESS_FS_READ_FILE})
			}
			if abi >= 9 {
				want = append(want, landlockRule{fd: 12, rights: landlockAccessFSResolveUnix}, landlockRule{fd: 13, rights: landlockAccessFSResolveUnix})
			}
			if !reflect.DeepEqual(got, want) {
				t.Errorf("ABI %d daemon-read plan (interp %d) = %+v, want %+v", abi, interp, got, want)
			}
			for _, rule := range got {
				if rule.fd < 0 && rule.rights&(execute|landlockAccessFSResolveUnix) != 0 {
					t.Errorf("ABI %d: path rule %s grants EXECUTE or RESOLVE_UNIX", abi, rule.path)
				}
			}
		}
	}
}

// TestLane2FilterRows: a daemon read's filter decides every syscall exactly as
// a plain read's, except that memfd_create and memfd_secret are denied (and
// socket, whose Unix branch TestLane2SocketTable covers).
func TestLane2FilterRows(t *testing.T) {
	for _, abi := range []int{1, 6, 10} {
		plain, lane2 := buildFilter(filterParams{abi: abi}), buildFilter(filterParams{abi: abi, lane2: true})
		for _, row := range syscallTable {
			if row.nr == unix.SYS_SOCKET {
				continue
			}
			data := dataFor(row.nr, x8664)
			want := evalFilter(t, plain, data)
			if row.name == "MEMFD_CREATE" || row.name == "MEMFD_SECRET" {
				if want != actAllow {
					t.Errorf("ABI %d: plain %s = %#x, want allow", abi, row.name, want)
				}
				want = actDeny
			}
			if got := evalFilter(t, lane2, data); got != want {
				t.Errorf("ABI %d: daemon-read %s = %#x, want %#x", abi, row.name, got, want)
			}
		}
	}
}

// TestLane2SocketTable: a daemon read may create Unix stream sockets (with any
// type flags) and no other Unix socket; a plain read none; every other family
// decides the same either way.
func TestLane2SocketTable(t *testing.T) {
	plain, lane2 := buildFilter(filterParams{abi: 10}), buildFilter(filterParams{abi: 10, lane2: true})
	flags := []uint64{0, unix.SOCK_CLOEXEC, unix.SOCK_NONBLOCK, unix.SOCK_CLOEXEC | unix.SOCK_NONBLOCK}
	for _, kind := range []uint64{unix.SOCK_STREAM, unix.SOCK_DGRAM, unix.SOCK_SEQPACKET, unix.SOCK_RAW} {
		for _, flag := range flags {
			data := dataFor(unix.SYS_SOCKET, x8664, unix.AF_UNIX, kind|flag, 0)
			want := actDeny
			if kind == unix.SOCK_STREAM {
				want = actAllow
			}
			if got := evalFilter(t, lane2, data); got != want {
				t.Errorf("daemon-read AF_UNIX type %d|%#x = %#x, want %#x", kind, flag, got, want)
			}
			if got := evalFilter(t, plain, data); got != actDeny {
				t.Errorf("plain AF_UNIX type %d|%#x = %#x, want deny", kind, flag, got)
			}
		}
	}
	for _, family := range []uint64{unix.AF_INET, unix.AF_INET6, unix.AF_NETLINK, unix.AF_PACKET, unix.AF_VSOCK} {
		for _, kind := range []uint64{unix.SOCK_STREAM, unix.SOCK_DGRAM, unix.SOCK_RAW} {
			for _, proto := range []uint64{0, unix.IPPROTO_TCP, unix.IPPROTO_UDP, unix.NETLINK_ROUTE, unix.NETLINK_SOCK_DIAG} {
				data := dataFor(unix.SYS_SOCKET, x8664, family, kind, proto)
				if got, want := evalFilter(t, lane2, data), evalFilter(t, plain, data); got != want {
					t.Errorf("family %d type %d proto %d: daemon-read %#x, plain %#x", family, kind, proto, got, want)
				}
			}
		}
	}
}
