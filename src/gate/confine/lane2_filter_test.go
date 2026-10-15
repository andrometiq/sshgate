//go:build linux

package confine

import (
	"reflect"
	"slices"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

// unitLane2LandlockRules is U-Lane2LandlockRules: the plain read's Landlock
// plan is unchanged, and a daemon read's grants EXECUTE only on its client and
// interpreter inodes and, from ABI 9, Unix-socket connects only on its socket
// inodes. P-L2-EXEC-NARROW and P-L2-SOCK-PIN each change a row.
func unitLane2LandlockRules(t *testing.T) {
	const execute = uint64(unix.LANDLOCK_ACCESS_FS_EXECUTE)
	filterM1TableCheck(t, "U-Lane2LandlockRules", func(check func(bool)) {
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
				if len(got) != len(want) {
					t.Fatalf("ABI %d daemon-read plan = %+v, want %+v", abi, got, want)
				}
				// A mutation may widen / only; every other rule must match.
				check(got[0] != want[0])
				if !reflect.DeepEqual(got[1:], want[1:]) {
					t.Errorf("ABI %d daemon-read plan = %+v, want %+v", abi, got, want)
				}
			}
		}
	})
}

// unitLane2FilterRows is U-Lane2FilterRows: a daemon read's filter decides
// every syscall as a plain read's, except that memfd_create and memfd_secret
// are denied (and socket, which U-Lane2SocketTable covers).
func unitLane2FilterRows(t *testing.T) {
	filterM1TableCheck(t, "U-Lane2FilterRows", func(check func(bool)) {
		for _, abi := range []int{1, 6, 10} {
			plain, lane2 := buildFilter(filterParams{abi: abi}), buildFilter(filterParams{abi: abi, lane2: true})
			for _, row := range syscallTable {
				if row.nr == unix.SYS_SOCKET {
					continue
				}
				data := dataFor(row.nr, x8664)
				want, got := evalFilter(t, plain, data), evalFilter(t, lane2, data)
				if row.name == "MEMFD_CREATE" || row.name == "MEMFD_SECRET" {
					if want != actAllow {
						t.Errorf("ABI %d: plain %s = %#x, want allow", abi, row.name, want)
					}
					check(got != actDeny)
					continue
				}
				if got != want {
					t.Errorf("ABI %d: daemon-read %s = %#x, plain %#x", abi, row.name, got, want)
				}
			}
		}
	})
}

// unitLane2SocketTable is U-Lane2SocketTable: a daemon read may create Unix
// stream sockets (with any type flags) and no other Unix socket; a plain read
// none; every other family decides the same either way.
func unitLane2SocketTable(t *testing.T) {
	filterM1TableCheck(t, "U-Lane2SocketTable", func(check func(bool)) {
		plain, lane2 := buildFilter(filterParams{abi: 10}), buildFilter(filterParams{abi: 10, lane2: true})
		for _, kind := range []uint64{unix.SOCK_STREAM, unix.SOCK_DGRAM, unix.SOCK_SEQPACKET, unix.SOCK_RAW} {
			for _, flag := range []uint64{0, unix.SOCK_CLOEXEC, unix.SOCK_NONBLOCK, unix.SOCK_CLOEXEC | unix.SOCK_NONBLOCK} {
				data := dataFor(unix.SYS_SOCKET, x8664, unix.AF_UNIX, kind|flag, 0)
				want := actDeny
				if kind == unix.SOCK_STREAM {
					want = actAllow
				}
				if got := evalFilter(t, lane2, data); got != want {
					t.Errorf("daemon-read AF_UNIX type %d|%#x = %#x, want %#x", kind, flag, got, want)
				}
				check(evalFilter(t, plain, data) != actDeny)
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
	})
}

// unitLane2IdentityCompare is U-Lane2IdentityCompare: the worker's identity
// check passes only the admitted inode, both where the path resolves and on
// the held reference. P-L2-IDENTITY skips the inode comparison; the file-type
// rows still fail under it.
func unitLane2IdentityCompare(t *testing.T) {
	filterM1TableCheck(t, "U-Lane2IdentityCompare", func(check func(bool)) {
		stat := func(dev, ino uint64, kind uint32) unix.Stat_t {
			return unix.Stat_t{Dev: dev, Ino: ino, Mode: kind | 0o644}
		}
		want := FileID{Dev: 1, Ino: 10}
		for _, socket := range []bool{false, true} {
			kind := uint32(unix.S_IFREG)
			if socket {
				kind = unix.S_IFSOCK
			}
			same := stat(1, 10, kind)
			if err := lane2Identity(same, same, want, socket); err != nil {
				t.Errorf("socket=%t: the admitted inode refused: %v", socket, err)
			}
			for _, changed := range []unix.Stat_t{stat(1, 11, kind), stat(2, 10, kind)} {
				check(lane2Identity(changed, same, want, socket) == nil)
				check(lane2Identity(same, changed, want, socket) == nil)
			}
			other := uint32(unix.S_IFSOCK)
			if socket {
				other = unix.S_IFREG
			}
			if lane2Identity(stat(1, 10, other), same, want, socket) == nil {
				t.Errorf("socket=%t: the wrong file type passed", socket)
			}
		}
	})
}

// unitLane2EnvConstant is U-Lane2EnvConstant: a daemon read's environment is
// exactly Lane2Env, which carries no loader, docker or bus override, and the
// worker uses the same slice as the gate's unjailed fallback.
func unitLane2EnvConstant(t *testing.T) {
	filterM1TableCheck(t, "U-Lane2EnvConstant", func(check func(bool)) {
		env := Lane2Env()
		for _, kv := range env {
			key, _, _ := strings.Cut(kv, "=")
			if strings.HasPrefix(key, "LD_") || strings.HasPrefix(key, "DBUS_") || key == "DOCKER_HOST" || key == "DOCKER_CONTEXT" {
				t.Errorf("Lane2Env carries %s", kv)
			}
		}
		want := []string{"PATH=/usr/bin:/bin", "LANG=C", "SYSTEMD_COLORS=0", "TERM=dumb", "TMPDIR=/dev/shm", "DOCKER_CONFIG=" + Lane2NoDockerConfig}
		if !slices.Equal(env, want) {
			t.Errorf("Lane2Env = %q, want %q", env, want)
		}
		check(!slices.Equal(lane2ExecEnv("/"), want))
	})
}
