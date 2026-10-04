package main

import (
	"encoding/binary"
	"fmt"
	"io"
	"strings"

	"golang.org/x/sys/unix"
)

const setter = 0x40085301
const writebackCache = 1 << 16
const maxFileSize = 1024 * 1024

var wire = binary.NativeEndian
var opcodeNames = map[uint32]string{1: "LOOKUP", 2: "FORGET", 3: "GETATTR", 4: "SETATTR", 16: "WRITE", 14: "OPEN", 15: "READ", 17: "STATFS", 18: "RELEASE", 20: "FSYNC", 22: "GETXATTR", 23: "LISTXATTR", 25: "FLUSH", 26: "INIT", 27: "OPENDIR", 28: "READDIR", 29: "RELEASEDIR", 30: "FSYNCDIR", 34: "ACCESS", 36: "INTERRUPT", 38: "DESTROY", 39: "IOCTL", 42: "BATCH_FORGET", 50: "SYNCFS"}

type server struct {
	writeback            bool
	mtime, ctime         uint64
	mtimeNsec, ctimeNsec uint32
	log                  io.Writer
	data                 []byte
	uid, gid             uint32
}

func (s *server) attr(node uint64) []byte {
	b := make([]byte, 88)
	wire.PutUint64(b, node)
	mode := uint32(unix.S_IFREG | 0555)
	if s.writeback {
		mode = unix.S_IFREG | 0755
	}
	size := uint64(len(s.data))
	links := uint32(1)
	if node == 1 || node == 3 {
		mode = unix.S_IFDIR | 0755
		size = 0
		links = 2
	}
	wire.PutUint64(b[8:], size)
	wire.PutUint64(b[16:], (size+511)/512)
	wire.PutUint64(b[32:], s.mtime)
	wire.PutUint64(b[40:], s.ctime)
	wire.PutUint32(b[52:], s.mtimeNsec)
	wire.PutUint32(b[56:], s.ctimeNsec)
	wire.PutUint32(b[60:], mode)
	wire.PutUint32(b[64:], links)
	wire.PutUint32(b[68:], s.uid)
	wire.PutUint32(b[72:], s.gid)
	wire.PutUint32(b[80:], 4096)
	return b
}

// dispatch uses native Linux FUSE framing. A nil response means the opcode has no reply.
func (s *server) dispatch(request []byte) ([]byte, error) {
	if len(request) < 40 || int(wire.Uint32(request)) != len(request) {
		return nil, fmt.Errorf("invalid FUSE request length")
	}
	opcode, node := wire.Uint32(request[4:]), wire.Uint64(request[16:])
	body := request[40:]
	name, ok := opcodeNames[opcode]
	if !ok {
		name = fmt.Sprintf("OPCODE_%d", opcode)
	}
	if _, err := fmt.Fprintln(s.log, name); err != nil {
		return nil, err
	}
	var output []byte
	var errno unix.Errno
	switch opcode {
	case 2, 42:
		return nil, nil
	case 26:
		if len(body) < 16 {
			errno = unix.EINVAL
			break
		}
		major, minor := wire.Uint32(body), wire.Uint32(body[4:])
		if major > 7 {
			output = make([]byte, 8)
			wire.PutUint32(output, 7)
			wire.PutUint32(output[4:], 38)
			break
		}
		if major != 7 || minor < 34 {
			return nil, fmt.Errorf("FUSE protocol %d.%d lacks SYNCFS", major, minor)
		}
		if minor > 38 {
			minor = 38
		}
		output = make([]byte, 64)
		wire.PutUint32(output, 7)
		wire.PutUint32(output[4:], minor)
		wire.PutUint32(output[8:], wire.Uint32(body[8:]))
		if s.writeback {
			if wire.Uint32(body[12:])&writebackCache == 0 {
				return nil, fmt.Errorf("FUSE writeback cache unavailable")
			}
			wire.PutUint32(output[12:], writebackCache)
		}
		wire.PutUint32(output[20:], 128*1024)
		wire.PutUint32(output[24:], 1)
	case 1:
		if node != 1 && node != 3 {
			errno = unix.ENOTDIR
			break
		}
		switch strings.TrimRight(string(body), "\x00") {
		case "f":
			node = 2
		case "nested":
			node = 3
		default:
			errno = unix.ENOENT
		}
		if errno == 0 {
			output = make([]byte, 40)
			wire.PutUint64(output, node)
			wire.PutUint64(output[8:], 1)
			output = append(output, s.attr(node)...)
		}
	case 3:
		if node < 1 || node > 3 {
			errno = unix.ENOENT
			break
		}
		output = append(make([]byte, 16), s.attr(node)...)
	case 14, 27:
		if len(body) < 8 {
			errno = unix.EINVAL
			break
		}
		if opcode == 14 && node != 2 {
			errno = unix.EISDIR
			break
		}
		if opcode == 27 && node == 2 {
			errno = unix.ENOTDIR
			break
		}
		if wire.Uint32(body)&unix.O_ACCMODE != unix.O_RDONLY && !(s.writeback && opcode == 14) {
			errno = unix.EROFS
			break
		}
		output = make([]byte, 16)
		wire.PutUint64(output, node)
		if opcode == 14 && !s.writeback {
			wire.PutUint32(output[8:], 1)
		} // FOPEN_DIRECT_IO ensures every read is observed.
	case 4:
		if !s.writeback || node != 2 {
			errno = unix.EROFS
			break
		}
		if len(body) != 88 {
			errno = unix.EINVAL
			break
		}
		valid := wire.Uint32(body)
		// Writeback flushes mtime/ctime with an optional file handle.
		if valid & ^uint32((1<<5)|(1<<6)|(1<<10)) != 0 {
			errno = unix.EOPNOTSUPP
			break
		}
		if valid&(1<<5) != 0 {
			s.mtime, s.mtimeNsec = wire.Uint64(body[40:]), wire.Uint32(body[60:])
		}
		if valid&(1<<10) != 0 {
			s.ctime, s.ctimeNsec = wire.Uint64(body[48:]), wire.Uint32(body[64:])
		}
		output = append(make([]byte, 16), s.attr(node)...)
	case 16:
		if !s.writeback || node != 2 {
			errno = unix.EROFS
			break
		}
		if len(body) < 40 || uint64(wire.Uint32(body[16:])) != uint64(len(body)-40) {
			errno = unix.EINVAL
			break
		}
		offset, size := wire.Uint64(body[8:]), uint64(wire.Uint32(body[16:]))
		if offset > maxFileSize || size > maxFileSize-offset {
			errno = unix.EFBIG
			break
		}
		end := int(offset + size)
		if end > len(s.data) {
			s.data = append(s.data, make([]byte, end-len(s.data))...)
		}
		copy(s.data[int(offset):end], body[40:])
		output = make([]byte, 8)
		wire.PutUint32(output, uint32(size))
	case 15:
		if len(body) < 24 {
			errno = unix.EINVAL
			break
		}
		offset, size := wire.Uint64(body[8:]), uint64(wire.Uint32(body[16:]))
		if offset < uint64(len(s.data)) {
			end := min(offset+size, uint64(len(s.data)))
			output = s.data[offset:end]
		}
	case 28:
		if len(body) < 24 {
			errno = unix.EINVAL
			break
		}
		offset, limit := wire.Uint64(body[8:]), int(wire.Uint32(body[16:]))
		names := []string{".", "..", "f", "nested"}
		nodes := []uint64{node, 1, 2, 3}
		for i := int(offset); i < len(names) && i >= 0; i++ {
			name := names[i]
			entry := make([]byte, (24+len(name)+7)&^7)
			wire.PutUint64(entry, nodes[i])
			wire.PutUint64(entry[8:], uint64(i+1))
			wire.PutUint32(entry[16:], uint32(len(name)))
			kind := uint32(unix.DT_DIR)
			if name == "f" {
				kind = unix.DT_REG
			}
			wire.PutUint32(entry[20:], kind)
			copy(entry[24:], name)
			if len(output)+len(entry) > limit {
				break
			}
			output = append(output, entry...)
		}
	case 17:
		output = make([]byte, 80)
		wire.PutUint64(output, 1024)
		wire.PutUint64(output[24:], 3)
		wire.PutUint32(output[40:], 4096)
		wire.PutUint32(output[44:], 255)
		wire.PutUint32(output[48:], 4096)
	case 18, 20, 25, 29, 30, 34, 38, 50:
	case 22, 23:
		errno = unix.ENOSYS
	case 39:
		if len(body) != 40 || wire.Uint32(body[12:]) != setter || wire.Uint32(body[24:]) != 8 || wire.Uint32(body[28:]) != 0 || wire.Uint32(body[8:])&2 != 0 {
			errno = unix.ENOTTY
			break
		}
		if _, err := fmt.Fprintf(s.log, "IOCTL %d\n", wire.Uint64(body[32:])); err != nil {
			return nil, err
		}
		output = make([]byte, 16)
	default:
		errno = unix.ENOSYS
	}
	response := make([]byte, 16, len(output)+16)
	wire.PutUint32(response, uint32(16+len(output)))
	wire.PutUint32(response[4:], uint32(-int32(errno)))
	wire.PutUint64(response[8:], wire.Uint64(request[8:]))
	return append(response, output...), nil
}
