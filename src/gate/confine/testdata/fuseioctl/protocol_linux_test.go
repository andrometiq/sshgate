package main

import (
	"bytes"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

func request(opcode uint32, node uint64, body []byte) []byte {
	b := make([]byte, 40)
	wire.PutUint32(b, uint32(len(b)+len(body)))
	wire.PutUint32(b[4:], opcode)
	wire.PutUint64(b[8:], 71)
	wire.PutUint64(b[16:], node)
	return append(b, body...)
}
func TestProtocol(t *testing.T) {
	var log bytes.Buffer
	s := server{log: &log, data: []byte("fixture\n"), uid: 1000, gid: 1000}
	init := make([]byte, 16)
	wire.PutUint32(init, 7)
	wire.PutUint32(init[4:], 38)
	response, err := s.dispatch(request(26, 0, init))
	if err != nil {
		t.Fatal(err)
	}
	if wire.Uint32(response[20:]) < 34 {
		t.Fatal("SYNCFS not negotiated")
	}
	response, err = s.dispatch(request(1, 1, []byte("f\x00")))
	if err != nil {
		t.Fatal(err)
	}
	if wire.Uint64(response[16:]) != 2 || !bytes.Equal(response[32:56], make([]byte, 24)) {
		t.Fatal("lookup must have zero cache timeouts")
	}
	if wire.Uint32(response[116:]) != unix.S_IFREG|0555 {
		t.Fatal("regular executable fixture attributes")
	}
	response, err = s.dispatch(request(14, 2, make([]byte, 8)))
	if err != nil {
		t.Fatal(err)
	}
	if wire.Uint32(response[24:]) != 1 {
		t.Fatal("reads must bypass page cache")
	}
	read := make([]byte, 40)
	wire.PutUint32(read[16:], 3)
	response, err = s.dispatch(request(15, 2, read))
	if err != nil || string(response[16:]) != "fix" {
		t.Fatalf("read %q: %v", response, err)
	}
	ioctl := make([]byte, 40)
	wire.PutUint32(ioctl[12:], setter)
	wire.PutUint32(ioctl[24:], 8)
	wire.PutUint64(ioctl[32:], 123)
	response, err = s.dispatch(request(39, 2, ioctl))
	if err != nil || wire.Uint32(response[4:]) != 0 {
		t.Fatalf("ioctl: %v %v", response, err)
	}
	if _, err = s.dispatch(request(50, 1, make([]byte, 8))); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"INIT\n", "LOOKUP\n", "OPEN\n", "READ\n", "IOCTL 123\n", "SYNCFS\n"} {
		if !strings.Contains(log.String(), want) {
			t.Errorf("missing log %q", want)
		}
	}
	wire.PutUint32(ioctl[12:], setter+1)
	response, err = s.dispatch(request(39, 2, ioctl))
	if err != nil || int32(wire.Uint32(response[4:])) != -int32(unix.ENOTTY) {
		t.Fatal("unknown setter accepted")
	}
}
func TestRejectMalformedAndOldProtocol(t *testing.T) {
	s := server{log: &bytes.Buffer{}}
	if _, err := s.dispatch([]byte{1}); err == nil {
		t.Fatal("short header accepted")
	}
	init := make([]byte, 16)
	wire.PutUint32(init, 7)
	wire.PutUint32(init[4:], 33)
	if _, err := s.dispatch(request(26, 0, init)); err == nil {
		t.Fatal("protocol without SYNCFS accepted")
	}
}
func TestNoReplyOpcodes(t *testing.T) {
	s := server{log: &bytes.Buffer{}}
	for _, opcode := range []uint32{2, 42} {
		response, err := s.dispatch(request(opcode, 1, nil))
		if err != nil || response != nil {
			t.Errorf("opcode %d returned a reply", opcode)
		}
	}
}

func TestProtocolWriteback(t *testing.T) {
	var log bytes.Buffer
	s := server{log: &log, data: []byte("fixture\n"), writeback: true}
	call := func(op uint32, body []byte, errno unix.Errno) []byte {
		t.Helper()
		response, err := s.dispatch(request(op, 2, body))
		if err != nil || int32(wire.Uint32(response[4:])) != -int32(errno) {
			t.Fatalf("opcode %d: response=%v err=%v", op, response, err)
		}
		return response[16:]
	}
	init := make([]byte, 16)
	wire.PutUint32(init, 7)
	wire.PutUint32(init[4:], 38)
	if _, err := s.dispatch(request(26, 0, init)); err == nil {
		t.Fatal("accepted writeback without kernel support")
	}
	wire.PutUint32(init[12:], writebackCache)
	if flags := wire.Uint32(call(26, init, 0)[12:]); flags != writebackCache {
		t.Fatalf("INIT flags: %#x", flags)
	}
	open := make([]byte, 8)
	wire.PutUint32(open, unix.O_WRONLY)
	if flags := wire.Uint32(call(14, open, 0)[8:]); flags != 0 {
		t.Fatalf("writeback OPEN flags: %#x", flags)
	}
	write := make([]byte, 43)
	wire.PutUint64(write[8:], 2)
	wire.PutUint32(write[16:], 3)
	copy(write[40:], "NEW")
	if size := wire.Uint32(call(16, write, 0)); size != 3 {
		t.Fatalf("WRITE size: %d", size)
	}
	read := make([]byte, 40)
	wire.PutUint32(read[16:], 100)
	if got := string(call(15, read, 0)); got != "fiNEWre\n" {
		t.Fatalf("readback: %q", got)
	}
	wire.PutUint64(write[8:], 10)
	call(16, write, 0)
	if !bytes.Equal(s.data[8:], []byte{0, 0, 'N', 'E', 'W'}) {
		t.Fatalf("extended data: %q", s.data)
	}
	call(16, write[:39], unix.EINVAL)
	call(16, write[:42], unix.EINVAL)
	wire.PutUint64(write[8:], ^uint64(0))
	call(16, write, unix.EFBIG)
	attr := make([]byte, 88)
	wire.PutUint32(attr, (1<<5)|(1<<6)|(1<<10))
	wire.PutUint64(attr[40:], 123)
	wire.PutUint64(attr[48:], 456)
	wire.PutUint32(attr[60:], 789)
	wire.PutUint32(attr[64:], 321)
	got := call(4, attr, 0)[16:]
	if wire.Uint64(got[8:]) != 13 || wire.Uint64(got[32:]) != 123 || wire.Uint64(got[40:]) != 456 || wire.Uint32(got[52:]) != 789 || wire.Uint32(got[56:]) != 321 {
		t.Fatalf("SETATTR response: %v", got)
	}
	call(4, attr[:87], unix.EINVAL)
	wire.PutUint32(attr, 1<<3)
	call(4, attr, unix.EOPNOTSUPP)
	for _, name := range []string{"WRITE\n", "SETATTR\n"} {
		if !strings.Contains(log.String(), name) {
			t.Errorf("missing request log %q", name)
		}
	}
	s.writeback = false
	call(14, open, unix.EROFS)
	call(16, write, unix.EROFS)
	call(4, attr, unix.EROFS)
}
