package main

import (
	"encoding/binary"
	"runtime"
	"sync/atomic"
	"unsafe"

	"golang.org/x/sys/unix"
)

// Minimal single-outstanding-operation ring using the stable Linux UAPI layout.
func uringM1Probe(path string, port int) {
	var pins runtime.Pinner
	defer pins.Unpin()
	var params [120]byte
	descriptor, _, errno := unix.Syscall(unix.SYS_IO_URING_SETUP, 2, uintptr(unsafe.Pointer(&params[0])), 0)
	if !report("io_uring_setup", errnoOrNil(errno)) {
		return
	}
	fd := int(descriptor)
	defer unix.Close(fd)
	eventfd, err := unix.Eventfd(0, unix.EFD_CLOEXEC)
	if !report("eventfd", err) {
		return
	}
	defer unix.Close(eventfd)
	event := int32(eventfd)
	_, _, errno = unix.Syscall6(unix.SYS_IO_URING_REGISTER, descriptor, 4, uintptr(unsafe.Pointer(&event)), 1, 0, 0)
	if !report("io_uring_register", errnoOrNil(errno)) {
		return
	}
	read := func(offset int) uint32 { return binary.LittleEndian.Uint32(params[offset:]) }
	sqLength := int(read(64) + read(0)*4)
	cqLength := int(read(100) + read(4)*16)
	if read(20)&1 != 0 {
		sqLength = max(sqLength, cqLength)
	}
	sq, err := unix.Mmap(fd, 0, sqLength, unix.PROT_READ|unix.PROT_WRITE, unix.MAP_SHARED)
	if !report("sq-map", err) {
		return
	}
	defer unix.Munmap(sq)
	cq := sq
	if read(20)&1 == 0 {
		cq, err = unix.Mmap(fd, 0x8000000, cqLength, unix.PROT_READ|unix.PROT_WRITE, unix.MAP_SHARED)
		if !report("cq-map", err) {
			return
		}
		defer unix.Munmap(cq)
	} else {
		report("cq-map", nil)
	}
	entries, err := unix.Mmap(fd, 0x10000000, int(read(0))*64, unix.PROT_READ|unix.PROT_WRITE, unix.MAP_SHARED)
	if !report("sqes-map", err) {
		return
	}
	defer unix.Munmap(entries)
	submit := func(operation string, entry [64]byte) (int32, bool) {
		tail := binary.LittleEndian.Uint32(sq[read(44):])
		mask := binary.LittleEndian.Uint32(sq[read(48):])
		index := tail & mask
		copy(entries[index*64:], entry[:])
		binary.LittleEndian.PutUint32(sq[read(64)+index*4:], index)
		atomic.StoreUint32((*uint32)(unsafe.Pointer(&sq[read(44)])), tail+1)
		_, _, e := unix.Syscall6(unix.SYS_IO_URING_ENTER, descriptor, 1, 1, 1, 0, 0)
		if e != 0 {
			report(operation+"-enter", e)
			return 0, false
		}
		result, err := uringCompletion(cq, read(80), read(84), read(88), read(100), func() unix.Errno {
			_, _, errno := unix.Syscall6(unix.SYS_IO_URING_ENTER, descriptor, 0, 1, 1, 0, 0)
			return errno
		})
		if err != 0 {
			report(operation+"-enter", err)
			return 0, false
		}
		report(operation+"-enter", nil)
		return result, true
	}
	resultErr := func(result int32) error {
		if result < 0 {
			return unix.Errno(-result)
		}
		return nil
	}
	var entry [64]byte
	entry[0] = 45
	binary.LittleEndian.PutUint32(entry[4:], unix.AF_INET)
	binary.LittleEndian.PutUint64(entry[8:], unix.SOCK_STREAM)
	socket, completed := submit("uring-socket", entry)
	if !completed {
		return
	}
	if report("uring-socket", resultErr(socket)) {
		defer unix.Close(int(socket))
		address := unix.RawSockaddrInet4{Family: unix.AF_INET, Addr: [4]byte{127, 0, 0, 1}}
		pins.Pin(&address)
		address.Port = uint16(port>>8) | uint16(port&255)<<8
		entry = [64]byte{}
		entry[0] = 16
		binary.LittleEndian.PutUint32(entry[4:], uint32(socket))
		binary.LittleEndian.PutUint64(entry[8:], 16)
		binary.LittleEndian.PutUint64(entry[16:], uint64(uintptr(unsafe.Pointer(&address))))
		result, completed := submit("uring-connect", entry)
		if !completed {
			return
		}
		report("uring-connect", resultErr(result))
	}
	name := append([]byte("user.sshgate_uring"), 0)
	target := append([]byte(path), 0)
	value := []byte("changed")
	pins.Pin(&name[0])
	pins.Pin(&target[0])
	pins.Pin(&value[0])
	entry = [64]byte{}
	entry[0] = 42
	binary.LittleEndian.PutUint64(entry[8:], uint64(uintptr(unsafe.Pointer(&value[0]))))
	binary.LittleEndian.PutUint64(entry[16:], uint64(uintptr(unsafe.Pointer(&name[0]))))
	binary.LittleEndian.PutUint32(entry[24:], uint32(len(value)))
	binary.LittleEndian.PutUint64(entry[48:], uint64(uintptr(unsafe.Pointer(&target[0]))))
	result, completed := submit("uring-setxattr", entry)
	if !completed {
		return
	}
	report("uring-setxattr", resultErr(result))
}
