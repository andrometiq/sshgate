//go:build linux

package confine

import (
	"fmt"
	"unsafe"

	"github.com/karthikeyan5/sshgate/src/gate/confine/jailmut"
	"golang.org/x/sys/unix"
)

// Classic-BPF opcode bytes (hand-assembled; no x/net/bpf dependency).
const (
	bpfLD   = 0x00
	bpfW    = 0x00
	bpfABS  = 0x20
	bpfJMP  = 0x05
	bpfJEQ  = 0x10
	bpfJGT  = 0x20
	bpfJSET = 0x40
	bpfJA   = 0x00
	bpfALU  = 0x04
	bpfAND  = 0x50
	bpfRET  = 0x06
	bpfK    = 0x00
)

// seccomp_data field byte offsets (amd64, little-endian: a 32-bit ABS load of a
// u64 arg reads its low word).
const (
	offNR   = 0  // int   nr
	offArch = 4  // u32   arch
	offArg0 = 16 // u64   args[0] -> low word at 16
	offArg1 = 24 // u64   args[1] -> low word at 24
	offArg2 = 32 // u64   args[2] -> low word at 32
)

// filterParams are the only inputs that shape the filter. Kept as explicit
// booleans (not a Spec) so buildFilter is purely mechanical and a unit test can
// assemble and evaluate every combination.
type filterParams struct {
	allowInet        bool
	denyOpenByHandle bool // true only for a root SSH user (pairs with CAP_DAC_READ_SEARCH)
}

// retErrno builds a SECCOMP_RET_ERRNO action carrying errno in the low 16 bits.
func retErrno(e unix.Errno) uint32 {
	return uint32(unix.SECCOMP_RET_ERRNO) | (uint32(e) & uint32(unix.SECCOMP_RET_DATA))
}

// bpfAsm is a tiny forward-jump label assembler for the seccomp program. A jump
// target of "" means "fall through to the next instruction" (relative offset 0).
type bpfAsm struct {
	ops    []unix.SockFilter
	labels map[string]int
	fixups []fixup
}

type fixup struct {
	idx  int
	isJA bool
	jt   string
	jf   string
	ja   string
}

func newAsm() *bpfAsm { return &bpfAsm{labels: map[string]int{}} }

func (a *bpfAsm) mark(label string) { a.labels[label] = len(a.ops) }

func (a *bpfAsm) ld(off uint32) {
	a.ops = append(a.ops, unix.SockFilter{Code: bpfLD | bpfW | bpfABS, K: off})
}

func (a *bpfAsm) and(k uint32) {
	a.ops = append(a.ops, unix.SockFilter{Code: bpfALU | bpfAND | bpfK, K: k})
}

func (a *bpfAsm) cond(op uint16, k uint32, jt, jf string) {
	a.fixups = append(a.fixups, fixup{idx: len(a.ops), jt: jt, jf: jf})
	a.ops = append(a.ops, unix.SockFilter{Code: bpfJMP | op | bpfK, K: k})
}

func (a *bpfAsm) jeq(k uint32, jt, jf string)  { a.cond(bpfJEQ, k, jt, jf) }
func (a *bpfAsm) jgt(k uint32, jt, jf string)  { a.cond(bpfJGT, k, jt, jf) }
func (a *bpfAsm) jset(k uint32, jt, jf string) { a.cond(bpfJSET, k, jt, jf) }

func (a *bpfAsm) ja(target string) {
	a.fixups = append(a.fixups, fixup{idx: len(a.ops), isJA: true, ja: target})
	a.ops = append(a.ops, unix.SockFilter{Code: bpfJMP | bpfJA})
}

func (a *bpfAsm) ret(k uint32) {
	a.ops = append(a.ops, unix.SockFilter{Code: bpfRET | bpfK, K: k})
}

// build resolves every symbolic jump to a relative offset and returns the
// finished program. It panics on an unknown label or an offset that overflows a
// conditional jump's 8-bit field — both are author bugs, caught by the unit test.
func (a *bpfAsm) build() []unix.SockFilter {
	rel := func(label string, from int) int {
		if label == "" {
			return 0 // fall through to the next instruction
		}
		t, ok := a.labels[label]
		if !ok {
			panic("confine: unknown bpf label " + label)
		}
		return t - (from + 1)
	}
	for _, f := range a.fixups {
		if f.isJA {
			off := rel(f.ja, f.idx)
			if off < 0 {
				panic("confine: backward JA to " + f.ja)
			}
			a.ops[f.idx].K = uint32(off)
			continue
		}
		jt := rel(f.jt, f.idx)
		jf := rel(f.jf, f.idx)
		if jt < 0 || jt > 255 || jf < 0 || jf > 255 {
			panic(fmt.Sprintf("confine: jump offset out of range (jt=%d jf=%d)", jt, jf))
		}
		a.ops[f.idx].Jt = uint8(jt)
		a.ops[f.idx].Jf = uint8(jf)
	}
	return a.ops
}

// buildFilter guards the architecture and unknown syscalls, then applies
// syscall denies and argument filters. The remaining known calls are allowed.
func buildFilter(p filterParams) []unix.SockFilter {
	a := newAsm()

	// 1. Arch gate: anything but x86_64 (i386-compat, x32) is killed.
	a.ld(offArch)
	a.jeq(uint32(unix.AUDIT_ARCH_X86_64), "", "kill")

	// 2. x32 guard: the __X32_SYSCALL_BIT distinguishes x32 from amd64.
	a.ld(offNR)
	a.jset(0x40000000, "kill", "")

	// 3. Unknown-high syscall -> ENOSYS (A still holds nr).
	a.jgt(uint32(maxKnownSyscall), "enosys", "")

	// 4. clone3 -> ENOSYS so glibc falls back to the arg-filtered legacy clone.
	a.jeq(uint32(unix.SYS_CLONE3), "enosys", "")

	// Flat denylist (EPERM), plus the conditional metadata/handle entries.
	for _, s := range flatDeny {
		a.jeq(s, "deny", "")
	}
	if !jailmut.On("P-SC-META") {
		for _, s := range metadataDeny {
			a.jeq(s, "deny", "")
		}
	}
	for _, s := range mqueueDeny {
		a.jeq(s, "deny", "")
	}
	if p.denyOpenByHandle {
		a.jeq(uint32(unix.SYS_OPEN_BY_HANDLE_AT), "deny", "")
	}

	// Argument-filtered dispatch.
	a.jeq(uint32(unix.SYS_CLONE), "cloneH", "")
	a.jeq(uint32(unix.SYS_UNSHARE), "unshareH", "")
	a.jeq(uint32(unix.SYS_SETNS), "setnsH", "")
	a.jeq(uint32(unix.SYS_IOCTL), "ioctlH", "")
	a.jeq(uint32(unix.SYS_SOCKET), "socketH", "")
	a.ja("allow")

	// clone: deny if the legacy flags carry any namespace bit.
	a.mark("cloneH")
	a.ld(offArg0)
	a.and(uint32(nsLegacyCloneBits))
	a.jeq(0, "allow", "deny")

	// unshare: deny if arg0 carries any namespace bit.
	a.mark("unshareH")
	a.ld(offArg0)
	a.and(uint32(nsCloneBits))
	a.jeq(0, "allow", "deny")

	// setns: deny if the nstype (arg1) carries any namespace bit.
	a.mark("setnsH")
	a.ld(offArg1)
	a.and(uint32(nsCloneBits))
	a.jeq(0, "allow", "deny")

	// Block terminal injection and generic VFS fileattr setters.
	a.mark("ioctlH")
	a.ld(offArg1)
	a.jeq(uint32(unix.TIOCSTI), "deny", "")
	a.jeq(uint32(unix.TIOCLINUX), "deny", "")
	if !jailmut.On("P-SC-META") {
		for _, r := range fileattrIoctlDeny {
			a.jeq(r, "deny", "")
		}
	}
	a.ja("allow")

	// socket: AF_UNIX/AF_PACKET denied; AF_NETLINK restricted to ROUTE/SOCK_DIAG
	// (so ss/ip keep working); AF_INET/AF_INET6 follow the inet policy.
	a.mark("socketH")
	a.ld(offArg0)
	a.jeq(uint32(unix.AF_UNIX), "deny", "")
	a.jeq(uint32(unix.AF_PACKET), "deny", "")
	a.jeq(uint32(unix.AF_NETLINK), "netlinkH", "")
	if !p.allowInet {
		a.jeq(uint32(unix.AF_INET), "deny", "")
		a.jeq(uint32(unix.AF_INET6), "deny", "")
	}
	a.ja("allow")

	a.mark("netlinkH")
	a.ld(offArg2)
	a.jeq(uint32(unix.NETLINK_ROUTE), "allow", "")
	a.jeq(uint32(unix.NETLINK_SOCK_DIAG), "allow", "")
	a.ja("deny")

	// Terminal actions.
	a.mark("allow")
	a.ret(uint32(unix.SECCOMP_RET_ALLOW))
	a.mark("deny")
	a.ret(retErrno(unix.EPERM))
	a.mark("enosys")
	a.ret(retErrno(unix.ENOSYS))
	a.mark("kill")
	a.ret(uint32(unix.SECCOMP_RET_KILL_PROCESS))

	return a.build()
}

// installSeccomp loads the filter on the calling (locked) thread. NNP must
// already be set. It treats ANY non-zero return as fatal: with TSYNC the syscall
// does NOT report a partial-sync failure through errno — on success it returns 0,
// but if a thread cannot synchronise it returns the positive offending thread id
// with errno 0. A naive errno-only check would execve with an incomplete filter.
func installSeccomp(filter []unix.SockFilter, spec Spec) error {
	if len(filter) == 0 {
		return fmt.Errorf("confine: empty seccomp filter")
	}
	prog := unix.SockFprog{Len: uint16(len(filter)), Filter: &filter[0]}
	r1, _, errno := unix.Syscall(uintptr(unix.SYS_SECCOMP),
		uintptr(unix.SECCOMP_SET_MODE_FILTER),
		uintptr(unix.SECCOMP_FILTER_FLAG_TSYNC),
		uintptr(unsafe.Pointer(&prog)))
	if stage, injected := spec.inject(); stage == "seccomp" {
		errno = injected
	}
	if !jailmut.On("P-FAULT-seccomp") && errno != 0 {
		return errno
	}
	if stage, _ := spec.inject(); stage == "tsync" {
		r1 = 4242
	}
	if !jailmut.On("P-SC-TSYNC") && r1 != 0 {
		return &SetupError{Stage: "tsync", Errno: unix.EIO}
	}
	return nil
}
