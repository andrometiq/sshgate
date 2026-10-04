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
// values (not a Spec) so buildFilter is purely mechanical and a unit test can
// assemble and evaluate every combination.
type filterParams struct {
	allowInet bool
	abi       int
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
	next := fmt.Sprintf("next%d", len(a.ops))
	if jt == "" {
		jt = next
	}
	if jf == "" {
		jf = next
	}
	a.ops = append(a.ops, unix.SockFilter{Code: bpfJMP | op | bpfK, K: k, Jf: 1})
	a.ja(jt)
	a.ja(jf)
	a.mark(next)
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

// buildFilter dispatches only explicitly reviewed syscall rows.
func buildFilter(p filterParams) []unix.SockFilter {
	a := newAsm()
	a.ld(offArch)
	if !jailmut.On("P-SC-ARCH") {
		a.jeq(uint32(unix.AUDIT_ARCH_X86_64), "", "kill")
	}
	a.ld(offNR)
	if !jailmut.On("P-SC-X32") {
		a.jset(0x40000000, "kill", "")
	}
	if !jailmut.On("P-SC-CEILING") {
		a.jgt(uint32(maxKnownSyscall), "enosys", "")
	}

	var allowed []uint32
	actions := make([]string, len(syscallTable))
	for i, row := range syscallTable {
		action := row.action
		if row.name == "PROCESS_MRELEASE" && jailmut.On("P-SC-PROCESS-MRELEASE") {
			action = "allow"
		}
		if action != "allow" && jailmut.On("P-SC-"+row.name) {
			action = "allow"
		}
		if jailmut.On("P-SC-META") && row.why == "metadata" {
			action = "allow"
		}
		if jailmut.On("P-MQ") && row.why == "mqueue" {
			action = "allow"
		}
		actions[i] = action
		if action == "allow" {
			allowed = append(allowed, row.nr)
		}
	}
	for _, kind := range []string{"deny", "enosys", "filter"} {
		for i, row := range syscallTable {
			action := actions[i]
			if action == kind || kind == "filter" && len(action) > 7 && action[:7] == "filter:" {
				a.jeq(row.nr, action, "")
			}
		}
	}
	for i := 0; i < len(allowed); i++ {
		first, last := allowed[i], allowed[i]
		for i+1 < len(allowed) && allowed[i+1] == last+1 {
			i++
			last = allowed[i]
		}
		next := fmt.Sprintf("range%d", first)
		if first > 0 {
			a.jgt(first-1, "", next)
		}
		a.jgt(last, next, "")
		a.ret(uint32(unix.SECCOMP_RET_ALLOW))
		a.mark(next)
	}
	if jailmut.On("P-SC-TOTAL") {
		a.ja("allow")
	} else {
		a.ja("enosys")
	}
	buildArgumentFilters(a, p)
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
