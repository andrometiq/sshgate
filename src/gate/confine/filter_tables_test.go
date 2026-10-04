//go:build linux

package confine

import (
	"golang.org/x/sys/unix"
	"testing"
)

func filterTableCheck(t *testing.T, leg string, checks func(func(bool))) {
	t.Helper()
	failed := false
	checks(func(b bool) { failed = failed || b })
	mutationEffect(t, leg, "decision", failed)
}

func filterM1TableCheck(t *testing.T, leg string, checks func(func(bool))) {
	t.Helper()
	p := newProof(t, leg)
	filterTableCheck(t, leg, checks)
	p.Control("decision", ControlResult{Valid: !t.Failed(), Detail: "independent filter decision table evaluated"})
	p.Finish()
}

func TestFilterTables(t *testing.T) {
	for _, abi := range []string{"native", "abi1"} {
		t.Run(abi, func(t *testing.T) {
			t.Run("U-CloneIPC", func(t *testing.T) {
				p := newProof(t, "U-CloneIPC")
				mutationEffect(t, "U-CloneIPC", "decision", cloneSysProcAttr().Cloneflags&unix.CLONE_NEWIPC == 0)
				p.Control("decision", ControlResult{Valid: !t.Failed(), Detail: "independent clone IPC flag checked"})
				p.Finish()
			})

			t.Run("U-FcntlCommandTable", func(t *testing.T) {
				filterM1TableCheck(t, "U-FcntlCommandTable", func(check func(bool)) {
					allowed := map[int]bool{}
					for _, n := range []int{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 16, 36, 37, 38, 1027, 1028, 1030, 1032, 1033, 1034, 1035, 1037} {
						allowed[n] = true
					}
					f := buildFilter(filterParams{})
					for n := 0; n <= 1100; n++ {
						if n > 64 && n < 1024 {
							continue
						}
						want := actDeny
						if allowed[n] {
							want = actAllow
						}
						check(evalFilter(t, f, dataFor(unix.SYS_FCNTL, x8664, 0, uint64(n))) != want)
					}
					for _, n := range []uint64{0xffffffff, 0x100000001} {
						want := actDeny
						if n == 0x100000001 {
							want = actAllow
						}
						check(evalFilter(t, f, dataFor(unix.SYS_FCNTL, x8664, 0, n)) != want)
					}
				})
			})
			t.Run("U-FlockOpTable", func(t *testing.T) {
				filterM1TableCheck(t, "U-FlockOpTable", func(check func(bool)) {
					f := buildFilter(filterParams{})
					for n := 0; n < 256; n++ {
						want := actDeny
						if n == 1 || n == 5 || n == 8 || n == 12 {
							want = actAllow
						}
						check(evalFilter(t, f, dataFor(unix.SYS_FLOCK, x8664, 0, uint64(n))) != want)
					}
				})
			})
			t.Run("U-RlimitFilterTable", func(t *testing.T) {
				filterM1TableCheck(t, "U-RlimitFilterTable", func(check func(bool)) {
					f := buildFilter(filterParams{})
					for resource := uint64(0); resource < 32; resource++ {
						want := actAllow
						if resource == 4 || resource > 15 {
							want = actDeny
						}
						check(evalFilter(t, f, dataFor(unix.SYS_SETRLIMIT, x8664, resource, 1)) != want)
						for _, ptr := range []uint64{0, 1, 1 << 32, (1 << 32) | 1} {
							expected := want
							if ptr == 0 {
								expected = actAllow
							}
							check(evalFilter(t, f, dataFor(unix.SYS_PRLIMIT64, x8664, 0, resource, ptr)) != expected)
						}
					}
				})
			})
			t.Run("U-CloneMaskTable", func(t *testing.T) {
				filterM1TableCheck(t, "U-CloneMaskTable", func(check func(bool)) {
					f := buildFilter(filterParams{})
					const allowed uint32 = 0x81ffffff &^ 0x00020000 // literal legacy clone bits plus CLONE_IO
					for bit := uint(0); bit < 32; bit++ {
						want := actDeny
						if (uint32(1)<<bit)&allowed != 0 {
							want = actAllow
						}
						check(evalFilter(t, f, dataFor(unix.SYS_CLONE, x8664, 1<<bit)) != want)
					}
				})
			})
			t.Run("U-UnshareMaskTable", func(t *testing.T) {
				filterM1TableCheck(t, "U-UnshareMaskTable", func(check func(bool)) {
					f := buildFilter(filterParams{})
					for bit := uint(0); bit < 64; bit++ {
						want := actDeny
						if bit == 9 || bit == 10 || bit == 18 {
							want = actAllow
						}
						check(evalFilter(t, f, dataFor(unix.SYS_UNSHARE, x8664, 1<<bit)) != want)
					}
				})
			})
			t.Run("U-SocketTupleTable", func(t *testing.T) {
				filterM1TableCheck(t, "U-SocketTupleTable", func(check func(bool)) {
					protocols := []uint64{}
					for p := uint64(0); p <= 31; p++ {
						protocols = append(protocols, p)
					}
					protocols = append(protocols, 58, 115, 132, 136, 255, 256, 262)
					for _, net := range []bool{false, true} {
						f := buildFilter(filterParams{allowInet: net})
						for domain := uint64(0); domain < 64; domain++ {
							for kind := uint64(1); kind <= 10; kind++ {
								for _, protocol := range protocols {
									allow := domain == 16 && (kind == 2 || kind == 3) && protocol == 0
									if net && (domain == 2 || domain == 10) {
										allow = allow || kind == 1 && (protocol == 0 || protocol == 6) || kind == 2 && (protocol == 0 || protocol == 17 || domain == 2 && protocol == 1 || domain == 10 && protocol == 58)
									}
									want := actDeny
									if allow {
										want = actAllow
									}
									for _, flags := range []uint64{0, 0x80000, 0x800, 0x80800} {
										got := evalFilter(t, f, dataFor(unix.SYS_SOCKET, x8664, domain, kind|flags, protocol))
										check(got != want)
									}
								}
							}
						}
					}
				})
			})
			t.Run("U-SocketpairTable", func(t *testing.T) {
				filterM1TableCheck(t, "U-SocketpairTable", func(check func(bool)) {
					f := buildFilter(filterParams{})
					for domain := uint64(0); domain < 64; domain++ {
						for kind := uint64(0); kind <= 10; kind++ {
							want := actDeny
							if domain == 1 && (kind == 1 || kind == 5) {
								want = actAllow
							}
							for _, flags := range []uint64{0, 0x80000, 0x800, 0x80800} {
								check(evalFilter(t, f, dataFor(unix.SYS_SOCKETPAIR, x8664, domain, kind|flags)) != want)
							}
						}
					}
				})
			})
			t.Run("U-IoctlBlocksLiteral", func(t *testing.T) {
				filterM1TableCheck(t, "U-IoctlBlocksLiteral", func(check func(bool)) {
					f := buildFilter(filterParams{})
					for _, req := range []uint64{0x5412, 0x541c, 0xc0506617, 0xc0406618, 0xc0406619, 0x40086602, 0x40046602, 0x401c5820, 0x9408, 0x80089418, 0x40089416} {
						for _, high := range []uint64{0, 0xffffffff00000000} {
							check(evalFilter(t, f, dataFor(unix.SYS_IOCTL, x8664, 3, req|high)) != actDeny)
						}
					}
					for _, req := range []uint64{0x5401, 0x5413, 0x541b, 0x80086601, 0xc020660b} {
						check(evalFilter(t, f, dataFor(unix.SYS_IOCTL, x8664, 3, req)) != actAllow)
					}
				})
			})
			t.Run("U-RulesetAttrScoped", func(t *testing.T) {
				filterM1TableCheck(t, "U-RulesetAttrScoped", func(check func(bool)) {
					for abi := 1; abi <= 10; abi++ {
						want := uint64(0)
						if abi >= 6 {
							want = 3
						}
						check(landlockRuleset(abi).Scoped != want)
					}
				})
			})
			t.Run("U-HandledByABI", func(t *testing.T) {
				filterM1TableCheck(t, "U-HandledByABI", func(check func(bool)) {
					for abi := 1; abi <= 10; abi++ {
						want := uint64((1 << 13) - 1)
						if abi >= 2 {
							want |= 1 << 13
						}
						if abi >= 3 {
							want |= 1 << 14
						}
						if abi >= 5 {
							want |= 1 << 15
						}
						if abi >= 9 {
							want |= 1 << 16
						}
						check(handledFS(abi) != want)
						check(writeRights(abi)&((1<<13)|(1<<16)) != 0)
					}
				})
			})
			t.Run("U-Architecture", func(t *testing.T) {
				filterM1TableCheck(t, "U-Architecture", func(check func(bool)) { check(evalFilter(t, buildFilter(filterParams{}), dataFor(0, 0)) != actKill) })
			})
			t.Run("U-X32", func(t *testing.T) {
				filterM1TableCheck(t, "U-X32", func(check func(bool)) {
					check(evalFilter(t, buildFilter(filterParams{}), dataFor(0x40000000, x8664)) != actKill)
				})
			})
			t.Run("U-UnknownSyscall", func(t *testing.T) {
				filterM1TableCheck(t, "U-UnknownSyscall", func(check func(bool)) {
					check(evalFilter(t, buildFilter(filterParams{}), dataFor(337, x8664)) != actEnosys)
				})
			})
			t.Run("U-SyscallCeiling", func(t *testing.T) {
				filterM1TableCheck(t, "U-SyscallCeiling", func(check func(bool)) {
					check(evalFilter(t, buildFilter(filterParams{}), dataFor(472, x8664)) != actEnosys)
				})
			})
		})
	}
}

func checkSyscallRow(t *testing.T, name string, nr uint32, action uint32, args ...uint64) {
	t.Helper()
	got := evalFilter(t, buildFilter(filterParams{}), dataFor(nr, x8664, args...))
	if got != action {
		t.Logf("syscall=%s got %#x want %#x", name, got, action)
	}
	mutationEffect(t, "U-SC-"+name, "decision", got != action)
}
