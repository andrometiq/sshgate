package main

import (
	"cmp"
	"debug/elf"
	"encoding/binary"
	"errors"
	"io"
	"math"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"syscall"

	"github.com/karthikeyan5/sshgate/src/gate/confine/jailmut"
	"golang.org/x/sys/unix"
)

var lane2TrustedUIDs = []uint32{0}
var lane2SystemEndpoints = map[string][]string{
	"docker":    {"/run/docker.sock"},
	"systemctl": {"/run/dbus/system_bus_socket", "/run/systemd/private"},
}

type lane2Path struct {
	path string
	stat syscall.Stat_t
}

// walkTrustedPath separates resolution errors from trust verdicts: mutation
// may ignore a verdict, but cannot invent the identity of an absent object.
func walkTrustedPath(name string, owners []uint32) (lane2Path, bool, error) {
	if !filepath.IsAbs(name) || filepath.Clean(name) != name {
		return lane2Path{}, false, syscall.EINVAL
	}
	pending := strings.Split(strings.TrimPrefix(name, "/"), "/")
	current, trusted, links := "/", true, 0
	var parent syscall.Stat_t
	if err := syscall.Lstat(current, &parent); err != nil {
		return lane2Path{}, false, err
	}
	trusted = slices.Contains(owners, parent.Uid)
	for len(pending) > 0 {
		part := pending[0]
		pending = pending[1:]
		if part == "" || part == "." {
			continue
		}
		if part == ".." {
			var ancestor syscall.Stat_t
			current = filepath.Dir(current)
			if err := syscall.Lstat(current, &ancestor); err != nil {
				return lane2Path{}, false, err
			}
			trusted = trusted && slices.Contains(owners, parent.Uid) && (parent.Mode&0022 == 0 || parent.Mode&syscall.S_ISVTX != 0 && slices.Contains(owners, ancestor.Uid))
			parent = ancestor
			continue
		}
		next := filepath.Join(current, part)
		var st syscall.Stat_t
		if err := syscall.Lstat(next, &st); err != nil {
			return lane2Path{}, false, err
		}
		owned := slices.Contains(owners, st.Uid)
		trusted = trusted && slices.Contains(owners, parent.Uid) && (parent.Mode&0022 == 0 || parent.Mode&syscall.S_ISVTX != 0 && owned) && owned
		if st.Mode&syscall.S_IFMT == syscall.S_IFLNK {
			links++
			if links > 40 {
				return lane2Path{}, false, syscall.ELOOP
			}
			target, err := os.Readlink(next)
			if err != nil {
				return lane2Path{}, false, err
			}
			if filepath.IsAbs(target) {
				current = "/"
				if err := syscall.Lstat(current, &parent); err != nil {
					return lane2Path{}, false, err
				}
			}
			pending = append(strings.Split(target, "/"), pending...)
			continue
		}
		if len(pending) > 0 && st.Mode&syscall.S_IFMT != syscall.S_IFDIR {
			return lane2Path{}, false, syscall.ENOTDIR
		}
		current, parent = next, st
	}
	trusted = trusted && slices.Contains(owners, parent.Uid) && (parent.Mode&syscall.S_IFMT == syscall.S_IFSOCK || parent.Mode&0022 == 0)
	return lane2Path{current, parent}, trusted, nil
}

func trustedPath(name string, owners []uint32) (lane2Path, error) {
	result, trusted, err := walkTrustedPath(name, owners)
	if err == nil && !trusted {
		err = syscall.EACCES
	}
	return result, err
}

type lane2Execution struct {
	argv   []string
	binary lane2Path
	held   []*os.File
}

func (p *lane2Execution) Close() {
	for _, f := range p.held {
		f.Close()
	}
	p.held = nil
}

func lane2Plan(cmd string, pin pinState) (plan lane2Execution, matched bool, refusal string) {
	call, ok := lane2Parse(cmd)
	if !ok {
		return plan, false, ""
	}
	name := ""
	for _, dir := range lane2BinDirs {
		candidate := filepath.Join(dir, call.client)
		if _, err := os.Lstat(candidate); !errors.Is(err, os.ErrNotExist) {
			name = candidate
			break
		}
	}
	if name == "" {
		return plan, false, ""
	}
	plan.argv = call.render(name)
	var file *os.File
	var err error
	plan.binary, file, refusal, err = lane2Admit(name)
	if file != nil {
		plan.held = append(plan.held, file)
	}
	if err != nil {
		return plan, true, "binary"
	}
	if refusal != "" && !jailmut.On("P-L2-ADMIT") {
		return plan, true, refusal
	}
	return plan, true, ""
}

func lane2Admit(name string) (id lane2Path, file *os.File, refusal string, err error) {
	id, trusted, err := walkTrustedPath(name, lane2TrustedUIDs)
	if err != nil {
		return id, nil, "binary", err
	}
	// NONBLOCK prevents a substituted FIFO or device from blocking admission.
	fd, err := syscall.Open(id.path, syscall.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC|syscall.O_NONBLOCK|syscall.O_NOCTTY, 0)
	if err != nil {
		return id, nil, "binary", err
	}
	file = os.NewFile(uintptr(fd), id.path)
	var st syscall.Stat_t
	if err = syscall.Fstat(fd, &st); err != nil {
		return id, file, "binary", err
	}
	if st.Dev != id.stat.Dev || st.Ino != id.stat.Ino {
		return id, file, "binary", syscall.ESTALE
	}
	id.stat = st
	if !trusted || !slices.Contains(lane2TrustedUIDs, st.Uid) || st.Mode&0022 != 0 || st.Mode&syscall.S_IFMT != syscall.S_IFREG || st.Mode&0111 == 0 || st.Mode&(syscall.S_ISUID|syscall.S_ISGID) != 0 {
		return id, file, "binary", nil
	}
	_, xerr := unix.Fgetxattr(fd, "security.capability", nil)
	if xerr == nil || xerr != unix.ENODATA && xerr != unix.ENOTSUP {
		return id, file, "binary", nil
	}
	executable, eerr := elf.NewFile(file)
	if eerr != nil {
		return id, file, "binary-elf", nil
	}
	if executable.Class != elf.ELFCLASS64 || executable.Data != elf.ELFDATA2LSB || executable.Machine != elf.EM_X86_64 || executable.Type != elf.ET_EXEC && executable.Type != elf.ET_DYN {
		return id, file, "binary-elf", nil
	}
	interps, dynamics := 0, 0
	for _, ph := range executable.Progs {
		if ph.Type == elf.PT_INTERP {
			interps++
		}
		if ph.Type == elf.PT_DYNAMIC {
			dynamics++
		}
	}
	if interps > 1 || dynamics > 1 || !lane2LoadPagesDisjoint(executable) {
		return id, file, "binary-elf", nil
	}
	if !lane2SearchTags(executable) {
		return id, file, "search-tag", nil
	}
	return id, file, "", nil
}

// The loader consumes program headers, not sections, and reads PT_DYNAMIC and
// DT_STRTAB at their virtual addresses. Read both through the PT_LOAD that maps
// them and require an in-bounds terminator.
func lane2SearchTags(executable *elf.File) bool {
	var dynamic *elf.Prog
	for _, ph := range executable.Progs {
		if ph.Type == elf.PT_DYNAMIC {
			dynamic = ph
		}
	}
	if dynamic == nil {
		return true
	}
	if dynamic.Filesz > 16<<20 || dynamic.Filesz%16 != 0 {
		return false
	}
	segment, offset, ok := lane2MappedRegion(executable, dynamic.Vaddr, dynamic.Filesz)
	if !ok {
		return false
	}
	data, err := io.ReadAll(io.NewSectionReader(segment, int64(offset), int64(dynamic.Filesz)))
	if err != nil || uint64(len(data)) != dynamic.Filesz {
		return false
	}
	type entry struct {
		tag   elf.DynTag
		value uint64
	}
	var entries []entry
	var address, size uint64
	haveAddress, haveSize, terminated := false, false, false
	for offset := 0; offset+16 <= len(data); offset += 16 {
		tag, value := elf.DynTag(binary.LittleEndian.Uint64(data[offset:])), binary.LittleEndian.Uint64(data[offset+8:])
		if tag == elf.DT_NULL {
			terminated = true
			break
		}
		switch tag {
		case elf.DT_STRTAB:
			if haveAddress {
				return false
			}
			address, haveAddress = value, true
		case elf.DT_STRSZ:
			if haveSize {
				return false
			}
			size, haveSize = value, true
		case elf.DT_AUDIT, elf.DT_DEPAUDIT:
			return false
		case elf.DT_RPATH, elf.DT_RUNPATH, elf.DT_NEEDED, elf.DT_FILTER, elf.DT_AUXILIARY:
			entries = append(entries, entry{tag, value})
		}
	}
	if !terminated {
		return false
	}
	if len(entries) == 0 {
		return true
	}
	if !haveAddress || !haveSize || size == 0 || size > 16<<20 {
		return false
	}
	segment, offset, ok = lane2MappedRegion(executable, address, size)
	if !ok {
		return false
	}
	table := make([]byte, int(size))
	if _, err := segment.ReadAt(table, int64(offset)); err != nil {
		return false
	}
	seen := map[elf.DynTag]bool{}
	for _, item := range entries {
		if item.value >= uint64(len(table)) {
			return false
		}
		end := slices.Index(table[item.value:], byte(0))
		if end < 0 {
			return false
		}
		value := string(table[item.value : item.value+uint64(end)])
		if strings.ContainsAny(value, "${}") {
			return false
		}
		if item.tag != elf.DT_RPATH && item.tag != elf.DT_RUNPATH {
			if value == "" || strings.Contains(value, "/") {
				return false
			}
			continue
		}
		if seen[item.tag] {
			return false
		}
		seen[item.tag] = true
		for _, directory := range strings.Split(value, ":") {
			if !lane2SearchDirectory(directory) {
				return false
			}
		}
	}
	return true
}

func lane2SearchDirectory(directory string) bool {
	if !filepath.IsAbs(directory) || filepath.Clean(directory) != directory {
		return false
	}
	for {
		result, err := trustedPath(directory, lane2TrustedUIDs)
		if err == nil {
			return result.stat.Mode&syscall.S_IFMT == syscall.S_IFDIR
		}
		if !errors.Is(err, os.ErrNotExist) {
			return false
		}
		// A dangling symlink is not a missing directory a trusted parent can create.
		if _, err := os.Lstat(directory); !errors.Is(err, os.ErrNotExist) {
			return false
		}
		parent := filepath.Dir(directory)
		if parent == directory {
			return false
		}
		directory = parent
	}
}

// The kernel maps each PT_LOAD by whole pages, so a segment that shares a page
// with another can replace bytes the other's range claims. With no shared page,
// every mapped byte is the file byte its one segment names: the view admission
// reads.
func lane2LoadPagesDisjoint(executable *elf.File) bool {
	page := uint64(os.Getpagesize())
	type span struct{ start, end uint64 }
	var spans []span
	for _, segment := range executable.Progs {
		if segment.Type != elf.PT_LOAD {
			continue
		}
		end := segment.Vaddr + segment.Memsz
		if segment.Filesz > segment.Memsz || end < segment.Vaddr || end > math.MaxUint64-page {
			return false
		}
		spans = append(spans, span{segment.Vaddr &^ (page - 1), (end + page - 1) &^ (page - 1)})
	}
	slices.SortFunc(spans, func(a, b span) int { return cmp.Compare(a.start, b.start) })
	for i := 1; i < len(spans); i++ {
		if spans[i].start < spans[i-1].end {
			return false
		}
	}
	return true
}

// lane2MappedRegion returns the PT_LOAD whose file bytes the loader sees at
// [address, address+size), and the region's offset in it.
func lane2MappedRegion(executable *elf.File, address, size uint64) (*elf.Prog, uint64, bool) {
	for _, segment := range executable.Progs {
		if segment.Type == elf.PT_LOAD && address >= segment.Vaddr && address-segment.Vaddr <= segment.Filesz && size <= segment.Filesz-(address-segment.Vaddr) {
			return segment, address - segment.Vaddr, true
		}
	}
	return nil, 0, false
}
