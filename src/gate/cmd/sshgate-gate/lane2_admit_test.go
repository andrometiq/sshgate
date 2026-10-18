//go:build linux

package main

import (
	"bytes"
	"context"
	"debug/elf"
	"encoding/binary"
	"encoding/json"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"

	"github.com/karthikeyan5/sshgate/src/gate"
	"github.com/karthikeyan5/sshgate/src/gate/confine"
	"github.com/karthikeyan5/sshgate/src/gate/confine/jailmut"
	"golang.org/x/sys/unix"
)

func lane2Write(t *testing.T, path string, data []byte, mode os.FileMode) {
	t.Helper()
	if err := os.WriteFile(path, data, mode); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, mode); err != nil {
		t.Fatal(err)
	}
}

func lane2BuildSearch(t *testing.T, dir, search string, rpath bool) string {
	t.Helper()
	library := filepath.Join(dir, "lib")
	if err := os.MkdirAll(library, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(library, 0755); err != nil {
		t.Fatal(err)
	}
	nonce := lane2Mode(t, "library")
	args := []string{"-shared", "-fPIC", "-Wall", "-Werror", `-DNONCE="` + nonce + `"`, "-o", filepath.Join(library, "libsg.so"), "testdata/lane2client/libsg.c"}
	if out, err := exec.Command("cc", args...).CombinedOutput(); err != nil {
		t.Fatalf("cc: %v: %s", err, out)
	}
	tags := "--enable-new-dtags"
	if rpath {
		tags = "--disable-new-dtags"
	}
	args = []string{"-O2", "-Wall", "-Werror", "-o", filepath.Join(dir, "systemctl"), "testdata/lane2client/main.c", "-L" + library, "-Wl,--no-as-needed", "-lsg", "-Wl," + tags + ",-rpath," + search}
	if out, err := exec.Command("cc", args...).CombinedOutput(); err != nil {
		t.Fatalf("cc: %v: %s", err, out)
	}
	return nonce
}

// lane2PatchDynamic changes the loader's table without consulting sections.
func lane2PatchDynamic(t *testing.T, data []byte, patch func([]byte)) {
	t.Helper()
	phoff := binary.LittleEndian.Uint64(data[32:])
	phsize, phnum := binary.LittleEndian.Uint16(data[54:]), binary.LittleEndian.Uint16(data[56:])
	for i := uint16(0); i < phnum; i++ {
		ph := data[phoff+uint64(i)*uint64(phsize):]
		if elf.ProgType(binary.LittleEndian.Uint32(ph)) == elf.PT_DYNAMIC {
			offset, size := binary.LittleEndian.Uint64(ph[8:]), binary.LittleEndian.Uint64(ph[32:])
			patch(data[offset : offset+size])
			return
		}
	}
	t.Fatal("no dynamic table")
}

func lane2AdmissionRows(t *testing.T, verdict func(name string, accepted bool)) {
	t.Helper()
	dir := buildLane2Fixtures(t)
	for _, name := range []string{"systemctl", "docker"} {
		if path, err := exec.LookPath(name); err == nil {
			_, file, _, refusal, err := lane2Admit(path)
			if file != nil {
				file.Close()
			}
			if err != nil || refusal != "" {
				t.Fatalf("installed %s: refusal=%s err=%v", path, refusal, err)
			}
		}
	}
	original, err := os.ReadFile(filepath.Join(dir, "systemctl"))
	if err != nil {
		t.Fatal(err)
	}
	check := func(t *testing.T, name string, allowed, resolvable bool) {
		t.Helper()
		plan, matched, refusal := lane2Plan("systemctl status test.service", pinState{})
		defer plan.Close()
		if !matched {
			t.Fatalf("%s: present name did not match", name)
		}
		if refusal == "" {
			var outside syscall.Stat_t
			if err := syscall.Stat(plan.binary.path, &outside); err != nil {
				t.Fatal(err)
			}
			if plan.binary.stat.Dev == 0 || plan.binary.stat.Ino == 0 || outside.Dev != plan.binary.stat.Dev || outside.Ino != plan.binary.stat.Ino {
				t.Fatalf("%s: invalid admitted identity", name)
			}
		}
		if allowed {
			if refusal != "" {
				t.Fatalf("%s: unexpected refusal %s", name, refusal)
			}
			return
		}
		if !resolvable {
			if refusal == "" {
				t.Fatalf("%s: resolution failure admitted", name)
			}
			return
		}
		if jailmut.On("P-L2-ADMIT") && refusal != "" {
			t.Fatalf("%s: resolvable verdict not bypassed: %s", name, refusal)
		}

		verdict(name, refusal == "")
	}
	for _, tag := range []bool{false, true} {
		for _, value := range []string{dir, "relative", "", dir + ":", "$ORIGIN/lib", "${ORIGIN}/lib", "$LIB", "$PLATFORM", filepath.Join(dir, "missing", "child")} {
			name := "runpath-" + value
			if tag {
				name = "rpath-" + value
			}
			t.Run(name, func(t *testing.T) {
				lane2BuildSearch(t, dir, value, tag)
				check(t, name, value == dir || value == filepath.Join(dir, "missing", "child"), true)
			})
		}
	}
	for _, shape := range []string{"writable", "untrusted"} {
		t.Run("search-"+shape, func(t *testing.T) {
			search := filepath.Join(dir, "search-"+shape)
			if err := os.Mkdir(search, 0755); err != nil {
				t.Fatal(err)
			}
			old := lane2TrustedUIDs
			t.Cleanup(func() { lane2TrustedUIDs = old })
			if shape == "writable" {
				if err := os.Chmod(search, 0775); err != nil {
					t.Fatal(err)
				}
			} else {
				lane2Untrust(t, search)
			}
			if lane2SearchDirectory(search) {
				t.Fatal("untrusted search directory accepted")
			}
			if lane2SearchDirectory(filepath.Join(search, "missing")) {
				t.Fatal("missing search under untrusted directory accepted")
			}
			lane2BuildSearch(t, dir, search, false)
			if shape == "writable" {
				_, f, _, reason, err := lane2Admit(filepath.Join(dir, "systemctl"))
				if f != nil {
					f.Close()
				}
				if err != nil || reason != "search-tag" {
					t.Fatalf("search refusal=%s err=%v", reason, err)
				}
			}
			check(t, shape, false, true)
			lane2BuildSearch(t, dir, filepath.Join(search, "missing"), false)
			check(t, shape+"-missing", false, true)
		})
	}
	lane2BuildSearch(t, dir, dir, false)
	baseline, err := os.ReadFile(filepath.Join(dir, "systemctl"))
	if err != nil {
		t.Fatal(err)
	}
	for _, item := range []struct {
		name    string
		tag     elf.DynTag
		text    string
		allowed bool
	}{
		{"duplicate-runpath", elf.DT_RUNPATH, "", false}, {"both-search-tags", elf.DT_RPATH, "", true},
		{"audit", elf.DT_AUDIT, "", false}, {"depaudit", elf.DT_DEPAUDIT, "", false},
		{"needed-path", elf.DT_NEEDED, "/tmp/evil.so", false}, {"needed-token", elf.DT_NEEDED, "$LIB/evil", false},
		{"filter-path", elf.DT_FILTER, "/tmp/evil.so", false}, {"filter-token", elf.DT_FILTER, "${LIB}", false},
		{"aux-path", elf.DT_AUXILIARY, "/tmp/evil.so", false}, {"aux-token", elf.DT_AUXILIARY, "$PLATFORM", false},
	} {
		t.Run(item.name, func(t *testing.T) {
			data := append([]byte(nil), baseline...)
			lane2PatchDynamic(t, data, func(dynamic []byte) {
				var search uint64
				for i := 0; i+16 <= len(dynamic); i += 16 {
					if elf.DynTag(binary.LittleEndian.Uint64(dynamic[i:])) == elf.DT_RUNPATH {
						search = binary.LittleEndian.Uint64(dynamic[i+8:])
						if item.text != "" {
							binary.LittleEndian.PutUint64(dynamic[i:], uint64(item.tag))
						}
					}
				}
				if item.text == "" {
					for i := 0; i+32 <= len(dynamic); i += 16 {
						if binary.LittleEndian.Uint64(dynamic[i:]) == 0 {
							binary.LittleEndian.PutUint64(dynamic[i:], uint64(item.tag))
							binary.LittleEndian.PutUint64(dynamic[i+8:], search)
							break
						}
					}
				}
			})
			if item.text != "" {
				index := strings.Index(string(data), dir+"\x00")
				if index < 0 || len(item.text) > len(dir) {
					t.Fatal("string patch missing")
				}
				copy(data[index:], item.text+"\x00")
			}
			lane2Write(t, filepath.Join(dir, "systemctl"), data, 0755)
			check(t, item.name, item.allowed, true)
		})
	}
	for _, shape := range []string{"sections-removed", "sections-removed-forbidden", "sections-disagree", "script", "elf32", "big-endian", "duplicate-interp", "duplicate-dynamic", "unterminated-dynamic", "bad-strtab", "dynamic-offset-decoy", "overlapping-load", "load-page-shared", "aarch64", "rel", "setuid", "setgid", "no-exec", "dangling", "loop", "open-failure", "fifo", "unreadable", "writable-dir", "dir-link", "dir-link-untrusted", "sticky-child", "symlink-dotdot", "capability"} {
		if shape == "capability" && os.Geteuid() != 0 {
			continue
		}
		t.Run(shape, func(t *testing.T) {
			sub, err := os.MkdirTemp("", "l2-row-")
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { os.RemoveAll(sub) })
			if err := os.Chmod(sub, 0755); err != nil {
				t.Fatal(err)
			}
			oldDirs, oldUIDs := lane2BinDirs, lane2TrustedUIDs
			lane2BinDirs = []string{sub}
			t.Cleanup(func() { lane2BinDirs, lane2TrustedUIDs = oldDirs, oldUIDs })
			data := append([]byte(nil), original...)
			mode := os.FileMode(0755)
			allowed, resolvable := false, true
			switch shape {
			case "sections-removed", "sections-removed-forbidden":
				data = append([]byte(nil), baseline...)
				binary.LittleEndian.PutUint64(data[40:], 0)
				binary.LittleEndian.PutUint16(data[60:], 0)
				binary.LittleEndian.PutUint16(data[62:], 0)
				allowed = shape == "sections-removed"
				if !allowed {
					index := strings.Index(string(data), dir+"\x00")
					copy(data[index:], "$ORIGIN\x00")
				}
			case "sections-disagree":
				data = append([]byte(nil), baseline...)
				// Hide SHT_DYNAMIC while leaving the loader's forbidden RUNPATH intact.
				shoff := binary.LittleEndian.Uint64(data[40:])
				shsize, shnum := binary.LittleEndian.Uint16(data[58:]), binary.LittleEndian.Uint16(data[60:])
				for i := uint16(0); i < shnum; i++ {
					sh := data[shoff+uint64(i)*uint64(shsize):]
					if elf.SectionType(binary.LittleEndian.Uint32(sh[4:])) == elf.SHT_DYNAMIC {
						binary.LittleEndian.PutUint32(sh[4:], uint32(elf.SHT_PROGBITS))
					}
				}
				index := strings.Index(string(data), dir+"\x00")
				copy(data[index:], "$ORIGIN\x00")
			case "script":
				data = []byte("#!/bin/sh\necho UNSAFE\n")
			case "elf32":
				data[4] = byte(elf.ELFCLASS32)
			case "big-endian":
				data[5] = byte(elf.ELFDATA2MSB)
			case "duplicate-interp", "duplicate-dynamic":
				phoff := binary.LittleEndian.Uint64(data[32:])
				phsize, phnum := binary.LittleEndian.Uint16(data[54:]), binary.LittleEndian.Uint16(data[56:])
				target := elf.PT_INTERP
				if shape == "duplicate-dynamic" {
					target = elf.PT_DYNAMIC
				}
				patched := false
				for i := uint16(0); i < phnum; i++ {
					ph := data[phoff+uint64(i)*uint64(phsize):]
					if elf.ProgType(binary.LittleEndian.Uint32(ph)) == elf.PT_NOTE {
						binary.LittleEndian.PutUint32(ph, uint32(target))
						patched = true
						break
					}
				}
				if !patched {
					t.Fatal("fixture has no note header")
				}
			case "dynamic-offset-decoy", "overlapping-load":
				// p_offset is ignored: the loader's view of this client is the clean table.
				allowed = shape == "dynamic-offset-decoy"
				phoff := binary.LittleEndian.Uint64(data[32:])
				phsize, phnum := binary.LittleEndian.Uint16(data[54:]), binary.LittleEndian.Uint16(data[56:])
				var load []byte
				for i := uint16(0); i < phnum; i++ {
					ph := data[phoff+uint64(i)*uint64(phsize):]
					if elf.ProgType(binary.LittleEndian.Uint32(ph)) == elf.PT_LOAD {
						load = append([]byte(nil), ph[:phsize]...)
					}
				}
				patched := false
				for i := uint16(0); i < phnum; i++ {
					ph := data[phoff+uint64(i)*uint64(phsize):]
					kind := elf.ProgType(binary.LittleEndian.Uint32(ph))
					if shape == "dynamic-offset-decoy" && kind == elf.PT_DYNAMIC {
						size := binary.LittleEndian.Uint64(ph[32:])
						binary.LittleEndian.PutUint64(ph[8:], uint64(len(data)))
						data = append(data, make([]byte, size)...)
						patched = true
						break
					}
					if shape == "overlapping-load" && kind == elf.PT_NOTE {
						copy(ph, load)
						patched = true
						break
					}
				}
				if !patched {
					t.Fatal("fixture header not patched")
				}
			case "unterminated-dynamic", "bad-strtab":
				lane2PatchDynamic(t, data, func(dynamic []byte) {
					for i := 0; i+16 <= len(dynamic); i += 16 {
						tag := elf.DynTag(binary.LittleEndian.Uint64(dynamic[i:]))
						if shape == "unterminated-dynamic" && tag == elf.DT_NULL {
							binary.LittleEndian.PutUint64(dynamic[i:], uint64(elf.DT_DEBUG))
						}
						if shape == "bad-strtab" && tag == elf.DT_STRTAB {
							binary.LittleEndian.PutUint64(dynamic[i+8:], ^uint64(0))
						}
					}
				})
			case "load-page-shared":
				data = lane2ShareStringPage(t, append([]byte(nil), baseline...), dir, "$ORIGIN")
			case "aarch64":
				binary.LittleEndian.PutUint16(data[18:], uint16(elf.EM_AARCH64))
			case "rel":
				binary.LittleEndian.PutUint16(data[16:], uint16(elf.ET_REL))
			case "setuid":
				mode |= os.ModeSetuid
			case "setgid":
				mode |= os.ModeSetgid
			case "no-exec":
				mode = 0644
			case "dangling", "loop", "open-failure":
				resolvable = false
			case "unreadable":
				mode = 0
				resolvable = os.Geteuid() == 0
			case "writable-dir":
				if err := os.Chmod(sub, 0775); err != nil {
					t.Fatal(err)
				}
			case "dir-link":
				allowed = true
			}
			path := filepath.Join(sub, "systemctl")
			lane2Write(t, path, data, mode)
			switch shape {
			case "dangling":
				if err := os.Remove(path); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink("missing", path); err != nil {
					t.Fatal(err)
				}
			case "loop", "open-failure", "fifo":
				if err := os.Remove(path); err != nil {
					t.Fatal(err)
				}
				switch shape {
				case "loop":
					if err := os.Symlink("systemctl", path); err != nil {
						t.Fatal(err)
					}
				case "open-failure":
					listener, err := net.Listen("unix", path)
					if err != nil {
						t.Fatal(err)
					}
					defer listener.Close()
				case "fifo":
					if err := syscall.Mkfifo(path, 0755); err != nil {
						t.Fatal(err)
					}
				}
			case "dir-link", "dir-link-untrusted":
				links := t.TempDir()
				link := filepath.Join(links, "bin")
				if err := os.Symlink(sub, link); err != nil {
					t.Fatal(err)
				}
				lane2BinDirs = []string{link}
				if shape == "dir-link-untrusted" {
					lane2Untrust(t, links)
				}
			case "sticky-child":
				if err := os.Chmod(sub, os.ModeSticky|0777); err != nil {
					t.Fatal(err)
				}
				lane2Untrust(t, path)
			case "symlink-dotdot":
				unsafe := filepath.Join(sub, "unsafe")
				if err := os.Mkdir(unsafe, 0777); err != nil {
					t.Fatal(err)
				}
				if err := os.Chmod(unsafe, 0777); err != nil {
					t.Fatal(err)
				}
				link := filepath.Join(sub, "link")
				if err := os.Symlink("unsafe/..", link); err != nil {
					t.Fatal(err)
				}
				lane2BinDirs = []string{link}
			case "capability":

				cap := make([]byte, 20)
				binary.LittleEndian.PutUint32(cap, 0x02000001)
				binary.LittleEndian.PutUint32(cap[4:], 1)
				if err := unix.Setxattr(path, "security.capability", cap, 0); err != nil {
					t.Fatal(err)
				}
			}
			check(t, shape, allowed, resolvable)
		})
	}
	lane2TrustedSocketRows(t)
	// A missing client is not a match, even under mutation.
	old := lane2BinDirs
	lane2BinDirs = []string{t.TempDir()}
	plan, matched, refusal := lane2Plan("systemctl status test.service", pinState{})
	plan.Close()
	lane2BinDirs = old
	if matched || refusal != "" {
		t.Fatal("missing binary did not fall through")
	}
}

func lane2Untrust(t *testing.T, path string) {
	t.Helper()
	if os.Geteuid() == 0 {
		if err := os.Chown(path, 65534, -1); err != nil {
			t.Fatal(err)
		}
	} else {
		lane2TrustedUIDs = []uint32{0}
	}
}

func TestLane2Admission(t *testing.T) {
	lane2AdmissionRows(t, func(name string, accepted bool) {
		if accepted {
			t.Errorf("%s: unsafe client admitted", name)
		}
	})
}

func lane2TrustedSocketRows(t *testing.T) {
	t.Helper()
	dir, err := os.MkdirTemp("", "l2-trust-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)
	owners := []uint32{0, uint32(os.Getuid())}
	path := filepath.Join(dir, "socket")
	listener, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	for _, mode := range []os.FileMode{0660, 0666} {
		if err := os.Chmod(path, mode); err != nil {
			t.Fatal(err)
		}
		if _, err := trustedPath(path, owners); err != nil {
			t.Fatalf("socket %o: %v", mode, err)
		}
	}
	if err := os.Chmod(dir, 0770); err != nil {
		t.Fatal(err)
	}
	if _, err := trustedPath(path, owners); err == nil {
		t.Fatal("group-writable parent accepted")
	}
	if os.Geteuid() == 0 {
		if err := os.Chmod(dir, os.ModeSticky|0777); err != nil {
			t.Fatal(err)
		}
		if err := os.Chown(dir, 65534, -1); err != nil {
			t.Fatal(err)
		}
		if _, err := trustedPath(path, owners); err == nil {
			t.Fatal("untrusted sticky owner accepted")
		}
	}
}

func TestLane2AdmitDenyAudit(t *testing.T) {
	for _, reason := range []string{"binary", "binary-elf", "search-tag", "endpoint"} {
		t.Run(reason, func(t *testing.T) {
			dir := buildLane2Fixtures(t)
			gateDir := t.TempDir()
			withGateDir(t, gateDir)
			switch reason {
			case "binary":
				if err := os.Chmod(dir, 0777); err != nil {
					t.Fatal(err)
				}
			case "binary-elf":
				lane2Write(t, filepath.Join(dir, "systemctl"), []byte("#!/bin/sh\necho unsafe\n"), 0755)
			case "search-tag":
				lane2BuildSearch(t, dir, "$ORIGIN/lib", false)
			case "endpoint":
				missing := filepath.Join(t.TempDir(), "missing")
				lane2SystemEndpoints.bus, lane2SystemEndpoints.private = missing, missing
			}
			code, out, stderr := runWith(t, "systemctl status sg-agent-private-value.service")
			if code != exitNoPermVal || out != "" || !strings.Contains(stderr, "daemon read refused: "+reason+"; nothing ran") || strings.Contains(stderr, "sg-agent-private") {
				t.Fatalf("code=%d out=%q err=%q", code, out, stderr)
			}
			records := auditRecords(t, gateDir)
			if len(records) != 1 || records[0]["deny_reason"] != "lane2:admit:"+reason {
				t.Fatalf("audit=%v", records)
			}
		})
	}
}

func TestLane2ExecPathSeparate(t *testing.T) {
	dir := withLane2Bins(t)
	plan, matched, refusal := lane2Plan("systemctl status test.service", pinState{})
	defer plan.Close()
	if !matched || refusal != "" || plan.binary.path == plan.argv[0] {
		t.Fatalf("plan=%+v refusal=%s", plan, refusal)
	}
	// The fixed-directory name no longer exists; execution must use the
	// separately admitted path while preserving the original argv[0].
	if err := os.Remove(filepath.Join(dir, "systemctl")); err != nil {
		t.Fatal(err)
	}
	out := captureStdout(t, func() {
		result, err := gate.ExecArgvWithRedaction(context.Background(), plan.binary.path, plan.argv, confine.Lane2Env(), gate.ExecOpts{})
		if err != nil || result.ExitCode != 0 {
			t.Fatalf("result=%+v err=%v", result, err)
		}
	})
	var report execReport
	if err := json.Unmarshal([]byte(out), &report); err != nil {
		t.Fatal(err)
	}
	if report.Args[0] != filepath.Join(dir, "systemctl") {
		t.Fatalf("argv=%q", report.Args)
	}
}

func testLane2ELFSearchTags(t *testing.T) {
	p := newProof(t, "U-Lane2ELFSearchTags")
	missed := false
	lane2AdmissionRows(t, func(name string, accepted bool) { missed = missed || accepted })
	p.Control("decision", true)
	p.Effect("decision", missed)
	p.Finish()
}

func TestLane2InstalledClients(t *testing.T) {
	for _, name := range []string{"systemctl", "docker"} {
		t.Run(name, func(t *testing.T) {
			path, err := exec.LookPath(name)
			if err != nil {
				t.Skipf("client not installed: %v", err)
			}
			_, file, _, refusal, err := lane2Admit(path)
			if file != nil {
				defer file.Close()
			}
			if err != nil || refusal != "" {
				t.Fatalf("installed %s: refusal=%s err=%v", path, refusal, err)
			}
		})
	}
}

// lane2ShareStringPage turns the first PT_NOTE after the PT_LOADs into a
// 16-byte PT_LOAD at the end of the page holding old (a dynamic string), backed
// by a copy of that page with replacement in old's place. The new segment's
// range stays clear of the string table, but the kernel maps it by the page.
func lane2ShareStringPage(t *testing.T, data []byte, old, replacement string) []byte {
	t.Helper()
	executable, err := elf.NewFile(bytes.NewReader(data))
	if err != nil {
		t.Fatal(err)
	}
	table := executable.Section(".dynstr")
	index := bytes.Index(data, []byte(old+"\x00"))
	if table == nil || index < int(table.Offset) || index >= int(table.Offset+table.Size) || len(replacement) > len(old) {
		t.Fatal("string not in .dynstr")
	}
	page := uint64(os.Getpagesize())
	pageAddress := (table.Addr + uint64(index) - table.Offset) &^ (page - 1)
	pageOffset := uint64(index) - (table.Addr + uint64(index) - table.Offset - pageAddress)
	address := pageAddress + page - 16
	if table.Addr+table.Size > address {
		t.Fatal("string table reaches the end of its page")
	}
	phoff := binary.LittleEndian.Uint64(data[32:])
	phsize, phnum := uint64(binary.LittleEndian.Uint16(data[54:])), binary.LittleEndian.Uint16(data[56:])
	var header []byte
	for i, seenLoad := uint64(0), false; i < uint64(phnum); i++ {
		ph := data[phoff+i*phsize:]
		switch elf.ProgType(binary.LittleEndian.Uint32(ph)) {
		case elf.PT_LOAD:
			seenLoad, header = true, nil
		case elf.PT_NOTE:
			if seenLoad && header == nil {
				header = ph[:phsize]
			}
		}
	}
	if header == nil {
		t.Fatal("no PT_NOTE after the PT_LOADs")
	}
	copyOffset := (uint64(len(data)) + page - 1) &^ (page - 1)
	binary.LittleEndian.PutUint32(header, uint32(elf.PT_LOAD))
	binary.LittleEndian.PutUint32(header[4:], uint32(elf.PF_R))
	for field, value := range []uint64{copyOffset + page - 16, address, address, 16, 16, page} {
		binary.LittleEndian.PutUint64(header[8+8*field:], value)
	}
	pageCopy := append([]byte(nil), data[pageOffset:pageOffset+page]...)
	copy(pageCopy[uint64(index)-pageOffset:], replacement+"\x00")
	data = append(data, make([]byte, copyOffset-uint64(len(data)))...)
	return append(data, pageCopy...)
}

// TestLane2ELFLoaderView: admission reads the dynamic table and its strings
// where the loader does. Each row's control shows the loader really took the
// $ORIGIN search path (LIB-RAN on a direct exec); the gate must refuse it.
func TestLane2ELFLoaderView(t *testing.T) {
	for _, row := range []struct{ name, reason string }{
		// PT_DYNAMIC's p_offset names a zeroed copy; the loader uses p_vaddr.
		{"dynamic-offset-decoy", "search-tag"},
		// A segment clear of the string table replaces the table's page.
		{"load-page-shared", "binary-elf"},
	} {
		t.Run(row.name, func(t *testing.T) {
			dir := buildLane2Fixtures(t)
			path := filepath.Join(dir, "systemctl")
			var nonce string
			var data []byte
			switch row.name {
			case "dynamic-offset-decoy":
				nonce = lane2BuildSearch(t, dir, "$ORIGIN/lib", false)
				data = lane2ReadFile(t, path)
				phoff := binary.LittleEndian.Uint64(data[32:])
				phsize, phnum := binary.LittleEndian.Uint16(data[54:]), binary.LittleEndian.Uint16(data[56:])
				patched := false
				for i := uint16(0); i < phnum && !patched; i++ {
					ph := data[phoff+uint64(i)*uint64(phsize):]
					if elf.ProgType(binary.LittleEndian.Uint32(ph)) == elf.PT_DYNAMIC {
						size := binary.LittleEndian.Uint64(ph[32:])
						binary.LittleEndian.PutUint64(ph[8:], uint64(len(data)))
						data = append(data, make([]byte, size)...)
						patched = true
					}
				}
				if !patched {
					t.Fatal("fixture has no dynamic header")
				}
			case "load-page-shared":
				// The file's own RUNPATH is a missing directory under /, which passes.
				const placeholder = "/sg-absent/runpath-placeholder"
				nonce = lane2BuildSearch(t, dir, placeholder, false)
				data = lane2ShareStringPage(t, lane2ReadFile(t, path), placeholder, "$ORIGIN/lib")
			}
			lane2Write(t, path, data, 0755)
			mode := lane2Mode(t, "report")
			direct, err := exec.Command(path, "status", mode).CombinedOutput()
			if err != nil || !strings.Contains(string(direct), "LIB-RAN "+nonce) {
				t.Fatalf("SETUP: the loader did not take the hidden search path: %v: %s", err, direct)
			}
			gateDir := t.TempDir()
			withGateDir(t, gateDir)
			code, out, stderr := runWith(t, "systemctl status "+mode)
			if code != exitNoPermVal || out != "" {
				t.Fatalf("hidden search path admitted: code=%d out=%q err=%q", code, out, stderr)
			}
			records := auditRecords(t, gateDir)
			if len(records) != 1 || records[0]["deny_reason"] != "lane2:admit:"+row.reason {
				t.Fatalf("audit=%v", records)
			}
		})
	}
}

func lane2ReadFile(t *testing.T, path string) []byte {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func TestLane2TrustedSockets(t *testing.T) { lane2TrustedSocketRows(t) }

// TestLane2WritableFileRefused: a valid client, or the loader it names, that is
// group- or world-writable is refused at admission, before anything runs, even
// in trusted 0755 directories.
func TestLane2WritableFileRefused(t *testing.T) {
	dir := buildLane2Fixtures(t)
	client := filepath.Join(dir, "systemctl")
	original, err := os.ReadFile(client)
	if err != nil {
		t.Fatal(err)
	}
	host := lane2HostInterp(t, client)
	resolved, err := filepath.EvalSymlinks(host)
	if err != nil {
		t.Fatal(err)
	}
	loader, err := os.ReadFile(resolved)
	if err != nil {
		t.Fatal(err)
	}
	loaders := t.TempDir()
	if err := os.Chmod(loaders, 0o755); err != nil {
		t.Fatal(err)
	}
	plan := func(t *testing.T) string {
		t.Helper()
		plan, matched, refusal := lane2Plan("systemctl status test.service", pinState{})
		plan.Close()
		if !matched {
			t.Fatal("present client did not match")
		}
		return refusal
	}
	lane2Write(t, client, original, 0o755)
	if refusal := plan(t); refusal != "" {
		t.Fatalf("SETUP: 0755 client refused %q", refusal)
	}
	for _, mode := range []os.FileMode{0o775, 0o757} {
		t.Run("client "+mode.String(), func(t *testing.T) {
			lane2Write(t, client, original, mode)
			defer lane2Write(t, client, original, 0o755)
			if refusal := plan(t); refusal != "binary" {
				t.Fatalf("refusal=%q, want binary", refusal)
			}
		})
		t.Run("interpreter "+mode.String(), func(t *testing.T) {
			path := filepath.Join(loaders, "ld-"+strconv.FormatUint(uint64(mode), 8)+".so")
			lane2Write(t, path, loader, 0o755)
			lane2Write(t, client, lane2SetInterp(t, append([]byte(nil), original...), path), 0o755)
			defer lane2Write(t, client, original, 0o755)
			if refusal := plan(t); refusal != "" {
				t.Fatalf("SETUP: 0755 loader refused %q", refusal)
			}
			if err := os.Chmod(path, mode); err != nil {
				t.Fatal(err)
			}
			if refusal := plan(t); refusal != "interp" {
				t.Fatalf("refusal=%q, want interp", refusal)
			}
		})
	}
}
