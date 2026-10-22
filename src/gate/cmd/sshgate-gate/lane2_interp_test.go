//go:build linux

package main

import (
	"debug/elf"
	"encoding/binary"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"

	"github.com/karthikeyan5/sshgate/src/gate/confine/jailmut"
)

// lane2BuildClient builds the C client with extra cc arguments into out.
func lane2BuildClient(t *testing.T, out string, extra ...string) {
	t.Helper()
	args := append([]string{"-O2", "-Wall", "-Werror", "-o", out, "testdata/lane2client/main.c"}, extra...)
	if output, err := exec.Command("cc", args...).CombinedOutput(); err != nil {
		t.Fatalf("SETUP: cc: %v: %s", err, output)
	}
}

// lane2HostInterp is the PT_INTERP string cc gives a client on this host.
func lane2HostInterp(t *testing.T, client string) string {
	t.Helper()
	executable, err := elf.Open(client)
	if err != nil {
		t.Fatal(err)
	}
	defer executable.Close()
	for _, ph := range executable.Progs {
		if ph.Type == elf.PT_INTERP {
			raw := make([]byte, ph.Filesz)
			if _, err := ph.ReadAt(raw, 0); err != nil {
				t.Fatal(err)
			}
			return strings.TrimRight(string(raw), "\x00")
		}
	}
	t.Fatal("SETUP: client has no PT_INTERP")
	return ""
}

// lane2SetInterp rewrites the client's PT_INTERP to name, NUL-terminated and
// sized exactly; a name too long for the original bytes is appended.
func lane2SetInterp(t *testing.T, data []byte, name string) []byte {
	t.Helper()
	phoff := binary.LittleEndian.Uint64(data[32:])
	phsize, phnum := uint64(binary.LittleEndian.Uint16(data[54:])), uint64(binary.LittleEndian.Uint16(data[56:]))
	for i := uint64(0); i < phnum; i++ {
		ph := data[phoff+i*phsize:]
		if elf.ProgType(binary.LittleEndian.Uint32(ph)) != elf.PT_INTERP {
			continue
		}
		offset, size := binary.LittleEndian.Uint64(ph[8:]), binary.LittleEndian.Uint64(ph[32:])
		value := []byte(name + "\x00")
		if uint64(len(value)) > size {
			offset = uint64(len(data))
			binary.LittleEndian.PutUint64(ph[8:], offset)
			data = append(data, value...)
		} else {
			copy(data[offset:], value)
		}
		binary.LittleEndian.PutUint64(ph[32:], uint64(len(value)))
		binary.LittleEndian.PutUint64(ph[40:], uint64(len(value)))
		return data
	}
	t.Fatal("SETUP: client has no PT_INTERP")
	return nil
}

// lane2InterpRows drives every interpreter row through lane2Plan; verdict
// gets each row whose trust verdict a mutation may ignore.
func lane2InterpRows(t *testing.T, verdict func(name string, accepted bool)) {
	t.Helper()
	dir := buildLane2Fixtures(t)
	host := lane2HostInterp(t, filepath.Join(dir, "systemctl"))
	hostResolved, err := filepath.EvalSymlinks(host)
	if err != nil {
		t.Fatal(err)
	}
	loader, err := os.ReadFile(hostResolved)
	if err != nil {
		t.Fatal(err)
	}
	client := filepath.Join(t.TempDir(), "client")
	lane2BuildClient(t, client, "-Wl,--dynamic-linker=/"+strings.Repeat("p", 400))
	clientData, err := os.ReadFile(client)
	if err != nil {
		t.Fatal(err)
	}
	loaders := t.TempDir()
	mkdir := func(path string, mode os.FileMode) string {
		if err := os.MkdirAll(path, mode); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(path, mode); err != nil {
			t.Fatal(err)
		}
		return path
	}
	mkdir(loaders, 0o755)
	link := func(target, path string) string {
		if err := os.Symlink(target, path); err != nil {
			t.Fatal(err)
		}
		return path
	}
	real := filepath.Join(loaders, "real.so")
	lane2Write(t, real, loader, 0o755)
	for _, row := range []struct {
		name                string
		setup               func(t *testing.T) string
		resolved            string // set for a row that passes
		resolvable, refused bool
	}{
		{"host loader", func(*testing.T) string { return host }, hostResolved, true, false},
		{"file link chain", func(*testing.T) string { return link("real.so", filepath.Join(loaders, "link.so")) }, real, true, false},
		{"directory link chain", func(*testing.T) string {
			lane2Write(t, filepath.Join(mkdir(filepath.Join(loaders, "usr", "lib"), 0o755), "ld.so"), loader, 0o755)
			link(filepath.Join("usr", "lib"), filepath.Join(loaders, "lib"))
			return link(filepath.Join("..", "lib", "ld.so"), filepath.Join(mkdir(filepath.Join(loaders, "lib64"), 0o755), "ld.so"))
		}, filepath.Join(loaders, "usr", "lib", "ld.so"), true, false},
		{"relative", func(*testing.T) string { return "lib/ld.so" }, "", false, true},
		{"not clean", func(*testing.T) string { return loaders + "/x/../real.so" }, "", false, true},
		{"over 4096 bytes", func(*testing.T) string { return "/" + strings.Repeat("a", 4096) }, "", false, true},
		{"missing", func(*testing.T) string { return filepath.Join(loaders, "missing.so") }, "", false, true},
		{"dangling link", func(*testing.T) string { return link("gone.so", filepath.Join(loaders, "dangling.so")) }, "", false, true},
		{"41 links", func(*testing.T) string {
			previous := "real.so"
			for i := 0; i < 41; i++ {
				previous = filepath.Base(link(previous, filepath.Join(loaders, "chain"+strconv.Itoa(i))))
			}
			return filepath.Join(loaders, previous)
		}, "", false, true},
		{"link through a writable directory", func(*testing.T) string {
			return link(filepath.Join("..", "real.so"), filepath.Join(mkdir(filepath.Join(loaders, "writable"), 0o777), "ld.so"))
		}, "", true, true},
		{"untrusted owner", func(t *testing.T) string {
			path := filepath.Join(loaders, "untrusted.so")
			lane2Write(t, path, loader, 0o755)
			lane2Untrust(t, path)
			return path
		}, "", true, true},
		{"not ELF", func(t *testing.T) string {
			path := filepath.Join(loaders, "script")
			lane2Write(t, path, []byte("#!/bin/sh\n"), 0o755)
			return path
		}, "", true, true},
		{"ET_EXEC", func(t *testing.T) string {
			data := append([]byte(nil), loader...)
			binary.LittleEndian.PutUint16(data[16:], uint16(elf.ET_EXEC))
			path := filepath.Join(loaders, "exec.so")
			lane2Write(t, path, data, 0o755)
			return path
		}, "", true, true},
		{"its own PT_INTERP", func(t *testing.T) string {
			path := filepath.Join(loaders, "client.so")
			lane2Write(t, path, clientData, 0o755)
			return path
		}, "", true, true},
	} {
		t.Run(row.name, func(t *testing.T) {
			oldUIDs := lane2TrustedUIDs
			t.Cleanup(func() { lane2TrustedUIDs = oldUIDs })
			lane2Write(t, filepath.Join(dir, "systemctl"), lane2SetInterp(t, append([]byte(nil), clientData...), row.setup(t)), 0o755)
			if row.name == "untrusted owner" && os.Geteuid() != 0 {
				// Non-root, the narrowed trust set refuses the test-owned client
				// first; check the loader's verdict directly. The root twin
				// chowns the loader alone and runs through lane2Plan.
				executable, err := elf.Open(filepath.Join(dir, "systemctl"))
				if err != nil {
					t.Fatal(err)
				}
				defer executable.Close()
				var plan lane2Execution
				defer plan.Close()
				if refusal, err := plan.admitInterp(executable); err != nil || refusal != "interp" || plan.interp.stat.Ino == 0 {
					t.Fatalf("refusal=%q err=%v interp=%+v", refusal, err, plan.interp)
				}
				return
			}
			plan, matched, refusal := lane2Plan("systemctl status x", pinState{})
			defer plan.Close()
			if !matched {
				t.Fatal("present client did not match")
			}
			if refusal == "" {
				var outside syscall.Stat_t
				if err := syscall.Stat(plan.interp.path, &outside); err != nil || plan.interp.stat.Ino == 0 || outside.Dev != plan.interp.stat.Dev || outside.Ino != plan.interp.stat.Ino {
					t.Fatalf("interpreter identity %+v does not match %s", plan.interp, plan.interp.path)
				}
			}
			switch {
			case !row.refused:
				if refusal != "" || plan.interp.path != row.resolved {
					t.Fatalf("refusal=%q interp=%q, want admitted %q", refusal, plan.interp.path, row.resolved)
				}
			case !row.resolvable:
				if refusal != "interp" {
					t.Fatalf("unresolvable interpreter: refusal=%q, want interp", refusal)
				}
			default:
				if jailmut.On("P-L2-INTERP") && refusal != "" || !jailmut.On("P-L2-INTERP") && refusal != "interp" {
					t.Fatalf("refusal=%q", refusal)
				}
				verdict(row.name, refusal == "")
			}
		})
	}
	t.Run("two PT_INTERP", func(t *testing.T) {
		data := append([]byte(nil), clientData...)
		data = lane2SetInterp(t, data, host)
		phoff := binary.LittleEndian.Uint64(data[32:])
		phsize, phnum := uint64(binary.LittleEndian.Uint16(data[54:])), uint64(binary.LittleEndian.Uint16(data[56:]))
		for i := uint64(0); i < phnum; i++ {
			ph := data[phoff+i*phsize:]
			if elf.ProgType(binary.LittleEndian.Uint32(ph)) == elf.PT_NOTE {
				binary.LittleEndian.PutUint32(ph, uint32(elf.PT_INTERP))
				break
			}
		}
		lane2Write(t, filepath.Join(dir, "systemctl"), data, 0o755)
		plan, _, refusal := lane2Plan("systemctl status x", pinState{})
		plan.Close()
		if refusal != "binary-elf" && !jailmut.On("P-L2-ADMIT") {
			t.Fatalf("refusal=%q, want binary-elf", refusal)
		}
	})
}

func TestLane2Interp(t *testing.T) {
	lane2InterpRows(t, func(name string, accepted bool) {
		if accepted {
			t.Errorf("%s: untrusted interpreter admitted", name)
		}
	})
}

// testLane2Interp is U-Lane2Interp.
func testLane2Interp(t *testing.T) {
	p := newProof(t, "U-Lane2Interp")
	missed := false
	lane2InterpRows(t, func(_ string, accepted bool) { missed = missed || accepted })
	p.Control("decision", true)
	p.Effect("decision", missed)
	p.Finish()
}

// TestLane2InterpSystemClients: the installed clients' interpreters pass.
func TestLane2InterpSystemClients(t *testing.T) {
	for _, name := range []string{"systemctl", "docker"} {
		path, err := exec.LookPath(name)
		if err != nil {
			continue
		}
		executable, err := elf.Open(path)
		if err != nil {
			t.Fatal(err)
		}
		var plan lane2Execution
		refusal, err := plan.admitInterp(executable)
		executable.Close()
		plan.Close()
		if err != nil || refusal != "" {
			t.Errorf("%s: interpreter refusal=%q err=%v", path, refusal, err)
		}
	}
}
