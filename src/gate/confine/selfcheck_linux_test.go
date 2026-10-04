//go:build linux

package confine

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"testing"
)

func TestSelfcheckCredentials(t *testing.T) {
	clean := "CapInh: 0\nCapPrm: 0\nCapEff: 0\nCapBnd: 0\nCapAmb: 0\nNoNewPrivs: 1\nSeccomp: 2\nSeccomp_filters: 1\n"
	for _, root := range []bool{false, true} {
		status := clean
		if root {
			for _, key := range []string{"CapPrm", "CapEff", "CapBnd"} {
				status = strings.Replace(status, key+": 0", key+": 4", 1)
			}
		}
		if err := selfcheckCredentials(status, root); err != nil {
			t.Fatal(err)
		}
		for _, key := range []string{"CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb", "NoNewPrivs", "Seccomp", "Seccomp_filters"} {
			lines := strings.Split(status, "\n")
			for i, line := range lines {
				if strings.HasPrefix(line, key+":") {
					lines[i] = key + ": 99"
					if key == "Seccomp_filters" {
						lines[i] = key + ": 0"
					}
				}
			}
			if err := selfcheckCredentials(strings.Join(lines, "\n"), root); err == nil {
				t.Errorf("accepted altered %s", key)
			}
			if err := selfcheckCredentials(status+key+": 0\n", root); err == nil {
				t.Errorf("accepted duplicate %s", key)
			}
		}
	}
	if err := selfcheckCredentials("", false); err == nil {
		t.Fatal("accepted absent credentials")
	}
}

func TestSelfcheckMountFlags(t *testing.T) {
	fixture := func() []mountEntry {
		return []mountEntry{
			{id: 1, point: "/", fstype: "tmpfs", opts: []string{"ro", "nosuid", "nodev"}},
			{id: 2, point: "/dev/shm", fstype: "tmpfs", opts: []string{"ro", "nosuid", "nodev"}},
			{id: 3, point: "/dev/shm", fstype: "tmpfs", opts: []string{"rw", "nosuid", "nodev", "noexec"}},
			{id: 4, point: "/dev/null", fstype: "devtmpfs", opts: []string{"ro", "nosuid"}},
		}
	}
	if err := selfcheckMountFlags(fixture(), 3, map[int]bool{4: true}); err != nil {
		t.Fatal(err)
	}
	for _, tag := range []string{"master:1", "shared:2"} {
		entries := fixture()
		entries[0].optional = []string{tag}
		if selfcheckMountFlags(entries, 3, map[int]bool{4: true}) == nil {
			t.Errorf("accepted %s", tag)
		}
	}
	for _, option := range []string{"ro", "nosuid", "nodev"} {
		entries := fixture()
		for i, value := range entries[0].opts {
			if value == option {
				entries[0].opts[i] = ""
			}
		}
		if selfcheckMountFlags(entries, 3, map[int]bool{4: true}) == nil {
			t.Errorf("accepted missing %s", option)
		}
	}
	if selfcheckMountFlags(fixture(), 2, map[int]bool{4: true}) == nil {
		t.Error("picked scratch by path rather than ID")
	}
	if selfcheckMountFlags(fixture(), 3, nil) == nil {
		t.Error("accepted nodev exception without node ID")
	}
}

func TestStatusProtocol(t *testing.T) {
	valid := `I{"profile":"ro-v1","abi":2,"net":false,"lane2":false}` + "\nX"
	for _, test := range []struct {
		name, raw string
		spec      Spec
		valid     bool
	}{
		{"valid", valid, Spec{Profile: ProfileROv1}, true},
		{"missing-I", "X", Spec{Profile: ProfileROv1}, false},
		{"wrong-profile", valid, Spec{Profile: "other"}, false},
		{"wrong-net", valid, Spec{Profile: ProfileROv1, Net: true}, false},
		{"abi-cap", valid, Spec{Profile: ProfileROv1, ForceABI: 1}, false},
		{"missing-field", strings.Replace(valid, `,"net":false`, "", 1), Spec{Profile: ProfileROv1}, false},
		{"null-field", strings.Replace(valid, `"net":false`, `"net":null`, 1), Spec{Profile: ProfileROv1}, false},
		{"duplicate-field", strings.Replace(valid, `"abi":2`, `"abi":2,"abi":2`, 1), Spec{Profile: ProfileROv1}, false},
		{"wrong-case-field", strings.Replace(valid, `"net":false`, `"net":false,"Net":false`, 1), Spec{Profile: ProfileROv1}, false},
		{"duplicate-I", valid + "\n" + valid, Spec{Profile: ProfileROv1}, false},
		{"extra-X", valid + "X", Spec{Profile: ProfileROv1}, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			reader, writer, err := os.Pipe()
			if err != nil {
				t.Fatal(err)
			}
			_, _ = writer.WriteString(test.raw)
			writer.Close()
			jailed := Jailed{statusR: reader, spec: test.spec}
			facts, err := jailed.Status()
			if (err == nil) != test.valid {
				t.Fatalf("facts=%+v err=%v", facts, err)
			}
		})
	}
}

func TestStatusProtocolFacts(t *testing.T) {
	raw := `I{"profile":"ro-v1","abi":2,"net":true,"lane2":false,"cwd_reset":true,"cover_at_ancestor":["cover_at_ancestor@/closed"],"unmet":["fs-view:overlay@/"]}` + "\nX"
	for _, strict := range []bool{false, true} {
		reader, writer, err := os.Pipe()
		if err != nil {
			t.Fatal(err)
		}
		_, _ = writer.WriteString(raw)
		writer.Close()
		jailed := Jailed{statusR: reader, spec: Spec{Profile: ProfileROv1, Net: true}, strict: strict}
		facts, err := jailed.Status()
		if strict {
			var setup *SetupError
			if !errors.As(err, &setup) || setup.Stage != "report" {
				t.Fatalf("strict: %+v %v", facts, err)
			}
			continue
		}
		if err != nil || !facts.CwdReset || !facts.Net || facts.ABI != 2 || !slices.Equal(facts.CoverAtAncestor, []string{"cover_at_ancestor@/closed"}) || !slices.Equal(facts.Unmet, []string{"fs-view:overlay@/"}) {
			t.Fatalf("roundtrip: %+v %v", facts, err)
		}
	}
	for _, test := range []struct {
		raw, stage string
		errno      syscall.Errno
	}{
		{"Fselfcheck:1\n", "selfcheck", syscall.EPERM},
		{`I{"profile":"ro-v1","abi":2,"net":false,"lane2":false}` + "\nXgarbage", "exec", 0},
		{`I{"profile":"ro-v1","abi":2,"net":false,"lane2":false}` + "\nXFexec:2\n", "exec", syscall.ENOENT},
	} {
		reader, writer, err := os.Pipe()
		if err != nil {
			t.Fatal(err)
		}
		_, _ = writer.WriteString(test.raw)
		writer.Close()
		jailed := Jailed{statusR: reader, spec: Spec{Profile: ProfileROv1}}
		_, err = jailed.Status()
		var setup *SetupError
		if !errors.As(err, &setup) || setup.Stage != test.stage || setup.Errno != test.errno {
			t.Fatalf("%q: %v", test.raw, err)
		}
	}
}

func TestDeniedSubtreeSafe(t *testing.T) {
	// U-DeniedSubtreeSafe: judge the complete table, including hidden mounts.
	sys, proc := t.TempDir(), t.TempDir()
	for _, device := range []struct{ number, controller, transport, driver string }{
		{"259:0", "nvme0", "tcp", "nvme-tcp"},
		{"259:1", "nvme1", "pcie", "nvme"},
	} {
		disk := filepath.Join(sys, "devices", device.controller, device.controller+"n1")
		mkdir(t, disk)
		write(t, filepath.Join(filepath.Dir(disk), "transport"), device.transport)
		driver := filepath.Join(sys, "drivers", device.driver)
		mkdir(t, driver)
		link(t, driver, filepath.Join(filepath.Dir(disk), "driver"))
		link(t, disk, filepath.Join(sys, "dev/block", device.number))
		mkdir(t, filepath.Join(proc, "fs/jbd2", device.controller+"n1-8"))
	}
	for _, test := range []struct {
		name, denied, point, fstype, device string
		accept                              []string
		want                                bool
	}{
		{"all-safe", "/run/docker", "/run/docker/netns/id", "nsfs", "0:3", nil, true},
		{"unsafe-at", "/run/docker", "/run/docker", "fuse", "0:3", nil, false},
		{"unsafe-hidden", "/run/docker", "/run/docker/safe", "fuse", "0:3", nil, false},
		{"unsafe-child", "/run/docker", "/run/docker/f", "fuse", "0:3", nil, false},
		{"unsafe-deep", "/run/docker", "/run/docker/a/b/f", "fuse", "0:3", nil, false},
		{"unsafe-sibling", "/run/docker", "/run/dockerx/f", "fuse", "0:3", nil, true},
		{"empty-denied", "", "/run/docker/f", "tmpfs", "0:3", nil, false},
		{"network-fs-denied", "/run/docker", "/run/docker/f", "nfs", "0:3", nil, false},
		{"network-fs-accepted", "/run/docker", "/run/docker/f", "nfs", "0:3", []string{"network"}, true},
		{"autofs-accepted", "/run/docker", "/run/docker/f", "autofs", "0:3", []string{"autofs"}, true},
		{"fuse-not-accepted", "/run/docker", "/run/docker/f", "fuse", "0:3", []string{"network", "autofs"}, false},
		{"network-block-denied", "/run/docker", "/run/docker/f", "ext4", "259:0", nil, false},
		{"network-block-accepted", "/run/docker", "/run/docker/f", "ext4", "259:0", []string{"network"}, true},
		{"direct-block", "/run/docker", "/run/docker/f", "ext4", "259:1", nil, true},
		{"unknown-block", "/run/docker", "/run/docker/f", "ext4", "259:2", []string{"network"}, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			fixture := "1 0 0:1 / / rw - tmpfs tmpfs rw\n" +
				"2 1 0:2 / /run/docker/safe rw - tmpfs tmpfs rw\n" +
				fmt.Sprintf("3 1 %s / %s rw - %s fixture rw\n", test.device, test.point, test.fstype) +
				"4 1 0:4 / /run/docker/safe rw - tmpfs tmpfs rw\n"
			entries, err := parseMountInfo(strings.NewReader(fixture))
			if err != nil {
				t.Fatal(err)
			}
			if got := deniedSubtreeSafe(entries, test.denied, test.accept, backingInspector{sys: sys, proc: proc}); got != test.want {
				t.Fatalf("deniedSubtreeSafe = %v, want %v", got, test.want)
			}
		})
	}
}
