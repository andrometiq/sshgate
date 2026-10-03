//go:build linux

package confine

import (
	"encoding/json"
	"fmt"
	"golang.org/x/sys/unix"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"
)

func TestReachableMounts(t *testing.T) {
	cases := []struct {
		name, fixture string
		want          []int
		unmet         bool
	}{
		{"stack", "1 0 0:1 / / rw - tmpfs x rw\n257 1 0:2 / /X rw - tmpfs x rw\n258 257 0:3 / /X/sub rw - ramfs x rw\n259 257 0:4 / /X rw - tmpfs x rw\n260 259 0:5 / /X/inner rw - ramfs x rw\n", []int{1, 259, 260}, false},
		{"nested-depth3", "1 0 0:1 / / rw - tmpfs x rw\n2 1 0:2 / /a rw - tmpfs x rw\n3 2 0:3 / /a/b rw - ramfs x rw\n4 3 0:4 / /a/b/c rw - fuse x rw\n", []int{1, 2, 3, 4}, false},
		{"cover-inside-stack", "1 0 0:1 / / rw - tmpfs x rw\n2 1 0:2 / /a rw - tmpfs x rw\n3 2 0:3 / /a rw - tmpfs x rw\n4 3 0:4 / /a/unsafe rw - fuse x rw\n5 4 0:5 / /a/unsafe ro - tmpfs cover ro\n6 4 0:6 / /a/unsafe/hidden rw - fuse x rw\n", []int{1, 3, 5}, false},
		{"escaped-name", "1 0 0:1 / / rw - tmpfs x rw\n2 1 0:2 / /with\\040space rw - tmpfs x rw\n3 2 0:3 / /with\\040space/inner\\011tab rw - fuse x rw\n", []int{1, 2, 3}, false},
		{"root-stack", "1 0 0:1 / / rw - tmpfs x rw\n2 1 0:2 / / rw - fuse x rw\n3 2 0:3 / /hidden rw - tmpfs x rw\n", []int{1}, false},
		{"three-stack", "1 0 0:1 / / rw - tmpfs x rw\n2 1 0:2 / /X rw - fuse x rw\n3 2 0:3 / /X rw - tmpfs x rw\n4 3 0:4 / /X rw - fuse x rw\n", []int{1, 4}, false},
		{"duplicate", "1 0 0:1 / / rw - tmpfs x rw\n2 1 0:2 / /X rw - tmpfs x rw\n3 1 0:3 / /X rw - fuse x rw\n", []int{1}, true},
		{"outside-parent", "1 0 0:1 / / rw - tmpfs x rw\n2 1 0:2 / /X rw - tmpfs x rw\n3 2 0:3 / /Y rw - fuse x rw\n", []int{1, 2}, true},
		{"deleted", "1 0 0:1 / / rw - tmpfs x rw\n2 1 0:2 / /X\\040(deleted) rw - fuse x rw\n", []int{1}, true},
		{"cycle", "1 0 0:1 / / rw - tmpfs x rw\n2 3 0:2 / /X rw - fuse x rw\n3 2 0:3 / /X rw - tmpfs x rw\n", []int{1}, true},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			entries, err := parseMountInfo(strings.NewReader(test.fixture))
			if err != nil {
				t.Fatal(err)
			}
			view := reachableMounts(entries, 1)
			var ids []int
			for _, entry := range view.entries {
				ids = append(ids, entry.id)
			}
			if !reflect.DeepEqual(ids, test.want) || (len(view.unmet) > 0) != test.unmet {
				t.Fatalf("%v unmet %v", ids, view.unmet)
			}
			if test.name == "stack" {
				entry, _ := view.expectedAt("/X/sub")
				if entry.id != 259 {
					t.Fatalf("shadowed name lands on %d", entry.id)
				}
			}
		})
	}
}
func TestParseMountInfoExtended(t *testing.T) {
	for _, optional := range []string{"", "shared:1 ", "shared:1 master:2 ", "shared:1 master:2 propagate_from:3 "} {
		entries, err := parseMountInfo(strings.NewReader("1 0 8:1 /a\\040b /c\\011d ro " + optional + "- ext4 /dev/a\\134b rw,errors=remount-ro\n"))
		if err != nil {
			t.Fatal(err)
		}
		entry := entries[0]
		if entry.root != "/a b" || entry.point != "/c\td" || entry.source != "/dev/a\\b" || len(entry.superOpts) != 2 {
			t.Fatalf("%+v", entry)
		}
	}
	for _, line := range []string{"1 0 8:1 / / rw ext4 /dev/a rw", "1 0 8:1 / / rw - ext4 x", "1 x 8:1 / / rw - ext4 x rw", "1 0 nope / / rw - ext4 x rw"} {
		if _, err := parseMountInfo(strings.NewReader(line)); err == nil {
			t.Errorf("accepted %q", line)
		}
	}
}
func TestSpecCwdValidate(t *testing.T) {
	for _, cwd := range []string{"", "relative", "/a/../b", "/a/", "/a\x00b", "/" + strings.Repeat("a", 4096)} {
		spec := Spec{Profile: ProfileROv1, ParentNS: NSIDs{1, 2, 3, 4}, Cwd: cwd}
		raw, _ := json.Marshal(spec)
		if decodeSpec(string(raw), new(Spec)) == nil {
			t.Errorf("accepted %q", cwd)
		}
	}
	for _, accept := range [][]string{{"network", "network"}, {"fuse"}, {"autofs", "autofs"}} {
		spec := Spec{Profile: ProfileROv1, Cwd: "/", AcceptFS: accept}
		if spec.validate(false) == nil {
			t.Errorf("accepted %v", accept)
		}
	}
	spec := Spec{Profile: ProfileROv1, Cwd: "/", Strict: true, AcceptFS: []string{"network", "autofs"}, ParentNS: NSIDs{1, 2, 3, 4}}
	raw, _ := json.Marshal(spec)
	if err := decodeSpec(string(raw), new(Spec)); err != nil {
		t.Fatal(err)
	}
}
func TestJailEnvironment(t *testing.T) {
	t.Setenv("SSH_ORIGINAL_COMMAND", "secret")
	t.Setenv("TMPDIR", "/tmp")
	t.Setenv("PWD", "/forged")
	env := jailEnv("/actual")
	for _, value := range []string{"TMPDIR=/dev/shm", "TMP=/dev/shm", "TEMP=/dev/shm", "TMPPREFIX=/dev/shm", "HISTFILE=/dev/shm/.sh_history", "XDG_CACHE_HOME=/dev/shm/.cache", "XDG_STATE_HOME=/dev/shm/.state", "XDG_RUNTIME_DIR=/dev/shm", "LESSHISTFILE=-", "PWD=/actual"} {
		if !slices.Contains(env, value) {
			t.Error(value)
		}
	}
	for _, value := range env {
		if strings.HasPrefix(value, "SSH_ORIGINAL_COMMAND=") {
			t.Fatal("envelope leaked")
		}
	}
}
func TestReadSafeFstypesLiteral(t *testing.T) {
	if strings.Join(readSafeFstypes, " ") != "ext2 ext3 ext4 xfs btrfs vfat msdos exfat iso9660 squashfs tmpfs ramfs devtmpfs devpts proc sysfs cgroup cgroup2 pstore binfmt_misc fusectl nsfs selinuxfs" {
		t.Fatal(readSafeFstypes)
	}
	if strings.Join(networkFstypes, " ") != "nfs nfs4 cifs smb3 smbfs ceph 9p afs" {
		t.Fatal(networkFstypes)
	}
	for _, name := range strings.Fields("overlay erofs fuse fuse.portal fuseblk virtiofs rpc_pipefs mqueue hugetlbfs efivarfs bpf securityfs configfs zfs unknown") {
		if mountAccepted(mountEntry{fstype: name}, []string{"network", "autofs"}, backingInspector{sys: t.TempDir()}) {
			t.Errorf("accepted %s", name)
		}
	}
}
func TestBackingLiterals(t *testing.T) {
	if strings.Join(directDrivers, " ") != "pcieport nvme ahci ata_piix virtio-pci virtio_pci virtio-mmio virtio_mmio virtio_blk virtio_scsi sd xen-blkfront xen_blkfront vbd hv_storvsc storvsc mmcblk mmc_block sdhci-pci sdhci-pci-data sdhci-acpi mpt3sas mpt2sas megaraid_sas smartpqi aacraid hpsa vmw_pvscsi" {
		t.Fatal(directDrivers)
	}
	if strings.Join(directSCSIHosts, " ") != "ahci ata_piix virtio_scsi storvsc_host vmw_pvscsi mpt3sas mpt2sas megaraid_sas smartpqi aacraid hpsa" {
		t.Fatal(directSCSIHosts)
	}
}
func TestBackingClass(t *testing.T) {
	for _, test := range []struct {
		name, transport, driver string
		want                    backingClass
	}{{"nvme", "pcie", "nvme", backingDirect}, {"tcp", "tcp", "nvme-tcp", backingNetwork}, {"rdma", "rdma", "nvme-rdma", backingNetwork}, {"fc", "fc", "nvme-fc", backingNetwork}, {"loop", "loop", "nvme-loop", backingCovered}, {"unknown-driver", "pcie", "unknown", backingCovered}} {
		t.Run(test.name, func(t *testing.T) {
			sys := t.TempDir()
			disk := filepath.Join(sys, "devices/pci/nvme0/nvme0n1")
			mkdir(t, disk)
			write(t, filepath.Join(filepath.Dir(disk), "transport"), test.transport)
			driver := filepath.Join(sys, "drivers", test.driver)
			mkdir(t, driver)
			link(t, driver, filepath.Join(filepath.Dir(disk), "driver"))
			link(t, disk, filepath.Join(sys, "dev/block/259:0"))
			inspector := backingInspector{sys: sys}
			if got := inspector.device("259:0"); got != test.want {
				t.Fatalf("%v want %v", got, test.want)
			}
			if mountAccepted(mountEntry{fstype: "ext4", dev: "259:0"}, []string{"network"}, inspector) != (test.want != backingCovered) {
				t.Fatal("network acceptance")
			}
		})
	}
	for _, test := range []struct {
		name, driver, backing string
		want                  backingClass
	}{{"loop0", "", "", backingCovered}, {"nbd0", "", "", backingCovered}, {"ublkb0", "", "", backingCovered}, {"ram0", "", "", backingDirect}, {"zram0", "", "none", backingDirect}, {"zram0", "", "8:1", backingCovered}, {"vda", "virtio_blk", "", backingDirect}, {"xvda", "xen-blkfront", "", backingDirect}, {"mmcblk0", "mmcblk", "", backingDirect}, {"rbd0", "rbd", "", backingNetwork}} {
		t.Run(test.name+test.backing, func(t *testing.T) {
			sys := t.TempDir()
			disk := filepath.Join(sys, "devices", test.name)
			mkdir(t, disk)
			if test.backing != "" {
				write(t, filepath.Join(disk, "backing_dev"), test.backing)
			}
			if test.driver != "" {
				driver := filepath.Join(sys, "drivers", test.driver)
				mkdir(t, driver)
				link(t, driver, filepath.Join(disk, "driver"))
			}
			if got := (backingInspector{sys: sys}).chain(disk, 0, map[string]bool{}); got != test.want {
				t.Fatalf("%v want %v", got, test.want)
			}
		})
	}
}
func mkdir(t *testing.T, path string) {
	t.Helper()
	if err := os.MkdirAll(path, 0755); err != nil {
		t.Fatal(err)
	}
}
func write(t *testing.T, path, value string) {
	t.Helper()
	mkdir(t, filepath.Dir(path))
	if err := os.WriteFile(path, []byte(value), 0644); err != nil {
		t.Fatal(err)
	}
}
func link(t *testing.T, target, path string) {
	t.Helper()
	mkdir(t, filepath.Dir(path))
	if err := os.Symlink(target, path); err != nil {
		t.Fatal(err)
	}
}

func TestBackingChains(t *testing.T) {
	sys := t.TempDir()
	inspector := backingInspector{sys: sys}
	inspector.auxiliaryDevice = func(path string) (string, error) {
		dev := inspector.read(filepath.Join(sys, "class/block", strings.TrimPrefix(path, "/dev/"), "dev"))
		if dev == "" {
			return "", os.ErrNotExist
		}
		return dev, nil
	}
	disk := func(name, dev, driver string) string {
		path := filepath.Join(sys, "devices", name)
		mkdir(t, path)
		if driver != "" {
			driverPath := filepath.Join(sys, "drivers", driver)
			mkdir(t, driverPath)
			link(t, driverPath, filepath.Join(path, "driver"))
		}
		link(t, path, filepath.Join(sys, "dev/block", dev))
		link(t, path, filepath.Join(sys, "class/block", filepath.Base(path)))
		write(t, filepath.Join(path, "dev"), dev)
		return path
	}
	nvme := disk("pci/nvme0/nvme0n1", "259:0", "nvme")
	write(t, filepath.Join(filepath.Dir(nvme), "transport"), "pcie")
	partition := filepath.Join(nvme, "nvme0n1p1")
	mkdir(t, partition)
	write(t, filepath.Join(partition, "partition"), "1")
	link(t, partition, filepath.Join(sys, "dev/block/259:1"))
	loop := disk("virtual/loop0", "7:0", "")
	tcp := disk("virtual/nvme1/nvme1n1", "259:2", "nvme-tcp")
	write(t, filepath.Join(filepath.Dir(tcp), "transport"), "tcp")
	chain := func(name, dev, directory string, paths ...string) string {
		path := disk("virtual/"+name, dev, "")
		for _, child := range paths {
			link(t, child, filepath.Join(path, directory, filepath.Base(child)))
		}
		return path
	}
	chain("dm-0", "253:0", "slaves", nvme)
	chain("dm-1", "253:1", "slaves", loop)
	chain("md0", "9:0", "slaves", nvme, tcp)
	nvmePath := disk("pci/nvme0/nvme0c0n1", "259:4", "nvme")
	chain("nvme2n1", "259:3", "multipath", nvmePath)
	for dev, want := range map[string]backingClass{"259:1": backingDirect, "253:0": backingDirect, "253:1": backingCovered, "9:0": backingNetwork, "259:3": backingDirect, "0:1": backingCovered, "999:0": backingCovered} {
		if got := inspector.device(dev); got != want {
			t.Errorf("%s=%v want %v", dev, got, want)
		}
	}
	previous := nvme
	for i := 0; i < 10; i++ {
		previous = chain(fmt.Sprintf("dm-depth-%d", i), fmt.Sprintf("254:%d", i), "slaves", previous)
	}
	if inspector.device("254:9") != backingCovered {
		t.Error("depth admitted")
	}
	for _, test := range []struct {
		options []string
		want    backingClass
	}{{[]string{"logdev=/dev/nvme0n1", "rtdev=/dev/nvme0n1"}, backingDirect}, {[]string{"logdev=/dev/loop0"}, backingCovered}, {[]string{"logdev=/dev/nvme1n1"}, backingNetwork}, {[]string{"rtdev=/dev/missing"}, backingCovered}, {[]string{"logdev=/dev/nvme1n1", "rtdev=/dev/loop0"}, backingCovered}} {
		entry := mountEntry{fstype: "xfs", dev: "259:0", superOpts: test.options}
		if got := inspector.mount(entry); got != test.want {
			t.Errorf("xfs %v=%v want %v", test.options, got, test.want)
		}
	}
	link(t, nvme, filepath.Join(sys, "fs/btrfs/fsid/devices/nvme"))
	if inspector.mount(mountEntry{fstype: "btrfs"}) != backingDirect {
		t.Error("btrfs direct")
	}
	link(t, loop, filepath.Join(sys, "fs/btrfs/other/devices/loop"))
	if inspector.mount(mountEntry{fstype: "btrfs"}) != backingCovered {
		t.Error("btrfs union")
	}
}
func TestBackingSCSITransports(t *testing.T) {
	tests := []struct {
		name, host, class, ancestor string
		want                        backingClass
	}{
		{"virtio", "virtio_scsi", "", "", backingDirect}, {"hyperv", "storvsc_host", "", "", backingDirect}, {"sas", "mpt3sas", "", "", backingDirect}, {"unknown", "unknown", "", "", backingCovered},
		{"iscsi", "iscsi_tcp", "iscsi_host", "session1", backingNetwork}, {"fc", "qla2xxx", "fc_host", "rport-1", backingNetwork}, {"fcoe", "fcoe", "fc_host", "", backingNetwork}, {"srp", "ib_srp", "srp_host", "", backingNetwork}, {"usbip", "usb-storage", "", "vhci_hcd.0", backingNetwork},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			sys := t.TempDir()
			path := filepath.Join(sys, "devices/platform", test.ancestor, "host1/target1/block/sda")
			mkdir(t, path)
			write(t, filepath.Join(sys, "class/scsi_host/host1/proc_name"), test.host)
			if test.class != "" {
				mkdir(t, filepath.Join(sys, "class", test.class, "host1"))
			}
			if got := (backingInspector{sys: sys}).chain(path, 0, map[string]bool{}); got != test.want {
				t.Fatalf("%v want %v", got, test.want)
			}
		})
	}
}
func TestBackingUnknownAncestorAndBrokenDriver(t *testing.T) {
	for _, broken := range []bool{false, true} {
		t.Run(fmt.Sprint(broken), func(t *testing.T) {
			sys := t.TempDir()
			path := filepath.Join(sys, "devices/pci/nvme0/nvme0n1")
			mkdir(t, path)
			write(t, filepath.Join(filepath.Dir(path), "transport"), "pcie")
			driver := filepath.Join(sys, "drivers/unreviewed")
			if !broken {
				mkdir(t, driver)
			}
			link(t, driver, filepath.Join(sys, "devices/pci/driver"))
			if (backingInspector{sys: sys}).chain(path, 0, map[string]bool{}) != backingCovered {
				t.Fatal("unverified driver admitted")
			}
		})
	}
}

func TestParseHostMountInfo(t *testing.T) {
	if _, err := readMountInfo(); err != nil {
		t.Fatal(err)
	}
}

func TestWalkToCheckedComponents(t *testing.T) {
	entries, err := readMountInfo()
	if err != nil {
		t.Fatal(err)
	}
	root, err := unix.Open("/", unix.O_PATH|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	rootID, err := mountID(root)
	unix.Close(root)
	if err != nil {
		t.Fatal(err)
	}
	view := reachableMounts(entries, rootID)
	accepted := map[int]bool{}
	for _, entry := range view.entries {
		accepted[entry.id] = true
	}
	directory := t.TempDir()
	closed := filepath.Join(directory, "closed")
	mkdir(t, closed)
	mkdir(t, filepath.Join(closed, "child"))
	result := walkTo(filepath.Join(closed, "child"), view, accepted, nil)
	if result.err != nil {
		t.Fatal(result.err)
	}
	result.close()
	result = walkTo(directory, view, map[int]bool{}, nil)
	if result.err != unix.ESTALE {
		t.Fatalf("unconfirmed root traversed: %v", result.err)
	}
	result.close()
	if os.Getuid() != 0 {
		if err := os.Chmod(closed, 0); err != nil {
			t.Fatal(err)
		}
		defer os.Chmod(closed, 0700)
		result = walkTo(filepath.Join(closed, "child"), view, accepted, nil)
		defer result.close()
		if result.err != unix.EACCES || result.denied != closed || result.parent < 0 {
			t.Fatalf("denied component: %+v", result)
		}
	}
}
func TestAuxiliaryDeviceRefusesSymlinkAndNonDevice(t *testing.T) {
	inspector := backingInspector{sys: "/sys"}
	path := filepath.Join(t.TempDir(), "node")
	write(t, path, "not a device")
	if _, err := inspector.resolveAuxiliaryDevice(path); err == nil {
		t.Fatal("accepted regular file")
	}
	link(t, "/dev/null", path+"-link")
	if _, err := inspector.resolveAuxiliaryDevice(path + "-link"); err == nil {
		t.Fatal("accepted symlink")
	}
}

func TestDevNodesLiteral(t *testing.T) {
	if strings.Join(devNodes, " ") != "null zero full random urandom tty" {
		t.Fatal(devNodes)
	}
}

func TestBtrfsEnumerationErrorsCover(t *testing.T) {
	for _, kind := range []string{"dangling", "not-directory", "empty"} {
		t.Run(kind, func(t *testing.T) {
			sys := t.TempDir()
			disk := filepath.Join(sys, "devices/ram0")
			mkdir(t, disk)
			write(t, filepath.Join(disk, "dev"), "1:0")
			link(t, disk, filepath.Join(sys, "dev/block/1:0"))
			link(t, disk, filepath.Join(sys, "fs/btrfs/good/devices/disk"))
			bad := filepath.Join(sys, "fs/btrfs/bad/devices")
			switch kind {
			case "dangling":
				link(t, filepath.Join(sys, "absent"), bad)
			case "not-directory":
				write(t, bad, "bad")
			case "empty":
				mkdir(t, bad)
			}
			if (backingInspector{sys: sys}).mount(mountEntry{fstype: "btrfs"}) != backingCovered {
				t.Fatal("partial btrfs union admitted")
			}
		})
	}
}

func TestBackingOptionalMetadataErrors(t *testing.T) {
	for _, property := range []string{"partition", "slaves", "multipath", "driver"} {
		t.Run(property, func(t *testing.T) {
			sys := t.TempDir()
			disk := filepath.Join(sys, "devices/ram0")
			mkdir(t, disk)
			link(t, filepath.Join(sys, "missing"), filepath.Join(disk, property))
			if (backingInspector{sys: sys}).chain(disk, 0, map[string]bool{}) != backingCovered {
				t.Fatalf("broken %s treated absent", property)
			}
		})
	}
	sys := t.TempDir()
	if (backingInspector{sys: sys}).chain(filepath.Join(sys, "devices/ram0"), 0, map[string]bool{}) != backingCovered {
		t.Fatal("missing RAM disk accepted")
	}
}
