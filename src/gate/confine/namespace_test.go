//go:build linux

package confine

import (
	"reflect"
	"strings"
	"testing"
)

const mountinfoFixture = `22 1 8:2 / / rw,relatime shared:1 - ext4 /dev/sda2 rw
23 22 0:5 / /dev rw,nosuid master:2 - devtmpfs devtmpfs rw
24 22 0:21 / /tmp rw,nosuid,nodev - tmpfs tmpfs rw
25 22 0:30 / /mnt/with\040space\011tab rw,noexec,noatime,nodiratime - tmpfs tmpfs rw
26 22 0:31 / /mnt/back\134slash\012nl ro,nosymfollow - tmpfs tmpfs rw
27 24 0:32 / /tmp rw,noexec,relatime - tmpfs tmpfs rw
`

func TestParseMountInfo(t *testing.T) {
	got, err := parseMountInfo(strings.NewReader(mountinfoFixture))
	if err != nil {
		t.Fatal(err)
	}
	want := []mountEntry{
		{id: 22, parent: 1, dev: "8:2", root: "/", point: "/", opts: []string{"rw", "relatime"}, optional: []string{"shared:1"}, fstype: "ext4", source: "/dev/sda2", superOpts: []string{"rw"}},
		{id: 23, parent: 22, dev: "0:5", root: "/", point: "/dev", opts: []string{"rw", "nosuid"}, optional: []string{"master:2"}, fstype: "devtmpfs", source: "devtmpfs", superOpts: []string{"rw"}},
		{id: 24, parent: 22, dev: "0:21", root: "/", point: "/tmp", opts: []string{"rw", "nosuid", "nodev"}, optional: []string{}, fstype: "tmpfs", source: "tmpfs", superOpts: []string{"rw"}},
		{id: 25, parent: 22, dev: "0:30", root: "/", point: "/mnt/with space\ttab", opts: []string{"rw", "noexec", "noatime", "nodiratime"}, optional: []string{}, fstype: "tmpfs", source: "tmpfs", superOpts: []string{"rw"}},
		{id: 26, parent: 22, dev: "0:31", root: "/", point: "/mnt/back\\slash\nnl", opts: []string{"ro", "nosymfollow"}, optional: []string{}, fstype: "tmpfs", source: "tmpfs", superOpts: []string{"rw"}},
		{id: 27, parent: 24, dev: "0:32", root: "/", point: "/tmp", opts: []string{"rw", "noexec", "relatime"}, optional: []string{}, fstype: "tmpfs", source: "tmpfs", superOpts: []string{"rw"}},
	}

	if !reflect.DeepEqual(got, want) {
		t.Fatalf("parseMountInfo:\n got %#v\nwant %#v", got, want)
	}
}

func TestParseMountInfoRejectsMalformed(t *testing.T) {
	for _, bad := range []string{
		"22 1 8:2 / /\n",                       // too few fields
		"x 1 8:2 / / rw - ext4 /dev/sda2 rw\n", // non-numeric id
		"22 1 8:2 / /a\\04 rw - ext4 x rw\n",   // truncated escape
		"22 1 8:2 / /a\\09x rw - ext4 x rw\n",  // non-octal escape
		"22 1 8:2 / /a\\777 rw - ext4 x rw\n",  // escape overflows a byte
	} {
		if _, err := parseMountInfo(strings.NewReader(bad)); err == nil {
			t.Errorf("parseMountInfo(%q) accepted a malformed line", bad)
		}
	}
}
