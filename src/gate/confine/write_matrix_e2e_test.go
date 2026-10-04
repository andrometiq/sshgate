//go:build linux && jail_e2e

package confine

import (
	"bytes"
	"encoding/binary"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/karthikeyan5/sshgate/src/gate/confine/jailmut"
	"golang.org/x/sys/unix"
)

func TestJailMatrixWrite(t *testing.T) {
	for _, cfg := range []struct {
		name string
		abi  int
	}{{"native", 0}, {"abi1", 1}} {
		t.Run(cfg.name, func(t *testing.T) {
			spec := Spec{Profile: ProfileROv1, ForceABI: cfg.abi, Net: true}
			t.Run("L-FIFO-WRITE", func(t *testing.T) { legFifo(t, spec) })
			t.Run("L-WRITE-ERRNO", func(t *testing.T) {
				probe := buildProbe(t)
				bad := false
				for _, submount := range []bool{false, true} {
					directory := writeSweepFixture(t, submount)
					seedWriteSweep(t, directory)
					output := requireProbeOutput(t, runP12(t, spec, probe+" write-sweep "+directory, nil), writeSweepOperations...)
					if jailmut.On("P-RO") && !jailmut.On("P-LL-FS") {
						for _, op := range []string{"write", "append", "open-trunc"} {
							if !strings.Contains(output, op+"=13\n") {
								t.Fatalf("SETUP: Landlock write denial invariant failed for %s: %s", op, output)
							}
						}
					}
					for _, op := range []string{"write", "append", "open-trunc", "open-rdonly-trunc", "truncate-path"} {
						bad = bad || !strings.Contains(output, op+"=30\n")
					}
				}
				mutationEffect(t, "L-WRITE-ERRNO", "errno", bad)
			})
			metadata := func(t *testing.T, leg string, mounts ...bool) {
				var effects map[string]bool
				for _, submount := range mounts {
					observed := legMetadataMount(t, spec, submount)
					if effects == nil {
						effects = observed
					} else {
						for key := range effects {
							effects[key] = effects[key] && observed[key]
						}
					}
				}
				for effect, changed := range effects {
					mutationEffect(t, leg, "metadata-"+effect, changed)
				}
			}
			t.Run("L-META-EROFS", func(t *testing.T) { metadata(t, "L-META-EROFS", false, true) })
			t.Run("L-META-ROOT", func(t *testing.T) { metadata(t, "L-META-ROOT", false) })
			t.Run("L-META-SUBMOUNT", func(t *testing.T) { metadata(t, "L-META-SUBMOUNT", true) })

		})
	}
}

type metadataSnapshot struct {
	mode           os.FileMode
	mtime          int64
	flags          int
	acl, removeACL []byte
}

func readMetadata(t *testing.T, path string) metadataSnapshot {
	t.Helper()
	info, err := os.Stat(path)
	mutationSetup(t, err)
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC, 0)
	mutationSetup(t, err)
	defer unix.Close(fd)
	flags, err := unix.IoctlGetInt(fd, unix.FS_IOC_GETFLAGS)
	mutationSetup(t, err)
	readACL := func(name string) []byte {
		data := make([]byte, 4096)
		n, err := unix.Getxattr(name, "system.posix_acl_access", data)
		if err == unix.ENODATA {
			return nil
		}
		mutationSetup(t, err)
		return data[:n]
	}
	return metadataSnapshot{info.Mode(), info.ModTime().UnixNano(), flags, readACL(path), readACL(path + "-remove")}
}

func metadataChanges(before, after metadataSnapshot) map[string]bool {
	return map[string]bool{"mode": before.mode != after.mode, "mtime": before.mtime != after.mtime, "flags": before.flags != after.flags, "xattr-set": !bytes.Equal(before.acl, after.acl), "xattr-remove": !bytes.Equal(before.removeACL, after.removeACL)}
}

func legMetadataMount(t *testing.T, spec Spec, submount bool) map[string]bool {
	probe := buildProbe(t)
	directory := writeSweepFixture(t, submount)
	path := filepath.Join(directory, "owned")
	seed := func() {
		for _, name := range []string{path, path + "-remove"} {
			mutationSetup(t, os.RemoveAll(name))
			mutationSetup(t, os.WriteFile(name, []byte("canary"), 0600))
		}
		// ACL xattrs work on tmpfs on kernel 6.1, where user.* xattrs do not.
		acl := make([]byte, 36)
		binary.LittleEndian.PutUint32(acl, 2)
		for i, entry := range []struct{ tag, permissions uint16 }{{1, 6}, {4, 4}, {16, 4}, {32, 0}} {
			offset := 4 + 8*i
			binary.LittleEndian.PutUint16(acl[offset:], entry.tag)
			binary.LittleEndian.PutUint16(acl[offset+2:], entry.permissions)
			binary.LittleEndian.PutUint32(acl[offset+4:], ^uint32(0))
		}
		mutationSetup(t, unix.Setxattr(path+"-remove", "system.posix_acl_access", acl, 0))
	}
	seed()
	before := readMetadata(t, path)
	control, err := exec.Command(probe, "metadata-mount", path).CombinedOutput()
	mutationSetup(t, err)
	operations := []string{"chmod", "chown", "setxattr", "removexattr", "utimensat", "setflags"}
	for _, op := range operations {
		if !strings.Contains(string(control), op+"=ok\n") {
			t.Fatalf("SETUP: %s control: %s", op, control)
		}
	}
	for effect, changed := range metadataChanges(before, readMetadata(t, path)) {
		if !changed {
			t.Fatalf("SETUP: control did not change %s", effect)
		}
	}
	seed()
	before = readMetadata(t, path)
	output := requireProbeOutput(t, runP12(t, spec, probe+" metadata-mount "+path, nil), operations...)
	want := "1"
	fullEffect := jailmut.On("P-SC-META") && jailmut.On("P-RO") && jailmut.On("P-SELFCHECK-MOUNTS")
	if jailmut.On("P-SC-META") {
		want = "30"
	}
	for _, op := range operations {
		if fullEffect {
			if !strings.Contains(output, op+"=ok\n") {
				unexpected(t, "%s mutation did not succeed: %s", op, output)
			}
			continue
		}
		if !strings.Contains(output, op+"="+want+"\n") {
			unexpected(t, "%s expected errno %s: %s", op, want, output)
		}
	}
	return metadataChanges(before, readMetadata(t, path))
}
