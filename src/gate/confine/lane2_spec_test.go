//go:build linux

package confine

import (
	"encoding/json"
	"errors"
	"os"
	"strings"
	"syscall"
	"testing"
)

// lane2TestSpec is a valid daemon-read Spec as the worker decodes it.
func lane2TestSpec() Spec {
	return Spec{Profile: ProfileROv1, Cwd: "/", ParentNS: NSIDs{1, 2, 3, 4}, Lane2: &Lane2{
		Client: "docker", Binary: "/usr/bin/docker", BinaryID: FileID{1, 10}, BinaryFD: 5,
		Interp: "/usr/lib/ld.so", InterpID: FileID{1, 11}, InterpFD: 6,
		Sockets: []Endpoint{{Path: "/run/docker.sock", ID: FileID{2, 12}, FD: 7}},
	}}
}

func TestLane2SpecValidate(t *testing.T) {
	if err := lane2TestSpec().validate(true); err != nil {
		t.Fatalf("valid spec: %v", err)
	}
	static := lane2TestSpec()
	static.Lane2.Interp, static.Lane2.InterpID, static.Lane2.InterpFD = "", FileID{}, 0
	static.Lane2.Sockets[0].FD = 6
	if err := static.validate(true); err != nil {
		t.Fatalf("static client: %v", err)
	}
	two := lane2TestSpec()
	two.Lane2.Client = "systemctl"
	two.Lane2.Sockets = append(two.Lane2.Sockets, Endpoint{Path: "/run/systemd/private", ID: FileID{2, 13}, FD: 8})
	if err := two.validate(true); err != nil {
		t.Fatalf("two sockets: %v", err)
	}
	long := "/" + strings.Repeat("s", 107)
	for name, change := range map[string]func(*Spec){
		"unknown client":              func(s *Spec) { s.Lane2.Client = "kubectl" },
		"relative binary":             func(s *Spec) { s.Lane2.Binary = "usr/bin/docker" },
		"unclean binary":              func(s *Spec) { s.Lane2.Binary = "/usr/bin/../bin/docker" },
		"NUL in binary":               func(s *Spec) { s.Lane2.Binary = "/usr/bin/doc\x00ker" },
		"zero binary ID":              func(s *Spec) { s.Lane2.BinaryID = FileID{} },
		"relative interpreter":        func(s *Spec) { s.Lane2.Interp = "lib/ld.so" },
		"interpreter without ID":      func(s *Spec) { s.Lane2.InterpID = FileID{} },
		"ID without interpreter":      func(s *Spec) { s.Lane2.Interp = "" },
		"no socket":                   func(s *Spec) { s.Lane2.Sockets = nil },
		"three sockets":               func(s *Spec) { s.Lane2.Sockets = append(s.Lane2.Sockets, s.Lane2.Sockets[0], s.Lane2.Sockets[0]) },
		"relative socket":             func(s *Spec) { s.Lane2.Sockets[0].Path = "run/docker.sock" },
		"unclean socket":              func(s *Spec) { s.Lane2.Sockets[0].Path = "/run//docker.sock" },
		"NUL in socket":               func(s *Spec) { s.Lane2.Sockets[0].Path = "/run/doc\x00ker.sock" },
		"socket path over 107 bytes":  func(s *Spec) { s.Lane2.Sockets[0].Path = long },
		"zero socket ID":              func(s *Spec) { s.Lane2.Sockets[0].ID = FileID{} },
		"cwd not /":                   func(s *Spec) { s.Cwd = "/tmp" },
		"network":                     func(s *Spec) { s.Net = true },
		"binary fd not 5":             func(s *Spec) { s.Lane2.BinaryFD = 3 },
		"interpreter fd out of order": func(s *Spec) { s.Lane2.InterpFD = 7 },
		"socket fd reused":            func(s *Spec) { s.Lane2.Sockets[0].FD = 6 },
	} {
		spec := lane2TestSpec()
		lane2 := *spec.Lane2
		lane2.Sockets = append([]Endpoint(nil), lane2.Sockets...)
		spec.Lane2 = &lane2
		change(&spec)
		if spec.validate(true) == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	for _, stage := range []string{"lane2argv:EINVAL", "lane2id:EACCES"} {
		if err := (Spec{Profile: ProfileROv1, InjectFailAt: stage}).validate(false); err != nil {
			t.Errorf("inject stage %s rejected: %v", stage, err)
		}
	}
}

func TestArgvCodec(t *testing.T) {
	argv := []string{"/usr/bin/docker", "--host=unix:///run/docker.sock", "ps", "--format={{json .}}"}
	got, err := DecodeArgv(EncodeArgv(argv), "docker")
	if err != nil || strings.Join(got, " ") != strings.Join(argv, " ") {
		t.Fatalf("round trip = %q, %v", got, err)
	}
	for name, command := range map[string]string{
		"one token":       "/usr/bin/docker",
		"empty token":     "/usr/bin/docker\x00\x00ps",
		"relative name":   "docker\x00ps",
		"unclean name":    "/usr/bin/../bin/docker\x00ps",
		"another client":  "/usr/bin/systemctl\x00status",
		"65 tokens":       "/usr/bin/docker" + strings.Repeat("\x00ps", 64),
		"over 4096 bytes": "/usr/bin/docker\x00" + strings.Repeat("a", 4097),
	} {
		if _, err := DecodeArgv(command, "docker"); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if _, err := DecodeArgv("/usr/bin/docker"+strings.Repeat("\x00ps", 63), "docker"); err != nil {
		t.Errorf("64 tokens refused: %v", err)
	}
}

func FuzzArgvCodec(f *testing.F) {
	for _, seed := range []string{"/usr/bin/docker\x00ps", "/usr/bin/systemctl\x00status\x00a", "", "\x00", "/usr/bin/docker\x00\x00"} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, command string) {
		for _, client := range []string{"docker", "systemctl"} {
			argv, err := DecodeArgv(command, client)
			if err != nil {
				continue
			}
			if EncodeArgv(argv) != command || len(argv) < 2 || len(argv) > 64 || !strings.HasSuffix(argv[0], "/"+client) {
				t.Fatalf("decode(%q) = %q", command, argv)
			}
		}
	})
}

// TestStatusLane2Mismatch: the worker's lane2 fact must match the Spec either
// way, else the report is Failed.
func TestStatusLane2Mismatch(t *testing.T) {
	report := func(lane2 bool) string {
		raw, _ := json.Marshal(map[string]any{"profile": ProfileROv1, "abi": 2, "net": false, "lane2": lane2})
		return "I" + string(raw) + "\nX"
	}
	for _, test := range []struct {
		name      string
		spec      Spec
		lane2, ok bool
	}{
		{"plain read", Spec{Profile: ProfileROv1}, false, true},
		{"plain spec, lane2 report", Spec{Profile: ProfileROv1}, true, false},
		{"lane2 read", lane2TestSpec(), true, true},
		{"lane2 spec, plain report", lane2TestSpec(), false, false},
	} {
		reader, writer, err := os.Pipe()
		if err != nil {
			t.Fatal(err)
		}
		_, _ = writer.WriteString(report(test.lane2))
		writer.Close()
		jailed := Jailed{statusR: reader, spec: test.spec}
		_, err = jailed.Status()
		var setup *SetupError
		if test.ok && err != nil || !test.ok && (!errors.As(err, &setup) || setup.Stage != "report") {
			t.Errorf("%s: %v", test.name, err)
		}
	}
}

// TestLane2StagesFailed: a daemon read's own setup failures are always Failed,
// even with the errnos that make a landlock failure Absent, so a daemon read
// never falls back unjailed for a reason a plain read would not.
func TestLane2StagesFailed(t *testing.T) {
	noJail := HostFacts{MaxUserNS: 0, AppArmorUsernsClamp: true, LandlockABI: -1, LandlockErrno: syscall.ENOSYS}
	for _, stage := range []string{"lane2argv", "lane2id"} {
		for _, errno := range []syscall.Errno{0, syscall.ENOSYS, syscall.EOPNOTSUPP, syscall.EPERM, syscall.EACCES, syscall.EINVAL, syscall.ENOENT, syscall.ESTALE, syscall.EBADF} {
			if AbsentCandidate(stage, errno) || ClassifySetupFailure(stage, errno, noJail) != Failed || ClassifySetupFailure(stage, errno, HostFacts{}) != Failed {
				t.Errorf("%s:%v is not always Failed", stage, errno)
			}
		}
	}
}

// TestStrictSpecDecodeLane2: the worker's decoder takes a daemon-read Spec
// exactly, and never the held files or an unknown field.
func TestStrictSpecDecodeLane2(t *testing.T) {
	raw, err := json.Marshal(lane2TestSpec())
	if err != nil {
		t.Fatal(err)
	}
	var spec Spec
	if err := decodeSpec(string(raw), &spec); err != nil || spec.Lane2 == nil || spec.Lane2.Sockets[0].FD != 7 {
		t.Fatalf("decode = %+v, %v", spec.Lane2, err)
	}
	for name, mutate := range map[string]func(string) string{
		"held file field":   func(s string) string { return strings.Replace(s, `"Client"`, `"BinaryFile":{},"Client"`, 1) },
		"unknown field":     func(s string) string { return strings.Replace(s, `"Client"`, `"Extra":1,"Client"`, 1) },
		"socket file field": func(s string) string { return strings.Replace(s, `"Path"`, `"File":3,"Path"`, 1) },
		"network":           func(s string) string { return strings.Replace(s, `"Net":false`, `"Net":true`, 1) },
	} {
		var decoded Spec
		if err := decodeSpec(mutate(string(raw)), &decoded); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	plain, _ := json.Marshal(Spec{Profile: ProfileROv1})
	if strings.Contains(string(plain), "Lane2") {
		t.Errorf("a plain Spec's wire form changed: %s", plain)
	}
}
