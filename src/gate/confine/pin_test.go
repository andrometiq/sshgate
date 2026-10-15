package confine

import (
	"errors"
	"reflect"
	"strings"
	"testing"
)

func TestParsePin(t *testing.T) {
	const base = "profile=ro-v1\nnet=deny\n"
	valid := []struct {
		name string
		in   string
		want Pin
	}{
		{"minimal", base, Pin{Profile: "ro-v1"}},
		{"no final newline", "profile=ro-v1\nnet=allow", Pin{Profile: "ro-v1", Net: true}},
		{"comments and blank lines", "# operator note\n\nnet=deny\n#x=y\nprofile=ro-v1\n\n", Pin{Profile: "ro-v1"}},
		{"accept_fs keeps order", base + "accept_fs=autofs,network\n", Pin{Profile: "ro-v1", AcceptFS: []string{"autofs", "network"}}},
		{"docker_socket", base + "docker_socket=/run/docker.sock\n", Pin{Profile: "ro-v1", DockerSocket: "/run/docker.sock"}},
		{"docker_socket at sun_path limit", base + "docker_socket=/" + strings.Repeat("s", 106) + "\n", Pin{Profile: "ro-v1", DockerSocket: "/" + strings.Repeat("s", 106)}},
		{"exactly 4096 bytes", base + "#" + strings.Repeat("x", MaxPinBytes-len(base)-2) + "\n", Pin{Profile: "ro-v1"}},
	}
	for _, c := range valid {
		t.Run(c.name, func(t *testing.T) {
			got, err := ParsePin([]byte(c.in))
			if err != nil || !reflect.DeepEqual(got, c.want) {
				t.Fatalf("ParsePin = %+v, %v; want %+v", got, err, c.want)
			}
		})
	}

	damaged := []struct {
		name   string
		in     string
		line   int
		reason string
	}{
		{"empty", "", 0, `missing key "profile"`},
		{"missing net", "profile=ro-v1\n", 0, `missing key "net"`},
		{"missing profile", "net=deny\n", 0, `missing key "profile"`},
		{"4097 bytes", base + "#" + strings.Repeat("x", MaxPinBytes-len(base)-1) + "\n", 0, "larger than 4096 bytes"},
		{"other profile", "profile=ro-v2\nnet=deny\n", 1, `bad value for "profile"`},
		{"net not allow or deny", "profile=ro-v1\nnet=yes\n", 2, `bad value for "net"`},
		{"unknown key", base + "floor=full\n", 3, `unknown key "floor"`},
		{"duplicate key", base + "profile=ro-v1\n", 3, `duplicate key "profile"`},
		{"space around =", "profile = ro-v1\nnet=deny\n", 1, "not key=value"},
		{"leading space", " profile=ro-v1\nnet=deny\n", 1, "not key=value"},
		{"indented comment", base + " # note\n", 3, "not key=value"},
		{"whitespace-only line", base + "   \n", 3, "not key=value"},
		{"no =", base + "net\n", 3, "not key=value"},
		{"empty key", base + "=x\n", 3, "not key=value"},
		{"upper-case key", "PROFILE=ro-v1\nnet=deny\n", 1, "not key=value"},
		{"empty value", "profile=ro-v1\nnet=\n", 2, "not key=value"},
		{"space in value", "profile=ro-v1\nnet=deny now\n", 2, "not key=value"},
		{"carriage return", "profile=ro-v1\r\nnet=deny\n", 1, "invalid byte"},
		{"tab", "profile=ro-v1\nnet=deny\t\n", 2, "invalid byte"},
		{"NUL", base + "#\x00\n", 3, "invalid byte"},
		{"non-ASCII", base + "# caf\xc3\xa9\n", 3, "invalid byte"},
		{"accept_fs empty element", base + "accept_fs=network,\n", 3, `bad value for "accept_fs"`},
		{"accept_fs duplicate", base + "accept_fs=network,network\n", 3, `bad value for "accept_fs"`},
		{"accept_fs unknown class", base + "accept_fs=nfs\n", 3, `bad value for "accept_fs"`},
		{"docker_socket relative", base + "docker_socket=run/docker.sock\n", 3, `bad value for "docker_socket"`},
		{"docker_socket root", base + "docker_socket=/\n", 3, `bad value for "docker_socket"`},
		{"docker_socket unclean", base + "docker_socket=/run//docker.sock\n", 3, `bad value for "docker_socket"`},
		{"docker_socket dot-dot", base + "docker_socket=/run/../docker.sock\n", 3, `bad value for "docker_socket"`},
		{"docker_socket too long", base + "docker_socket=/" + strings.Repeat("s", 107) + "\n", 3, `bad value for "docker_socket"`},
	}
	for _, c := range damaged {
		t.Run("damaged/"+c.name, func(t *testing.T) {
			got, err := ParsePin([]byte(c.in))
			var pinErr *PinError
			if !errors.As(err, &pinErr) || pinErr.Line != c.line || pinErr.Reason != c.reason {
				t.Fatalf("ParsePin = %+v, %v; want line %d %q", got, err, c.line, c.reason)
			}
			if !reflect.DeepEqual(got, Pin{}) {
				t.Fatalf("a damaged pin returned values: %+v", got)
			}
		})
	}
}

func TestPinCanonicalRoundTrip(t *testing.T) {
	pin := Pin{Profile: "ro-v1", Net: true, DockerSocket: "/run/docker.sock", AcceptFS: []string{"network", "autofs"}}
	want := "# written by gate doctor\nprofile=ro-v1\nnet=allow\naccept_fs=network,autofs\ndocker_socket=/run/docker.sock\n"
	if got := string(pin.Canonical()); got != want {
		t.Fatalf("Canonical = %q, want %q", got, want)
	}
	if got, err := ParsePin(pin.Canonical()); err != nil || !reflect.DeepEqual(got, pin) {
		t.Fatalf("round trip = %+v, %v", got, err)
	}
	if got := string((Pin{Profile: "ro-v1"}).Canonical()); got != "# written by gate doctor\nprofile=ro-v1\nnet=deny\n" {
		t.Fatalf("minimal Canonical = %q", got)
	}
}

func FuzzParsePin(f *testing.F) {
	for _, seed := range []string{
		"profile=ro-v1\nnet=deny\n",
		"profile=ro-v1\nnet=allow\naccept_fs=network,autofs\ndocker_socket=/run/docker.sock",
		"# c\n\nnet=deny\nprofile=ro-v1\n",
		"profile=ro-v1\nnet=deny\nnet=allow\n",
		"profile=ro-v1\r\nnet=deny\n",
		"",
	} {
		f.Add([]byte(seed))
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		pin, err := ParsePin(data)
		if err != nil {
			var pinErr *PinError
			if !errors.As(err, &pinErr) || !reflect.DeepEqual(pin, Pin{}) {
				t.Fatalf("damaged pin: %+v, %v", pin, err)
			}
			return
		}
		if pin.Profile != ProfileROv1 {
			t.Fatalf("accepted profile %q", pin.Profile)
		}
		again, err := ParsePin(pin.Canonical())
		if err != nil || !reflect.DeepEqual(again, pin) {
			t.Fatalf("canonical form of %+v parsed to %+v, %v", pin, again, err)
		}
	})
}
