package main

import (
	"strings"
	"testing"

	"github.com/karthikeyan5/sshgate/src/sigwire"
)

var envelopeCases = []struct {
	name, raw string
	want      envelope
	valid     bool
}{
	{"confined", "SSHGATE_READ1 confined cat /file", envelope{cmd: "cat /file"}, true},
	{"network", "SSHGATE_READ1 confined,net cat /file", envelope{net: true, cmd: "cat /file"}, true},
	{"reverse", "SSHGATE_READ1 net,confined cat /file", envelope{net: true, cmd: "cat /file"}, true},
	{"command-leading-space", "SSHGATE_READ1 confined  cat /file", envelope{cmd: " cat /file"}, true},
	{"command-bytes", "SSHGATE_READ1 confined \tcat\r\n\x00\xff  ", envelope{cmd: "\tcat\r\n\x00\xff  "}, true},
	{"signed-inner", "SSHGATE_READ1 confined SSHGATE_SIG:payload", envelope{cmd: "SSHGATE_SIG:payload"}, true},
	{"jail-inner", "SSHGATE_READ1 confined SSHGATE_JAIL", envelope{cmd: "SSHGATE_JAIL"}, true},
	{"version-inner", "SSHGATE_READ1 confined SSHGATE_VERSION", envelope{cmd: "SSHGATE_VERSION"}, true},
	{"empty", "", envelope{}, false},
	{"ordinary", "cat /file", envelope{}, false},
	{"prefix-only", "SSHGATE_READ", envelope{}, false},
	{"version-only", "SSHGATE_READ1", envelope{}, false},
	{"other-version", "SSHGATE_READ2 confined cat", envelope{}, false},
	{"long-version", "SSHGATE_READ10 confined cat", envelope{}, false},
	{"leading-space", " SSHGATE_READ1 confined cat", envelope{}, false},
	{"verb-tab", "SSHGATE_READ1\tconfined cat", envelope{}, false},
	{"missing-fields", "SSHGATE_READ1 ", envelope{}, false},
	{"missing-command", "SSHGATE_READ1 confined", envelope{}, false},
	{"empty-command", "SSHGATE_READ1 confined ", envelope{}, false},
	{"whitespace-command", "SSHGATE_READ1 confined \t\r\n\v\f ", envelope{}, false},
	{"unicode-whitespace-command", "SSHGATE_READ1 confined \u00a0\u2003", envelope{}, false},
	{"empty-flags", "SSHGATE_READ1  cat", envelope{}, false},
	{"flags-tab", "SSHGATE_READ1 confined\tcat /file", envelope{}, false},
	{"flags-cr", "SSHGATE_READ1 confined\r cat", envelope{}, false},
	{"flags-lf", "SSHGATE_READ1 confined\n cat", envelope{}, false},
	{"flags-nul", "SSHGATE_READ1 confined\x00 cat", envelope{}, false},
	{"trailing-comma", "SSHGATE_READ1 confined, cat", envelope{}, false},
	{"leading-comma", "SSHGATE_READ1 ,confined cat", envelope{}, false},
	{"empty-flag", "SSHGATE_READ1 confined,,net cat", envelope{}, false},
	{"duplicate-confined", "SSHGATE_READ1 confined,confined cat", envelope{}, false},
	{"duplicate-net", "SSHGATE_READ1 confined,net,net cat", envelope{}, false},
	{"net-only", "SSHGATE_READ1 net cat", envelope{}, false},
	{"unknown", "SSHGATE_READ1 confined,other cat", envelope{}, false},
	{"case-sensitive", "SSHGATE_READ1 Confined cat", envelope{}, false},
}

func TestParseEnvelope(t *testing.T) {
	for _, tc := range envelopeCases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := parseEnvelope(tc.raw)
			if (err == nil) != tc.valid || got != tc.want {
				t.Fatalf("parseEnvelope(%q) = %+v, %v; want %+v, valid=%v", tc.raw, got, err, tc.want, tc.valid)
			}
			if err != nil && err.Error() != sigwire.GateDenyBadEnvelope {
				t.Fatalf("error = %q", err)
			}
			if tc.valid {
				flags := "confined"
				if tc.want.net {
					flags += ",net"
				}
				if want := "SSHGATE_READ1 " + flags + " " + tc.want.cmd; got.String() != want {
					t.Fatalf("String() = %q; want %q", got.String(), want)
				}
			}
		})
	}
}

func FuzzEnvelopeParse(f *testing.F) {
	for _, tc := range envelopeCases {
		f.Add(tc.raw)
	}
	f.Fuzz(func(t *testing.T, raw string) {
		e, err := parseEnvelope(raw)
		if err != nil {
			return
		}
		roundTrip, err := parseEnvelope(e.String())
		if err != nil || roundTrip != e {
			t.Fatalf("round trip of %q = %+v, %v; want %+v", raw, roundTrip, err, e)
		}
		verb, rest, ok := strings.Cut(raw, " ")
		flags, cmd, hasCommand := strings.Cut(rest, " ")
		if !ok || !hasCommand || verb != "SSHGATE_READ1" || cmd != e.cmd || strings.TrimSpace(cmd) == "" {
			t.Fatalf("accepted malformed or changed command: %q -> %+v", raw, e)
		}
		switch flags {
		case "confined", "confined,net":
			if e.String() != raw {
				t.Fatalf("canonical line changed: %q -> %q", raw, e.String())
			}
		case "net,confined":
			if !e.net {
				t.Fatal("lost net flag")
			}
		default:
			t.Fatalf("accepted flags %q", flags)
		}
	})
}
