package confine

import (
	"fmt"
	"path"
	"strings"
)

// PinFile is the name of the jail pin in the gate directory. The pin is static
// operator config, the same trust class as gate.pub: it is written only by
// `gate doctor --pin` or by a human-approved signed write, never by the command
// path.
const PinFile = "jail"

// MaxPinBytes bounds the pin file; a larger file is damaged.
const MaxPinBytes = 4096

// maxSocketPath is the usable length of sun_path (108 bytes, NUL included).
const maxSocketPath = 107

// Pin is a parsed, valid jail pin.
type Pin struct {
	Profile      string
	Net          bool
	DockerSocket string
	AcceptFS     []string
}

// PinError says why a pin is damaged. Line is 1-based; 0 means the whole file.
type PinError struct {
	Line   int
	Reason string
}

func (e *PinError) Error() string {
	if e.Line == 0 {
		return e.Reason
	}
	return fmt.Sprintf("line %d: %s", e.Line, e.Reason)
}

// ParsePin parses a jail pin. The format is `key=value` lines of printable
// ASCII; empty lines and lines starting with '#' are ignored. Nothing is
// trimmed. An unknown or duplicate key, a bad value or a missing required key
// makes the pin damaged.
func ParsePin(data []byte) (Pin, error) {
	if len(data) > MaxPinBytes {
		return Pin{}, &PinError{Reason: fmt.Sprintf("larger than %d bytes", MaxPinBytes)}
	}
	var pin Pin
	seen := map[string]bool{}
	lines := strings.Split(string(data), "\n")
	for i, line := range lines {
		number := i + 1
		for j := 0; j < len(line); j++ {
			if line[j] < 0x20 || line[j] > 0x7e {
				return Pin{}, &PinError{Line: number, Reason: "invalid byte"}
			}
		}
		if line == "" || line[0] == '#' {
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		if !ok || !pinKeyName(key) || value == "" || strings.Contains(value, " ") {
			return Pin{}, &PinError{Line: number, Reason: "not key=value"}
		}
		if seen[key] {
			return Pin{}, &PinError{Line: number, Reason: fmt.Sprintf("duplicate key %q", key)}
		}
		seen[key] = true
		if err := pin.set(key, value); err != nil {
			return Pin{}, &PinError{Line: number, Reason: err.Error()}
		}
	}
	for _, key := range []string{"profile", "net"} {
		if !seen[key] {
			return Pin{}, &PinError{Reason: fmt.Sprintf("missing key %q", key)}
		}
	}
	return pin, nil
}

func pinKeyName(key string) bool {
	if key == "" {
		return false
	}
	for j := 0; j < len(key); j++ {
		if (key[j] < 'a' || key[j] > 'z') && key[j] != '_' {
			return false
		}
	}
	return true
}

func (p *Pin) set(key, value string) error {
	bad := fmt.Errorf("bad value for %q", key)
	switch key {
	case "profile":
		if value != ProfileROv1 {
			return bad
		}
		p.Profile = value
	case "net":
		switch value {
		case "allow":
			p.Net = true
		case "deny":
			p.Net = false
		default:
			return bad
		}
	case "accept_fs":
		seen := map[string]bool{}
		for _, class := range strings.Split(value, ",") {
			if (class != "network" && class != "autofs") || seen[class] {
				return bad
			}
			seen[class] = true
			p.AcceptFS = append(p.AcceptFS, class)
		}
	case "docker_socket":
		if !strings.HasPrefix(value, "/") || value == "/" || path.Clean(value) != value || len(value) > maxSocketPath {
			return bad
		}
		p.DockerSocket = value
	default:
		return fmt.Errorf("unknown key %q", key)
	}
	return nil
}

// Canonical is the pin as `gate doctor --pin` writes it.
func (p Pin) Canonical() []byte {
	var b strings.Builder
	b.WriteString("# written by gate doctor\nprofile=" + p.Profile + "\nnet=")
	if p.Net {
		b.WriteString("allow\n")
	} else {
		b.WriteString("deny\n")
	}
	if len(p.AcceptFS) > 0 {
		b.WriteString("accept_fs=" + strings.Join(p.AcceptFS, ",") + "\n")
	}
	if p.DockerSocket != "" {
		b.WriteString("docker_socket=" + p.DockerSocket + "\n")
	}
	return []byte(b.String())
}
