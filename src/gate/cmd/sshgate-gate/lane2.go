package main

import (
	"os"
	"path/filepath"
	"strings"
)

// Lane 2 is the exact daemon-read allowlist: a few systemctl and docker read
// verbs that must talk to a local daemon over AF_UNIX, which the read jail
// denies. A match runs SHELL-FREE and UNJAILED, so the door is deliberately
// narrow: an allowlisted binary from a fixed directory (never $PATH), an
// allowlisted verb, allowlisted flags, a closed environment built from scratch
// and /dev/null stdin. Anything that is not an exact match is not Lane 2 and
// takes the normal (jailed) read path. docker.sock is root-equivalent, so every
// new entry here is review-gated.

// lane2BinDirs is the fixed search list for an allowlisted binary. It is a var
// only so tests can point it at a fake binary; it is never derived from $PATH
// or any other environment.
var lane2BinDirs = []string{"/usr/bin", "/bin", "/usr/sbin"}

// lane2Argv returns the canonical argv for cmd, or ok=false when cmd is not a
// daemon read (it then takes the normal read path). argv[0] is the
// fixed-directory path of the client.
func lane2Argv(cmd string) (argv []string, ok bool) {
	call, ok := lane2Parse(cmd)
	if !ok {
		return nil, false
	}
	name, ok := lane2Binary(call.client)
	if !ok {
		return nil, false
	}
	return call.render(name), true
}

// lane2Tokens splits cmd on spaces and tabs. Every byte of every token must be
// in a small positive charset, so any shell syntax at all (quotes, $, `, ;, |,
// &, <, >, globs, ~, #, \, braces, newlines) makes cmd not a Lane-2 candidate:
// Lane 2 only ever runs commands whose meaning is the same with or without sh.
func lane2Tokens(cmd string) ([]string, bool) {
	for i := 0; i < len(cmd); i++ {
		b := cmd[i]
		if b == ' ' || b == '\t' || lane2TokenByte(b) {
			continue
		}
		return nil, false
	}
	return strings.FieldsFunc(cmd, func(r rune) bool { return r == ' ' || r == '\t' }), true
}

func lane2TokenByte(b byte) bool {
	switch {
	case b >= 'a' && b <= 'z', b >= 'A' && b <= 'Z', b >= '0' && b <= '9':
		return true
	}
	return strings.IndexByte("._-:@/=,+", b) >= 0
}

// lane2Binary resolves name to an executable regular file in lane2BinDirs.
func lane2Binary(name string) (string, bool) {
	for _, dir := range lane2BinDirs {
		p := filepath.Join(dir, name)
		fi, err := os.Stat(p)
		if err == nil && fi.Mode().IsRegular() && fi.Mode().Perm()&0o111 != 0 {
			return p, true
		}
	}
	return "", false
}
