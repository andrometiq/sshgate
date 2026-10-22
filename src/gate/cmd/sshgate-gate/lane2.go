package main

import (
	"strings"
)

// Lane 2 is the daemon-read allowlist: a few systemctl and docker read verbs
// that must talk to a local daemon over AF_UNIX, which an ordinary read's jail
// denies. A match is a line the typed grammar accepts (lane2grammar.go), and it
// runs SHELL-FREE in its own narrower jail (readjail.go: only the admitted
// client and interpreter executable, Unix sockets bound to the admitted
// endpoints from Landlock ABI 9, no memfd, no network). Only where an ordinary
// read would run classifier-only does it run unjailed instead. Either way the
// gate runs its own canonical argv, never the agent's tokens, with a
// gate-chosen prefix that pins the daemon endpoint, from /, with a closed
// environment built from scratch and /dev/null stdin. Admission
// (lane2admit.go) first checks the client binary from a fixed directory (never
// $PATH), its ELF search paths, its interpreter and its endpoint against the
// trusted-path rule; a failed check refuses the read with exit 77. Anything
// that is not a grammar match takes the ordinary read path. docker.sock is
// root-equivalent, so every new entry here is review-gated.

// lane2BinDirs is the fixed search list for an allowlisted binary. It is a var
// only so tests can point it at a fake binary; it is never derived from $PATH
// or any other environment.
var lane2BinDirs = []string{"/usr/bin", "/bin", "/usr/sbin"}

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
