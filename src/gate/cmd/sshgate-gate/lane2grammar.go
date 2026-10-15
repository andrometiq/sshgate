package main

import (
	"slices"
	"strconv"
	"strings"

	"github.com/karthikeyan5/sshgate/src/gate/confine/jailmut"
)

// The daemon-read grammar: per client and verb, typed flags (one canonical
// long spelling, its aliases, a value type) and bounded, typed positionals.
// lane2Parse turns an agent line into a lane2Call; render turns that into the
// canonical argv. The agent never chooses spelling, order or endpoint, and
// nothing that is not a grammar token reaches the client.

const (
	lane2MaxLine   = 1024 // the input line and its canonical line, each
	lane2MaxTokens = 32
	lane2MaxValue  = 128 // every flag value and positional
)

// lane2JSONTemplate is what the admitted --format word json renders to: docker
// 20.10 treats a bare "json" as a literal template, and every CLI since accepts
// this one. It is a gate constant, never built from agent bytes.
const lane2JSONTemplate = "{{json .}}"

// lane2Type accepts a value of one type. lane2Parse has already checked the
// common bounds (1..lane2MaxValue bytes, no leading '-').
type lane2Type func(string) bool

type lane2Flag struct {
	long    string
	aliases []string
	value   lane2Type // nil: the flag takes no value
}

type lane2Verb struct {
	flags                          []lane2Flag // grammar order, which is render order
	positional                     lane2Type
	minPositionals, maxPositionals int
	required                       []string // long spellings that must be present
}

type lane2Client struct {
	prefix   []string // gate-chosen arguments before the verb
	hostFlag string   // completed with the admitted endpoint, after prefix
	dropped  []string // accepted from the agent and dropped: the prefix pins them
	verbs    map[string]lane2Verb
}

// lane2Arg is one admitted flag in canonical form.
type lane2Arg struct {
	long, value string
	hasValue    bool
}

// lane2Call is a parsed daemon read: client and verb, flags in grammar order,
// positionals in the agent's order.
type lane2Call struct {
	client, verb string
	flags        []lane2Arg
	positionals  []string
}

// lane2RedirectFlags point a client at another daemon, machine, user or root.
// The grammar cannot express any of them; the explicit refusal keeps that from
// hinging on a table never gaining one.
var lane2RedirectFlags = []string{"-H", "--host", "-M", "--machine", "--context", "-c", "--user", "--root", "--image", "--global"}

func lane2Bytes(value, extra string) bool {
	for i := 0; i < len(value); i++ {
		b := value[i]
		if !(b >= 'a' && b <= 'z' || b >= 'A' && b <= 'Z' || b >= '0' && b <= '9' || strings.IndexByte(extra, b) >= 0) {
			return false
		}
	}
	return value != ""
}

func lane2Uint(maximum uint64) lane2Type {
	return func(value string) bool {
		if !lane2Bytes(value, "") || strings.Trim(value, "0123456789") != "" || len(value) > 1 && value[0] == '0' {
			return false
		}
		n, err := strconv.ParseUint(value, 10, 64)
		return err == nil && n <= maximum
	}
}

func lane2Enum(words ...string) lane2Type {
	return func(value string) bool { return slices.Contains(words, value) }
}

func lane2Filter(keys ...string) lane2Type {
	return func(value string) bool {
		key, rest, ok := strings.Cut(value, "=")
		return ok && slices.Contains(keys, key) && lane2Bytes(rest, "._:@/-")
	}
}

// lane2Name is a unit, PID or unit path for systemctl, and a container or
// image name, ID or digest for docker.
func lane2Name(value string) bool { return lane2Bytes(value, ":_.@/-") }

func lane2Tail(value string) bool { return value == "all" || lane2Uint(1000000)(value) }

// lane2Time is an RFC 3339 date or timestamp or a relative duration; its
// first byte is a digit.
func lane2Time(value string) bool {
	return lane2Bytes(value, ":.+-") && value[0] >= '0' && value[0] <= '9'
}

func lane2State(value string) bool {
	return strings.Trim(value, "abcdefghijklmnopqrstuvwxyz-") == "" && value != ""
}

func lane2Props(value string) bool {
	items := strings.Split(value, ",")
	if len(items) > 32 {
		return false
	}
	for _, item := range items {
		if !lane2Bytes(item, "") {
			return false
		}
	}
	return true
}

func lane2Switch(long string, aliases ...string) lane2Flag {
	return lane2Flag{long: long, aliases: aliases}
}

func lane2Valued(long string, value lane2Type, aliases ...string) lane2Flag {
	return lane2Flag{long: long, aliases: aliases, value: value}
}

func systemctlVerb(minimum, maximum int, flags ...lane2Flag) lane2Verb {
	common := []lane2Flag{lane2Switch("--full", "-l"), lane2Switch("--all", "-a"), lane2Switch("--no-legend"), lane2Switch("--plain"), lane2Switch("--quiet", "-q")}
	return lane2Verb{flags: append(common, flags...), positional: lane2Name, minPositionals: minimum, maxPositionals: maximum}
}

func dockerVerb(minimum, maximum int, flags ...lane2Flag) lane2Verb {
	return lane2Verb{flags: flags, positional: lane2Name, minPositionals: minimum, maxPositionals: maximum}
}

// lane2Grammar is the whole daemon-read surface. docker.sock is
// root-equivalent: every new entry is review-gated.
var lane2Grammar = func() map[string]lane2Client {
	unitTypes := lane2Enum("service", "socket", "target", "device", "mount", "automount", "swap", "timer", "path", "slice", "scope")
	listing := []lane2Flag{lane2Valued("--type", unitTypes, "-t"), lane2Valued("--state", lane2State)}
	table := lane2Enum("json", "table")
	return map[string]lane2Client{
		"systemctl": {
			prefix:  []string{"--no-pager", "--no-ask-password"},
			dropped: []string{"--no-pager", "--no-ask-password", "--system"},
			verbs: map[string]lane2Verb{
				"status":          systemctlVerb(0, 16, lane2Valued("--lines", lane2Uint(10000), "-n")),
				"is-active":       systemctlVerb(0, 16),
				"is-failed":       systemctlVerb(0, 16),
				"list-units":      systemctlVerb(0, 16, listing...),
				"list-unit-files": systemctlVerb(0, 16, listing...),
				"show":            systemctlVerb(0, 16, lane2Valued("--property", lane2Props, "-p"), lane2Switch("--value")),
				"cat":             systemctlVerb(1, 16),
				"get-default":     systemctlVerb(0, 0),
			},
		},
		"docker": {
			hostFlag: "--host=unix://",
			verbs: map[string]lane2Verb{
				"ps": dockerVerb(0, 0, lane2Switch("--all", "-a"), lane2Switch("--quiet", "-q"), lane2Switch("--no-trunc"),
					lane2Switch("--latest", "-l"), lane2Switch("--size", "-s"), lane2Valued("--last", lane2Uint(1000), "-n"),
					lane2Valued("--filter", lane2Filter("id", "name", "label", "exited", "status", "ancestor", "before", "since",
						"volume", "network", "publish", "expose", "health", "isolation", "is-task"), "-f"),
					lane2Valued("--format", table)),
				"inspect": dockerVerb(1, 16, lane2Switch("--size", "-s"), lane2Valued("--format", lane2Enum("json"), "-f"),
					lane2Valued("--type", lane2Enum("container", "image", "volume", "network"))),
				"logs": dockerVerb(1, 1, lane2Switch("--timestamps", "-t"), lane2Switch("--details"), lane2Valued("--tail", lane2Tail, "-n"),
					lane2Valued("--since", lane2Time), lane2Valued("--until", lane2Time)),
				"images": dockerVerb(0, 1, lane2Switch("--all", "-a"), lane2Switch("--quiet", "-q"), lane2Switch("--no-trunc"), lane2Switch("--digests"),
					lane2Valued("--filter", lane2Filter("dangling", "label", "before", "since", "reference", "until"), "-f"),
					lane2Valued("--format", table)),
				"version": dockerVerb(0, 0, lane2Valued("--format", lane2Enum("json"), "-f")),
				"stats": {flags: []lane2Flag{lane2Switch("--no-stream"), lane2Switch("--all", "-a"), lane2Switch("--no-trunc"), lane2Valued("--format", table)},
					positional: lane2Name, maxPositionals: 16, required: []string{"--no-stream"}},
				"top": dockerVerb(1, 1),
			},
		},
	}
}()

// lane2Redirect reports whether token names a refused flag: exactly, with an
// inline value, as a getopt_long abbreviation of a long one, or as a short one
// with an attached value.
func lane2Redirect(token string) bool {
	if jailmut.On("P-L2-REDIRECT") {
		return false
	}
	name, _, _ := strings.Cut(token, "=")
	for _, flag := range lane2RedirectFlags {
		isLong := strings.HasPrefix(flag, "--")
		if name == flag || isLong && len(name) > 2 && strings.HasPrefix(flag, name) || !isLong && strings.HasPrefix(token, flag) {
			return true
		}
	}
	return false
}

func (v lane2Verb) flag(name string) *lane2Flag {
	for i := range v.flags {
		if v.flags[i].long == name || slices.Contains(v.flags[i].aliases, name) {
			return &v.flags[i]
		}
	}
	return nil
}

func lane2ValueBounds(value string) bool {
	return value != "" && len(value) <= lane2MaxValue && value[0] != '-'
}

// lane2Parse returns the typed call for cmd, or false when cmd is not a
// daemon read (it then takes the normal read path).
func lane2Parse(cmd string) (lane2Call, bool) {
	if len(cmd) > lane2MaxLine {
		return lane2Call{}, false
	}
	toks, ok := lane2Tokens(cmd)
	if !ok || len(toks) < 2 || len(toks) > lane2MaxTokens {
		return lane2Call{}, false
	}
	client, ok := lane2Grammar[toks[0]]
	if !ok {
		return lane2Call{}, false
	}
	verb, ok := client.verbs[toks[1]]
	if !ok {
		return lane2Call{}, false
	}
	call := lane2Call{client: toks[0], verb: toks[1]}
	set := map[string]lane2Arg{}
	var unlisted []lane2Arg
	seen := map[string]bool{}
	args := toks[2:]
	for i := 0; i < len(args); i++ {
		token := args[i]
		if !strings.HasPrefix(token, "-") {
			if !lane2ValueBounds(token) || !verb.positional(token) {
				return lane2Call{}, false
			}
			call.positionals = append(call.positionals, token)
			continue
		}
		if lane2Redirect(token) {
			return lane2Call{}, false
		}
		if slices.Contains(client.dropped, token) {
			if seen[token] {
				return lane2Call{}, false
			}
			seen[token] = true
			continue
		}
		name, value, hasInline := strings.Cut(token, "=")
		flag := verb.flag(name)
		if flag == nil {
			if jailmut.On("P-L2-GRAMMAR") {
				unlisted = append(unlisted, lane2Arg{long: token})
				continue
			}
			return lane2Call{}, false
		}
		if seen[flag.long] || hasInline && (flag.value == nil || name != flag.long) {
			return lane2Call{}, false
		}
		seen[flag.long] = true
		if flag.value == nil {
			set[flag.long] = lane2Arg{long: flag.long}
			continue
		}
		if !hasInline {
			if i+1 >= len(args) {
				return lane2Call{}, false
			}
			i++
			value = args[i]
		}
		if !lane2ValueBounds(value) || !flag.value(value) {
			return lane2Call{}, false
		}
		set[flag.long] = lane2Arg{long: flag.long, value: value, hasValue: true}
	}
	if len(call.positionals) < verb.minPositionals || len(call.positionals) > verb.maxPositionals {
		return lane2Call{}, false
	}
	for _, required := range verb.required {
		if !seen[required] {
			return lane2Call{}, false
		}
	}
	for _, flag := range verb.flags {
		if arg, ok := set[flag.long]; ok {
			call.flags = append(call.flags, arg)
		}
	}
	call.flags = append(call.flags, unlisted...)
	if len(call.canonicalLine()) > lane2MaxLine {
		return lane2Call{}, false
	}
	return call, true
}

// tokens is the verb, the flags and the positionals; forArgv renders the
// admitted --format word json as the gate's template.
func (c lane2Call) tokens(forArgv bool) []string {
	out := []string{c.verb}
	for _, arg := range c.flags {
		switch {
		case !arg.hasValue:
			out = append(out, arg.long)
		case forArgv && arg.long == "--format" && arg.value == "json":
			out = append(out, "--format="+lane2JSONTemplate)
		default:
			out = append(out, arg.long+"="+arg.value)
		}
	}
	return append(out, c.positionals...)
}

// render is the canonical argv: name (the fixed-directory path that matched),
// the client's prefix, the verb, the flags in grammar order and the
// positionals in the agent's order.
func (c lane2Call) render(name, endpoint string) []string {
	return append(append([]string{name}, c.prefix(endpoint)...), c.tokens(true)...)
}

// prefix is the gate-chosen arguments before the verb: the client's fixed
// prefix and, for docker, --host naming the admitted endpoint.
func (c lane2Call) prefix(endpoint string) []string {
	client := lane2Grammar[c.client]
	if client.hostFlag == "" {
		return client.prefix
	}
	return append(slices.Clone(client.prefix), client.hostFlag+endpoint)
}

// canonicalLine is an agent-shaped line that lane2Parse accepts: the client
// name and the canonical verb and arguments, without the prefix.
func (c lane2Call) canonicalLine() string {
	return c.client + " " + strings.Join(c.tokens(false), " ")
}
