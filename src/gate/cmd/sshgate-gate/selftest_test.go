package main

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"slices"
	"strconv"
	"strings"
	"testing"
)

// jailedStatus is the credential part of a jailed command's
// /proc/<pid>/status.
func jailedStatus(root bool) string {
	caps := "0000000000000000"
	if root {
		caps = "0000000000000004" // CAP_DAC_READ_SEARCH
	}
	return "Name:\tgate\nCapInh:\t0000000000000000\nCapPrm:\t" + caps + "\nCapEff:\t" + caps + "\nCapBnd:\t" + caps +
		"\nCapAmb:\t0000000000000000\nNoNewPrivs:\t1\nSeccomp:\t2\nSeccomp_filters:\t1\n"
}

// unitSelftestRefusesUnjailed: the selftest runs only with the jailed
// credentials and in namespaces other than the declared outer ones.
func unitSelftestRefusesUnjailed(t *testing.T) {
	p := newProof(t, "U-SelftestRefusesUnjailed")
	outer, own := [2]uint64{11, 12}, [2]uint64{21, 22}
	control := selftestAllowed(jailedStatus(false), false, outer, own) && selftestAllowed(jailedStatus(true), true, outer, own)
	replace := func(old, new string) string { return strings.Replace(jailedStatus(false), old, new, 1) }
	liveStatus, err := os.ReadFile("/proc/thread-self/status")
	liveNS, nsErr := ownNamespaces()
	if err != nil || nsErr != nil {
		t.Fatalf("SETUP: %v %v", err, nsErr)
	}
	refused := []struct {
		name       string
		status     string
		root       bool
		outer, own [2]uint64
	}{
		{"no no_new_privs", replace("NoNewPrivs:\t1", "NoNewPrivs:\t0"), false, outer, own},
		{"seccomp off", replace("Seccomp:\t2", "Seccomp:\t0"), false, outer, own},
		{"no seccomp filter", replace("Seccomp_filters:\t1", "Seccomp_filters:\t0"), false, outer, own},
		{"effective capability", replace("CapEff:\t0000000000000000", "CapEff:\t0000000000000001"), false, outer, own},
		{"bounding set", replace("CapBnd:\t0000000000000000", "CapBnd:\t000001ffffffffff"), false, outer, own},
		{"ambient capability", replace("CapAmb:\t0000000000000000", "CapAmb:\t0000000000000004"), false, outer, own},
		{"missing field", replace("NoNewPrivs:\t1\n", ""), false, outer, own},
		{"duplicate field", jailedStatus(false) + "Seccomp:\t2\n", false, outer, own},
		{"root capabilities, not root", jailedStatus(true), false, outer, own},
		{"same user namespace", jailedStatus(false), false, outer, [2]uint64{11, 22}},
		{"same mount namespace", jailedStatus(false), false, outer, [2]uint64{21, 12}},
		{"no outer namespaces", jailedStatus(false), false, [2]uint64{}, own},
		{"this process, unjailed", string(liveStatus), os.Geteuid() == 0, liveNS, liveNS},
	}
	allowed := false
	for _, row := range refused {
		if selftestAllowed(row.status, row.root, row.outer, row.own) {
			allowed = true
			t.Logf("allowed: %s", row.name)
		}
	}
	p.Effect("decision", allowed)
	p.Control("decision", control)
	p.Finish()
}

// TestSelftestGrammar: the closed grammar refuses anything but each flag once
// with a well-formed value; tcp6 is optional.
func TestSelftestGrammar(t *testing.T) {
	valid := []string{"--canary=/d/canary", "--fifo=/d/fifo", "--unix=/d/sock", "--abstract=sshgate-doctor-ab", "--tcp4=127.0.0.1:4000",
		"--pid=1234", "--tmp=/tmp/sshgate-doctor-x", "--shm=sshgate-doctor-cd", "--nonce=" + strings.Repeat("a", 32), "--net=deny"}
	if _, ok := parseSelftestFlags(valid); !ok {
		t.Fatal("valid arguments refused")
	}
	if _, ok := parseSelftestFlags(append(slices.Clone(valid), "--tcp6=[::1]:4001")); !ok {
		t.Fatal("tcp6 refused")
	}
	for name, args := range map[string][]string{
		"duplicate":        append(slices.Clone(valid), "--net=allow"),
		"unknown":          append(slices.Clone(valid), "--exec=/bin/sh"),
		"bare word":        append(slices.Clone(valid), "extra"),
		"missing":          valid[1:],
		"relative canary":  append([]string{"--canary=canary"}, valid[1:]...),
		"short nonce":      append(slices.Clone(valid[:8]), "--nonce=ab", "--net=deny"),
		"bad net":          append(slices.Clone(valid[:9]), "--net=maybe"),
		"remote tcp4":      append(append(slices.Clone(valid[:4]), "--tcp4=10.0.0.1:4000"), valid[5:]...),
		"pid one":          append(append(slices.Clone(valid[:5]), "--pid=1"), valid[6:]...),
		"remote tcp6":      append(slices.Clone(valid), "--tcp6=[::2]:4001"),
		"shm with a slash": append(append(slices.Clone(valid[:7]), "--shm=../x"), valid[8:]...),
		"empty value":      append(slices.Clone(valid), "--tcp6="),
	} {
		if _, ok := parseSelftestFlags(args); ok {
			t.Errorf("%s: accepted %v", name, args)
		}
	}
}

// TestSelftestRowSets: every row has a set (the connect rows by network), no
// set holds an errno that means the probe missed its target, and only
// shm-write and an allowed connect may succeed.
func TestSelftestRowSets(t *testing.T) {
	forbidden := []string{"ENOENT", "EBADF", "EINVAL", "ESRCH", "ENOSYS", "ENXIO", "EXDEV"}
	if len(rowErrnos) != len(rehearsalRows)-2 {
		t.Fatalf("%d row sets for %d rows", len(rowErrnos), len(rehearsalRows))
	}
	for _, row := range rehearsalRows {
		sets := [][]string{rowErrnos[row]}
		if row == "tcp4-connect" || row == "tcp6-connect" {
			sets = [][]string{tcpRowErrnos(false), tcpRowErrnos(true)}
		}
		for _, set := range sets {
			if len(set) == 0 {
				t.Errorf("%s has no set", row)
			}
			for _, errno := range set {
				if slices.Contains(forbidden, errno) || errno == "0" && row != "shm-write" && !slices.Equal(set, tcpRowErrnos(true)) {
					t.Errorf("%s allows %s", row, errno)
				}
			}
		}
	}
}

// TestSelftestNeverExecs holds selftest.go to its allowlists: a few imports,
// only CheckJailedCredentials from confine, and no way to start a program.
func TestSelftestNeverExecs(t *testing.T) {
	file, err := parser.ParseFile(token.NewFileSet(), "selftest.go", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	allowed := []string{"fmt", "os", "strconv", "strings", "syscall", "golang.org/x/sys/unix",
		"github.com/karthikeyan5/sshgate/src/gate/confine", "github.com/karthikeyan5/sshgate/src/gate/confine/jailmut"}
	for _, imp := range file.Imports {
		path, _ := strconv.Unquote(imp.Path.Value)
		if !slices.Contains(allowed, path) || imp.Name != nil {
			t.Errorf("selftest.go imports %s", imp.Path.Value)
		}
	}
	forbidden := []string{"exec", "Exec", "ForkExec", "StartProcess", "Clone", "Clone3", "Syscall", "Syscall6", "RawSyscall", "RawSyscall6", "Vfork", "Fork"}
	ast.Inspect(file, func(node ast.Node) bool {
		switch n := node.(type) {
		case *ast.Ident:
			if slices.Contains(forbidden, n.Name) {
				t.Errorf("selftest.go names %s", n.Name)
			}
		case *ast.SelectorExpr:
			if x, ok := n.X.(*ast.Ident); ok && x.Name == "confine" && n.Sel.Name != "CheckJailedCredentials" {
				t.Errorf("selftest.go uses confine.%s", n.Sel.Name)
			}
			if x, ok := n.X.(*ast.Ident); ok && x.Name == "jailmut" && n.Sel.Name != "On" {
				t.Errorf("selftest.go uses jailmut.%s", n.Sel.Name)
			}
		}
		return true
	})
}
