//go:build linux

package main

import (
	"os"
	"os/exec"
	"strconv"
	"strings"
	"testing"

	"github.com/karthikeyan5/sshgate/src/gate/confine"
)

// TestFixtureChildNotOurChild builds the fixtures in a fresh process (no
// subreaper bit): the child is alive and not this process's child, the
// fixtures pass their liveness controls, and teardown ends the child. Once
// this process is a subreaper, fixtures are refused.
func TestFixtureChildNotOurChild(t *testing.T) {
	if os.Getenv("SSHGATE_FIXTURE_CHILD") != "1" {
		command := exec.Command(os.Args[0], "-test.run=^TestFixtureChildNotOurChild$", "-test.v")
		command.Env = append(os.Environ(), "SSHGATE_FIXTURE_CHILD=1")
		if out, err := command.CombinedOutput(); err != nil || !strings.Contains(string(out), "--- PASS: TestFixtureChildNotOurChild") {
			t.Fatalf("fixture process: %v\n%s", err, out)
		}
		return
	}
	fx, err := buildFixtures(shortTempDir(t))
	if err != nil {
		t.Fatal(err)
	}
	facts, err := readProcessFacts(fx.pid)
	if err != nil || facts.ppid == strconv.Itoa(os.Getpid()) {
		t.Fatalf("child %d: %+v, %v", fx.pid, facts, err)
	}
	if reason := fx.liveness(); reason != "" {
		t.Fatal(reason)
	}
	pid := fx.pid
	if err := fx.teardown(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat("/proc/" + strconv.Itoa(pid)); err == nil {
		if facts, _ := readProcessFacts(pid); facts.state != "Z" {
			t.Fatalf("child %d outlived teardown: %+v", pid, facts)
		}
	}
	for _, path := range []string{fx.dir, fx.tmp} {
		if _, err := os.Lstat(path); err == nil {
			t.Fatalf("teardown left %s", path)
		}
	}
	if err := confine.EnableSubreaper(); err != nil {
		t.Fatal(err)
	}
	if _, err := buildFixtures(shortTempDir(t)); err == nil {
		t.Fatal("fixtures built in a subreaper")
	}
}

// TestRehearsalAttestation: the selftest report must name every row once, in
// order, each errno in its set, tcp6 skipped exactly when there is no ::1
// listener, with the right END count and without the child's nonce.
func TestRehearsalAttestation(t *testing.T) {
	report := func(tcp6 bool, change func(row, errno string) string) string {
		var lines []string
		count := 0
		for _, row := range rehearsalRows {
			if row == "tcp6-connect" && !tcp6 {
				lines = append(lines, "SELFTEST tcp6-connect skipped")
				continue
			}
			errno := "EPERM"
			if set := rowErrnos[row]; set != nil {
				errno = set[0]
			}
			if line := change(row, errno); line != "" {
				lines = append(lines, line)
			}
			count++
		}
		return strings.Join(lines, "\n") + "\nSELFTEST-END " + strconv.Itoa(count) + "\n"
	}
	keep := func(row, errno string) string { return "SELFTEST " + row + " errno=" + errno }
	fx := &fixtures{envNonce: "envnonce", tcp6: "[::1]:1"}
	for _, tc := range []struct {
		name   string
		tcp6   bool
		stdout string
		ok     bool
	}{
		{"complete", true, report(true, keep), true},
		{"complete without tcp6", false, report(false, keep), true},
		{"wrong errno", true, report(true, func(row, errno string) string {
			if row == "canary-write" {
				return "SELFTEST canary-write errno=0"
			}
			return keep(row, errno)
		}), false},
		{"missed target", true, report(true, func(row, errno string) string {
			if row == "pid-stop" {
				return "SELFTEST pid-stop errno=ESRCH"
			}
			return keep(row, errno)
		}), false},
		{"missing row", true, report(true, func(row, errno string) string {
			if row == "fifo-write" {
				return ""
			}
			return keep(row, errno)
		}), false},
		{"tcp6 skipped with a listener", true, report(false, keep), false},
		{"nonce leaked", true, strings.Replace(report(true, keep), "SELFTEST-END", "envnonce\nSELFTEST-END", 1), false},
		{"wrong END", true, strings.Replace(report(true, keep), "SELFTEST-END 23", "SELFTEST-END 22", 1), false},
		{"empty", true, "", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fx.tcp6 = ""
			if tc.tcp6 {
				fx.tcp6 = "[::1]:1"
			}
			r := rehearsalResult{Ran: true}
			r.Rows = fx.attest(&r, tc.stdout)
			r.finish()
			if r.Passed != tc.ok {
				t.Fatalf("passed %v, failures %v, rows %+v", r.Passed, r.Failures, r.Rows)
			}
		})
	}
}

// shortTempDir is a temporary gate dir short enough for the fixture's Unix
// socket path, under the jail-visible TMPDIR.
func shortTempDir(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "g")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	return dir
}
