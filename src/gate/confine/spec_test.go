//go:build linux

package confine

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"syscall"
	"testing"
	"time"
)

func TestRungString(t *testing.T) {
	for r, want := range map[Rung]string{
		Rung1Full:       "full",
		Rung2Landlock:   "landlock",
		Rung3Unconfined: "unconfined",
	} {
		if got := r.String(); got != want {
			t.Errorf("Rung(%d).String()=%q want %q", r, got, want)
		}
	}
}

// TestSpecJSONRoundTrip covers the parent->shim->worker marshalling: the Spec
// travels as JSON in argv and must survive unchanged.
func TestSpecJSONRoundTrip(t *testing.T) {
	in := Spec{
		Rung:         Rung2Landlock,
		ForceABI:     2,
		AllowInet:    true,
		ScratchDir:   "/tmp/scratch-xyz",
		InjectFailAt: "seccomp",
	}
	b, err := json.Marshal(in)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var out Spec
	if err := json.Unmarshal(b, &out); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if out != in {
		t.Errorf("round trip mismatch: got %+v want %+v", out, in)
	}
}

func TestSetupErrorMessage(t *testing.T) {
	e := &SetupError{Stage: "landlock", Errno: syscall.EPERM}
	if e.Error() == "" {
		t.Fatal("empty error string")
	}
}

// TestFailReportRoundTrip feeds the formatter's own output through the same
// parser Status uses, so the fd-4 wire format round-trips end to end.
func TestFailReportRoundTrip(t *testing.T) {
	for _, c := range []struct {
		stage string
		errno syscall.Errno
	}{
		{"seccomp", syscall.EPERM},
		{"landlock", syscall.EINVAL},
		{"mounts", syscall.ENOSPC},
		{"cmdread", 0},
	} {
		msg := formatFailReport(c.stage, c.errno)
		var se *SetupError
		if err := statusFromReport([]byte(msg)); !errors.As(err, &se) {
			t.Fatalf("statusFromReport(%q) = %v, want *SetupError", msg, err)
		}
		if se.Stage != c.stage || se.Errno != c.errno {
			t.Errorf("round trip of %q = {%q %v}, want {%q %v}", msg, se.Stage, se.Errno, c.stage, c.errno)
		}
	}
	// A report with no errno field still parses its stage.
	s2, e2 := parseFailReport("Funknown")
	if s2 != "unknown" || e2 != 0 {
		t.Errorf("parse bare stage: %q,%v", s2, e2)
	}
}

// TestStatusFromReport pins the fail-closed reading of fd 4: only an exact "X"
// means the worker reached execve.
func TestStatusFromReport(t *testing.T) {
	if err := statusFromReport([]byte(statusReachedExec)); err != nil {
		t.Errorf(`"X" -> %v, want nil`, err)
	}
	for _, raw := range []string{"", "\n", "XX", "XFexec:2\n", "garbage", "x"} {
		var se *SetupError
		if err := statusFromReport([]byte(raw)); !errors.As(err, &se) {
			t.Errorf("%q -> %v, want *SetupError", raw, err)
		}
	}
}

// TestCommandRung3Refused proves Command never builds a jail for rung 3.
func TestCommandRung3Refused(t *testing.T) {
	_, err := Spec{Rung: Rung3Unconfined}.Command(context.Background(), "echo hi")
	if err == nil {
		t.Fatal("expected an error for rung-3 Command")
	}
}

func TestStrictSpecDecode(t *testing.T) {
	t.Run("U-SpecRejectsUnknownRung", func(t *testing.T) {
		for _, raw := range []string{`{"Rung":5}`, `{"Rung":-1}`, `{"Rung":0}`, `{"Rung":1,"Unexpected":true}`, `{"Rung":1} {}`, `{"Rung":1} garbage`, `null`, `{"Rung":1,"ForceABI":-2}`, `{"Rung":1,"InjectFailAt":"rbind"}`, `{"Rung":1,"InjectFailAt":"nnp:UNKNOWN"}`, `{"Rung":2}`} {
			var spec Spec
			if err := decodeSpec(raw, &spec); err != syscall.EINVAL {
				t.Errorf("decode %s: got %v want EINVAL", raw, err)
			}
		}
	})
	for _, rung := range []Rung{-1, 0, 5} {
		jailed, err := (Spec{Rung: rung}).Command(context.Background(), "true")
		if jailed != nil {
			jailed.Abort()
		}
		var setup *SetupError
		if !errors.As(err, &setup) || setup.Stage != "spec" || setup.Errno != syscall.EINVAL {
			t.Errorf("parent rung %d: got %v", rung, err)
		}
	}
	var spec Spec
	if err := decodeSpec(`{"Rung":1,"InjectFailAt":"seccomp:EIO"}`, &spec); err != nil {
		t.Fatal(err)
	}
}

func TestSpecRequiresEveryParentNamespace(t *testing.T) {
	for _, ids := range []NSIDs{{0, 2, 3, 4}, {1, 0, 3, 4}, {1, 2, 0, 4}, {1, 2, 3, 0}} {
		raw, err := json.Marshal(Spec{Rung: Rung1Full, ParentNS: ids})
		if err != nil {
			t.Fatal(err)
		}
		var decoded Spec
		if err := decodeSpec(string(raw), &decoded); err != syscall.EINVAL {
			t.Errorf("parent IDs %+v: %v", ids, err)
		}
	}
}

func TestWorkerRejectsInvalidSpecBeforeInjection(t *testing.T) {
	for _, raw := range []string{
		`{"Rung":1,"InjectFailAt":"spec:UNKNOWN"}`,
		`{"Rung":5,"InjectFailAt":"spec:EIO"}`,
		`{"Rung":1,"Unknown":true,"InjectFailAt":"spec:EIO"}`,
	} {
		t.Run(raw, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			jailed, err := (Spec{Rung: Rung2Landlock}).Command(ctx, "echo MUST_NOT_RUN")
			if err != nil {
				t.Fatal(err)
			}
			defer jailed.Abort()
			jailed.Cmd.Args[2] = raw
			var output bytes.Buffer
			jailed.Cmd.Stdout = &output
			if err := jailed.Cmd.Start(); err != nil {
				t.Fatal(err)
			}
			if err := jailed.Started(); err != nil {
				t.Fatal(err)
			}
			if err := jailed.Cmd.Wait(); err == nil {
				t.Fatal("invalid worker spec exited successfully")
			}
			report, err := io.ReadAll(jailed.statusR)
			if err != nil {
				t.Fatal(err)
			}
			if string(report) != formatFailReport("spec", syscall.EINVAL) {
				t.Errorf("report=%q want Fspec:EINVAL", report)
			}
			if output.Len() != 0 {
				t.Errorf("command ran: %q", output.String())
			}
		})
	}
}
