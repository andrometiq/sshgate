package gate_test

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/karthikeyan5/sshgate/src/gate"
	"github.com/karthikeyan5/sshgate/src/gate/confine"
	"github.com/karthikeyan5/sshgate/src/redact"
	redactrules "github.com/karthikeyan5/sshgate/src/redact/rules"
)

// TestExecArgvWithRedaction pins the shell-free argv exec the gate's Lane 2
// uses: argv reaches the program verbatim (no shell ever parses it), the child
// env is exactly the env passed (never the gate's), stdin is /dev/null, and
// output flows through the same redactor + counters as ExecWithRedaction.
func TestExecArgvWithRedaction(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	t.Run("argv is never shell-parsed", func(t *testing.T) {
		var res gate.ExecResult
		out := captureStdout(t, func() {
			var err error
			res, err = gate.ExecArgvWithRedaction(ctx, []string{"/bin/echo", "a;b", "$HOME", "`id`", "$(id)", "*"}, nil, gate.ExecOpts{})
			if err != nil {
				t.Errorf("err = %v", err)
			}
		})
		if want := "a;b $HOME `id` $(id) *\n"; out != want {
			t.Errorf("stdout = %q, want %q (a shell would have expanded these)", out, want)
		}
		if res.ExitCode != 0 || res.StdoutBytes != int64(len(out)) || res.Lines != 1 {
			t.Errorf("res = %+v, want exit 0 with counted bytes/lines", res)
		}
	})

	t.Run("env is exactly the passed env, never inherited", func(t *testing.T) {
		t.Setenv("DOCKER_HOST", "tcp://attacker.invalid:2375")
		out := captureStdout(t, func() {
			if _, err := gate.ExecArgvWithRedaction(ctx, []string{"/usr/bin/env"}, []string{"LANG=C"}, gate.ExecOpts{}); err != nil {
				t.Errorf("err = %v", err)
			}
		})
		if out != "LANG=C\n" {
			t.Errorf("child env = %q, want exactly LANG=C", out)
		}
		out = captureStdout(t, func() {
			if _, err := gate.ExecArgvWithRedaction(ctx, []string{"/usr/bin/env"}, nil, gate.ExecOpts{}); err != nil {
				t.Errorf("err = %v", err)
			}
		})
		if out != "" {
			t.Errorf("nil env leaked the gate env into the child: %q", out)
		}
	})

	t.Run("stdin is /dev/null", func(t *testing.T) {
		r, w, err := os.Pipe()
		if err != nil {
			t.Fatal(err)
		}
		orig := os.Stdin
		os.Stdin = r
		t.Cleanup(func() { os.Stdin = orig; _ = r.Close() })
		go func() { _, _ = w.WriteString("MARKER_STDIN_REACHED\n"); _ = w.Close() }()
		out := captureStdout(t, func() {
			if _, err := gate.ExecArgvWithRedaction(ctx, []string{"/bin/cat"}, nil, gate.ExecOpts{}); err != nil {
				t.Errorf("err = %v", err)
			}
		})
		if out != "" {
			t.Errorf("gate stdin reached the argv child: %q", out)
		}
	})

	t.Run("output is redacted", func(t *testing.T) {
		out := captureStdout(t, func() {
			if _, err := gate.ExecArgvWithRedaction(ctx, []string{"/bin/echo", "AKIA1234567890ABCDEF"}, nil, gate.ExecOpts{Rules: redactrules.Combined()}); err != nil {
				t.Errorf("err = %v", err)
			}
		})
		if strings.Contains(out, "AKIA1234567890ABCDEF") || !strings.Contains(out, redact.MarkerPrefix) {
			t.Errorf("argv output bypassed the redactor: %q", out)
		}
	})

	t.Run("exit code passes through", func(t *testing.T) {
		res, err := gate.ExecArgvWithRedaction(ctx, []string{"/bin/false"}, nil, gate.ExecOpts{})
		if err != nil || res.ExitCode != 1 {
			t.Errorf("res = %+v, err = %v; want exit 1", res, err)
		}
	})

	t.Run("refusals", func(t *testing.T) {
		for name, tc := range map[string]struct {
			argv []string
			opts gate.ExecOpts
		}{
			"empty argv":        {nil, gate.ExecOpts{}},
			"relative argv[0]":  {[]string{"echo", "x"}, gate.ExecOpts{}},
			"confine requested": {[]string{"/bin/echo", "x"}, gate.ExecOpts{Confine: &confine.Spec{Profile: confine.ProfileROv1}}},
		} {
			res, err := gate.ExecArgvWithRedaction(ctx, tc.argv, nil, tc.opts)
			if err == nil || res.ExitCode != -1 {
				t.Errorf("%s: res = %+v, err = %v; want refusal with exit -1", name, res, err)
			}
		}
	})
}
