package elapsedtest

import (
	"fmt"
	"strings"
	"testing"
)

// recorder captures failures so a test can assert that the check fails.
type recorder struct {
	testing.TB
	errs []string
}

func (r *recorder) Helper() {}
func (r *recorder) Errorf(format string, args ...any) {
	r.errs = append(r.errs, fmt.Sprintf(format, args...))
}

func check(t *testing.T, file string, allow ...string) []string {
	t.Helper()
	r := &recorder{TB: t}
	AssertNoDirectTimeReads(r, []string{"testdata/" + file}, allow...)
	return r.errs
}

func TestAssertNoDirectTimeReads(t *testing.T) {
	cases := []struct {
		file  string
		allow []string
		want  []string // substrings, one per expected failure
	}{
		{file: "direct_now.go.txt", want: []string{"direct time.Now"}},
		{file: "context_timeout.go.txt", want: []string{"direct context.WithTimeout", "direct context.WithTimeout"}},
		{file: "context_timeout.go.txt", allow: []string{"testdata/context_timeout.go.txt:wakeUp"}, want: []string{"context_timeout.go.txt:9"}},
		{file: "aliased.go.txt", want: []string{"direct stdtime.Since"}},
		{file: "dot.go.txt", want: []string{"dot import"}},
		{file: "adapter.go.txt", want: []string{"direct time.Now"}},
		{file: "adapter.go.txt", allow: []string{"testdata/adapter.go.txt"}},
		{file: "clean.go.txt"},
	}
	for _, tc := range cases {
		errs := check(t, tc.file, tc.allow...)
		if len(errs) != len(tc.want) {
			t.Errorf("%s allow=%v: got %d failures %q, want %d", tc.file, tc.allow, len(errs), errs, len(tc.want))
			continue
		}
		for i, w := range tc.want {
			if !strings.Contains(errs[i], w) {
				t.Errorf("%s: failure %q does not mention %q", tc.file, errs[i], w)
			}
		}
	}
}

func TestAssertNoDirectTimeReadsPassesOnElapsedAdapter(t *testing.T) {
	AssertNoDirectTimeReads(t, []string{"../elapsed.go"}, "../elapsed.go:realClock.Wall")
	AssertNoDirectTimeReads(t, []string{"../elapsed_linux.go"})
}
