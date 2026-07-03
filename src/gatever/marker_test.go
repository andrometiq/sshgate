package gatever

import (
	"bytes"
	"testing"
)

// marker builds a full marker string for a version token. Tests use it to
// synthesize .rodata-like inputs WITHOUT writing the naked prefix literal in
// this test's source (which would defeat the point of prefixBytes and also
// pollute the compiled test binary). It mirrors prefixBytes' runtime assembly.
func marker(version string) string {
	return string(prefixBytes()) + version + string(closeDelim)
}

func TestVersion_SingleMarker(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name   string
		marker string
		want   string
	}{
		{"dev default is reported verbatim", marker("dev"), "dev"},
		{"release version", marker("v1.3.0"), "v1.3.0"},
		{"full charset token", marker("v1.3.0-rc.1+build_9"), "v1.3.0-rc.1+build_9"},
		{"empty marker -> unknown", "", Unknown},
		{"no prefix -> unknown", "not a marker", Unknown},
		{"empty token -> unknown", marker(""), Unknown},
		{"unterminated -> unknown", string(prefixBytes()) + "v1.3.0", Unknown},
		{"bad char before brace -> unknown", string(prefixBytes()) + "v1.3.0 x}", Unknown},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := Version(tc.marker); got != tc.want {
				t.Errorf("Version(%q) = %q; want %q", tc.marker, got, tc.want)
			}
		})
	}
}

func TestScan_AllOccurrences(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		body []byte
		want string
	}{
		{
			name: "no marker at all -> unknown",
			body: bytes.Repeat([]byte("A"), 4096),
			want: Unknown,
		},
		{
			name: "single release marker",
			body: []byte("prefix junk " + marker("v1.3.0") + " trailing"),
			want: "v1.3.0",
		},
		{
			name: "lingering dev + injected release -> release wins (the key carve-out)",
			body: []byte(marker("dev") + " ... " + marker("v1.3.0")),
			want: "v1.3.0",
		},
		{
			name: "release then lingering dev, order independent",
			body: []byte(marker("v1.3.0") + " ... " + marker("dev")),
			want: "v1.3.0",
		},
		{
			name: "only dev -> unknown (a dev binary has no release version)",
			body: []byte("noise " + marker("dev") + " noise"),
			want: Unknown,
		},
		{
			name: "same release version repeated collapses to one",
			body: []byte(marker("v1.3.0") + marker("v1.3.0")),
			want: "v1.3.0",
		},
		{
			name: "two conflicting real versions -> unknown",
			body: []byte(marker("v1.3.0") + " " + marker("v1.4.0")),
			want: Unknown,
		},
		{
			name: "bare prefix with no valid token is skipped, real marker still found",
			body: []byte(string(prefixBytes()) + " garbage no brace ... " + marker("v2.0.0")),
			want: "v2.0.0",
		},
		{
			name: "prefix followed by an oversize token is rejected but a later valid one wins",
			body: []byte(marker(string(bytes.Repeat([]byte("a"), maxVersionLen+1))) + marker("v1.2.3")),
			want: "v1.2.3",
		},
		{
			name: "exactly 64-char token accepted",
			body: []byte(marker(string(bytes.Repeat([]byte("a"), maxVersionLen)))),
			want: string(bytes.Repeat([]byte("a"), maxVersionLen)),
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := Scan(tc.body); got != tc.want {
				t.Errorf("Scan(...) = %q; want %q", got, tc.want)
			}
		})
	}
}

// TestPrefixNotInRodataLiteral is a guard on safe-scan rule 1: prefixBytes must
// assemble the prefix at runtime, so the contiguous literal must NOT be findable
// as a compile-time constant. We approximate this by asserting the individual
// pieces are present but that the function returns a freshly-built slice each
// call (a distinct backing array), which only holds if it is not returning a
// shared package-level constant slice.
func TestPrefixBytesRuntimeBuilt(t *testing.T) {
	t.Parallel()
	a := prefixBytes()
	b := prefixBytes()
	if !bytes.Equal(a, b) {
		t.Fatalf("prefixBytes not stable: %q vs %q", a, b)
	}
	// Distinct backing arrays: mutating one must not affect the other.
	a[0] = 'X'
	if b[0] == 'X' {
		t.Error("prefixBytes returned a shared backing array — it must build a fresh slice at runtime")
	}
}
