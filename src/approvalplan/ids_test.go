package approvalplan

import (
	"bytes"
	"crypto/rand"
	"errors"
	"strings"
	"testing"
)

func TestRequestIDs(t *testing.T) {
	for range 1000 {
		id, err := NewRequestID(rand.Reader)
		if err != nil || !ValidRequestID(id) {
			t.Fatalf("NewRequestID = %q, %v", id, err)
		}
	}
	if _, err := NewRequestID(bytes.NewReader(make([]byte, 15))); err == nil {
		t.Fatal("a short reader minted an ID")
	}
	for _, bad := range []string{
		"", "a2_", "a2_AAAAAAAAAAAAAAAAAAAAA", "a2_AAAAAAAAAAAAAAAAAAAAAAA", "a3_AAAAAAAAAAAAAAAAAAAAAA",
		"A2_AAAAAAAAAAAAAAAAAAAAAA", "a2_AAAAAAAAAAAAAAAAAAAAA=", "a2_AAAAAAAAAAAAAAAAAAAAA+", "a2_AAAAAAAAAAAAAAAAAAAAA/",
		"r_AAAAAAAAAAAAAAAAAAAAAAA", "a2_AAAAAAAAAAAAAAAAAAAAA\x00",
	} {
		if ValidRequestID(bad) {
			t.Errorf("ValidRequestID(%q) = true", bad)
		}
	}
}

func TestShortGrammars(t *testing.T) {
	h, err := NewCardHandle(rand.Reader)
	if err != nil || !ValidCardHandle(h) || len("v:a:"+h+":"+strings.Repeat("0", ChallengeLen)) > 35 {
		t.Fatalf("card handle %q, %v", h, err)
	}
	c, err := NewChallenge(rand.Reader)
	if err != nil || !ValidChallenge(c) {
		t.Fatalf("challenge %q, %v", c, err)
	}
	e, err := NewEpoch(rand.Reader)
	if err != nil || !ValidEpoch(e) {
		t.Fatalf("epoch %q, %v", e, err)
	}
	for name, f := range map[string]func() error{
		"handle":    func() error { _, err := NewCardHandle(bytes.NewReader(nil)); return err },
		"challenge": func() error { _, err := NewChallenge(bytes.NewReader(nil)); return err },
		"epoch":     func() error { _, err := NewEpoch(bytes.NewReader(nil)); return err },
	} {
		if err := f(); err == nil {
			t.Errorf("%s minted from an empty reader", name)
		}
	}
	for _, bad := range []string{"", "ABCDEFGHIJKL", "abcdefghijk1", "abcdefghijk", "abcdefghijklm"} {
		if ValidCardHandle(bad) {
			t.Errorf("ValidCardHandle(%q)", bad)
		}
	}
	for _, bad := range []string{"0123456789ABCDEF", "0123456789abcde", "0123456789abcdefg", "0123456789abcdeg"} {
		if ValidChallenge(bad) {
			t.Errorf("ValidChallenge(%q)", bad)
		}
	}
	for s, want := range map[string]bool{
		"local-uid:0": true, "local-uid:4294967295": true, "local-uid:12345678901": false,
		"local-uid:": false, "local-uid:-1": false, "local-uid:1 ": false, "uid:1": false,
	} {
		if ValidRequesterSub(s) != want {
			t.Errorf("ValidRequesterSub(%q) != %v", s, want)
		}
	}
	for s, want := range map[string]bool{
		"alice": true, "telegram:123456": true, "a.b_c@d-e": true, strings.Repeat("a", 128): true,
		strings.Repeat("a", 129): false, "": false, "-alice": false, "al ice": false, "al,ice": false, "alicé": false,
	} {
		if ValidOperatorID(s) != want {
			t.Errorf("ValidOperatorID(%q) != %v", s, want)
		}
	}
}

func FuzzValidRequestID(f *testing.F) {
	f.Add("a2_AAAAAAAAAAAAAAAAAAAAAA")
	f.Add("a2_x-_0123456789abcdefghi")
	f.Add("a2_")
	f.Fuzz(func(t *testing.T, s string) {
		if !ValidRequestID(s) {
			return
		}
		if len(s) != 25 || !strings.HasPrefix(s, "a2_") || strings.ContainsAny(s[3:], "=+/ \x00") {
			t.Fatalf("accepted %q", s)
		}
	})
}

type failingReader struct{}

func (failingReader) Read([]byte) (int, error) { return 0, errors.New("no entropy") }

func TestMintersPropagateReaderErrors(t *testing.T) {
	if _, err := NewRequestID(failingReader{}); err == nil || !strings.Contains(err.Error(), "no entropy") {
		t.Fatalf("NewRequestID error = %v", err)
	}
}
