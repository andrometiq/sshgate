package tools

import (
	"strings"
	"testing"

	"github.com/karthikeyan5/sshgate/src/xfer"
)

// realBoxIDLines returns a valid (box, id) canonical PublicText pair.
func realBoxIDLines(t *testing.T) (boxLine, idLine string) {
	t.Helper()
	bk, err := xfer.GenerateBoxKey()
	if err != nil {
		t.Fatal(err)
	}
	ik, err := xfer.GenerateIDKey()
	if err != nil {
		t.Fatal(err)
	}
	return bk.PublicText(), ik.PublicText()
}

func TestParseGenKeysReadback(t *testing.T) {
	box, id := realBoxIDLines(t)
	block := func(body string) []byte {
		return []byte("SSHGATE_XFER_PUBKEYS_BEGIN\n" + body + "SSHGATE_XFER_PUBKEYS_END\n")
	}

	t.Run("golden", func(t *testing.T) {
		b := block(box + "\n" + id + "\n")
		gotBox, gotID, err := parseGenKeysReadback(b)
		if err != nil {
			t.Fatalf("parse: %v", err)
		}
		if gotBox != box || gotID != id {
			t.Errorf("parsed (%q,%q); want (%q,%q)", gotBox, gotID, box, id)
		}
	})

	t.Run("motd noise before BEGIN tolerated", func(t *testing.T) {
		raw := []byte("Last login: whatever\nMOTD banner line\n" + string(block(box+"\n"+id+"\n")) + "trailing noise\n")
		gotBox, gotID, err := parseGenKeysReadback(raw)
		if err != nil {
			t.Fatalf("parse with noise: %v", err)
		}
		if gotBox != box || gotID != id {
			t.Error("noise-tolerant parse returned the wrong lines")
		}
	})

	t.Run("id order swapped still parses", func(t *testing.T) {
		b := block(id + "\n" + box + "\n")
		if _, _, err := parseGenKeysReadback(b); err != nil {
			t.Errorf("parse (id before box): %v", err)
		}
	})

	t.Run("missing END errors", func(t *testing.T) {
		raw := []byte("SSHGATE_XFER_PUBKEYS_BEGIN\n" + box + "\n" + id + "\n")
		if _, _, err := parseGenKeysReadback(raw); err == nil {
			t.Error("missing END: want error")
		}
	})

	t.Run("missing BEGIN errors", func(t *testing.T) {
		raw := []byte(box + "\n" + id + "\nSSHGATE_XFER_PUBKEYS_END\n")
		if _, _, err := parseGenKeysReadback(raw); err == nil {
			t.Error("missing BEGIN: want error")
		}
	})

	t.Run("missing box line errors", func(t *testing.T) {
		if _, _, err := parseGenKeysReadback(block(id + "\n")); err == nil {
			t.Error("missing box: want error")
		}
	})

	t.Run("missing id line errors", func(t *testing.T) {
		if _, _, err := parseGenKeysReadback(block(box + "\n")); err == nil {
			t.Error("missing id: want error")
		}
	})

	t.Run("malformed base64 errors", func(t *testing.T) {
		bad := "sshgate-xfer-box-x25519 !!!not-base64!!!"
		if _, _, err := parseGenKeysReadback(block(bad + "\n" + id + "\n")); err == nil {
			t.Error("malformed base64: want error")
		}
	})

	t.Run("unknown tag on a line errors", func(t *testing.T) {
		// A line with an unrecognised tag hits the default branch (neither box nor
		// id) and is rejected — the block must contain ONLY the two known tags.
		unknown := strings.Replace(box, "sshgate-xfer-box-x25519", "sshgate-xfer-box-x999", 1)
		if _, _, err := parseGenKeysReadback(block(unknown + "\n" + id + "\n")); err == nil {
			t.Error("unknown-tag line: want error")
		}
	})

	t.Run("unexpected line in block errors", func(t *testing.T) {
		if _, _, err := parseGenKeysReadback(block(box + "\n" + id + "\ngarbage line\n")); err == nil {
			t.Error("unexpected line in block: want error")
		}
	})

	t.Run("duplicate box line errors", func(t *testing.T) {
		if _, _, err := parseGenKeysReadback(block(box + "\n" + box + "\n" + id + "\n")); err == nil {
			t.Error("duplicate box: want error")
		}
	})
}
