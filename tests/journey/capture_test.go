//go:build journey

package journey

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"testing"
)

// Keep raw streams in memory only; overflow invalidates evidence rather than truncating silently.
type journeyCapture struct {
	mu       sync.Mutex
	data     []byte
	overflow bool
}

func (c *journeyCapture) Write(p []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	remaining := (8 << 20) - len(c.data)
	if len(p) > remaining {
		c.overflow = true
	}
	c.data = append(c.data, p[:min(len(p), remaining)]...)
	return len(p), nil
}
func (c *journeyCapture) check(t *testing.T) {
	t.Helper()
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.overflow {
		t.Error("MCP stream exceeded capture bound; evidence withheld")
	}
	if containsSecret(c.data) {
		t.Error("synthetic plaintext leaked into MCP stream; evidence withheld")
	}
}

type journeyForward struct {
	capture *journeyCapture
	pipe    *io.PipeWriter
}

func (w journeyForward) Write(p []byte) (int, error) {
	w.capture.Write(p)
	// Once the protocol reader closes, keep draining shutdown output into capture.
	_, _ = w.pipe.Write(p)
	return len(p), nil
}

var journeySecretByteArray = func() *regexp.Regexp {
	parts := make([]string, len(journeySentinel))
	for i, b := range []byte(journeySentinel) {
		parts[i] = strconv.Itoa(int(b))
	}
	return regexp.MustCompile(`(?:\[|,)\s*` + strings.Join(parts, `\s*,\s*`) + `\s*(?:,|\])`)
}()

func containsSecret(data []byte) bool {
	if journeySecretByteArray.Match(data) {
		return true
	}
	secret := make([]byte, 256)
	for i := range secret {
		secret[i] = byte(i)
	}
	secret = append(secret, []byte(journeySentinel)...)
	secret = append(secret, 0, 255, '\n')
	for _, value := range [][]byte{[]byte(journeySentinel), secret} {
		if bytes.Contains(data, value) {
			return true
		}
		for _, encoding := range []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding} {
			if bytes.Contains(data, []byte(encoding.EncodeToString(value))) {
				return true
			}
		}
		encoded := hex.EncodeToString(value)
		if bytes.Contains(data, []byte(encoded)) || bytes.Contains(data, []byte(strings.ToUpper(encoded))) {
			return true
		}
	}
	return false
}

func TestJourneyLeakCapture(t *testing.T) {
	secret := make([]byte, 256)
	for i := range secret {
		secret[i] = byte(i)
	}
	secret = append(secret, []byte(journeySentinel)...)
	secret = append(secret, 0, 255, '\n')
	integers := make([]int, len(secret))
	for i, b := range secret {
		integers[i] = int(b)
	}
	compact, _ := json.Marshal(map[string]any{"_meta": map[string]any{"debug_plaintext": integers}})
	pretty, _ := json.MarshalIndent(integers, "", "  ")
	values := []string{string(compact), string(pretty), journeySentinel, string(secret), "notification: " + journeySentinel}
	for _, raw := range [][]byte{[]byte(journeySentinel), secret} {
		for _, encoding := range []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding} {
			values = append(values, encoding.EncodeToString(raw))
		}
		values = append(values, hex.EncodeToString(raw), strings.ToUpper(hex.EncodeToString(raw)))
	}
	for _, value := range values {
		var capture journeyCapture
		capture.Write([]byte(value[:3]))
		capture.Write([]byte(value[3:]))
		if !containsSecret(capture.data) {
			t.Fatal("missed encoded or split leak")
		}
	}
	var capture journeyCapture
	capture.Write(make([]byte, (8<<20)+1))
	if !capture.overflow || len(capture.data) != 8<<20 {
		t.Fatal("capture bound not enforced")
	}
}

type journeyInput struct {
	io.WriteCloser
	capture *journeyCapture
}

func (w journeyInput) Write(p []byte) (int, error) { w.capture.Write(p); return w.WriteCloser.Write(p) }

func TestJourneyCaptureAfterProtocolClose(t *testing.T) {
	reader, writer := io.Pipe()
	_ = reader.Close()
	var capture journeyCapture
	forward := journeyForward{&capture, writer}
	if _, err := forward.Write([]byte(journeySentinel)); err != nil {
		t.Fatal(err)
	}
	if !containsSecret(capture.data) {
		t.Fatal("shutdown output lost")
	}
	_ = writer.Close()
}
