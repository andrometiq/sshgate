package hosted

import (
	"crypto/rand"
	"encoding/base64"
	"net/http"
	"time"
)

// generateRequestID returns an opaque, URL-safe request ID. v2.0 uses
// 9 bytes of randomness rendered as 12 base64 chars; collision space
// is ~2^72 which is overkill for a one-laptop scaffold but cheap.
// Format mirrors the spec example "r_a1b2c3" with an "r_" prefix.
func generateRequestID() string {
	var b [9]byte
	if _, err := rand.Read(b[:]); err != nil {
		// rand.Read on Linux only fails if the kernel CSPRNG is
		// broken — we'd rather crash here than emit a predictable
		// ID. Tests don't exercise this branch because they wrap
		// the call site, not this function.
		panic("hosted: crypto/rand failed: " + err.Error())
	}
	return "r_" + base64.RawURLEncoding.EncodeToString(b[:])
}

// logRequest wraps next with a single log line per request: method,
// path, status, duration. The status is captured via a thin
// ResponseWriter wrapper because http.ResponseWriter does not expose
// the chosen status code.
//
// v2.0 logs to s.Logger; v2.1 should swap this for structured logging
// (slog or zap) and add a request_id correlation field once
// observability tooling is wired up.
func (s *Server) logRequest(w http.ResponseWriter, r *http.Request, next func(http.ResponseWriter, *http.Request)) {
	start := time.Now()
	sw := &statusWriter{ResponseWriter: w, status: http.StatusOK}
	next(sw, r)
	s.Logger.Printf("%s %s -> %d (%s)", r.Method, r.URL.Path, sw.status, time.Since(start))
}

// statusWriter wraps http.ResponseWriter to capture the status code.
// Handlers that never call WriteHeader implicitly get 200, matching
// stdlib semantics.
type statusWriter struct {
	http.ResponseWriter
	status      int
	wroteHeader bool
}

func (s *statusWriter) WriteHeader(code int) {
	if s.wroteHeader {
		return
	}
	s.wroteHeader = true
	s.status = code
	s.ResponseWriter.WriteHeader(code)
}

func (s *statusWriter) Write(b []byte) (int, error) {
	if !s.wroteHeader {
		s.WriteHeader(http.StatusOK)
	}
	return s.ResponseWriter.Write(b)
}
