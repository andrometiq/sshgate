package redact_test

import (
	"bytes"
	"crypto/rand"
	"io"
	"strings"
	"testing"

	"github.com/karthikeyan5/sshgate/src/redact"
	"github.com/karthikeyan5/sshgate/src/redact/rules"
)

// makeCorpus builds a 1 MB synthetic log corpus shaped like real
// command output: log-line noise interspersed with the occasional
// AWS access key and GitHub PAT. It inserts one secret line per 100
// benign lines (~1 secret per ~10 KB), so the scanner exercises the
// keyword pre-filter on the majority of bytes.
func makeCorpus(size int) []byte {
	var b bytes.Buffer
	b.Grow(size)
	line := "2026-05-19T12:34:56Z INFO request id=req-abcdef-12345 method=GET path=/api/foo status=200 dur=12ms\n"
	secretLine := "  user=admin AWS_ACCESS_KEY_ID=AKIA1234567890ABCDEF token=ghp_aaaabbbbccccddddeeeeffffgggghhhhiiii\n"
	for b.Len() < size {
		// Every 100 lines, a "secret" line.
		for i := 0; i < 100 && b.Len() < size; i++ {
			b.WriteString(line)
		}
		if b.Len() < size {
			b.WriteString(secretLine)
		}
	}
	return b.Bytes()[:size]
}

// BenchmarkScannerThroughput measures bytes/sec processed by the
// streaming writer over a 1 MB synthetic corpus. Reported with
// b.ReportMetric so `go test -bench` output includes MB/s directly.
func BenchmarkScannerThroughput(b *testing.B) {
	corpus := makeCorpus(1 << 20) // 1 MB
	var salt [32]byte
	if _, err := rand.Read(salt[:]); err != nil {
		b.Fatalf("rand: %v", err)
	}
	rs := rules.Combined()

	b.SetBytes(int64(len(corpus)))
	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		w := redact.NewWriter(io.Discard, salt, rs)
		if _, err := w.Write(corpus); err != nil {
			b.Fatalf("Write: %v", err)
		}
		if err := w.Close(); err != nil {
			b.Fatalf("Close: %v", err)
		}
	}
}

// BenchmarkScannerChunkedThroughput is the same corpus driven through
// the writer in 4 KiB chunks (closer to the real exec.Cmd pipe-read
// pattern).
func BenchmarkScannerChunkedThroughput(b *testing.B) {
	corpus := makeCorpus(1 << 20)
	var salt [32]byte
	if _, err := rand.Read(salt[:]); err != nil {
		b.Fatalf("rand: %v", err)
	}
	rs := rules.Combined()
	chunk := 4 * 1024

	b.SetBytes(int64(len(corpus)))
	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		w := redact.NewWriter(io.Discard, salt, rs)
		for j := 0; j < len(corpus); j += chunk {
			end := j + chunk
			if end > len(corpus) {
				end = len(corpus)
			}
			if _, err := w.Write(corpus[j:end]); err != nil {
				b.Fatalf("Write: %v", err)
			}
		}
		if err := w.Close(); err != nil {
			b.Fatalf("Close: %v", err)
		}
	}
}

// BenchmarkScannerNoMatch measures the cost of the keyword pre-filter
// against a 1 MB corpus with no secrets — the common case.
func BenchmarkScannerNoMatch(b *testing.B) {
	// 1 MB of repeated benign log lines.
	corpus := []byte(strings.Repeat("2026-05-19T12:34:56Z INFO request id=req-abcdef-12345 method=GET path=/api/foo status=200 dur=12ms\n", 11000))
	corpus = corpus[:1<<20]

	var salt [32]byte
	if _, err := rand.Read(salt[:]); err != nil {
		b.Fatalf("rand: %v", err)
	}
	rs := rules.Combined()

	b.SetBytes(int64(len(corpus)))
	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		w := redact.NewWriter(io.Discard, salt, rs)
		if _, err := w.Write(corpus); err != nil {
			b.Fatalf("Write: %v", err)
		}
		if err := w.Close(); err != nil {
			b.Fatalf("Close: %v", err)
		}
	}
}
