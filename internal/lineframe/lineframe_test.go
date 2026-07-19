package lineframe

import (
	"bytes"
	"errors"
	"io"
	"testing"
)

type oneByteReader struct{ r io.Reader }

func (r oneByteReader) Read(p []byte) (int, error) {
	if len(p) > 1 {
		p = p[:1]
	}
	return r.r.Read(p)
}

type bytesThenErrorReader struct {
	body []byte
	err  error
}

func (r *bytesThenErrorReader) Read(p []byte) (int, error) {
	if len(r.body) == 0 {
		return 0, r.err
	}
	n := copy(p, r.body)
	r.body = r.body[n:]
	return n, nil
}

func TestReadBoundaryAndEOFCompatibility(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		max     int
		want    string
		wantErr error
	}{
		{name: "newline at bound", input: "abc\nrest", max: 4, want: "abc\n"},
		{name: "complete EOF at bound", input: "abcd", max: 4, want: "abcd"},
		{name: "empty EOF", input: "", max: 4, wantErr: io.EOF},
		{name: "over bound before newline", input: "abcde\nsecond\n", max: 4, wantErr: ErrTooLarge},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := Read(bytes.NewBufferString(tc.input), tc.max)
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("error = %v; want %v", err, tc.wantErr)
			}
			if string(got) != tc.want {
				t.Fatalf("frame = %q; want %q", got, tc.want)
			}
		})
	}
}

func TestReadOversizeDoesNotReturnPartialFrame(t *testing.T) {
	got, err := Read(bytes.NewBufferString("12345\nsecond\n"), 5)
	if !errors.Is(err, ErrTooLarge) {
		t.Fatalf("error = %v; want ErrTooLarge", err)
	}
	if got != nil {
		t.Fatalf("oversize returned partial bytes %q", got)
	}
}

func TestReadFragmentedAndTransportError(t *testing.T) {
	got, err := Read(oneByteReader{r: bytes.NewBufferString("fragmented\nnext")}, 32)
	if err != nil || string(got) != "fragmented\n" {
		t.Fatalf("fragmented frame = %q, %v", got, err)
	}

	transportErr := errors.New("transport failed")
	got, err = Read(&bytesThenErrorReader{body: []byte("partial"), err: transportErr}, 32)
	if !errors.Is(err, transportErr) || string(got) != "partial" {
		t.Fatalf("erroring frame = %q, %v; want partial bytes and transport error", got, err)
	}
}

func TestReadRejectsInvalidArguments(t *testing.T) {
	if _, err := Read(nil, 1); err == nil {
		t.Fatal("nil reader accepted")
	}
	if _, err := Read(bytes.NewReader(nil), 0); err == nil {
		t.Fatal("zero maximum accepted")
	}
}
