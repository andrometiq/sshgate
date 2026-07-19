// Package lineframe provides bounded newline-delimited framing without
// draining bytes beyond an oversized frame. It deliberately knows nothing
// about JSON or any SSHGate protocol.
package lineframe

import (
	"bufio"
	"errors"
	"fmt"
	"io"
)

// ErrTooLarge marks a frame that crossed its configured byte bound.
var ErrTooLarge = errors.New("line frame too large")

// Read reads through the first newline, returning the newline as part of the
// frame just like bufio.Reader.ReadBytes. A non-empty final frame ending at
// EOF is returned with a nil error; the caller's typed decoder decides whether
// those bytes are complete. An empty EOF remains io.EOF, preserving the
// transport-level "no response" distinction.
//
// Once max bytes would be crossed Read returns ErrTooLarge immediately. It
// does not drain the rest of the input, which is important for one-request
// connections: an attacker cannot smuggle a second request behind an
// oversized first frame and have a caller accidentally process it.
func Read(r io.Reader, max int) ([]byte, error) {
	if r == nil {
		return nil, errors.New("line frame: nil reader")
	}
	if max <= 0 {
		return nil, fmt.Errorf("line frame: invalid maximum %d", max)
	}

	br := bufio.NewReader(r)
	frame := make([]byte, 0, min(max, 4096))
	for {
		fragment, err := br.ReadSlice('\n')
		if len(fragment) > max-len(frame) {
			return nil, fmt.Errorf("%w: maximum is %d bytes", ErrTooLarge, max)
		}
		frame = append(frame, fragment...)

		switch {
		case err == nil:
			return frame, nil
		case errors.Is(err, bufio.ErrBufferFull):
			continue
		case errors.Is(err, io.EOF) && len(frame) > 0:
			return frame, nil
		default:
			return frame, err
		}
	}
}
