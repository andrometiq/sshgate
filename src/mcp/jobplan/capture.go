package jobplan

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"sync"
)

// Both SSH output streams share the job budget, but own their stream state.
type captureBudget struct {
	sync.Mutex
	remaining int64
}

type capture struct {
	body             []byte
	count            int64
	limit            int64
	budget           *captureBudget
	tail             string
	jail, afterStart bool
}

func newCapture(limit int64, budget *captureBudget) *capture {
	return &capture{limit: limit, budget: budget}
}

func (c *capture) Write(p []byte) (int, error) {
	c.count += int64(len(p))
	// Preserve execution evidence even when the retained output cap is tiny.
	const jailLine = "gate: read jail unavailable"
	const afterLine = "the jail failed after the read may have started"
	joined := c.tail + string(p)
	c.jail = c.jail || strings.Contains(joined, jailLine)
	c.afterStart = c.afterStart || strings.Contains(joined, afterLine)
	c.tail = strings.Clone(joined[max(0, len(joined)-len(afterLine)+1):])
	keep := int64(len(p))
	if c.budget != nil {
		c.budget.Lock()
		keep = min(keep, max(0, c.limit-int64(len(c.body))), c.budget.remaining)
		c.budget.remaining -= keep
		c.budget.Unlock()
	}
	c.body = append(c.body, p[:keep]...)
	return len(p), nil
}

func (c *capture) finish() ([]byte, bool) {
	truncated := c.count > int64(len(c.body))
	if truncated {
		marker := []byte("\n[...truncated]")
		n := min(len(marker), len(c.body))
		copy(c.body[len(c.body)-n:], marker[:n])
	}
	return c.body, truncated
}

func outputDigest(body []byte) string { sum := sha256.Sum256(body); return hex.EncodeToString(sum[:]) }

func (c *capture) outcomeBytes(body []byte) []byte {
	if !c.jail {
		return body
	}
	text := "gate: read jail unavailable"
	if c.afterStart {
		text += ": the jail failed after the read may have started"
	}
	return []byte(text)
}
