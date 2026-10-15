package tools

import (
	"context"
	"strings"
	"testing"
)

func TestRunBatchNetworkRefused(t *testing.T) {
	r, s, ssh := networkRunner(t, false, networkCap(true, true))
	out, err := r.RunBatch(context.Background(), RunBatchInput{Alias: "test", Commands: []string{"cat x"}, Network: true})
	if err == nil || !strings.Contains(err.Error(), "single-read") || out.Denial != nil || len(s.calls) != 0 || len(ssh.calls) != 0 {
		t.Fatalf("batch network: %+v %v signs=%v ssh=%v", out, err, s.calls, ssh.calls)
	}
}
