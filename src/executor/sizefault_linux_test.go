//go:build linux && sshgate_sizefault

package executor

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"testing"

	ap "github.com/karthikeyan5/sshgate/src/approvalplan"
	st "github.com/karthikeyan5/sshgate/src/approvalplan/statetest"
)

// Run with the reservation-size overlay described in README.md. The overlay
// reduces only the reservation allowance; Commit and EncodeR2 are real.
func TestCommandJobRealStoreSizeRefusal(t *testing.T) {
	s, mem, _, request := commandFixture(t)
	_, disk := retentionStore(t)
	job := mem.jobs[request.Input.RequestID]
	job.Draft.CommandJob.MaxOutputBytes = 1 << 20
	job.DraftHash, _ = ap.DraftHash(job.Draft)
	job.Reservation = int64(ap.R2Reservation(job.Draft, ap.PermittedOutputBytes(job.Draft)))
	job.SignerAck = job.DraftHash
	job, answer := ap.ApplyJob(job, ap.MarkStep{Ordinal: 1}, ap.Now{Wall: st.T0}, s.epoch)
	if !answer.Changed {
		t.Fatal(answer)
	}
	if err := disk.Commit(job); err != nil {
		t.Fatal(err)
	}
	s.store = disk
	result := ap.NoOutputResult(ap.StepSucceeded, "")
	zero := 0
	result.ExitCode = &zero
	result.Stdout = bytes.Repeat([]byte("x"), 1<<20)
	result.StdoutBytes = int64(len(result.Stdout))
	hash := sha256.Sum256(result.Stdout)
	result.StdoutSHA256 = hex.EncodeToString(hash[:])
	candidate, _ := ap.ApplyJob(job, ap.RecordResult{Ordinal: 1, Result: result}, ap.Now{Wall: st.T0}, s.epoch)
	err := disk.Commit(candidate)
	var code *ap.CodeError
	if !errors.As(err, &code) || code.Code != ap.CodeRequestTooLarge {
		t.Fatalf("expected real EncodeR2 size refusal (reservation overlay required), got %v", err)
	}
	actor := commandActor{service: s, id: job.RequestID}
	if err := actor.AfterStep(1, result); err != nil {
		t.Fatal(err)
	}
	got, err := disk.Load(job.RequestID)
	if err != nil {
		t.Fatal(err)
	}
	r := got.Steps[0].Result
	if r == nil || !r.BodiesUnstorable || len(r.Stdout) != 0 || r.StdoutSHA256 != result.StdoutSHA256 || r.StdoutBytes != result.StdoutBytes {
		t.Fatal("fallback lost result metadata", r)
	}
}
