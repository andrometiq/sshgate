//go:build linux && sshgate_perf

// TestExecutorContention measures 100 concurrent submitters at production
// limits (C2, #33). It is a measurement, too slow for the unit suite under
// -race: run it with
//
//	go test -tags sshgate_perf -count=1 -run TestExecutorContention -v ./src/executor/

package executor

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	ap "github.com/karthikeyan5/sshgate/src/approvalplan"
	st "github.com/karthikeyan5/sshgate/src/approvalplan/statetest"
	"github.com/karthikeyan5/sshgate/src/executorwire"
)

// Exercise admission and whole-record rewrites at unchanged production limits.
// The pure transitions stand in for SSH; every marker and result reaches disk.
func TestExecutorContention(t *testing.T) {
	service, store, _, _ := submitService(t)
	requests := make([]executorwire.SubmitRequest, 100)
	for i := range requests {
		in := submitRequest(t, i+1).Input
		in.Tool, in.Command = "run_batch", ""
		in.Reason = strings.Repeat("<", ap.MaxRationaleBytes)
		in.MaxOutputBytes = ap.MaxStreamOutputBytes
		for j := 0; j < ap.MaxSteps; j++ {
			in.Commands = append(in.Commands, "printf '"+strings.Repeat("<", ap.MaxTotalBytes/ap.MaxSteps-len("printf '' > /tmp/job"))+"' > /tmp/job")
		}
		requests[i] = requestWith(t, in)
	}
	type admission struct {
		id      string
		latency time.Duration
		err     error
	}
	admitted := make(chan admission, len(requests))
	start := make(chan struct{})
	var group sync.WaitGroup
	for _, request := range requests {
		group.Add(1)
		go func(request executorwire.SubmitRequest) {
			defer group.Done()
			<-start
			began := time.Now()
			_, err := service.Submit(request)
			admitted <- admission{request.Input.RequestID, time.Since(began), err}
		}(request)
	}
	close(start)
	group.Wait()
	close(admitted)
	var ids []string
	var admissionLatencies []time.Duration
	refusals := 0
	for result := range admitted {
		if result.err != nil {
			var wire *executorwire.WireError
			if !errors.As(result.err, &wire) || wire.Code != "executor_full" {
				t.Fatal(result.err)
			}
			refusals++
			continue
		}
		ids = append(ids, result.id)
		admissionLatencies = append(admissionLatencies, result.latency)
	}
	if len(ids) == 0 {
		t.Fatal("no jobs admitted")
	}
	sort.Slice(admissionLatencies, func(i, j int) bool { return admissionLatencies[i] < admissionLatencies[j] })
	t.Logf("submitters=100 admitted=%d refused=%d admission_p99=%s", len(ids), refusals, admissionLatencies[(99*len(ids)-1)/100])
	// Fill the output budget first so later markers rewrite maximum-size records.
	body := bytes.Repeat([]byte("x"), ap.MaxStreamOutputBytes)
	digest := sha256.Sum256(body)
	exit := 0
	result := ap.StepResult{Status: ap.StepSucceeded, ExitCode: &exit,
		Stdout: body, Stderr: body, StdoutBytes: int64(len(body)), StderrBytes: int64(len(body)),
		StdoutSHA256: hex.EncodeToString(digest[:]), StderrSHA256: hex.EncodeToString(digest[:])}
	var written int64
	for _, id := range ids {
		job, err := store.Load(id)
		if err != nil {
			t.Fatal(err)
		}
		written += store.files[ap.JobKey(id)].EncodedBytes
		job, answer := ap.ApplyJob(job, ap.SignerAck{PlanHash: job.DraftHash}, ap.Now{Wall: st.T0}, service.epoch)
		if !answer.Changed {
			t.Fatal(answer)
		}
		if err := store.Commit(job); err != nil {
			t.Fatal(err)
		}
		written += store.files[ap.JobKey(id)].EncodedBytes
	}
	latencies := make(chan time.Duration, len(ids)*ap.MaxSteps)
	start = make(chan struct{})
	for _, id := range ids {
		group.Add(1)
		go func(id string) {
			defer group.Done()
			<-start
			for ordinal := 1; ordinal <= ap.MaxSteps; ordinal++ {
				began := time.Now()
				service.mu.Lock()
				job, err := store.Load(id)
				if err == nil {
					var answer ap.JobAnswer
					job, answer = ap.ApplyJob(job, ap.MarkStep{Ordinal: ordinal}, ap.Now{Wall: st.T0}, service.epoch)
					if !answer.Changed {
						t.Errorf("marker: %+v", answer)
						service.mu.Unlock()
						return
					}
					err = store.Commit(job)
				}
				latency := time.Since(began)
				if err == nil {
					written += store.files[ap.JobKey(id)].EncodedBytes
				}
				service.mu.Unlock()
				if err != nil {
					t.Error(err)
					return
				}
				latencies <- latency
				service.mu.Lock()
				job, err = store.Load(id)
				if err == nil {
					var answer ap.JobAnswer
					stepResult := result
					if ordinal > ap.MaxJobOutputBytes/(2*ap.MaxStreamOutputBytes) {
						stepResult = ap.NoOutputResult(ap.StepSucceeded, "")
						stepResult.ExitCode = &exit
					}
					job, answer = ap.ApplyJob(job, ap.RecordResult{Ordinal: ordinal, Result: stepResult}, ap.Now{Wall: st.T0}, service.epoch)
					if !answer.Changed {
						t.Errorf("result: %+v", answer)
						service.mu.Unlock()
						return
					}
					err = store.Commit(job)
				}
				if err == nil {
					written += store.files[ap.JobKey(id)].EncodedBytes
				}
				service.mu.Unlock()
				if err != nil {
					t.Error(err)
					return
				}
			}
		}(id)
	}
	close(start)
	group.Wait()
	close(latencies)
	var samples []time.Duration
	for duration := range latencies {
		samples = append(samples, duration)
	}
	if len(samples) != len(ids)*ap.MaxSteps {
		t.Fatalf("markers=%d want=%d", len(samples), len(ids)*ap.MaxSteps)
	}
	sort.Slice(samples, func(i, j int) bool { return samples[i] < samples[j] })
	p99 := samples[(99*len(samples)-1)/100]
	t.Logf("encoded_bytes_written=%d marker_commits=%d marker_p99=%s marker_max=%s", written, len(samples), p99, samples[len(samples)-1])
	if p99 > time.Second {
		t.Fatalf("marker p99 %s exceeds 1s; durable-format design required", p99)
	}
}
