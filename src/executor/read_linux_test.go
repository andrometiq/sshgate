//go:build linux

package executor

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	ap "github.com/karthikeyan5/sshgate/src/approvalplan"
	st "github.com/karthikeyan5/sshgate/src/approvalplan/statetest"
	"github.com/karthikeyan5/sshgate/src/executorwire"
)

func readWire(t *testing.T, s *Service, request any, kind string) (executorwire.Response, error) {
	t.Helper()
	server, client := net.Pipe()
	defer client.Close()
	client.SetDeadline(time.Now().Add(10 * time.Second))
	done := make(chan error, 1)
	go func() { done <- s.ServeConn(context.Background(), server) }()
	frame, err := executorwire.MarshalRequest(request)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = client.Write(frame); err != nil {
		t.Fatal(err)
	}
	frame, err = bufio.NewReader(client).ReadBytes('\n')
	if err != nil {
		t.Fatal(err)
	}
	if err = <-done; err != nil {
		t.Fatal(err)
	}
	return executorwire.DecodeResponse(kind, frame)
}

func TestReadsCommittedOnly(t *testing.T) {
	s, store, clock, _ := submitService(t)
	for i := 1; i <= 3; i++ {
		if _, err := s.Submit(submitRequest(t, i)); err != nil {
			t.Fatal(err)
		}
	}
	job, _ := store.Load(st.ID(1))
	job, _ = ap.ApplyJob(job, ap.SignerAck{PlanHash: job.DraftHash}, ap.Now{Wall: st.T0}, s.epoch)
	if err := store.Commit(job); err != nil {
		t.Fatal(err)
	}
	before := map[string][]byte{}
	files, _ := store.List()
	for _, file := range files {
		body, err := os.ReadFile(filepath.Join(store.local.directory.Name(), file.Key))
		if err != nil {
			t.Fatal(err)
		}
		before[file.Key] = body
	}
	commits := store.commits
	clock.StepWall(365 * 24 * time.Hour)
	response, err := readWire(t, s, executorwire.GetRequest{ProtoVersion: 1, Kind: executorwire.KindGet, RequestID: st.ID(1)}, executorwire.KindGet)
	if err != nil || response.Job.ExecutionStatus != ap.JobAcknowledged {
		t.Fatal(response, err)
	}
	frame, _ := executorwire.MarshalResponse(response)
	for _, secret := range []string{"approval_status", "claim_token", job.ClaimToken, "touch /tmp/job"} {
		if bytes.Contains(frame, []byte(secret)) {
			t.Fatalf("view leaked %s", secret)
		}
	}
	response, err = readWire(t, s, executorwire.AwaitRequest{ProtoVersion: 1, Kind: executorwire.KindAwait, RequestIDs: []string{st.ID(1), st.ID(99)}}, executorwire.KindAwait)
	if err != nil || response.Items[0].Job.ExecutionStatus != ap.JobAcknowledged || response.Items[1].Error.Code != "not_found" {
		t.Fatal(response, err)
	}
	_, err = readWire(t, s, executorwire.GetRequest{ProtoVersion: 1, Kind: executorwire.KindGet, RequestID: st.ID(99)}, executorwire.KindGet)
	requireCode(t, err, "not_found")
	seen := map[string]bool{}
	cursor := ""
	for {
		response, err = readWire(t, s, executorwire.ListRequest{ProtoVersion: 1, Kind: executorwire.KindList, Limit: 1, Cursor: cursor}, executorwire.KindList)
		if err != nil || len(response.Items) != 1 {
			t.Fatal(response, err)
		}
		id := response.Items[0].RequestID
		if seen[id] {
			t.Fatal("duplicate page")
		}
		seen[id] = true
		cursor = response.NextCursor
		if cursor == "" {
			break
		}
	}
	if len(seen) != 3 || store.commits != commits {
		t.Fatal("reads changed state or lost page")
	}
	for key, body := range before {
		after, err := os.ReadFile(filepath.Join(store.local.directory.Name(), key))
		if err != nil || !bytes.Equal(body, after) {
			t.Fatal("read changed job file", err)
		}
	}
	_, err = s.List(executorwire.ListRequest{ProtoVersion: 1, Kind: executorwire.KindList, Limit: 1, Cursor: "bad"})
	requireCode(t, err, "invalid_request")
}

func maximumJob(t *testing.T, id int) (ap.R2, []byte) {
	t.Helper()
	job := storeJob(t, id, true)
	body := bytes.Repeat([]byte{0xff, '<', 0xfe, '>', '&', 0, 0xc3, 0x80}, ap.MaxJobOutputBytes/64/8)
	sum := sha256.Sum256(body)
	digest := hex.EncodeToString(sum[:])
	exit := 0
	for i := range job.Steps {
		var answer ap.JobAnswer
		job, answer = ap.ApplyJob(job, ap.RecordResult{Ordinal: i + 1, Result: ap.StepResult{Status: ap.StepSucceeded, ExitCode: &exit, StdoutBytes: int64(len(body)), StderrBytes: int64(len(body)), StdoutSHA256: digest, StderrSHA256: digest, Stdout: body, Stderr: body}}, ap.Now{Wall: st.T0}, st.Epoch(1))
		if !answer.Changed {
			t.Fatal(answer)
		}
	}
	return job, body
}

func TestAwaitBinaryBodiesAndResponseCap(t *testing.T) {
	s, store, _, _ := submitService(t)
	var expected []byte
	for i := 1; i <= 2; i++ {
		job, body := maximumJob(t, i)
		expected = body
		if err := store.Commit(job); err != nil {
			t.Fatal(err)
		}
	}
	commits := store.commits
	request := executorwire.AwaitRequest{ProtoVersion: 1, Kind: executorwire.KindAwait, RequestIDs: []string{st.ID(1), st.ID(2)}}
	response, err := readWire(t, s, request, executorwire.KindAwait)
	if err != nil {
		t.Fatal(err)
	}
	first, second := response.Items[0].Job, response.Items[1].Job
	if len(first.Results) != 32 || second.ResultStatus != "result_withheld" || second.Hint != "await this id alone" {
		t.Fatal("body admission", len(first.Results), second)
	}
	for _, result := range first.Results {
		if !bytes.Equal(result.Stdout, expected) || !bytes.Equal(result.Stderr, expected) {
			t.Fatal("binary output changed")
		}
	}
	frame, err := executorwire.MarshalResponse(response)
	if err != nil || len(frame) > executorwire.MaxResponseBytes {
		t.Fatal("response cap", err)
	}
	request.RequestIDs = []string{st.ID(2)}
	response, err = readWire(t, s, request, executorwire.KindAwait)
	if err != nil || len(response.Items[0].Job.Results) != 32 {
		t.Fatal("alone", err)
	}
	if store.commits != commits {
		t.Fatal("await committed delivery")
	}
	for _, cause := range []string{ap.BodiesRemovedAge, ap.BodiesRemovedBudget} {
		job, _ := store.Load(st.ID(1))
		job, _ = ap.ApplyJob(job, ap.MarkDelivered{}, ap.Now{Wall: st.T0}, s.epoch)
		job, answer := ap.ApplyJob(job, ap.RemoveBodies{Cause: cause}, ap.Now{Wall: st.T0.Add(ap.BodyRetention)}, s.epoch)
		if !answer.Changed {
			t.Fatal(answer)
		}
		if err := store.Commit(job); err != nil {
			t.Fatal(err)
		}
		request.RequestIDs = []string{st.ID(1)}
		response, err = readWire(t, s, request, executorwire.KindAwait)
		want := "result_expired"
		if cause == ap.BodiesRemovedBudget {
			want = "result_evicted"
		}
		if err != nil || response.Items[0].Job.ResultStatus != want || len(response.Items[0].Job.Results) != 0 {
			t.Fatal(response, err)
		}
		original, _ := maximumJob(t, 1)
		if err := store.Commit(original); err != nil {
			t.Fatal(err)
		}
	}
}

func TestAwaitWaitCancelAndCommittedChange(t *testing.T) {
	s, store, clock, _ := submitService(t)
	if _, err := s.Submit(submitRequest(t, 1)); err != nil {
		t.Fatal(err)
	}
	request := executorwire.AwaitRequest{ProtoVersion: 1, Kind: executorwire.KindAwait, RequestIDs: []string{st.ID(1)}, WaitSeconds: 55}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { _, err := s.Await(ctx, request); done <- err }()
	cancel()
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	response := make(chan executorwire.Response, 1)
	go func() {
		r, err := s.Await(context.Background(), request)
		if err != nil {
			t.Error(err)
		}
		response <- r
	}()
	select {
	case <-response:
		t.Fatal("returned before commit or deadline")
	case <-time.After(150 * time.Millisecond):
	}
	s.mu.Lock()
	job, _ := store.Load(st.ID(1))
	job, _ = ap.ApplyJob(job, ap.SetOutcome{Outcome: ap.JobOutcome{Kind: ap.OutcomeDenied}}, ap.Now{Wall: st.T0}, s.epoch)
	err := store.Commit(job)
	s.mu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	select {
	case r := <-response:
		if r.Items[0].Job.ExecutionStatus != ap.JobFinal {
			t.Fatal(r)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("did not observe committed result")
	}
	if _, err := s.Submit(submitRequest(t, 2)); err != nil {
		t.Fatal(err)
	}
	request.RequestIDs = []string{st.ID(2)}
	go func() {
		r, err := s.Await(context.Background(), request)
		if err != nil {
			t.Error(err)
		}
		response <- r
	}()
	time.Sleep(150 * time.Millisecond)
	clock.Advance(time.Minute)
	select {
	case r := <-response:
		if r.Items[0].Job.ExecutionStatus != ap.JobSubmitted {
			t.Fatal(r)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("elapsed deadline ignored")
	}
}

func TestReadQuarantine(t *testing.T) {
	s, store, _, _ := submitService(t)
	path := filepath.Join(store.local.directory.Name(), ap.JobKey(st.ID(7)))
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	damaged := []byte("{")
	if err := os.WriteFile(path, damaged, 0600); err != nil {
		t.Fatal(err)
	}
	reopened, err := store.local.OpenJobStore()
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	s.store = reopened
	_, err = readWire(t, s, executorwire.GetRequest{ProtoVersion: 1, Kind: executorwire.KindGet, RequestID: st.ID(7)}, executorwire.KindGet)
	requireCode(t, err, "report_auth_lost")
	response, err := readWire(t, s, executorwire.AwaitRequest{ProtoVersion: 1, Kind: executorwire.KindAwait, RequestIDs: []string{st.ID(7)}}, executorwire.KindAwait)
	if err != nil || response.Items[0].Error.Code != "report_auth_lost" {
		t.Fatal(response, err)
	}
	response, err = readWire(t, s, executorwire.ListRequest{ProtoVersion: 1, Kind: executorwire.KindList, Limit: 100}, executorwire.KindList)
	if err != nil || len(response.Items) != 0 {
		t.Fatal(response, err)
	}
	after, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(after, damaged) {
		t.Fatal("quarantined file changed", err)
	}
}

func TestReadMalformedRequestKeepsKind(t *testing.T) {
	s, _, _, _ := submitService(t)
	for _, kind := range []string{executorwire.KindGet, executorwire.KindAwait, executorwire.KindList} {
		server, client := net.Pipe()
		done := make(chan error, 1)
		go func() { done <- s.ServeConn(context.Background(), server) }()
		client.SetDeadline(time.Now().Add(time.Second))
		if _, err := client.Write([]byte(`{"proto_version":1,"kind":"` + kind + `"}` + "\n")); err != nil {
			t.Fatal(err)
		}
		frame, err := bufio.NewReader(client).ReadBytes('\n')
		client.Close()
		if err != nil {
			t.Fatal(err)
		}
		if err := <-done; err != nil {
			t.Fatal(err)
		}
		_, err = executorwire.DecodeResponse(kind, frame)
		requireCode(t, err, "invalid_request")
	}
}
