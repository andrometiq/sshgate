package executorwire

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	ap "github.com/karthikeyan5/sshgate/src/approvalplan"
)

const id = "a2_ABEiM0RVZneImaq7zN3u_w"

func input() Input {
	return Input{RequestID: id, SubmitNotAfter: time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC), Tool: "run", Server: "example", Command: "touch /tmp/example", Reason: "Create the example file", MaxOutputBytes: 1024}
}
func submit(t *testing.T, in Input) SubmitRequest {
	t.Helper()
	h, err := in.Hash()
	if err != nil {
		t.Fatal(err)
	}
	return SubmitRequest{Proto, KindSubmit, in, h}
}
func golden(t *testing.T, name string, b []byte) {
	t.Helper()
	want, err := os.ReadFile("testdata/" + name + ".json")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(b, want) {
		t.Fatalf("golden %s mismatch\ngot %s\nwant %s", name, b, want)
	}
}
func TestRequestGoldens(t *testing.T) {
	requests := map[string]any{"submit": submit(t, input()), "get": GetRequest{Proto, KindGet, id}, "await": AwaitRequest{Proto, KindAwait, []string{id}, 55}, "list": ListRequest{Proto, KindList, 100, ""}}
	batch := input()
	batch.Tool = "run_batch"
	batch.Command = ""
	batch.Commands = []string{"ls /tmp", "touch /tmp/example"}
	stop := false
	batch.StopOnError = &stop
	requests["batch"] = submit(t, batch)
	for name, r := range requests {
		t.Run(name, func(t *testing.T) {
			b, err := MarshalRequest(r)
			if err != nil {
				t.Fatal(err)
			}
			golden(t, name, b)
			got, err := DecodeRequest(b)
			if err != nil {
				t.Fatal(err)
			}
			again, err := MarshalRequest(got)
			if err != nil || !bytes.Equal(b, again) {
				t.Fatalf("round trip: %v", err)
			}
		})
	}
}
func TestInputHashBinding(t *testing.T) {
	base := input()
	h, _ := base.Hash()
	changes := []func(*Input){func(i *Input) { i.RequestID = "a2_AAAAAAAAAAAAAAAAAAAAAA" }, func(i *Input) { i.SubmitNotAfter = i.SubmitNotAfter.Add(time.Second) }, func(i *Input) { i.Command += "x" }, func(i *Input) { i.Reason += "x" }, func(i *Input) { i.Server += "x" }, func(i *Input) { i.Reveal = true }, func(i *Input) { i.MaxOutputBytes++ }}
	for n, change := range changes {
		other := base
		change(&other)
		next, err := other.Hash()
		if err != nil || next == h {
			t.Fatalf("field %d not bound: %v", n, err)
		}
	}
	r := submit(t, base)
	r.Input.SubmitNotAfter = r.Input.SubmitNotAfter.Add(time.Second)
	b, _ := json.Marshal(r)
	if _, err := DecodeRequest(b); err == nil {
		t.Fatal("accepted tampered deadline with old hash")
	}
}
func TestStrictDecode(t *testing.T) {
	b, _ := MarshalRequest(GetRequest{Proto, KindGet, id})
	bad := [][]byte{append(append([]byte{}, b...), '\n'), append([]byte(" "), b...), bytes.Replace(b, []byte(`"kind"`), []byte(`"Kind"`), 1), bytes.Replace(b, []byte(`"proto_version":1`), []byte(`"proto_version":1,"proto_version":1`), 1), bytes.Replace(b, []byte(`"proto_version":1`), []byte(`"proto_version":2`), 1), bytes.Replace(b, []byte(`"kind":`), []byte(`"claim_token":"secret","kind":`), 1), []byte("null"), append(b, []byte("{}")...), bytes.Repeat([]byte("x"), MaxRequestBytes+1)}
	for n, frame := range bad {
		if _, err := DecodeRequest(frame); err == nil {
			t.Fatalf("accepted invalid frame %d", n)
		}
	}
}
func TestInputProtection(t *testing.T) {
	changes := map[string]func(*Input){"deadline": func(i *Input) { i.SubmitNotAfter = time.Time{} }, "reason": func(i *Input) { i.Reason = "" }, "id": func(i *Input) { i.RequestID = "bad" }, "output": func(i *Input) { i.MaxOutputBytes = 0 }, "tool": func(i *Input) { i.Tool = "request_grant" }, "alias": func(i *Input) { i.Server = "bad\nserver" }, "batch-reveal": func(i *Input) {
		i.Tool = "run_batch"
		i.Command = ""
		i.Commands = []string{"touch /tmp/a"}
		i.Reveal = true
	}, "command-bound": func(i *Input) { i.Command = strings.Repeat("x", ap.MaxStepBytes+1) }, "total-bound": func(i *Input) {
		i.Tool = "run_batch"
		i.Command = ""
		for range 7 {
			i.Commands = append(i.Commands, strings.Repeat("x", ap.MaxStepBytes))
		}
	}}
	for name, change := range changes {
		t.Run(name, func(t *testing.T) {
			in := input()
			change(&in)
			if _, err := in.Hash(); err == nil {
				t.Fatal("invalid input hashed")
			}
		})
	}
	for _, r := range []any{AwaitRequest{Proto, KindAwait, []string{id, id}, 1}, AwaitRequest{Proto, KindAwait, []string{id}, 56}, ListRequest{Proto, KindList, 101, ""}, ListRequest{Proto, KindList, 1, "!"}} {
		if _, err := MarshalRequest(r); err == nil {
			t.Fatal("invalid bounds accepted")
		}
	}
}
func TestResponseGoldens(t *testing.T) {
	job := FromSummary(ap.JobSummary{RequestID: id, State: ap.JobAcknowledged})
	responses := map[string]Response{"acknowledged": {ProtoVersion: Proto, Kind: KindGet, OK: true, Job: &job}, "list-empty": {ProtoVersion: Proto, Kind: KindList, OK: true}, "refusal": {ProtoVersion: Proto, Kind: KindSubmit, Error: &WireError{Code: "executor_full", Message: "executor capacity reached"}}}
	for name, r := range responses {
		b, err := MarshalResponse(r)
		if err != nil {
			t.Fatal(err)
		}
		golden(t, name, b)
		got, err := DecodeResponse(r.Kind, b)
		if (err != nil) != (!r.OK) {
			t.Fatalf("decode %s: %v", name, err)
		}
		again, e := MarshalResponse(got)
		if e != nil || !bytes.Equal(b, again) {
			t.Fatalf("response round trip: %v", e)
		}
		if bytes.Contains(b, []byte("approval_status")) {
			t.Fatal("executor guessed signer status")
		}
	}
}
func TestOutputBytes(t *testing.T) {
	body := []byte{0xff, 0, '<', '>', '&'}
	sum := sha256.Sum256(body)
	digest := hex.EncodeToString(sum[:])
	empty := sha256.Sum256(nil)
	job := Job{RequestID: id, ExecutionStatus: ap.JobFinal, Steps: []ap.StepStatus{ap.StepSucceeded}, Class: ap.JobClass("succeeded"), ExecutedOrdinals: []int{1}, Results: []ap.StepResult{{Status: ap.StepSucceeded, Stdout: body, StdoutBytes: int64(len(body)), StdoutSHA256: digest, StderrSHA256: hex.EncodeToString(empty[:])}}}
	r := Response{ProtoVersion: Proto, Kind: KindAwait, OK: true, Items: []Item{{RequestID: id, Job: &job}}}
	b, err := MarshalResponse(r)
	if err != nil {
		t.Fatal(err)
	}
	golden(t, "output", b)
	got, err := DecodeResponse(KindAwait, b)
	if err != nil || !bytes.Equal(got.Items[0].Job.Results[0].Stdout, body) {
		t.Fatalf("output changed: %v", err)
	}
}
func TestResponseProtection(t *testing.T) {
	job := Job{RequestID: id, ExecutionStatus: ap.JobAcknowledged, Steps: []ap.StepStatus{}, ExecutedOrdinals: []int{}}
	r := Response{ProtoVersion: Proto, Kind: KindGet, OK: true, Job: &job}
	b, _ := MarshalResponse(r)
	if _, err := DecodeResponse(KindSubmit, b); err == nil {
		t.Fatal("accepted wrong response kind")
	}
	injected := bytes.Replace(b, []byte(`"execution_status"`), []byte(`"approval_status":"approved","execution_status"`), 1)
	if _, err := DecodeResponse(KindGet, injected); err == nil {
		t.Fatal("accepted invented signer status")
	}
	job.ExecutionStatus = "invented"
	if _, err := MarshalResponse(r); err == nil {
		t.Fatal("accepted unknown state")
	}
	if _, err := DecodeResponse(KindAwait, bytes.Repeat([]byte("x"), MaxResponseBytes+1)); err == nil {
		t.Fatal("accepted oversized response")
	}
	if _, err := MarshalResponse(Response{ProtoVersion: Proto, Kind: KindList, Error: &WireError{Code: "invented", Message: "bad"}}); err == nil {
		t.Fatal("accepted unknown error")
	}
}

func TestToolInputs(t *testing.T) {
	for _, tool := range []string{"run", "run_batch", "revoke_server", "update_gate", "transfer"} {
		t.Run(tool, func(t *testing.T) {
			in := input()
			in.Tool = tool
			switch tool {
			case "run":
				in.Reveal = true
			case "run_batch":
				in.Commands = []string{in.Command}
				in.Command = ""
			case "revoke_server", "update_gate":
				in.Command = ""
			case "transfer":
				in.Command = ""
				in.Server = ""
				in.Transfer = &TransferInput{"source", "/tmp/source", "destination", "/tmp/destination", "0600"}
			}
			b, err := MarshalRequest(submit(t, in))
			if err != nil {
				t.Fatal(err)
			}
			if _, err := DecodeRequest(b); err != nil {
				t.Fatal(err)
			}
		})
	}
}
func TestFrameBounds(t *testing.T) {
	if _, err := marshal(strings.Repeat("x", MaxRequestBytes), MaxRequestBytes); err == nil {
		t.Fatal("marshal exceeded frame bound")
	}
	if _, err := DecodeRequest(bytes.Repeat([]byte(" "), MaxRequestBytes+1)); !isTooLarge(err) {
		t.Fatal("request size was not checked before parsing")
	}
	if _, err := DecodeResponse(KindAwait, bytes.Repeat([]byte(" "), MaxResponseBytes+1)); !isTooLarge(err) {
		t.Fatal("response size was not checked before parsing")
	}
}
func TestResultAvailability(t *testing.T) {
	for _, status := range []string{"result_expired", "result_evicted", "result_withheld"} {
		j := Job{RequestID: id, ExecutionStatus: ap.JobFinal, Steps: []ap.StepStatus{ap.StepSucceeded}, Class: ap.ClassSucceeded, ExecutedOrdinals: []int{1}, ResultStatus: status}
		if status == "result_withheld" {
			j.Hint = "await this id alone"
		}
		r := Response{ProtoVersion: Proto, Kind: KindAwait, OK: true, Items: []Item{{RequestID: id, Job: &j}}}
		b, err := MarshalResponse(r)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := DecodeResponse(KindAwait, b); err != nil {
			t.Fatal(err)
		}
		j.Results = []ap.StepResult{{Status: ap.StepSucceeded, Stdout: []byte("must not be returned")}}
		if _, err := MarshalResponse(r); err == nil {
			t.Fatal("unavailable result carried output")
		}
	}
}
func TestExecutionFacts(t *testing.T) {
	j := FromSummary(ap.JobSummary{RequestID: id, State: ap.JobExecuting, Executing: 2, Steps: []ap.StepStatus{ap.StepSucceeded, ap.StepNotRun}, ExecutedOrdinals: []int{1}})
	if err := j.Validate(); err != nil {
		t.Fatal(err)
	}
	j.ExecutedOrdinals = []int{2}
	if err := j.Validate(); err == nil {
		t.Fatal("accepted false execution facts")
	}
}

func TestSubmitNotification(t *testing.T) {
	j := FromSummary(ap.JobSummary{RequestID: id, State: ap.JobSubmitted})
	r := Response{ProtoVersion: Proto, Kind: KindSubmit, OK: true, Job: &j, NotificationStatus: ap.NotificationSending}
	b, err := MarshalResponse(r)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := DecodeResponse(KindSubmit, b); err != nil {
		t.Fatal(err)
	}
	r.Kind = KindGet
	if _, err := MarshalResponse(r); err == nil {
		t.Fatal("get carried submit notification")
	}
	r.Kind = KindSubmit
	r.NotificationStatus = "unknown"
	if _, err := MarshalResponse(r); err == nil {
		t.Fatal("unknown notification accepted")
	}
}
func TestOutcomeVocabulary(t *testing.T) {
	for _, o := range []ap.JobOutcome{{Kind: "unknown"}, {Kind: ap.OutcomeDenied, Code: ap.CodeBusy}, {Kind: ap.OutcomeJobError, Code: ap.CodeBusy}, {Kind: ap.OutcomeAdopted}} {
		j := Job{RequestID: id, ExecutionStatus: ap.JobFinal, Outcome: &o}
		if err := j.Validate(); err == nil {
			t.Fatal("invalid outcome accepted")
		}
	}
}

func isTooLarge(err error) bool {
	var e *ap.CodeError
	return errors.As(err, &e) && e.Code == ap.CodeRequestTooLarge
}

func TestMaximumOutputAndWithheld(t *testing.T) {
	body := bytes.Repeat([]byte{0xff, '<', '>', '&'}, ap.MaxStreamOutputBytes/4)
	hash := sha256.Sum256(body)
	digest := hex.EncodeToString(hash[:])
	j := Job{RequestID: id, ExecutionStatus: ap.JobFinal, Class: ap.ClassSucceeded}
	for n := 1; n <= 4; n++ {
		j.Steps = append(j.Steps, ap.StepSucceeded)
		j.ExecutedOrdinals = append(j.ExecutedOrdinals, n)
		j.Results = append(j.Results, ap.StepResult{Status: ap.StepSucceeded, StdoutBytes: int64(len(body)), StderrBytes: int64(len(body)), StdoutSHA256: digest, StderrSHA256: digest, Stdout: body, Stderr: body})
	}
	r := Response{ProtoVersion: Proto, Kind: KindAwait, OK: true, Items: []Item{{RequestID: id, Job: &j}}}
	b, err := MarshalResponse(r)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := DecodeResponse(KindAwait, b)
	if err != nil {
		t.Fatal(err)
	}
	for _, result := range decoded.Items[0].Job.Results {
		if !bytes.Equal(result.Stdout, body) || !bytes.Equal(result.Stderr, body) {
			t.Fatal("maximum output bytes changed")
		}
	}
	other := j
	other.RequestID = "a2_AAAAAAAAAAAAAAAAAAAAAA"
	r.Items = append(r.Items, Item{RequestID: other.RequestID, Job: &other})
	if _, err := MarshalResponse(r); !isTooLarge(err) {
		t.Fatalf("oversized await response accepted: %v", err)
	}
	other.Results = nil
	other.ResultStatus = "result_withheld"
	other.Hint = "await this id alone"
	if _, err := MarshalResponse(r); err != nil {
		t.Fatal(err)
	}
}

func TestTransferPathProtection(t *testing.T) {
	for _, path := range []string{"relative", "/bad\npath", "/bad\rpath", "/bad\x00path", "/bad\xffpath", strings.Repeat("/", 4097)} {
		in := input()
		in.Tool = "transfer"
		in.Server = ""
		in.Command = ""
		in.Transfer = &TransferInput{"source", path, "destination", "/tmp/destination", "0600"}
		if _, err := in.Hash(); err == nil {
			t.Fatal("invalid transfer path accepted")
		}
	}
}
