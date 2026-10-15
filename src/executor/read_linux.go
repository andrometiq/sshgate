//go:build linux

package executor

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/karthikeyan5/sshgate/internal/securestate"
	ap "github.com/karthikeyan5/sshgate/src/approvalplan"
	"github.com/karthikeyan5/sshgate/src/executorwire"
)

// Get returns committed execution facts without reading a signer or judging time.
func (s *Service) Get(request executorwire.GetRequest) (executorwire.Job, error) {
	if _, err := executorwire.MarshalRequest(request); err != nil {
		return executorwire.Job{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	job, err := s.store.Load(request.RequestID)
	if errors.Is(err, securestate.ErrNotFound) {
		err = refusal("not_found")
	}
	if err != nil {
		return executorwire.Job{}, err
	}
	return executorwire.FromSummary(ap.JobView(job, s.epoch)), nil
}

// List pages summaries by storage key. Quarantined files have no trustworthy ID
// and are omitted; an explicit Get or Await of their ID reports report_auth_lost.
func (s *Service) List(request executorwire.ListRequest) (executorwire.Response, error) {
	response := executorwire.Response{ProtoVersion: executorwire.Proto, Kind: executorwire.KindList, OK: true}
	if _, err := executorwire.MarshalRequest(request); err != nil {
		return response, err
	}
	if request.Cursor != "" && !validJobKey(request.Cursor) {
		return response, refusal("invalid_request")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	files, err := s.store.List()
	if err != nil {
		return response, err
	}
	last := ""
	for _, file := range files {
		if file.Quarantined || file.Key <= request.Cursor {
			continue
		}
		if len(response.Items) == request.Limit {
			response.NextCursor = last
			break
		}
		job, err := s.store.Load(file.RequestID)
		if err != nil {
			return response, err
		}
		view := executorwire.FromSummary(ap.JobView(job, s.epoch))
		response.Items = append(response.Items, executorwire.Item{RequestID: file.RequestID, Job: &view})
		last = file.Key
	}
	return response, nil
}

// Await waits until every requested job is final or absent, or the wait expires.
// Polling observes commits from any writer without adding a second state index.
func (s *Service) Await(ctx context.Context, request executorwire.AwaitRequest) (executorwire.Response, error) {
	if _, err := executorwire.MarshalRequest(request); err != nil {
		return executorwire.Response{}, err
	}
	deadline := s.clock.Elapsed() + time.Duration(request.WaitSeconds)*time.Second
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	for {
		if err := ctx.Err(); err != nil {
			return executorwire.Response{}, err
		}
		response, complete, err := s.awaitSnapshot(request.RequestIDs)
		if err != nil || complete || s.clock.Elapsed() >= deadline {
			return response, err
		}
		select {
		case <-ctx.Done():
			return executorwire.Response{}, ctx.Err()
		case <-ticker.C:
		}
	}
}

func (s *Service) awaitSnapshot(ids []string) (executorwire.Response, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	response := executorwire.Response{ProtoVersion: executorwire.Proto, Kind: executorwire.KindAwait, OK: true}
	results := make([][]ap.StepResult, len(ids))
	complete := true
	for i, id := range ids {
		item := executorwire.Item{RequestID: id}
		job, err := s.store.Load(id)
		switch {
		case errors.Is(err, securestate.ErrNotFound):
			item.Error = &executorwire.WireError{Code: "not_found", Message: "not_found"}
		case errors.Is(err, ErrReportAuthLost):
			item.Error = &executorwire.WireError{Code: "report_auth_lost", Message: "report_auth_lost"}
		case err != nil:
			return response, false, err
		default:
			view := executorwire.FromSummary(ap.JobView(job, s.epoch))
			item.Job = &view
			if view.ExecutionStatus != ap.JobFinal {
				complete = false
				break
			}
			if job.BodiesRemoved != nil {
				switch job.BodiesRemoved.Cause {
				case ap.BodiesRemovedAge:
					view.ResultStatus = "result_expired"
				case ap.BodiesRemovedBudget:
					view.ResultStatus = "result_evicted"
				default:
					return response, false, ErrReportAuthLost
				}
				break
			}
			for _, step := range job.Steps {
				if step.Result == nil {
					break
				}
				results[i] = append(results[i], *step.Result)
			}
			if len(results[i]) != 0 {
				view.ResultStatus, view.Hint = "result_withheld", "await this id alone"
			}
		}
		response.Items = append(response.Items, item)
	}
	// Reserve every item's summary first, then admit bodies in request order.
	body, err := executorwire.MarshalResponse(response)
	if err != nil {
		return response, false, err
	}
	size := len(body)
	for i, result := range results {
		if len(result) == 0 {
			continue
		}
		view := response.Items[i].Job
		before, _ := json.Marshal(view)
		candidate := *view
		candidate.Results, candidate.ResultStatus, candidate.Hint = result, "", ""
		after, err := json.Marshal(candidate)
		if err != nil {
			return response, false, err
		}
		if size+len(after)-len(before) <= executorwire.MaxResponseBytes {
			size += len(after) - len(before)
			*view = candidate
		}
	}
	return response, complete, nil
}
