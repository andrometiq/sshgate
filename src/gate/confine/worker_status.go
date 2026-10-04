package confine

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"syscall"
)

// WorkerStatus is the worker's wait status as the shim reaped it, published on
// fd 4 as a W record before descendant cleanup (BUILD-22-P2 §27, redesign E12).
type WorkerStatus struct {
	// Known is true when a W record carried an exit code or signal.
	Known  bool
	Exited bool
	Code   int
	Signal syscall.Signal
	Core   bool
	// Unavailable names why no status exists (no W record, or the shim's
	// W{"unavailable":...}); empty when Known.
	Unavailable string
}

// WorkerStatus returns the worker status validated by Status.
func (j *Jailed) WorkerStatus() WorkerStatus {
	if !j.workerStatus.Known && j.workerStatus.Unavailable == "" {
		return WorkerStatus{Unavailable: "no W record"}
	}
	return j.workerStatus
}

func parseWorkerStatus(raw string) (WorkerStatus, error) {
	invalid := fmt.Errorf("invalid worker status")
	decoder := json.NewDecoder(strings.NewReader(raw))
	token, err := decoder.Token()
	if err != nil || token != json.Delim('{') {
		return WorkerStatus{}, invalid
	}
	fields := make(map[string]json.RawMessage)
	for decoder.More() {
		token, err := decoder.Token()
		key, ok := token.(string)
		if err != nil || !ok {
			return WorkerStatus{}, invalid
		}
		if _, exists := fields[key]; exists {
			return WorkerStatus{}, invalid
		}
		var value json.RawMessage
		if decoder.Decode(&value) != nil || string(value) == "null" {
			return WorkerStatus{}, invalid
		}
		fields[key] = value
	}
	if token, err := decoder.Token(); err != nil || token != json.Delim('}') {
		return WorkerStatus{}, invalid
	}
	var extra any
	if decoder.Decode(&extra) != io.EOF {
		return WorkerStatus{}, invalid
	}
	var result WorkerStatus
	if value, ok := fields["exit"]; ok && len(fields) == 1 {
		if json.Unmarshal(value, &result.Code) != nil || result.Code < 0 || result.Code > 255 {
			return WorkerStatus{}, invalid
		}
		result.Known, result.Exited = true, true
		return result, nil
	}
	if value, ok := fields["signal"]; ok && len(fields) == 2 {
		core, present := fields["core"]
		if !present || json.Unmarshal(value, &result.Signal) != nil || result.Signal < 1 || result.Signal > 64 || json.Unmarshal(core, &result.Core) != nil {
			return WorkerStatus{}, invalid
		}
		result.Known = true
		return result, nil
	}
	if value, ok := fields["unavailable"]; ok && len(fields) == 1 {
		if json.Unmarshal(value, &result.Unavailable) != nil || strings.TrimSpace(result.Unavailable) == "" || strings.ContainsAny(result.Unavailable, "\r\n") {
			return WorkerStatus{}, invalid
		}
		return result, nil
	}
	return WorkerStatus{}, invalid
}

// splitStatusRecords validates the shim-owned suffix separately from setup status.
func splitStatusRecords(raw string) (string, WorkerStatus, string, error) {
	head, suffix, found := strings.Cut(raw, "\n")
	status := WorkerStatus{Unavailable: "no W record"}
	if !found {
		return head, status, "", nil
	}
	invalid := fmt.Errorf("invalid status record")
	// F records already end in a newline before the shim adds its separator.
	if strings.HasPrefix(head, "F") || strings.HasPrefix(head, "XFexec:") {
		if suffix == "" {
			return head, status, "", nil
		}
		if !strings.HasPrefix(suffix, "\n") {
			return "", status, "", invalid
		}
		suffix = suffix[1:]
	}
	if strings.HasPrefix(suffix, "W") {
		record, rest, complete := strings.Cut(suffix, "\n")
		if !complete {
			return "", status, "", invalid
		}
		parsed, err := parseWorkerStatus(record[1:])
		if err != nil {
			return "", status, "", err
		}
		status = parsed
		if rest == "" {
			return head, status, "", nil
		}
		if !strings.HasPrefix(rest, "\n") {
			return "", status, "", invalid
		}
		suffix = rest[1:]
	}
	if !strings.HasPrefix(suffix, "C") {
		return "", status, "", invalid
	}
	cleanup := strings.TrimSuffix(suffix[1:], "\n")
	if cleanup == "" || strings.ContainsAny(cleanup, "\r\n") {
		return "", status, "", invalid
	}
	return head, status, cleanup, nil
}
