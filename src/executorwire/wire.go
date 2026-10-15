// Package executorwire defines the executor's version-1, newline-delimited
// canonical JSON protocol. It carries no signer credentials or registry facts.
package executorwire

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/karthikeyan5/sshgate/src/approvalplan"
)

const (
	Proto            = 1
	KindSubmit       = "exec_submit"
	KindGet          = "exec_get"
	KindAwait        = "exec_await"
	KindList         = "exec_list"
	MaxRequestBytes  = 1 << 20
	MaxResponseBytes = 16 << 20
)

// Input is fixed once by the MCP. Registry lookup and draft construction belong
// to the executor. RequestID and SubmitNotAfter both participate in Hash.
type Input struct {
	RequestID      string         `json:"request_id"`
	SubmitNotAfter time.Time      `json:"submit_not_after"`
	Tool           string         `json:"tool"`
	Server         string         `json:"server,omitempty"`
	Command        string         `json:"command,omitempty"`
	Commands       []string       `json:"commands,omitempty"`
	Reveal         bool           `json:"reveal,omitempty"`
	StopOnError    *bool          `json:"stop_on_error,omitempty"`
	Reason         string         `json:"reason"`
	MaxOutputBytes int64          `json:"max_output_bytes"`
	Transfer       *TransferInput `json:"transfer,omitempty"`
}

type TransferInput struct {
	SourceAlias      string `json:"src_alias"`
	SourcePath       string `json:"src_path"`
	DestinationAlias string `json:"dest_alias"`
	DestinationPath  string `json:"dest_path"`
	Mode             string `json:"mode"`
}

type SubmitRequest struct {
	ProtoVersion int    `json:"proto_version"`
	Kind         string `json:"kind"`
	Input        Input  `json:"input"`
	InputHash    string `json:"input_hash"`
}
type GetRequest struct {
	ProtoVersion int    `json:"proto_version"`
	Kind         string `json:"kind"`
	RequestID    string `json:"request_id"`
}
type AwaitRequest struct {
	ProtoVersion int      `json:"proto_version"`
	Kind         string   `json:"kind"`
	RequestIDs   []string `json:"request_ids"`
	WaitSeconds  int      `json:"wait_seconds"`
}
type ListRequest struct {
	ProtoVersion int    `json:"proto_version"`
	Kind         string `json:"kind"`
	Limit        int    `json:"limit"`
	Cursor       string `json:"cursor,omitempty"`
}

func invalid(message string) error {
	return &approvalplan.CodeError{Code: approvalplan.CodeInvalidRequest, Msg: message}
}
func tooLarge() error {
	return &approvalplan.CodeError{Code: approvalplan.CodeRequestTooLarge, Msg: "executor frame or input exceeds its bound"}
}
func (in Input) Validate() error {
	if !approvalplan.ValidRequestID(in.RequestID) || in.SubmitNotAfter.IsZero() || in.SubmitNotAfter.Location() != time.UTC {
		return invalid("invalid request ID or submit deadline")
	}
	if _, err := approvalplan.ValidateRationale(in.Reason); err != nil {
		return err
	}
	if in.MaxOutputBytes < 1 || in.MaxOutputBytes > approvalplan.MaxStreamOutputBytes {
		return invalid("invalid output cap")
	}
	commands := []string(nil)
	switch in.Tool {
	case "run":
		if in.Command == "" || len(in.Commands) != 0 || in.StopOnError != nil || in.Transfer != nil {
			return invalid("invalid run input")
		}
		commands = []string{in.Command}
	case "run_batch":
		if in.Command != "" || len(in.Commands) == 0 || in.Reveal || in.Transfer != nil {
			return invalid("invalid batch input")
		}
		commands = in.Commands
	case "revoke_server", "update_gate":
		if in.Command != "" || len(in.Commands) != 0 || in.Reveal || in.StopOnError != nil || in.Transfer != nil {
			return invalid("invalid administrative input")
		}
	case "transfer":
		if in.Server != "" || in.Command != "" || len(in.Commands) != 0 || in.Reveal || in.StopOnError != nil || in.Transfer == nil {
			return invalid("invalid transfer input")
		}
		t := in.Transfer
		if !token(t.SourceAlias) || !token(t.DestinationAlias) || !validTransferPath(t.SourcePath) || !validTransferPath(t.DestinationPath) || t.Mode != approvalplan.TransferMode {
			return invalid("invalid transfer endpoints or mode")
		}
	default:
		return invalid("unknown executor tool")
	}
	if in.Tool != "transfer" && !token(in.Server) {
		return invalid("invalid server alias")
	}
	if len(commands) > approvalplan.MaxSteps {
		return tooLarge()
	}
	total := 0
	for _, command := range commands {
		if strings.TrimSpace(command) == "" {
			return invalid("blank command")
		}
		if err := approvalplan.ValidateGrantEntry(command); err != nil {
			return err
		}
		if err := approvalplan.ValidateStepBytes(approvalplan.RouteSignedWrite, command); err != nil {
			return err
		}
		total += len(command)
	}
	if total > approvalplan.MaxTotalBytes {
		return tooLarge()
	}
	return nil
}

// Mirrors approvalplan's unexported transfer-path check without widening the
// wire package's allowed dependency closure.
func validTransferPath(s string) bool {
	return len(s) > 0 && len(s) <= approvalplan.MaxTransferPathBytes && s[0] == '/' && utf8.ValidString(s) && !strings.ContainsAny(s, "\x00\r\n")
}

func token(s string) bool {
	if len(s) == 0 || len(s) > approvalplan.MaxAliasBytes {
		return false
	}
	for _, c := range s {
		if c <= 32 || c >= 127 || c == '"' || c == '\\' || c == '<' || c == '>' || c == '&' {
			return false
		}
	}
	return true
}
func (in Input) Hash() (string, error) {
	if err := in.Validate(); err != nil {
		return "", err
	}
	return approvalplan.InputHash(in)
}

func checkHeader(version int, kind, want string) error {
	if version != Proto || kind != want {
		return invalid("unsupported executor protocol or kind")
	}
	return nil
}
func validateRequest(request any) error {
	switch r := request.(type) {
	case SubmitRequest:
		if err := checkHeader(r.ProtoVersion, r.Kind, KindSubmit); err != nil {
			return err
		}
		hash, err := r.Input.Hash()
		if err != nil {
			return err
		}
		if r.InputHash != hash {
			return invalid("input hash mismatch")
		}
	case GetRequest:
		if err := checkHeader(r.ProtoVersion, r.Kind, KindGet); err != nil {
			return err
		}
		if !approvalplan.ValidRequestID(r.RequestID) {
			return invalid("invalid request ID")
		}
	case AwaitRequest:
		if err := checkHeader(r.ProtoVersion, r.Kind, KindAwait); err != nil {
			return err
		}
		if len(r.RequestIDs) < 1 || len(r.RequestIDs) > approvalplan.AwaitMaxIDs || r.WaitSeconds < 0 || r.WaitSeconds > int(approvalplan.AwaitMaxWait/time.Second) {
			return invalid("invalid await bounds")
		}
		seen := map[string]bool{}
		for _, id := range r.RequestIDs {
			if !approvalplan.ValidRequestID(id) || seen[id] {
				return invalid("invalid or duplicate request ID")
			}
			seen[id] = true
		}
	case ListRequest:
		if err := checkHeader(r.ProtoVersion, r.Kind, KindList); err != nil {
			return err
		}
		if r.Limit < 1 || r.Limit > 100 || len(r.Cursor) > 128 {
			return invalid("invalid list bounds")
		}
		for _, c := range r.Cursor {
			if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-' || c == '_') {
				return invalid("invalid cursor")
			}
		}
	default:
		return invalid("unknown request type")
	}
	return nil
}
func MarshalRequest(request any) ([]byte, error) {
	if err := validateRequest(request); err != nil {
		return nil, err
	}
	return marshal(request, MaxRequestBytes)
}
func DecodeRequest(frame []byte) (any, error) {
	if len(frame) > MaxRequestBytes {
		return nil, tooLarge()
	}
	var header struct {
		Kind string `json:"kind"`
	}
	if json.Unmarshal(frame, &header) != nil {
		return nil, invalid("malformed executor frame")
	}
	var request any
	switch header.Kind {
	case KindSubmit:
		request = &SubmitRequest{}
	case KindGet:
		request = &GetRequest{}
	case KindAwait:
		request = &AwaitRequest{}
	case KindList:
		request = &ListRequest{}
	default:
		return nil, invalid("unknown executor kind")
	}
	if err := decode(frame, request); err != nil {
		return nil, err
	}
	switch r := request.(type) {
	case *SubmitRequest:
		request = *r
	case *GetRequest:
		request = *r
	case *AwaitRequest:
		request = *r
	case *ListRequest:
		request = *r
	}
	if err := validateRequest(request); err != nil {
		return nil, err
	}
	return request, nil
}
func marshal(value any, limit int) ([]byte, error) {
	b, err := json.Marshal(value)
	if err != nil {
		return nil, err
	}
	if len(b)+1 > limit {
		return nil, tooLarge()
	}
	return append(b, '\n'), nil
}
func decode(frame []byte, value any) error {
	body := bytes.TrimSuffix(frame, []byte{'\n'})
	d := json.NewDecoder(bytes.NewReader(body))
	d.DisallowUnknownFields()
	if err := d.Decode(value); err != nil {
		return invalid("malformed executor frame")
	}
	canonical, err := json.Marshal(value)
	if err != nil || !bytes.Equal(body, canonical) {
		return invalid("noncanonical executor frame")
	}
	return nil
}

// WireError is a closed-code refusal; messages must never contain commands,
// signature material or underlying transport errors.
type WireError struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

func (e *WireError) Error() string { return fmt.Sprintf("executorwire: %s: %s", e.Code, e.Message) }
func (e *WireError) Validate() error {
	switch e.Code {
	case "not_found", "conflict", "invalid_request", "reserved_verb", "request_too_large", "request_unrenderable", "submit_window_closed", "executor_full", "executor_unavailable", "report_auth_lost":
	default:
		return invalid("unknown executor error")
	}
	if len(e.Message) == 0 || len(e.Message) > 512 || !utf8.ValidString(e.Message) {
		return invalid("invalid error message")
	}
	for _, c := range e.Message {
		if c < 32 || c >= 127 && c <= 159 {
			return invalid("invalid error message")
		}
	}
	return nil
}

var ErrResponseLost = errors.New("executorwire: request written but response lost")
