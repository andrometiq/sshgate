//go:build linux

package executor

import (
	"bufio"
	"bytes"
	"errors"
	"io"
	"net"

	ap "github.com/karthikeyan5/sshgate/src/approvalplan"
	"github.com/karthikeyan5/sshgate/src/executorwire"
)

// ServeSubmit handles one frame on an authenticated Local.AcceptUnix connection.
// The owner controls connection lifetime and must treat returned storage errors
// as service failures, including a fatal exit on an uncertain commit.
func (s *Service) ServeSubmit(conn net.Conn) error {
	defer conn.Close()
	frame, err := bufio.NewReader(io.LimitReader(conn, executorwire.MaxRequestBytes+1)).ReadBytes('\n')
	if err != nil {
		return err
	}
	response := executorwire.Response{ProtoVersion: executorwire.Proto, Kind: executorwire.KindSubmit}
	request, err := executorwire.DecodeRequest(frame)
	if err == nil {
		submit, ok := request.(executorwire.SubmitRequest)
		if !ok {
			err = refusal("invalid_request")
		} else {
			var job executorwire.Job
			job, err = s.Submit(submit)
			if err == nil {
				response.OK = true
				response.Job = &job
			}
		}
	}
	if err != nil {
		var wire *executorwire.WireError
		var plan *ap.CodeError
		switch {
		case errors.As(err, &wire):
			response.Error = &executorwire.WireError{Code: wire.Code, Message: wire.Code}
		case errors.As(err, &plan):
			response.Error = &executorwire.WireError{Code: string(plan.Code), Message: string(plan.Code)}
		case errors.Is(err, ErrReportAuthLost):
			response.Error = &executorwire.WireError{Code: "report_auth_lost", Message: "report_auth_lost"}
		default:
			return err
		}
	}
	body, err := executorwire.MarshalResponse(response)
	if err != nil {
		return err
	}
	_, err = io.Copy(conn, bytes.NewReader(body))
	return err
}
