//go:build linux

package executor

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
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
	return s.ServeConn(context.Background(), conn)
}

// ServeConn serves one validated request on an authenticated connection.
func (s *Service) ServeConn(ctx context.Context, conn net.Conn) error {
	defer conn.Close()
	frame, err := bufio.NewReader(io.LimitReader(conn, executorwire.MaxRequestBytes+1)).ReadBytes('\n')
	if err != nil {
		return err
	}
	response := executorwire.Response{ProtoVersion: executorwire.Proto, Kind: executorwire.KindSubmit}
	var header struct {
		Kind string `json:"kind"`
	}
	if json.Unmarshal(frame, &header) == nil {
		switch header.Kind {
		case executorwire.KindGet, executorwire.KindAwait, executorwire.KindList:
			response.Kind = header.Kind
		}
	}
	request, err := executorwire.DecodeRequest(frame)
	if err == nil {
		switch request := request.(type) {
		case executorwire.SubmitRequest:
			response.Kind = executorwire.KindSubmit
			response, err = s.SubmitAndNotify(ctx, request)
			response.ProtoVersion, response.Kind = executorwire.Proto, executorwire.KindSubmit
		case executorwire.GetRequest:
			response.Kind = executorwire.KindGet
			var job executorwire.Job
			job, err = s.Get(request)
			if err == nil {
				response.OK, response.Job = true, &job
			}
		case executorwire.AwaitRequest:
			response, err = s.Await(ctx, request)
		case executorwire.ListRequest:
			response, err = s.List(request)
		}
	}
	if err != nil {
		response.OK, response.Job, response.Items, response.NextCursor = false, nil, nil, ""
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
	if err == nil && response.Kind == executorwire.KindAwait {
		var ids []string
		for _, item := range response.Items {
			if item.Job != nil && len(item.Job.Results) != 0 {
				ids = append(ids, item.RequestID)
			}
		}
		s.delivered(ids)
	}
	return err
}
