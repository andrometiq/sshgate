package hosted

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/karthikeyan5/sshgate/pkg/signerkit/sqlitestore"
	ap "github.com/karthikeyan5/sshgate/src/approvalplan"
	aw "github.com/karthikeyan5/sshgate/src/approvalwire"
)

// AttachApprovals mounts the machine adapter before serving. Worker ownership is
// attached separately through StartOrdinaryWorkers.
func (s *Server) AttachApprovals(engine *ApprovalV2Engine) error {
	if s.MachineClientID == "" || engine == nil {
		return errors.New("hosted: approvals require a machine client and engine")
	}
	if s.approvalsMachine != nil {
		return errors.New("hosted: approvals already attached")
	}
	s.approvalsMachine = s.withAuth(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		kind, id := approvalRoute(r)
		if kind == "" {
			writeApprovalResponse(w, aw.KindGet, aw.ErrorResponse(ap.CodeNotFound, ""))
			return
		}
		response, err := s.dispatchApprovalHTTP(r, engine, kind, id)
		if err != nil {
			code := ap.CodeStorageUncertain
			var coded *ap.CodeError
			if errors.As(err, &coded) {
				code = coded.Code
			}
			response = aw.ErrorResponse(code, string(code))
		}
		writeApprovalResponse(w, kind, response)
	}))
	return nil
}

func approvalRoute(r *http.Request) (string, string) {
	path := r.URL.Path
	if r.URL.EscapedPath() != path {
		return "", ""
	}
	if path == aw.HostedRoot {
		switch r.Method {
		case http.MethodGet:
			return aw.KindList, ""
		case http.MethodPost:
			return aw.KindSubmit, ""
		}
	}
	if !strings.HasPrefix(path, aw.HostedRoot+"/") {
		return "", ""
	}
	parts := strings.Split(strings.TrimPrefix(path, aw.HostedRoot+"/"), "/")
	if len(parts) == 1 && parts[0] == "wait" && r.Method == http.MethodPost {
		return aw.KindWait, ""
	}
	if !ap.ValidRequestID(parts[0]) {
		return "", ""
	}
	if len(parts) == 1 && r.Method == http.MethodGet {
		return aw.KindGet, parts[0]
	}
	if len(parts) == 2 && r.Method == http.MethodPost {
		switch parts[1] {
		case "claim":
			return aw.KindClaim, parts[0]
		case "report":
			return aw.KindReport, parts[0]
		}
	}
	return "", ""
}

func writeApprovalResponse(w http.ResponseWriter, kind string, response aw.Response) {
	status, body, err := aw.MarshalHostedResponse(kind, response)
	if err != nil {
		status, body, _ = aw.MarshalHostedResponse(kind, aw.ErrorResponse(ap.CodeLifecycleUnavailable, "lifecycle unavailable"))
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	if response.Error != nil && response.Error.Code == ap.CodeBusy {
		w.Header().Set("Retry-After", "1")
	}
	w.WriteHeader(status)
	_, _ = w.Write(body)
}

func (s *Server) dispatchApprovalHTTP(r *http.Request, engine *ApprovalV2Engine, kind, id string) (aw.Response, error) {
	response := aw.Response{ApprovalProto: aw.Proto, OK: true}
	client, ok := machinePrincipalFromContext(r.Context())
	if !ok {
		return response, &ap.CodeError{Code: ap.CodeNotFound}
	}
	key := sqlitestore.V2Key{ClientID: client, RequestID: id}
	var err error
	if r.Method == http.MethodGet {
		if kind == aw.KindGet {
			var q aw.HostedGetQuery
			q, err = aw.DecodeHostedGetQuery(r.URL.RawQuery)
			if err != nil {
				return response, err
			}
			key.SubPrincipal = q.RequesterSub
			summary, getErr := engine.Get(r.Context(), key)
			response.Summary = &summary
			return response, getErr
		}
		q, decodeErr := aw.DecodeHostedListQuery(r.URL.RawQuery)
		if decodeErr != nil {
			return response, decodeErr
		}
		response.Summaries, response.NextCursor, err = approvalHTTPPage(r, engine, client, q)
		return response, err
	}
	if r.URL.RawQuery != "" {
		return response, &ap.CodeError{Code: ap.CodeInvalidRequest}
	}
	data, err := io.ReadAll(io.LimitReader(r.Body, aw.MaxFrameBytes+1))
	if err != nil {
		return response, &ap.CodeError{Code: ap.CodeInvalidRequest}
	}
	body, err := aw.DecodeHostedBody(kind, data)
	if err != nil {
		return response, err
	}
	switch body := body.(type) {
	case aw.HostedSubmitBody:
		if body.Draft.Kind != ap.KindCommandJob {
			return response, &ap.CodeError{Code: ap.CodeInvalidRequest}
		}
		for _, step := range body.Draft.CommandJob.Steps {
			if step.Route == ap.RouteSignedReveal {
				return response, &ap.CodeError{Code: ap.CodeInvalidRequest}
			}
		}
		summary, submitErr := engine.Submit(r.Context(), client, body.RequesterSub, body.Draft)
		response.Summary, err = &summary, submitErr
	case aw.HostedWaitBody:
		result, waitErr := engine.WaitMany(r.Context(), client, body.RequesterSub, body.RequestIDs, time.Duration(body.WaitSeconds)*time.Second)
		response.Summaries, err = result.Summaries, waitErr
	case aw.HostedClaimBody:
		key.SubPrincipal = body.RequesterSub
		token, _ := hex.DecodeString(body.ClaimToken) // The wire decoder validated the token.
		answer, claimErr := engine.Claim(r.Context(), key, ap.Claim{Token: [32]byte(token), PlanHash: body.PlanHash})
		response.Claim = &aw.ClaimAnswer{Status: answer.Claim, Reason: answer.Reason, Class: answer.Class, Signatures: answer.Signatures}
		if answer.Claim == ap.ClaimSignatures {
			response.Claim.DecidedAt = &answer.DecidedAt
		}
		err = claimErr
	case aw.HostedReportBody:
		key.SubPrincipal = body.RequesterSub
		token, _ := hex.DecodeString(body.ClaimToken)
		report := body.Report
		_, err = engine.Report(r.Context(), key, ap.Report{Token: [32]byte(token), PlanHash: body.PlanHash, Body: ap.FinalReport{Class: report.Class, Steps: report.Steps, ExecutedOrdinals: report.ExecutedOrdinals, Partial: report.Partial, ResultDigest: report.ResultDigest}})
	}
	return response, err
}

type approvalHTTPCursor struct {
	Created int64  `json:"c"`
	ID      string `json:"r"`
}

func approvalHTTPPage(r *http.Request, engine *ApprovalV2Engine, client string, q aw.HostedListQuery) ([]ap.Summary, string, error) {
	var cursor *sqlitestore.V2Cursor
	if q.Cursor != "" {
		raw, err := base64.RawURLEncoding.DecodeString(q.Cursor)
		var value approvalHTTPCursor
		if err != nil || json.Unmarshal(raw, &value) != nil || !ap.ValidRequestID(value.ID) {
			return nil, "", &ap.CodeError{Code: ap.CodeInvalidRequest}
		}
		canonical, _ := json.Marshal(value)
		if !bytes.Equal(raw, canonical) || base64.RawURLEncoding.EncodeToString(raw) != q.Cursor {
			return nil, "", &ap.CodeError{Code: ap.CodeInvalidRequest}
		}
		cursor = &sqlitestore.V2Cursor{CreatedAt: time.Unix(value.Created, 0).UTC(), RequestID: value.ID}
	}
	summaries, err := engine.List(r.Context(), client, q.RequesterSub, cursor, q.Limit+1)
	if err != nil {
		return nil, "", err
	}
	next := ""
	if len(summaries) > q.Limit {
		summaries = summaries[:q.Limit]
		last := summaries[len(summaries)-1]
		raw, _ := json.Marshal(approvalHTTPCursor{Created: last.CreatedAt.Unix(), ID: last.RequestID})
		next = base64.RawURLEncoding.EncodeToString(raw)
	}
	return summaries, next, nil
}
