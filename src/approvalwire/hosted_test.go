package approvalwire_test

import (
	"bytes"
	"errors"
	"fmt"
	"net/http"
	"reflect"
	"strings"
	"testing"

	"github.com/karthikeyan5/sshgate/src/approvalplan"
	"github.com/karthikeyan5/sshgate/src/approvalwire"
)

const sub = "local-uid:1000"

func hostedBodies(t *testing.T) map[string]any {
	return map[string]any{
		"submit":        approvalwire.HostedSubmitBody{ApprovalProto: 1, RequesterSub: sub, Draft: draft(t, "write")},
		"submit-direct": approvalwire.HostedSubmitBody{ApprovalProto: 1, Draft: draft(t, "grant-all")},
		"wait":          approvalwire.HostedWaitBody{ApprovalProto: 1, RequesterSub: sub, RequestIDs: []string{idOne, idTwo}, WaitSeconds: 30},
		"claim":         approvalwire.HostedClaimBody{ApprovalProto: 1, RequesterSub: sub, ClaimToken: tokenAHex, PlanHash: planHash},
		"report":        approvalwire.HostedReportBody{ApprovalProto: 1, RequesterSub: sub, ClaimToken: tokenAHex, PlanHash: planHash, Report: report()},
	}
}

var bodyKinds = map[string]string{
	"submit": approvalwire.KindSubmit, "submit-direct": approvalwire.KindSubmit,
	"wait": approvalwire.KindWait, "claim": approvalwire.KindClaim, "report": approvalwire.KindReport,
}

func TestGoldenHostedBodies(t *testing.T) {
	for name, body := range hostedBodies(t) {
		b, err := approvalwire.MarshalHostedBody(body)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		golden(t, "hosted/body-"+name+".json", b)
		got, err := approvalwire.DecodeHostedBody(bodyKinds[name], b)
		if err != nil {
			t.Fatalf("%s: decode own golden: %v", name, err)
		}
		if !reflect.DeepEqual(got, body) {
			t.Errorf("%s: decoded %#v", name, got)
		}
		for mutation, bad := range map[string][]byte{
			"unknown field": bytes.Replace(b, []byte(`"approval_proto":1,`), []byte(`"approval_proto":1,"kind":"x",`), 1),
			"bad sub":       bytes.Replace(b, []byte(`"approval_proto":1,`), []byte(`"approval_proto":1,"requester_sub":"uid:1",`), 1),
			"newline":       append(bytes.Clone(b), '\n'),
		} {
			if name == "submit-direct" || mutation != "bad sub" {
				var ce *approvalplan.CodeError
				if _, err := approvalwire.DecodeHostedBody(bodyKinds[name], bad); !errors.As(err, &ce) || ce.Code != approvalplan.CodeInvalidRequest {
					t.Errorf("%s with %s: %v; want invalid_request", name, mutation, err)
				}
			}
		}
	}
	for _, kind := range []string{approvalwire.KindGet, approvalwire.KindList} {
		if _, err := approvalwire.DecodeHostedBody(kind, []byte(`{}`)); err == nil {
			t.Errorf("%s has a body", kind)
		}
	}
}

func TestGoldenHostedQueriesAndRoutes(t *testing.T) {
	var table bytes.Buffer
	queries := map[string]func() (string, error){
		"get":              approvalwire.HostedGetQuery{RequesterSub: sub}.Encode,
		"get-direct":       approvalwire.HostedGetQuery{}.Encode,
		"list-first":       approvalwire.HostedListQuery{RequesterSub: sub, Limit: 50}.Encode,
		"list-next":        approvalwire.HostedListQuery{RequesterSub: sub, Limit: 50, Cursor: "c2_cursor-1"}.Encode,
		"list-direct-next": approvalwire.HostedListQuery{Limit: 1, Cursor: "c"}.Encode,
	}
	for _, name := range sortedKeys(queries) {
		q, err := queries[name]()
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		fmt.Fprintf(&table, "query %s ?%s\n", name, q)
		if strings.HasPrefix(name, "get") {
			if _, err := approvalwire.DecodeHostedGetQuery(q); err != nil {
				t.Errorf("%s: %v", name, err)
			}
		} else if _, err := approvalwire.DecodeHostedListQuery(q); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
	for _, kind := range approvalwire.Kinds {
		id := ""
		if kind == approvalwire.KindGet || kind == approvalwire.KindClaim || kind == approvalwire.KindReport {
			id = idOne
		}
		method, path, err := approvalwire.HostedRoute(kind, id)
		if err != nil {
			t.Fatalf("%s: %v", kind, err)
		}
		fmt.Fprintf(&table, "route %s %s %s\n", kind, method, path)
		if _, _, err := approvalwire.HostedRoute(kind, map[bool]string{true: "", false: idOne}[id != ""]); err == nil {
			t.Errorf("%s accepted the wrong id presence", kind)
		}
	}
	if _, _, err := approvalwire.HostedRoute(approvalwire.KindGet, "a2_../../../../policy/x"); err == nil {
		t.Error("a path-escaping id built a route")
	}
	golden(t, "hosted/routes-and-queries.txt", table.Bytes())

	for name, raw := range map[string]string{
		"unknown param":      "limit=5&x=1",
		"repeated":           "limit=5&limit=5",
		"non-canonical":      "requester_sub=local-uid%3A1000&limit=5",
		"no limit":           "cursor=abc",
		"limit over":         "limit=101",
		"limit sign":         "limit=+5",
		"bad sub":            "limit=5&requester_sub=root",
		"unescaped sub":      "limit=5&requester_sub=local-uid:1000",
		"empty cursor value": "cursor=&limit=5",
	} {
		if _, err := approvalwire.DecodeHostedListQuery(raw); err == nil {
			t.Errorf("list query %s decoded", name)
		}
	}
	for _, raw := range []string{"x=1", "requester_sub=a&requester_sub=a", "limit=5", "requester_sub="} {
		if _, err := approvalwire.DecodeHostedGetQuery(raw); err == nil {
			t.Errorf("get query %q decoded", raw)
		}
	}
}

func TestGoldenHTTPStatusTable(t *testing.T) {
	var table bytes.Buffer
	for _, code := range approvalplan.AllCodes {
		status := approvalwire.HTTPStatus(code)
		fmt.Fprintf(&table, "%s %d\n", code, status)
		if (status == 0) != (code == approvalplan.CodeSignerIncompatible) {
			t.Errorf("%s has status %d", code, status)
		}
		if code.Retryable() && code != approvalplan.CodeQueueFull && code != approvalplan.CodeSubmitWindowAhead && status != http.StatusServiceUnavailable {
			t.Errorf("transient %s is not a 503", code)
		}
	}
	golden(t, "hosted/http-status.txt", table.Bytes())
}

func TestGoldenHostedResponses(t *testing.T) {
	answers := localResponses()
	for _, name := range sortedKeys(answers) {
		a := answers[name]
		status, body, err := approvalwire.MarshalHostedResponse(a.kind, a.resp)
		if err != nil || status != http.StatusOK {
			t.Fatalf("%s: %d %v", name, status, err)
		}
		local, _ := approvalwire.MarshalLocalResponse(a.kind, a.resp)
		if !bytes.Equal(append(bytes.Clone(body), '\n'), local) {
			t.Errorf("%s: hosted body differs from the local frame", name)
		}
		if _, err := approvalwire.ClassifyHostedResponse(a.kind, status, "application/json", body); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
	status, busy, err := approvalwire.MarshalHostedResponse(approvalwire.KindClaim, refusal(approvalplan.CodeBusy))
	if err != nil || status != http.StatusServiceUnavailable {
		t.Fatalf("busy: %d %v", status, err)
	}
	golden(t, "hosted/response-busy.json", busy)
	status, notFound, err := approvalwire.MarshalHostedResponse(approvalwire.KindGet, refusal(approvalplan.CodeNotFound))
	if err != nil || status != http.StatusNotFound {
		t.Fatalf("not_found: %d %v", status, err)
	}
	golden(t, "hosted/response-not-found.json", notFound)
	if _, _, err := approvalwire.MarshalHostedResponse(approvalwire.KindGet, refusal(approvalplan.CodeSignerIncompatible)); err == nil {
		t.Error("a hosted server can emit signer_incompatible")
	}
}

// TestClassifyHostedResponse covers E69 and E21's hosted answers.
func TestClassifyHostedResponse(t *testing.T) {
	_, busy, _ := approvalwire.MarshalHostedResponse(approvalwire.KindClaim, refusal(approvalplan.CodeBusy))
	_, uncertain, _ := approvalwire.MarshalHostedResponse(approvalwire.KindReport, refusal(approvalplan.CodeStorageUncertain))
	_, notFound, _ := approvalwire.MarshalHostedResponse(approvalwire.KindGet, refusal(approvalplan.CodeNotFound))
	_, conflict, _ := approvalwire.MarshalHostedResponse(approvalwire.KindSubmit, refusal(approvalplan.CodeConflict))
	_, ok, _ := approvalwire.MarshalHostedResponse(approvalwire.KindSubmit, localResponses()["submit-ok"].resp)
	incompatibleFrame, _ := approvalwire.MarshalLocalResponse(approvalwire.KindGet, refusal(approvalplan.CodeSignerIncompatible))
	const policyPlane404 = `{"error":"not found"}` + "\n"
	const mux404 = "404 page not found\n"
	cases := []struct {
		name        string
		kind        string
		status      int
		contentType string
		body        string
		want        error
		wantCode    approvalplan.Code
	}{
		{"policy plane 404", approvalwire.KindSubmit, 404, "application/json", policyPlane404, approvalwire.ErrSignerIncompatible, ""},
		{"mux 404", approvalwire.KindClaim, 404, "text/plain; charset=utf-8", mux404, approvalwire.ErrSignerIncompatible, ""},
		{"empty 404", approvalwire.KindReport, 404, "", "", approvalwire.ErrSignerIncompatible, ""},
		{"not_found envelope", approvalwire.KindGet, 404, "application/json", string(notFound), nil, approvalplan.CodeNotFound},
		{"not_found envelope with charset", approvalwire.KindClaim, 404, "application/json; charset=utf-8", string(notFound), nil, approvalplan.CodeNotFound},
		{"not_found envelope as text", approvalwire.KindGet, 404, "text/plain", string(notFound), approvalwire.ErrSignerIncompatible, ""},
		{"busy envelope", approvalwire.KindClaim, 503, "application/json", string(busy), approvalwire.ErrBusy, approvalplan.CodeBusy},
		{"storage uncertain envelope", approvalwire.KindReport, 503, "application/json", string(uncertain), approvalwire.ErrStorageUncertain, approvalplan.CodeStorageUncertain},
		{"bare 503", approvalwire.KindClaim, 503, "text/html", "<html>Service Unavailable</html>", approvalwire.ErrTransport, ""},
		{"json 502", approvalwire.KindSubmit, 502, "application/json", `{"message":"bad gateway"}`, approvalwire.ErrTransport, ""},
		{"signer_incompatible envelope", approvalwire.KindGet, 503, "application/json", string(incompatibleFrame), approvalwire.ErrTransport, ""},
		{"conflict envelope", approvalwire.KindSubmit, 409, "application/json", string(conflict), nil, approvalplan.CodeConflict},
	}
	for _, c := range cases {
		_, err := approvalwire.ClassifyHostedResponse(c.kind, c.status, c.contentType, []byte(c.body))
		if c.want != nil && !errors.Is(err, c.want) {
			t.Errorf("%s: %v; want %v", c.name, err, c.want)
		}
		for _, other := range []error{approvalwire.ErrSignerIncompatible, approvalwire.ErrBusy, approvalwire.ErrStorageUncertain, approvalwire.ErrTransport, approvalwire.ErrResponseLost} {
			if other != c.want && errors.Is(err, other) {
				t.Errorf("%s: %v also matches %v", c.name, err, other)
			}
		}
		var we *approvalwire.WireError
		if (c.wantCode != "") != errors.As(err, &we) || (we != nil && we.Code != c.wantCode) {
			t.Errorf("%s: %v; want code %q", c.name, err, c.wantCode)
		}
	}
	resp, err := approvalwire.ClassifyHostedResponse(approvalwire.KindSubmit, 200, "application/json", ok)
	if err != nil || resp.Summary == nil || resp.Summary.RequestID != idOne {
		t.Fatalf("ok answer: %+v %v", resp, err)
	}
	for name, status := range map[string]int{"ok as 201": 201, "ok as 404": 404} {
		_, err := approvalwire.ClassifyHostedResponse(approvalwire.KindSubmit, status, "application/json", ok)
		if err == nil || errors.Is(err, approvalwire.ErrSignerIncompatible) || errors.Is(err, approvalwire.ErrTransport) {
			t.Errorf("%s: %v; want a malformed-response error", name, err)
		}
	}
	if _, err := approvalwire.ClassifyHostedResponse(approvalwire.KindClaim, 404, "application/json", busy); err == nil || errors.Is(err, approvalwire.ErrBusy) {
		t.Errorf("busy envelope with 404: %v; want a malformed-response error", err)
	}
}
