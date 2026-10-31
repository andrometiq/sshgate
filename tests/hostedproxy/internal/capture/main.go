//go:build fixturecapture

// Capture runs against the old source tree via a Go overlay, without sockets.
package main

import (
	"context"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"

	"github.com/karthikeyan5/sshgate/pkg/signerkit"
	"github.com/karthikeyan5/sshgate/pkg/signerkit/hosted"
	"github.com/karthikeyan5/sshgate/pkg/signerkit/policyarchive"
	"github.com/karthikeyan5/sshgate/pkg/signerkit/policystore"
)

type audit struct{}

func (audit) PolicyAuditReady(context.Context) error                { return nil }
func (audit) Call(context.Context, signerkit.AuditCall) error       { return nil }
func (audit) Verdict(context.Context, signerkit.AuditVerdict) error { return nil }

// These dependencies are never reached: dispatch rejects non-policy routes first.
type unusedStore struct{ policystore.Store }
type unusedCustody struct{ hosted.PolicyCustody }
type answer struct {
	Method string      `json:"method"`
	Target string      `json:"target"`
	Status int         `json:"status"`
	Header http.Header `json:"header"`
	Body   string      `json:"body"`
}

func must(err error) {
	if err != nil {
		panic(err)
	}
}
func main() {
	root, err := os.MkdirTemp("", "hosted-fixture-")
	must(err)
	defer os.RemoveAll(root)
	const id = "a2_AAAAAAAAAAAAAAAAAAAAAA"
	routes := [][2]string{{"POST", "/v2/approvals"}, {"GET", "/v2/approvals/" + id}, {"GET", "/v2/approvals?limit=10&cursor="}, {"POST", "/v2/approvals/wait"}, {"POST", "/v2/approvals/" + id + "/claim"}, {"POST", "/v2/approvals/" + id + "/report"}}
	results := make(map[string][]answer)
	for _, attached := range []bool{false, true} {
		server := hosted.NewServer("fixture-key", nil, log.New(io.Discard, "", 0))
		name := "policy-absent"
		if attached {
			name = "policy-attached"
			lease, err := policyarchive.AcquireMaintenanceLease(filepath.Join(root, "policy.db"), policyarchive.LeaseShared)
			must(err)
			defer lease.Close()
			archivePath := filepath.Join(root, "archive")
			must(os.Mkdir(archivePath, 0700))
			archive, err := policyarchive.OpenServing(archivePath, lease)
			must(err)
			defer archive.Close()
			sink := &audit{}
			engine, err := hosted.NewPolicyEngine(hosted.PolicyEngineConfig{AuthorityID: "pauth_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", WorkerID: "fixture", Store: unusedStore{}, Core: unusedCustody{}, Audit: sink})
			must(err)
			server.Human = &hosted.HumanAPI{}
			server.MachineClientID = "fixture"
			must(server.AttachPolicy(&hosted.PolicyAPIConfig{Engine: engine, Handler: http.HandlerFunc(func(http.ResponseWriter, *http.Request) { panic("policy handler reached") }), Archive: archive, Lease: lease, DurableAudit: sink}))
		}
		for _, route := range routes {
			req := httptest.NewRequest(route[0], "http://fixture.invalid"+route[1], nil)
			req.Header.Set("Authorization", "Bearer fixture-key")
			rec := httptest.NewRecorder()
			server.ServeHTTP(rec, req)
			results[name] = append(results[name], answer{route[0], route[1], rec.Code, rec.Header(), rec.Body.String()})
		}
	}
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	must(encoder.Encode(results))
}
