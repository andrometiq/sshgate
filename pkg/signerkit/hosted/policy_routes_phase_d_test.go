package hosted

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/karthikeyan5/sshgate/pkg/signerkit/policyarchive"
	"github.com/karthikeyan5/sshgate/pkg/signerkit/policystore"
	"github.com/karthikeyan5/sshgate/src/policy"
	"github.com/karthikeyan5/sshgate/src/policywire"
)

func newPolicyRouteServer(t testing.TB, handler http.Handler) (*Server, *PolicyEngine) {
	t.Helper()
	core := newTestPolicyCore(t)
	audit := &testPolicyAudit{}
	engine := newTestEngine(t, &embeddedPolicyStore{}, core, audit, time.Now().UTC(), nil)
	lease, archive := testPolicyArchive(t)
	t.Cleanup(func() { _ = archive.Close() })
	t.Cleanup(func() { _ = lease.Close() })
	server := NewServer("secret", nil, log.New(io.Discard, "", 0))
	server.MachineClientID = "machine"
	server.Human = &HumanAPI{}
	if err := server.AttachPolicy(&PolicyAPIConfig{Engine: engine, Handler: handler, Archive: archive, Lease: lease, DurableAudit: audit}); err != nil {
		t.Fatal(err)
	}
	return server, engine
}

func TestPolicyMachineRawRouteGrammarAndBearerPrincipal(t *testing.T) {
	var mu sync.Mutex
	principals := []string{}
	handler := http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		principal, ok := machinePrincipalFromContext(request.Context())
		if !ok {
			t.Error("machine principal was not injected")
		}
		mu.Lock()
		principals = append(principals, principal)
		mu.Unlock()
		writer.WriteHeader(http.StatusNoContent)
	})
	server, engine := newPolicyRouteServer(t, handler)
	if err := engine.Readiness().SetReady(context.Background()); err != nil {
		t.Fatal(err)
	}

	requestID := "pm_11111111111111111111111111111111"
	valid := []struct{ method, target string }{
		{http.MethodPost, "/v2/policy/base-manifests"},
		{http.MethodGet, "/v2/policy/base-manifests/" + requestID},
	}
	for _, test := range valid {
		request := httptest.NewRequest(test.method, test.target, nil)
		request.Header.Set("Authorization", "Bearer secret")
		response := httptest.NewRecorder()
		server.ServeHTTP(response, request)
		if response.Code != http.StatusNoContent || response.Header().Get("Cache-Control") != "no-store" {
			t.Fatalf("%s %s = %d headers=%v", test.method, test.target, response.Code, response.Header())
		}
	}
	mu.Lock()
	if len(principals) != 2 || principals[0] != "machine" || principals[1] != "machine" {
		t.Fatalf("injected principals = %#v", principals)
	}
	mu.Unlock()

	invalid := []string{
		"/v2/policy/base-manifests?x=1",
		"/v2/policy/base-manifests/" + requestID + "?x=1",
		"/v2/policy/base-manifests/",
		"//v2/policy/base-manifests/" + requestID,
		"/v2/policy/base-manifests//" + requestID,
		"/v2/policy/base-manifests/" + requestID + "/",
		"/v2/policy/base-manifests/PM_11111111111111111111111111111111",
		"/v2/policy/base-manifests/pm_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaA",
		"/v2/policy/base-manifests/pm_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa%61a",
		"/v2/policy/%62ase-manifests/" + requestID,
	}
	for _, target := range invalid {
		request := httptest.NewRequest(http.MethodGet, target, nil)
		request.Header.Set("Authorization", "Bearer secret")
		response := httptest.NewRecorder()
		server.ServeHTTP(response, request)
		if response.Code != http.StatusNotFound || response.Body.String() != "{\"error\":\"not found\"}\n" ||
			response.Header().Get("Content-Type") != "application/json" || response.Header().Get("Cache-Control") != "no-store" {
			t.Fatalf("invalid %q = %d %q headers=%v", target, response.Code, response.Body.String(), response.Header())
		}
	}

	wrongMethods := []struct{ method, target string }{
		{http.MethodGet, "/v2/policy/base-manifests"},
		{http.MethodPost, "/v2/policy/base-manifests/" + requestID},
		{http.MethodDelete, "/v2/policy/base-manifests/" + requestID},
	}
	for _, test := range wrongMethods {
		response := httptest.NewRecorder()
		server.ServeHTTP(response, httptest.NewRequest(test.method, test.target, nil))
		if response.Code != http.StatusMethodNotAllowed || response.Body.String() != "{\"error\":\"method not allowed\"}\n" ||
			response.Header().Get("Content-Type") != "application/json" || response.Header().Get("Cache-Control") != "no-store" {
			t.Fatalf("wrong method %s %s = %d %q headers=%v", test.method, test.target, response.Code, response.Body.String(), response.Header())
		}
	}
}

func TestPolicyMachineRollingLimitUsesFrozen429(t *testing.T) {
	server, engine := newPolicyRouteServer(t, http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		writer.WriteHeader(http.StatusNoContent)
	}))
	if err := engine.Readiness().SetReady(context.Background()); err != nil {
		t.Fatal(err)
	}
	for index := 0; index <= 120; index++ {
		request := httptest.NewRequest(http.MethodPost, "/v2/policy/base-manifests", nil)
		request.Header.Set("Authorization", "Bearer secret")
		response := httptest.NewRecorder()
		server.ServeHTTP(response, request)
		if index < 120 && response.Code != http.StatusNoContent {
			t.Fatalf("request %d = %d", index, response.Code)
		}
		if index == 120 && (response.Code != http.StatusTooManyRequests || response.Body.String() != "{\"error\":\"too many requests\"}\n" || response.Header().Get("Retry-After") != "60" || response.Header().Get("Cache-Control") != "no-store") {
			t.Fatalf("limited response = %d %q headers=%v", response.Code, response.Body.String(), response.Header())
		}
	}
}

func TestPolicyMachineCapacityClassesAndClosedStatusMap(t *testing.T) {
	handler := &PolicyMachineHandler{}
	window := httptest.NewRecorder()
	handler.writeAdmissionError(window, &policystore.CapacityError{Kind: policystore.CapacityWindow, RetryAfter: 1500 * time.Millisecond})
	if window.Code != http.StatusTooManyRequests || window.Body.String() != "{\"error\":\"too many requests\"}\n" || window.Header().Get("Retry-After") != "2" {
		t.Fatalf("window capacity = %d %q headers=%v", window.Code, window.Body.String(), window.Header())
	}
	for _, kind := range []policystore.CapacityKind{policystore.CapacityRetainedRows, policystore.CapacityRetainedBytes, policystore.CapacityGlobalHeadroom} {
		response := httptest.NewRecorder()
		handler.writeAdmissionError(response, &policystore.CapacityError{Kind: kind})
		if response.Code != http.StatusTooManyRequests || response.Body.String() != window.Body.String() || response.Header().Get("Retry-After") != "" {
			t.Fatalf("capacity %s = %d %q headers=%v", kind, response.Code, response.Body.String(), response.Header())
		}
	}

	for _, test := range []struct {
		response policywire.Response
		status   int
	}{
		{response: policywire.Response{Status: policywire.StatusPending}, status: http.StatusAccepted},
		{response: policywire.Response{Status: policywire.StatusApproved}, status: http.StatusOK},
		{response: policywire.Response{Status: policywire.StatusDenied}, status: http.StatusOK},
		{response: policywire.Response{Status: policywire.StatusTimeout}, status: http.StatusOK},
		{response: policywire.Response{Status: policywire.StatusInterrupted}, status: http.StatusOK},
		{response: policywire.Response{Status: policywire.StatusError, ErrorCode: policywire.ErrorInvalidPolicyRequest}, status: http.StatusBadRequest},
		{response: policywire.Response{Status: policywire.StatusError, ErrorCode: policywire.ErrorStalePolicyHead}, status: http.StatusConflict},
		{response: policywire.Response{Status: policywire.StatusError, ErrorCode: policywire.ErrorPolicyJournalFull}, status: http.StatusTooManyRequests},
		{response: policywire.Response{Status: policywire.StatusError, ErrorCode: policywire.ErrorPolicyNotificationFailed}, status: http.StatusInternalServerError},
		{response: policywire.Response{Status: policywire.StatusError, ErrorCode: policywire.ErrorPolicyNotSupported}, status: http.StatusNotImplemented},
	} {
		status, err := policyMachineHTTPStatus(test.response)
		if err != nil || status != test.status {
			t.Errorf("status map %+v = %d, %v; want %d", test.response, status, err, test.status)
		}
	}
	if _, err := policyMachineHTTPStatus(policywire.Response{Status: "unknown"}); err == nil {
		t.Fatal("unknown policy status was accepted")
	}
}

func TestPolicyMachinePendingTerminalHiddenAndPrincipalServing(t *testing.T) {
	database, store, core, audit, input := newHostedPolicyHarness(t, 1)
	t.Cleanup(func() { _ = database.Close() })
	engine := newTestEngine(t, store, core, audit, input.Now, nil)
	server := newPolicyMachineServer(t, engine, audit)

	post := httptest.NewRequest(http.MethodPost, "/v2/policy/base-manifests", io.NopCloser(bytes.NewReader(input.CanonicalRequest)))
	post.Header.Set("Authorization", "Bearer secret")
	response := httptest.NewRecorder()
	server.ServeHTTP(response, post)
	if response.Code != http.StatusAccepted || response.Header().Get("Location") != "/v2/policy/base-manifests/"+input.Key.RequestID || response.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("accepted POST = %d %q headers=%v", response.Code, response.Body.String(), response.Header())
	}
	pendingBytes := slices.Clone(response.Body.Bytes())

	get := httptest.NewRequest(http.MethodGet, "/v2/policy/base-manifests/"+input.Key.RequestID, nil)
	get.Header.Set("Authorization", "Bearer secret")
	response = httptest.NewRecorder()
	server.ServeHTTP(response, get)
	if response.Code != http.StatusAccepted || response.Header().Get("Location") != "" || !bytes.Equal(response.Body.Bytes(), pendingBytes) {
		t.Fatalf("pending GET = %d %q headers=%v", response.Code, response.Body.String(), response.Header())
	}
	conflicting := testPolicyAdmission(t, core.keyID, input.Key.RequestID, "", true, 1).CanonicalRequest
	conflictPost := httptest.NewRequest(http.MethodPost, "/v2/policy/base-manifests", bytes.NewReader(conflicting))
	conflictPost.Header.Set("Authorization", "Bearer secret")
	response = httptest.NewRecorder()
	server.ServeHTTP(response, conflictPost)
	conflict, decodeErr := policywire.DecodeResponse(response.Body.Bytes())
	if response.Code != http.StatusConflict || response.Header().Get("Location") != "" || decodeErr != nil || conflict.Wire.ErrorCode != policywire.ErrorIdempotencyConflict {
		t.Fatalf("idempotency conflict = %d %q headers=%v decode=%v", response.Code, response.Body.String(), response.Header(), decodeErr)
	}
	audit.mu.Lock()
	if len(audit.calls) != 3 {
		t.Fatalf("accepted submission plus conflict audits = %d; want 3", len(audit.calls))
	}
	audit.mu.Unlock()

	server.MachineClientID = "another-operator"
	response = httptest.NewRecorder()
	server.ServeHTTP(response, get)
	if response.Code != http.StatusNotFound || response.Body.String() != "{\"error\":\"not found\"}\n" {
		t.Fatalf("cross-principal GET = %d %q", response.Code, response.Body.String())
	}
	server.MachineClientID = "machine"

	rejected := rejectedPolicyCanonical(t, core.keyID, "pm_88888888888888888888888888888888")
	rejectPost := httptest.NewRequest(http.MethodPost, "/v2/policy/base-manifests", bytes.NewReader(rejected))
	rejectPost.Header.Set("Authorization", "Bearer secret")
	response = httptest.NewRecorder()
	server.ServeHTTP(response, rejectPost)
	if response.Code != http.StatusBadRequest || response.Header().Get("Location") != "" {
		t.Fatalf("terminal rejection POST = %d %q headers=%v", response.Code, response.Body.String(), response.Header())
	}
	terminalBytes := slices.Clone(response.Body.Bytes())
	retryPost := httptest.NewRequest(http.MethodPost, "/v2/policy/base-manifests", bytes.NewReader(rejected))
	retryPost.Header.Set("Authorization", "Bearer secret")
	response = httptest.NewRecorder()
	server.ServeHTTP(response, retryPost)
	if response.Code != http.StatusBadRequest || !bytes.Equal(response.Body.Bytes(), terminalBytes) {
		t.Fatalf("terminal retry = %d %q; want %q", response.Code, response.Body.String(), terminalBytes)
	}

	bad := httptest.NewRequest(http.MethodPost, "/v2/policy/base-manifests", strings.NewReader("{}"))
	bad.Header.Set("Authorization", "Bearer secret")
	response = httptest.NewRecorder()
	server.ServeHTTP(response, bad)
	if response.Code != http.StatusBadRequest || response.Body.String() != "{\"error\":\"invalid policy request\"}\n" {
		t.Fatalf("invalid POST = %d %q", response.Code, response.Body.String())
	}
	oversize := httptest.NewRequest(http.MethodPost, "/v2/policy/base-manifests", bytes.NewReader(make([]byte, policywire.MaxRequestFrameBytes+1)))
	oversize.Header.Set("Authorization", "Bearer secret")
	response = httptest.NewRecorder()
	server.ServeHTTP(response, oversize)
	if response.Code != http.StatusBadRequest || response.Body.String() != "{\"error\":\"invalid policy request\"}\n" {
		t.Fatalf("oversize POST = %d %q", response.Code, response.Body.String())
	}

	hiddenDatabase, hiddenStore, hiddenCore, hiddenAudit, hiddenInput := newHostedPolicyHarness(t, 1)
	t.Cleanup(func() { _ = hiddenDatabase.Close() })
	hiddenEngine := newTestEngine(t, hiddenStore, hiddenCore, hiddenAudit, hiddenInput.Now, func(point PolicyFaultPoint) error {
		if point == PolicyFaultAfterSubmissionAudit {
			return errors.New("crash after durable submission audit")
		}
		return nil
	})
	hiddenServer := newPolicyMachineServer(t, hiddenEngine, hiddenAudit)
	hiddenPost := httptest.NewRequest(http.MethodPost, "/v2/policy/base-manifests", bytes.NewReader(hiddenInput.CanonicalRequest))
	hiddenPost.Header.Set("Authorization", "Bearer secret")
	response = httptest.NewRecorder()
	hiddenServer.ServeHTTP(response, hiddenPost)
	if response.Code != http.StatusServiceUnavailable || response.Header().Get("Location") != "" || response.Body.String() != "{\"error\":\"policy authority unavailable\"}\n" {
		t.Fatalf("hidden POST = %d %q headers=%v", response.Code, response.Body.String(), response.Header())
	}
	hiddenGet := httptest.NewRequest(http.MethodGet, "/v2/policy/base-manifests/"+hiddenInput.Key.RequestID, nil)
	hiddenGet.Header.Set("Authorization", "Bearer secret")
	response = httptest.NewRecorder()
	hiddenServer.ServeHTTP(response, hiddenGet)
	if response.Code != http.StatusServiceUnavailable || response.Body.String() != "{\"error\":\"policy authority unavailable\"}\n" {
		t.Fatalf("hidden GET = %d %q", response.Code, response.Body.String())
	}
}

func TestPolicyMachineServesVerifiedTombstoneThroughFetch(t *testing.T) {
	database, store, core, audit, input := newHostedPolicyHarness(t, 1)
	t.Cleanup(func() { _ = database.Close() })
	engine := newTestEngine(t, store, core, audit, input.Now, nil)
	requestID := "pm_77777777777777777777777777777777"
	canonical := rejectedPolicyCanonical(t, core.keyID, requestID)
	decoded, err := policywire.DecodeRequest(canonical)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := engine.Admit(context.Background(), PolicyAdmissionInput{Principal: "machine", CanonicalRequest: canonical, Decoded: decoded}); err != nil {
		t.Fatal(err)
	}
	tuple, err := policyTuple(decoded)
	if err != nil {
		t.Fatal(err)
	}
	lookup, err := store.Lookup(context.Background(), policystore.Key{Principal: "machine", RequestID: requestID}, tuple)
	if err != nil || lookup.Request == nil || lookup.Class != policystore.RowTerminal {
		t.Fatalf("terminal lookup = %+v, %v", lookup, err)
	}
	terminalBytes := slices.Clone(lookup.Request.TerminalResponse)

	root := filepath.Join(t.TempDir(), "archive")
	if err := os.Mkdir(root, 0o700); err != nil {
		t.Fatal(err)
	}
	lockTarget := filepath.Join(filepath.Dir(root), "policy.db")
	exclusive, err := policyarchive.AcquireMaintenanceLease(lockTarget, policyarchive.LeaseExclusive)
	if err != nil {
		t.Fatal(err)
	}
	archive, err := policyarchive.OpenServing(root, exclusive)
	if err != nil {
		t.Fatal(err)
	}
	if err := archive.PublishBinding(exclusive, testPolicyArchiveID, testPolicyAuthority); err != nil {
		t.Fatal(err)
	}
	if err := archive.PrepareServingShards(exclusive); err != nil {
		t.Fatal(err)
	}
	record, err := store.SnapshotTerminalArchive(context.Background(), lookup.Request.Key(), lookup.Request.StateVersion)
	if err != nil {
		t.Fatal(err)
	}
	reference, encoded, err := record.ObjectRef()
	if err != nil {
		t.Fatal(err)
	}
	object, err := archive.PublishObject(exclusive, encoded)
	if err != nil {
		t.Fatal(err)
	}
	if object.SHA256 != reference.ObjectSHA256 || object.Bytes != reference.RecordBytes {
		t.Fatal("published archive object reference differs")
	}
	if _, err := store.CommitTerminalArchive(context.Background(), lookup.Request.Key(), lookup.Request.StateVersion, reference); err != nil {
		t.Fatal(err)
	}
	if err := archive.Close(); err != nil {
		t.Fatal(err)
	}
	if err := exclusive.Close(); err != nil {
		t.Fatal(err)
	}

	shared, err := policyarchive.AcquireMaintenanceLease(lockTarget, policyarchive.LeaseShared)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = shared.Close() })
	archive, err = policyarchive.OpenServing(root, shared)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = archive.Close() })
	if err := archive.VerifyBinding(testPolicyArchiveID, testPolicyAuthority); err != nil {
		t.Fatal(err)
	}
	if err := archive.VerifyShards(); err != nil {
		t.Fatal(err)
	}
	handler, err := NewPolicyMachineHandler(engine, archive)
	if err != nil {
		t.Fatal(err)
	}
	server := NewServer("secret", nil, log.New(io.Discard, "", 0))
	server.MachineClientID = "machine"
	server.Human = &HumanAPI{}
	if err := server.AttachPolicy(&PolicyAPIConfig{Engine: engine, Handler: handler, Archive: archive, Lease: shared, DurableAudit: audit}); err != nil {
		t.Fatal(err)
	}
	if err := engine.Readiness().SetReady(context.Background()); err != nil {
		t.Fatal(err)
	}
	get := httptest.NewRequest(http.MethodGet, "/v2/policy/base-manifests/"+requestID, nil)
	get.Header.Set("Authorization", "Bearer secret")
	response := httptest.NewRecorder()
	server.ServeHTTP(response, get)
	if response.Code != http.StatusBadRequest || !bytes.Equal(response.Body.Bytes(), terminalBytes) || response.Header().Get("Location") != "" {
		t.Fatalf("tombstone GET = %d %q headers=%v", response.Code, response.Body.String(), response.Header())
	}
}

func newPolicyMachineServer(t testing.TB, engine *PolicyEngine, audit *testPolicyAudit) *Server {
	t.Helper()
	lease, archive := testPolicyArchive(t)
	t.Cleanup(func() { _ = archive.Close() })
	t.Cleanup(func() { _ = lease.Close() })
	handler, err := NewPolicyMachineHandler(engine, archive)
	if err != nil {
		t.Fatal(err)
	}
	server := NewServer("secret", nil, log.New(io.Discard, "", 0))
	server.MachineClientID = "machine"
	server.Human = &HumanAPI{}
	if err := server.AttachPolicy(&PolicyAPIConfig{Engine: engine, Handler: handler, Archive: archive, Lease: lease, DurableAudit: audit}); err != nil {
		t.Fatal(err)
	}
	if err := engine.Readiness().SetReady(context.Background()); err != nil {
		t.Fatal(err)
	}
	return server
}

func rejectedPolicyCanonical(t testing.TB, keyID, requestID string) []byte {
	t.Helper()
	host := "SHA256:" + base64.RawStdEncoding.EncodeToString(bytes.Repeat([]byte{1}, 32))
	manifest := policy.BaseManifest{Schema: policy.SchemaV1, Host: host, Epoch: 2,
		MissAction: policy.MissActionAsk, Growth: policy.GrowthSignToAdd, Revision: 1}
	payload, err := policy.MarshalBaseManifest(manifest)
	if err != nil {
		t.Fatal(err)
	}
	wire, err := policywire.NewRequest(requestID, host, keyID, payload, "", true)
	if err != nil {
		t.Fatal(err)
	}
	canonical, err := policywire.MarshalRequest(wire)
	if err != nil {
		t.Fatal(err)
	}
	return canonical
}
