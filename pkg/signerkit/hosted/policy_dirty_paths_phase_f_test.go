package hosted

import (
	"context"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"
)

func TestDirtyPolicyPathsUseFrozenNotFound(t *testing.T) {
	server, engine := newPolicyRouteServer(t, http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		writer.WriteHeader(http.StatusNoContent)
	}))
	if err := engine.Readiness().SetReady(context.Background()); err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name, target, plane string
		headers             http.Header
	}{
		{name: "machine dot segments", target: "/x/../v2/policy/base-manifests", plane: "machine", headers: machineNotFoundHeaders()},
		{name: "machine duplicate slash", target: "/v2//policy/base-manifests", plane: "machine", headers: machineNotFoundHeaders()},
		{name: "machine through human prefix", target: "/ui/../v2/policy/base-manifests", plane: "machine", headers: machineNotFoundHeaders()},
		{name: "human dot segments", target: "/x/../ui/policy/pending", plane: "human", headers: humanNotFoundHeaders()},
		{name: "human duplicate slash", target: "/ui//policy/pending", plane: "human", headers: humanNotFoundHeaders()},
		{name: "human through machine prefix", target: "/v2/policy/../../../ui/policy/pending", plane: "human", headers: humanNotFoundHeaders()},
	} {
		t.Run(test.name, func(t *testing.T) {
			response := httptest.NewRecorder()
			server.ServeHTTP(response, httptest.NewRequest(http.MethodGet, test.target, nil))
			if response.Code != http.StatusNotFound || response.Body.String() != "{\"error\":\"not found\"}\n" {
				t.Fatalf("dirty %s path = %d %q headers=%v", test.plane, response.Code, response.Body.String(), response.Header())
			}
			if !reflect.DeepEqual(response.Header(), test.headers) {
				t.Fatalf("dirty %s path headers=%v; want %v", test.plane, response.Header(), test.headers)
			}
		})
	}
}

func machineNotFoundHeaders() http.Header {
	return http.Header{
		"Cache-Control": {"no-store"},
		"Content-Type":  {"application/json"},
	}
}

func humanNotFoundHeaders() http.Header {
	return http.Header{
		"Cache-Control": {"no-store"},
		"Content-Type":  {"application/json"},
		"Pragma":        {"no-cache"},
	}
}

func TestOrdinaryDirtyPathMuxBehaviorIsUnchanged(t *testing.T) {
	server := NewServer("secret", nil, nil)
	for _, target := range []string{"/x/../v1/sign", "/x/../ui/login"} {
		request := httptest.NewRequest(http.MethodGet, target, nil)
		want := httptest.NewRecorder()
		server.mux.ServeHTTP(want, request.Clone(request.Context()))
		got := httptest.NewRecorder()
		server.ServeHTTP(got, request)
		if got.Code != want.Code || got.Body.String() != want.Body.String() ||
			got.Header().Get("Location") != want.Header().Get("Location") ||
			got.Header().Get("Content-Type") != want.Header().Get("Content-Type") {
			t.Fatalf("ordinary dirty path %q changed: got=%d %q %v want=%d %q %v", target,
				got.Code, got.Body.String(), got.Header(), want.Code, want.Body.String(), want.Header())
		}
	}
}
