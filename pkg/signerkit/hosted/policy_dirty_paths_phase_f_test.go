package hosted

import (
	"context"
	"net/http"
	"net/http/httptest"
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
	}{
		{name: "machine dot segments", target: "/x/../v2/policy/base-manifests", plane: "machine"},
		{name: "machine duplicate slash", target: "/v2//policy/base-manifests", plane: "machine"},
		{name: "human dot segments", target: "/x/../ui/policy/pending", plane: "human"},
		{name: "human duplicate slash", target: "/ui//policy/pending", plane: "human"},
	} {
		t.Run(test.name, func(t *testing.T) {
			response := httptest.NewRecorder()
			server.ServeHTTP(response, httptest.NewRequest(http.MethodGet, test.target, nil))
			if response.Code != http.StatusNotFound || response.Body.String() != "{\"error\":\"not found\"}\n" ||
				response.Header().Get("Content-Type") != "application/json" || response.Header().Get("Cache-Control") != "no-store" {
				t.Fatalf("dirty %s path = %d %q headers=%v", test.plane, response.Code, response.Body.String(), response.Header())
			}
			if test.plane == "human" && response.Header().Get("Pragma") != "no-cache" {
				t.Fatalf("dirty human path headers=%v", response.Header())
			}
		})
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
