package refapp_test

import (
	"io/fs"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/karthikeyan5/sshgate/pkg/signerkit/hosted/refapp"
)

var wantAssets = []string{
	"index.html", "login.html", "pending.html", "request.html", "audit.html",
	"app.js", "index.js", "login.js", "pending.js", "request.js", "audit.js", "app.css",
}

func TestAssetsEmbedded(t *testing.T) {
	for _, name := range wantAssets {
		b, err := fs.ReadFile(refapp.Assets, "assets/"+name)
		if err != nil {
			t.Errorf("asset %q: %v", name, err)
			continue
		}
		if len(b) == 0 {
			t.Errorf("asset %q is empty", name)
		}
	}
}

func TestHandlerServes(t *testing.T) {
	t.Parallel()
	h := refapp.Handler()

	for _, tc := range []struct {
		path   string
		status int
		ct     string
	}{
		{"/", http.StatusOK, "text/html"},
		{"/login.html", http.StatusOK, "text/html"},
		{"/app.js", http.StatusOK, "javascript"},
		{"/app.css", http.StatusOK, "text/css"},
		{"/nope", http.StatusNotFound, ""},
		{"/assets/", http.StatusNotFound, ""},
	} {
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, tc.path, nil))
		if rr.Code != tc.status {
			t.Errorf("GET %s = %d; want %d", tc.path, rr.Code, tc.status)
		}
		if tc.ct != "" && !strings.Contains(rr.Header().Get("Content-Type"), tc.ct) {
			t.Errorf("GET %s Content-Type = %q; want %q", tc.path, rr.Header().Get("Content-Type"), tc.ct)
		}
	}
}

func TestHandlerMethodsAndHeaders(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/", nil)
	rr := httptest.NewRecorder()
	refapp.Handler().ServeHTTP(rr, req)
	if rr.Code != http.StatusMethodNotAllowed || rr.Header().Get("Allow") != "GET, HEAD" {
		t.Fatalf("POST / = %d Allow=%q", rr.Code, rr.Header().Get("Allow"))
	}

	req = httptest.NewRequest(http.MethodGet, "/login.html", nil)
	rr = httptest.NewRecorder()
	refapp.Handler().ServeHTTP(rr, req)
	if rr.Header().Get("X-Frame-Options") != "DENY" || rr.Header().Get("X-Content-Type-Options") != "nosniff" {
		t.Fatalf("missing response hardening headers: %v", rr.Header())
	}
	wantCSP := "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'"
	if got := rr.Header().Get("Content-Security-Policy"); got != wantCSP {
		t.Fatalf("Content-Security-Policy = %q; want %q", got, wantCSP)
	}
}

func TestNoDirectoryListing(t *testing.T) {
	index, err := fs.ReadFile(refapp.Assets, "assets/index.html")
	if err != nil {
		t.Fatal(err)
	}
	rr := httptest.NewRecorder()
	refapp.Handler().ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/", nil))
	if rr.Code != http.StatusOK || rr.Body.String() != string(index) {
		t.Fatalf("GET / did not return index.html verbatim")
	}
}

func TestAssetsSelfContained(t *testing.T) {
	forbidden := []string{"http://", "https://", "//cdn", "src=//", "href=//", "//fonts", "//unpkg", "//jsdelivr"}
	err := fs.WalkDir(refapp.Assets, "assets", func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		b, err := fs.ReadFile(refapp.Assets, p)
		if err != nil {
			return err
		}
		for _, bad := range forbidden {
			if strings.Contains(string(b), bad) {
				t.Errorf("asset %q contains external reference %q", p, bad)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestHTMLHasNoInlineScript(t *testing.T) {
	for _, name := range []string{"index.html", "login.html", "pending.html", "request.html", "audit.html"} {
		b, err := fs.ReadFile(refapp.Assets, "assets/"+name)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(b), "<script>") {
			t.Errorf("%s contains inline script forbidden by CSP", name)
		}
	}
}

func TestCommandRenderingSafetyIsPinned(t *testing.T) {
	b, err := fs.ReadFile(refapp.Assets, "assets/app.js")
	if err != nil {
		t.Fatal(err)
	}
	js := string(b)
	if strings.Contains(js, ".innerHTML") {
		t.Fatal("app.js must not render server data with innerHTML")
	}
	for _, want := range []string{"textContent", "neutralize", "character === '\\\\'", "host_key_fp", "sha256"} {
		if !strings.Contains(js, want) {
			t.Errorf("app.js does not pin %q", want)
		}
	}
}
