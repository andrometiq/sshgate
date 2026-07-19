// Package refapp serves SSHGate's embedded reference UI for the hosted signer.
// It is deliberately a leaf package: static assets and an HTTP handler only,
// with no approval or authentication logic.
package refapp

import (
	"bytes"
	"embed"
	"io/fs"
	"net/http"
	"path"
	"strings"
	"time"
)

// Assets contains the complete, self-contained reference application.
//
//go:embed assets/*
var Assets embed.FS

// Handler serves the embedded application. It serves only GET and HEAD,
// returns an explicit 404 for unknown paths and directories, and never exposes
// a directory listing.
func Handler() http.Handler {
	assets, err := fs.Sub(Assets, "assets")
	if err != nil {
		panic("refapp: embedded assets: " + err.Error())
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			w.Header().Set("Allow", "GET, HEAD")
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}

		name := strings.TrimPrefix(path.Clean("/"+r.URL.Path), "/")
		if name == "" {
			name = "index.html"
		}
		data, err := fs.ReadFile(assets, name)
		if err != nil {
			http.NotFound(w, r)
			return
		}

		w.Header().Set("Content-Type", contentType(name))
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Content-Security-Policy", "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'")
		http.ServeContent(w, r, name, time.Time{}, bytes.NewReader(data))
	})
}

func contentType(name string) string {
	switch {
	case strings.HasSuffix(name, ".html"):
		return "text/html; charset=utf-8"
	case strings.HasSuffix(name, ".js"):
		return "text/javascript; charset=utf-8"
	case strings.HasSuffix(name, ".css"):
		return "text/css; charset=utf-8"
	default:
		return "application/octet-stream"
	}
}
