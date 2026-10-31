//go:build fixturecapture

package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	sk "github.com/karthikeyan5/sshgate/pkg/signerkit"
	"github.com/karthikeyan5/sshgate/src/xfer"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
)

type exchange struct {
	Request  string   `json:"request"`
	Response string   `json:"response"`
	HTTP     []string `json:"http"`
}
type transport struct{ calls []string }

func (r *transport) RoundTrip(q *http.Request) (*http.Response, error) {
	b := []byte(nil)
	if q.Body != nil {
		b, _ = io.ReadAll(q.Body)
	}
	r.calls = append(r.calls, q.Method+" "+q.URL.RequestURI()+" "+string(b))
	status := 200
	body := `{"request_id":"r_fixture","status":"denied"}`
	if q.Method == "POST" {
		status = 202
		body = `{"request_id":"r_fixture"}`
	}
	return &http.Response{StatusCode: status, Header: http.Header{"Content-Type": {"application/json"}}, Body: io.NopCloser(strings.NewReader(body)), Request: q}, nil
}

type conn struct {
	io.Reader
	bytes.Buffer
}

func (c *conn) Read(p []byte) (int, error) { return c.Reader.Read(p) }
func must(e error) {
	if e != nil {
		panic(e)
	}
}
func main() {
	root, e := os.MkdirTemp("", "legacy-capture-")
	must(e)
	defer os.RemoveAll(root)
	key := ed25519.NewKeyFromSeed(make([]byte, 32))
	box := xfer.BoxPublicText(&[32]byte{1})
	id := xfer.IDPublicText(key.Public().(ed25519.PublicKey))
	registry, e := sk.LoadXferRegistry(filepath.Join(root, "registry.json"))
	must(e)
	src := "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	dest := "SHA256:BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"
	must(registry.Register(src, "source", box, id))
	must(registry.Register(dest, "destination", box, id))
	audit, e := sk.OpenAuditLog(filepath.Join(root, "audit.jsonl"))
	must(e)
	defer audit.Close()
	rt := &transport{}
	backend := &sk.HostedServerBackend{BaseURL: "https://signer.example", APIKey: "test-key", ClientID: "client", HTTPClient: &http.Client{Transport: rt}}
	svc, e := sk.New(sk.Config{Signer: key, Audit: audit, Backend: backend, XferRegistry: registry})
	must(e)
	defer svc.Close()
	registration, _ := json.Marshal(map[string]any{"kind": "register_xfer_key", "request_id": "register", "host_fp": src, "label": "source", "box_pub": box, "id_pub": id})
	requests := []string{`{"kind":"request_grant","request_id":"grant","alias":"web","scope":"all","duration_seconds":60}`, `{"kind":"list_grants","request_id":"list"}`, `{"kind":"sign","request_id":"sign","commands":[{"server":"web","cmd":"true","ttl_seconds":60}]}`, `{"kind":"transfer","request_id":"transfer","src_alias":"source","src_fp":"` + src + `","src_path":"/secret","dest_alias":"destination","dest_fp":"` + dest + `","dest_path":"/secret","mode":"0600","ttl_seconds":60}`, string(registration)}
	var out []exchange
	for _, request := range requests {
		rt.calls = nil
		c := &conn{Reader: strings.NewReader(request + "\n")}
		must(svc.HandleSignRequest(context.Background(), c))
		out = append(out, exchange{request, c.String(), append([]string{}, rt.calls...)})
	}
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	must(enc.Encode(out))
}
