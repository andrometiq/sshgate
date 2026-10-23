package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"testing/synctest"

	"github.com/karthikeyan5/sshgate/pkg/signerkit"
	ap "github.com/karthikeyan5/sshgate/src/approvalplan"
	"github.com/karthikeyan5/sshgate/src/signer/backend"
	"github.com/karthikeyan5/sshgate/src/xfer"
)

type wiringAPICall struct {
	method    string
	form      url.Values
	messageID int
}
type wiringTransport struct {
	mu      sync.Mutex
	calls   []wiringAPICall
	updates chan string
	stopped <-chan struct{}
}

func (api *wiringTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if err := req.ParseForm(); err != nil {
		return nil, err
	}
	method := filepath.Base(req.URL.Path)
	api.mu.Lock()
	id := len(api.calls) + 1
	api.calls = append(api.calls, wiringAPICall{method, req.Form, id})
	api.mu.Unlock()
	body := fmt.Sprintf(`{"ok":true,"result":{"message_id":%d,"chat":{"id":42,"type":"private"}}}`, id)
	switch method {
	case "getMe":
		body = `{"ok":true,"result":{"id":123,"is_bot":true,"first_name":"Test","username":"test_bot"}}`
	case "getUpdates":
		select {
		case body = <-api.updates:
		case <-api.stopped:
			return nil, context.Canceled
		case <-req.Context().Done():
			return nil, req.Context().Err()
		}
	}
	return &http.Response{StatusCode: http.StatusOK, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(body)), Request: req}, nil
}
func (api *wiringTransport) snapshot() []wiringAPICall {
	api.mu.Lock()
	defer api.mu.Unlock()
	return append([]wiringAPICall(nil), api.calls...)
}

type wiringConnection struct {
	input  *bytes.Reader
	output bytes.Buffer
}

func (c *wiringConnection) Read(p []byte) (int, error)  { return c.input.Read(p) }
func (c *wiringConnection) Write(p []byte) (int, error) { return c.output.Write(p) }

func wiringFingerprint(label string) string {
	sum := sha256.Sum256([]byte(label))
	return "SHA256:" + base64.RawStdEncoding.EncodeToString(sum[:])
}

func TestProductionApprovalWiring(t *testing.T) {
	// These tests replace the default transport serially; every HTTP request is
	// handled in-process, including an accidentally premature polling request.
	for _, switches := range []string{"", "enabled = false", "legacy_v1_via_lifecycle = false", "enabled = false\nlegacy_v1_via_lifecycle = false"} {
		t.Run(strings.ReplaceAll(switches, "\n", "/"), func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				api := &wiringTransport{updates: make(chan string, 1)}
				previous := http.DefaultTransport
				http.DefaultTransport = api
				defer func() { http.DefaultTransport = previous }()
				t.Setenv("SSHGATE_TELEGRAM_API_URL", "")
				cfg, err := loadConfig(writeTOML(t, validConfig+"\n[approvals]\n"+switches+"\n"))
				if err != nil {
					t.Fatal(err)
				}
				root := t.TempDir()
				tokenPath := filepath.Join(root, "token")
				if err := os.WriteFile(tokenPath, []byte("123:test-token"), 0600); err != nil {
					t.Fatal(err)
				}
				cfg.Backend.Type = "telegram"
				cfg.Backend.Telegram = telegramConfig{TokenPath: tokenPath, AllowedUserID: 42, ChatStorePath: filepath.Join(root, "chat.json")}
				chat := &backend.FileChatStore{Path: cfg.Backend.Telegram.ChatStorePath}
				if err := chat.Save(42); err != nil {
					t.Fatal(err)
				}
				ctx, cancel := context.WithCancel(context.Background())
				api.stopped = ctx.Done()
				defer cancel()
				bk, err := buildBackend(ctx, cfg.Backend, [32]byte{}, nil)
				if err != nil {
					t.Fatal(err)
				}
				defer func() { cancel(); bk.(*backend.TelegramBackend).Wait() }()
				synctest.Wait()
				for _, call := range api.snapshot() {
					if call.method != "getMe" {
						t.Fatalf("Bot API %s ran before lifecycle startup", call.method)
					}
				}
				audit, err := signerkit.OpenAuditLog(filepath.Join(root, "audit.jsonl"))
				if err != nil {
					t.Fatal(err)
				}
				defer audit.Close()
				_, key, err := ed25519.GenerateKey(rand.Reader)
				if err != nil {
					t.Fatal(err)
				}
				registry, err := signerkit.LoadXferRegistry(filepath.Join(root, "xfer.json"))
				if err != nil {
					t.Fatal(err)
				}
				boxKey, err := xfer.GenerateBoxKey()
				if err != nil {
					t.Fatal(err)
				}
				idKey, err := xfer.GenerateIDKey()
				if err != nil {
					t.Fatal(err)
				}
				for _, alias := range []string{"source", "destination"} {
					if err := registry.Register(wiringFingerprint(alias), alias, boxKey.PublicText(), idKey.PublicText()); err != nil {
						t.Fatal(err)
					}
				}
				svc, err := signerkit.New(signerkit.Config{Signer: key, Backend: bk, Audit: audit, XferRegistry: registry})
				if err != nil {
					t.Fatal(err)
				}
				defer svc.Close()
				runtime, err := attachApprovals(svc, bk, cfg, audit, nil)
				if err != nil {
					t.Fatal(err)
				}
				if runtime == nil || runtime.Legacy() == nil {
					t.Fatal("production lifecycle missing")
				}
				if err := runtime.Status(); err != nil {
					t.Fatalf("startup incomplete: %v", err)
				}
				if bk.(*backend.TelegramBackend).CommandAudit != audit {
					t.Fatal("command audit not wired")
				}
				api.updates <- `{"ok":true,"result":[]}`
				if err := bk.(*backend.TelegramBackend).Run(ctx); err != nil {
					t.Fatal(err)
				}
				defer func() { cancel(); bk.(*backend.TelegramBackend).Wait() }()
				synctest.Wait()
				for updateID, kind := range []string{"sign", "request_grant", "transfer", "register_xfer_key"} {
					request := map[string]any{"kind": kind, "request_id": "legacy-" + kind}
					switch kind {
					case "sign":
						request["commands"] = []map[string]any{{"server": "source", "host": wiringFingerprint("source"), "cmd": "touch /srv/example", "ttl_seconds": 37}}
					case "request_grant":
						request["alias"] = "source"
						request["scope"] = "all"
						request["duration_seconds"] = 60
					case "transfer":
						request["src_fp"] = wiringFingerprint("source")
						request["dest_fp"] = wiringFingerprint("destination")
						request["src_path"] = "/srv/source"
						request["dest_path"] = "/srv/destination"
						request["mode"] = "0600"
						request["ttl_seconds"] = 37
					case "register_xfer_key":
						request["host_fp"] = wiringFingerprint("new-host")
						request["label"] = "new-host"
						request["box_pub"] = boxKey.PublicText()
						request["id_pub"] = idKey.PublicText()
					}
					raw, err := json.Marshal(request)
					if err != nil {
						t.Fatal(err)
					}
					conn := &wiringConnection{input: bytes.NewReader(append(raw, '\n'))}
					before := len(api.snapshot())
					done := make(chan error, 1)
					go func() { done <- svc.HandleSignRequestWithPeer(ctx, conn, &signerkit.PeerCredentials{UID: 7}) }()
					synctest.Wait()
					var handle, challenge string
					var cardMessageID int
					var review strings.Builder
					buttons := 0
					for _, call := range api.snapshot()[before:] {
						review.WriteString(call.form.Get("text"))
						markup := call.form.Get("reply_markup")
						if strings.Contains(markup, "approve:") || strings.Contains(markup, "deny:") {
							t.Fatalf("%s used direct legacy backend: %s", kind, markup)
						}
						if markup == "" {
							continue
						}
						var keyboard struct {
							Rows [][]struct {
								Data string `json:"callback_data"`
							} `json:"inline_keyboard"`
						}
						if err := json.Unmarshal([]byte(markup), &keyboard); err != nil {
							t.Fatal(err)
						}
						for _, row := range keyboard.Rows {
							for _, button := range row {
								fields := strings.Split(button.Data, ":")
								if len(fields) != 4 || fields[0] != "v" || !ap.ValidCardHandle(fields[2]) || !ap.ValidChallenge(fields[3]) {
									t.Fatalf("%s invalid lifecycle callback %q", kind, button.Data)
								}
								handle, challenge = fields[2], fields[3]
								cardMessageID = call.messageID
								buttons++
							}
						}
					}
					label := ap.LegacyRationaleText
					if kind == "register_xfer_key" {
						label = ap.CLIRationaleText
					}
					if buttons < 2 || !strings.Contains(review.String(), label) || !strings.Contains(review.String(), "none (legacy v1 request)") {
						t.Fatalf("%s lacks lifecycle card/legacy label: calls=%+v response=%s", kind, api.snapshot()[before:], conn.output.String())
					}
					api.updates <- fmt.Sprintf(`{"ok":true,"result":[{"update_id":%d,"callback_query":{"id":"tap-%d","from":{"id":42,"first_name":"Operator"},"message":{"message_id":%d,"chat":{"id":42,"type":"private"}},"data":"v:d:%s:%s"}}]}`, updateID+1, updateID+1, cardMessageID, handle, challenge)
					synctest.Wait()
					select {
					case err := <-done:
						if err != nil {
							t.Fatal(err)
						}
					default:
						t.Fatalf("%s callback did not resolve the request", kind)
					}
					if !strings.Contains(conn.output.String(), `"status":"denied"`) {
						t.Fatalf("%s response=%s", kind, conn.output.String())
					}
				}
			})
		})
	}
}
