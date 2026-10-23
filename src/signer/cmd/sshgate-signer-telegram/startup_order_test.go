package main

import (
	"bytes"
	"context"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"testing/synctest"

	"github.com/BurntSushi/toml"
	"github.com/karthikeyan5/sshgate/pkg/signerkit"
	"github.com/karthikeyan5/sshgate/pkg/signerkit/lifecycle"
	"github.com/karthikeyan5/sshgate/src/signer/backend"
)

type startupBarrierStore struct {
	approvalMemoryStore
	entered chan struct{}
	release chan struct{}
}

func (s *startupBarrierStore) List() ([]lifecycle.StoreEntry, error) {
	close(s.entered)
	<-s.release
	return s.approvalMemoryStore.List()
}

func TestRunContextWaitsForLifecycleStartup(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("daemon refuses root")
	}
	// Initialize the process signal dispatcher outside the synctest bubble.
	signals := make(chan os.Signal, 1)
	signal.Notify(signals, syscall.SIGHUP)
	defer signal.Stop(signals)
	synctest.Test(t, func(t *testing.T) {
		configPath, _ := initDevTree(t)
		cfg, err := loadConfig(configPath)
		if err != nil {
			t.Fatal(err)
		}
		cfg.Backend.Type = "telegram"
		cfg.Backend.Telegram = telegramConfig{TokenPath: filepath.Join(filepath.Dir(configPath), "token"), AllowedUserID: 42, ChatStorePath: filepath.Join(filepath.Dir(configPath), "chat.json")}
		if err := os.WriteFile(cfg.Backend.Telegram.TokenPath, []byte("123:test-token"), 0600); err != nil {
			t.Fatal(err)
		}
		if err := (&backend.FileChatStore{Path: cfg.Backend.Telegram.ChatStorePath}).Save(42); err != nil {
			t.Fatal(err)
		}
		var encoded bytes.Buffer
		if err := toml.NewEncoder(&encoded).Encode(cfg); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(configPath, encoded.Bytes(), 0600); err != nil {
			t.Fatal(err)
		}
		t.Setenv("SSHGATE_TELEGRAM_API_URL", "")
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		api := &wiringTransport{updates: make(chan string, 1), stopped: ctx.Done()}
		api.updates <- `{"ok":true,"result":[{"update_id":1,"callback_query":{"id":"startup-tap","from":{"id":42,"first_name":"Operator"},"message":{"message_id":1,"chat":{"id":42,"type":"private"}},"data":"deny:missing"}}]}`
		store := &startupBarrierStore{entered: make(chan struct{}), release: make(chan struct{})}
		previousTransport, previousStore, previousListen := http.DefaultTransport, newApprovalStore, listenSignerSocket
		defer func() {
			http.DefaultTransport, newApprovalStore, listenSignerSocket = previousTransport, previousStore, previousListen
		}()
		http.DefaultTransport = api
		newApprovalStore = func() signerkit.RecoverableStore { return store }
		accepted := make(chan struct{})
		response := make(chan string, 1)
		listenSignerSocket = func(srv *signerkit.Server, ctx context.Context) error {
			close(accepted)
			conn := &wiringConnection{input: bytes.NewReader([]byte("{\"kind\":\"unknown\"}\n"))}
			err := srv.Handler.HandleSignRequest(ctx, conn)
			response <- conn.output.String()
			<-ctx.Done()
			return err
		}
		done := make(chan int, 1)
		go func() { done <- runContext(ctx, []string{"--config", configPath}) }()
		released := false
		defer func() {
			if !released {
				close(store.release)
			}
			cancel()
			if code := <-done; code != 0 {
				t.Errorf("runContext exit = %d, want 0", code)
			}
		}()
		synctest.Wait()
		select {
		case <-store.entered:
		default:
			t.Fatal("runContext did not enter lifecycle startup")
		}
		for _, call := range api.snapshot() {
			if call.method != "getMe" {
				t.Errorf("Bot API %s ran before lifecycle Startup returned", call.method)
			}
		}
		select {
		case <-accepted:
			t.Error("socket accepted before lifecycle Startup returned")
		default:
		}
		close(store.release)
		released = true
		synctest.Wait()
		select {
		case <-accepted:
		default:
			t.Fatal("socket never accepted after startup")
		}
		select {
		case body := <-response:
			if !strings.Contains(body, "error") {
				t.Errorf("socket handler response = %q", body)
			}
		default:
			t.Fatal("socket request was not processed")
		}
		answered := false
		for _, call := range api.snapshot() {
			if call.method == "answerCallbackQuery" && call.form.Get("callback_query_id") == "startup-tap" {
				answered = true
			}
		}
		if !answered {
			t.Fatal("queued callback was not processed after startup")
		}
	})
}
