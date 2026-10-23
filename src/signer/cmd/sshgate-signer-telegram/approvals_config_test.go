package main

import (
	"github.com/karthikeyan5/sshgate/pkg/signerkit/assist"
	"strings"
	"testing"
	"time"
)

func TestApprovalsConfigDurations(t *testing.T) {
	cfg, err := loadConfig(writeTOML(t, validConfig))
	if err != nil {
		t.Fatal(err)
	}
	d, err := cfg.Approvals.durations()
	if err != nil || d.pending != 24*time.Hour || d.retention != 168*time.Hour || d.report != 24*time.Hour || cfg.Approvals.JournalRoot != "/x/approvals" {
		t.Fatalf("defaults: %+v %+v %v", cfg.Approvals, d, err)
	}
	for _, key := range []string{"pending_validity", "retention", "report_horizon"} {
		for _, value := range []string{`""`, `"0"`, `"-1h"`, `"1m"`, `"169h"`, `"7d"`, `"nonsense"`, `24`} {
			t.Run(key+"/"+value, func(t *testing.T) {
				_, err := loadConfig(writeTOML(t, validConfig+"\n[approvals]\n"+key+" = "+value+"\n"))
				if err == nil || !strings.Contains(err.Error(), key) {
					t.Fatalf("expected key-specific refusal, got %v", err)
				}
			})
		}
		low := "1h"
		if key == "pending_validity" {
			low = "5m"
		}
		for _, value := range []string{low, "168h"} {
			t.Run(key+"/valid/"+value, func(t *testing.T) {
				cfg, err := loadConfig(writeTOML(t, validConfig+"\n[approvals]\n"+key+" = \""+value+"\"\n"))
				if err != nil {
					t.Fatal(err)
				}
				d, err := cfg.Approvals.durations()
				want, _ := time.ParseDuration(value)
				got := map[string]time.Duration{"pending_validity": d.pending, "retention": d.retention, "report_horizon": d.report}[key]
				if err != nil || got != want {
					t.Fatalf("got %v %v want %v", got, err, want)
				}
			})
		}
	}
}

func TestApprovalsConfigUIDs(t *testing.T) {
	for _, value := range []string{`[-1]`, `[1.5]`, `["12"]`, `[4294967296]`, `12`} {
		t.Run(value, func(t *testing.T) {
			_, err := loadConfig(writeTOML(t, validConfig+"\n[approvals]\nallowed_uids = "+value+"\n"))
			if err == nil || !strings.Contains(err.Error(), "allowed_uids") {
				t.Fatalf("got %v", err)
			}
		})
	}
	cfg, err := loadConfig(writeTOML(t, validConfig+"\n[approvals]\nallowed_uids = [0, 42, 4294967295]\njournal_root = \"/custom/approvals\"\n"))
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.Approvals.AllowedUIDs) != 3 || cfg.Approvals.AllowedUIDs[2] != ^uint32(0) || cfg.Approvals.JournalRoot != "/custom/approvals" {
		t.Fatalf("%+v", cfg.Approvals)
	}
}

func TestApprovalExplainerProviderAndWarning(t *testing.T) {
	key := writeKeyFile(t, "test-key")
	stderr, restore := captureStderr(t)
	defer restore()
	provider, err := buildExplainer(explainerConfig{Enabled: true, Endpoint: "https://provider.example/v1/chat/completions", Model: "test-model", APIKeyPath: key, TimeoutSec: 6})
	if err != nil {
		t.Fatal(err)
	}
	openAI, ok := provider.(*assist.OpenAI)
	if !ok || openAI.APIKeyFile != key || openAI.Model != "test-model" || openAI.Endpoint != "https://provider.example/v1/chat/completions" {
		t.Fatalf("provider %#v", provider)
	}
	if !waitForLog(stderr, "WARN backend.telegram.explainer.timeout_sec exceeds 5", time.Second) {
		t.Fatalf("missing timeout warning: %s", stderr.String())
	}
	for _, c := range []explainerConfig{
		{Endpoint: "bad-endpoint", Model: "test", APIKeyPath: key},
		{Endpoint: "https://provider.example", Model: "bad model", APIKeyPath: key},
	} {
		if _, err := buildExplainer(c); err == nil {
			t.Fatalf("invalid provider accepted: %+v", c)
		}
	}
}
