package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestTargetFailureSurvivesSuccessfulSentinel(t *testing.T) {
	directory := t.TempDir()
	if err := os.WriteFile(filepath.Join(directory, "failed"), make([]byte, 4096), 0600); err != nil {
		t.Fatal(err)
	}
	// A target-specific record-open failure must remain visible after recovery.
	if err := collect(directory, 42, 11, bytes.NewBufferString("core")); err == nil {
		t.Fatal("missing journal accepted")
	}
	if err := os.WriteFile(filepath.Join(directory, "records"), nil, 0600); err != nil {
		t.Fatal(err)
	}
	if err := collect(directory, 43, 11, bytes.NewBufferString("core")); err != nil {
		t.Fatal(err)
	}
	latch, err := os.ReadFile(filepath.Join(directory, "failed"))
	if err != nil || len(latch) != 4096 || latch[0] != 1 {
		t.Fatalf("failure latch: %v %v", latch, err)
	}
	if _, err := os.Stat(filepath.Join(directory, "inflight-42")); err != nil {
		t.Fatalf("target failure lost: %v", err)
	}
	if _, err := os.Stat(filepath.Join(directory, "inflight-43")); !os.IsNotExist(err) {
		t.Fatalf("sentinel not finalized: %v", err)
	}
	data, err := os.ReadFile(filepath.Join(directory, "records"))
	if err != nil {
		t.Fatal(err)
	}
	var item record
	if err = json.Unmarshal(data, &item); err != nil {
		t.Fatal(err)
	}
	if item.PID != 43 || item.Signal != 11 || item.Bytes != 4 || item.Error != "" {
		t.Fatalf("bad sentinel: %+v", item)
	}
}
func TestEmptyCoreLatchesFailure(t *testing.T) {
	directory := t.TempDir()
	if err := os.WriteFile(filepath.Join(directory, "failed"), make([]byte, 4096), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(directory, "records"), nil, 0600); err != nil {
		t.Fatal(err)
	}
	if err := collect(directory, 42, 11, bytes.NewReader(nil)); err == nil {
		t.Fatal("empty core accepted")
	}
	data, err := os.ReadFile(filepath.Join(directory, "records"))
	if err != nil {
		t.Fatal(err)
	}
	var item record
	if err = json.Unmarshal(data, &item); err != nil {
		t.Fatal(err)
	}
	if item.Error != "empty core" {
		t.Fatalf("failure not recorded: %+v", item)
	}
}
