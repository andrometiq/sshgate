package main

import (
	"errors"
	"os"
	"strings"
	"testing"
)

func TestVerdictJoinsProducerFailure(t *testing.T) {
	log, err := os.CreateTemp(t.TempDir(), "log")
	if err != nil {
		t.Fatal(err)
	}
	defer log.Close()
	f := &fixture{log: log, failures: make(chan error, 1)}
	release := make(chan struct{})
	f.workers.Add(1)
	go func() { defer f.workers.Done(); <-release; f.fail(errors.New("late producer failure")) }()
	done := make(chan error, 1)
	go func() { done <- f.close() }()
	close(release)
	if err := <-done; err == nil {
		t.Fatal("producer failure lost")
	}
	data, err := os.ReadFile(log.Name())
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "VERDICT fail late producer failure\n" {
		t.Fatalf("verdict %q", data)
	}
}

func TestVerdictCleanAndFailureLatch(t *testing.T) {
	for _, failed := range []bool{false, true} {
		log, err := os.CreateTemp(t.TempDir(), "log")
		if err != nil {
			t.Fatal(err)
		}
		f := &fixture{log: log, failures: make(chan error, 1)}
		if failed {
			f.fail(errors.New("first"))
			f.fail(errors.New("second"))
			<-f.failures
		}
		err = f.close()
		if (err != nil) != failed {
			t.Fatalf("close: %v", err)
		}
		data, readErr := os.ReadFile(log.Name())
		if readErr != nil {
			t.Fatal(readErr)
		}
		if !failed && string(data) != "VERDICT ok\n" {
			t.Fatalf("verdict %q", data)
		}
		if failed && (!strings.Contains(string(data), "first") || !strings.Contains(string(data), "second")) {
			t.Fatalf("lost error: %s", data)
		}
		log.Close()
	}
}

func TestVerdictIncludesTeardownFailure(t *testing.T) {
	log, err := os.CreateTemp(t.TempDir(), "log")
	if err != nil {
		t.Fatal(err)
	}
	defer log.Close()
	device, err := os.CreateTemp(t.TempDir(), "device")
	if err != nil {
		t.Fatal(err)
	}
	if err = device.Close(); err != nil {
		t.Fatal(err)
	}
	f := &fixture{log: log, devices: []*os.File{device}, failures: make(chan error, 1)}
	if err = f.close(); err == nil {
		t.Fatal("close failure discarded")
	}
	data, err := os.ReadFile(log.Name())
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(string(data), "VERDICT fail ") || !strings.Contains(string(data), "close FUSE device") {
		t.Fatalf("lost teardown verdict: %s", data)
	}
}

func TestOwnedMountFollowsRename(t *testing.T) {
	point, err := mountPointFromInfo("42 1 0:1 / /new\\040name rw - fuse sgtest rw\n", 42)
	if err != nil || point != "/new name" {
		t.Fatalf("mount point %q: %v", point, err)
	}
	if _, err = mountPointFromInfo("42 1 0:1 / /new rw - fuse sgtest rw\n", 43); err == nil {
		t.Fatal("missing owned mount accepted")
	}
}
