package confine

import (
	"errors"
	"syscall"
	"testing"
)

func TestWorkerStatusRecords(t *testing.T) {
	const info = `I{"profile":"ro-v1","abi":1,"net":false,"lane2":false}` + "\n"
	for _, test := range []struct {
		name, tail string
		want       WorkerStatus
		invalid    bool
	}{
		{"missing", "X", WorkerStatus{Unavailable: "no W record"}, false},
		{"exit", "X\nW{\"exit\":139}\n", WorkerStatus{Known: true, Exited: true, Code: 139}, false},
		{"signal", "X\nW{\"signal\":11,\"core\":true}\n", WorkerStatus{Known: true, Signal: syscall.SIGSEGV, Core: true}, false},
		{"unavailable", "X\nW{\"unavailable\":\"cancelled\"}\n", WorkerStatus{Unavailable: "cancelled"}, false},
		{"cleanup", "X\nW{\"exit\":23}\n\nCdeadline\n", WorkerStatus{Known: true, Exited: true, Code: 23}, false},
		{"bare-newline", "X\n", WorkerStatus{}, true},
		{"extra-newline", "X\n\n", WorkerStatus{}, true},
		{"before-worker-blank", "X\n\nW{\"exit\":0}\n", WorkerStatus{}, true},
		{"after-worker-blank", "X\nW{\"exit\":0}\n\n", WorkerStatus{}, true},
		{"partial-worker", "X\nW{\"exit\":0}", WorkerStatus{}, true},
		{"extra-cleanup-blank", "X\nCdeadline\n\n", WorkerStatus{}, true},
		{"legacy-cleanup", "X\nCdeadline", WorkerStatus{Unavailable: "no W record"}, false},
		{"missing-separator", "X\nW{\"exit\":0}\nCdeadline\n", WorkerStatus{}, true},
		{"duplicate", "X\nW{\"exit\":0}\nW{\"exit\":1}\n", WorkerStatus{}, true},
		{"before-exec", "W{\"exit\":0}\nX", WorkerStatus{}, true},
		{"late", "X\nCdeadline\nW{\"exit\":0}\n", WorkerStatus{}, true},
	} {
		t.Run(test.name, func(t *testing.T) {
			jailed, writer := startStatusFixture(t)
			if _, err := writer.WriteString(info + test.tail); err != nil {
				t.Fatal(err)
			}
			writer.Close()
			_, err := jailed.Status()
			if (err != nil) != test.invalid {
				t.Fatalf("status: %v", err)
			}
			if !test.invalid && jailed.WorkerStatus() != test.want {
				t.Fatalf("worker: %+v want %+v", jailed.WorkerStatus(), test.want)
			}
		})
	}
}

func TestWorkerStatusMalformed(t *testing.T) {
	for _, raw := range []string{
		`{}`, `null`, `[]`, `{"exit":null}`, `{"exit":-1}`, `{"exit":256}`, `{"exit":1.5}`, `{"exit":"1"}`,
		`{"exit":0,"exit":1}`, `{"exit":0,"signal":11}`, `{"signal":11}`, `{"signal":0,"core":false}`,
		`{"signal":65,"core":false}`, `{"signal":11,"core":null}`, `{"signal":11,"core":0}`, `{"signal":11,"core":false,"extra":0}`,
		`{"unavailable":""}`, `{"unavailable":"\n"}`, `{"unavailable":true}`, `{"exit":0} {}`, `{"other":1}`,
	} {
		if got, err := parseWorkerStatus(raw); err == nil {
			t.Errorf("accepted %s: %+v", raw, got)
		}
	}
}

func TestWorkerStatusPreservesSetupFailure(t *testing.T) {
	for _, report := range []string{"Flandlock:38\n\nW{\"exit\":70}\n", `I{"profile":"ro-v1","abi":1,"net":false,"lane2":false}` + "\nXFexec:2\n\nW{\"exit\":70}\n"} {
		jailed, writer := startStatusFixture(t)
		writer.WriteString(report)
		writer.Close()
		_, err := jailed.Status()
		var setup *SetupError
		if !errors.As(err, &setup) || setup.Errno == 0 {
			t.Fatalf("lost setup failure: %v", err)
		}
		if status := jailed.WorkerStatus(); !status.Known || !status.Exited || status.Code != ExitSetupFailed {
			t.Fatalf("lost worker setup exit: %+v", status)
		}
	}
}
