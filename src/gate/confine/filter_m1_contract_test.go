//go:build linux && jail_e2e

package confine

import (
	"errors"
	"fmt"
	"golang.org/x/sys/unix"
	"os"
	"os/exec"
	"strings"
	"testing"
)

func TestM1UringCompletionContract(t *testing.T) {
	complete := "io_uring_setup=ok\neventfd=ok\nio_uring_register=ok\nsq-map=ok\ncq-map=ok\nsqes-map=ok\nuring-socket-enter=ok\nuring-socket=ok\nuring-connect-enter=ok\nuring-connect=ok\nuring-setxattr-enter=ok\nuring-setxattr=30\n"
	for _, test := range []struct {
		name, output string
		exit         int
		valid        bool
	}{
		{"setup-denied", "io_uring_setup=1\n", 1, true},
		{"register-denied", "io_uring_setup=ok\neventfd=ok\nio_uring_register=1\n", 3, true},
		{"socket-submit-denied", "io_uring_setup=ok\neventfd=ok\nio_uring_register=ok\nsq-map=ok\ncq-map=ok\nsqes-map=ok\nuring-socket-enter=1\n", 3, true},
		{"complete", complete, 3, true},
		{"missing-xattr", strings.ReplaceAll(complete, "uring-setxattr=30\n", ""), 3, false},
		{"interrupted-xattr", strings.ReplaceAll(complete, "uring-setxattr-enter=ok\nuring-setxattr=30\n", "uring-setxattr-enter=4\n"), 3, false},
		{"wrong-xattr-errno", strings.ReplaceAll(complete, "uring-setxattr=30", "uring-setxattr=22"), 3, false},
		{"unproved-legacy-complete", "io_uring_setup=1\nuring-complete=ok\n", 1, false},
		{"unexpected-extra", complete + "garbage=ok\n", 3, false},
		{"wrong-exit", complete, 0, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			err := validateM1Uring(jailResult{stdout: test.output, exit: test.exit})
			if (err == nil) != test.valid {
				t.Fatalf("valid=%t want %t: %v", err == nil, test.valid, err)
			}
		})
	}
}
func TestM1FlockCompletionContract(t *testing.T) {
	for _, test := range []struct {
		output, stderr string
		exit           int
		valid          bool
	}{
		{"open=ok\nflock=1\nREADY\nrelease=ok\n", "", 3, true},
		{"open=ok\nflock=ok\nREADY\nrelease=ok\n", "", 0, true},
		{"open=ok\nflock=ok\nREADY\n", "", 0, false},
		{"open=ok\nflock=ok\nREADY\nrelease=ok\n", "", 139, false},
		{"open=ok\nflock=ok\nREADY\nrelease=ok\n", "crashed\n", 0, false},
	} {
		if err := validateM1Flock(test.output, test.stderr, test.exit); (err == nil) != test.valid {
			t.Fatalf("report=%q: %v", test.output, err)
		}
	}
}
func TestM1RecipientBarrier(t *testing.T) {
	for _, send := range []bool{false, true} {
		t.Run(fmt.Sprint(send), func(t *testing.T) {
			holder := startM1SignalRecipient(t)
			if send {
				if err := exec.Command("kill", "-USR1", fmt.Sprint(holder.command.Process.Pid)).Run(); err != nil {
					t.Fatal(err)
				}
			}
			observer := &m1RecipientObserver{holder: holder, t: t}
			observer.Start(t)
			mark := observer.Mark()
			if observer.Since(mark).Conclusive {
				t.Fatal("unsealed recipient was conclusive")
			}
			if err := observer.Seal(ProducerSync{Complete: true, Kind: "framed-op-ended"}); err != nil {
				t.Fatal(err)
			}
			want := "signal=0"
			if send {
				want = "signal=1"
			}
			got := observer.Since(mark)
			if !got.Sealed || !got.Conclusive || len(got.Records) != 1 || got.Records[0] != want {
				t.Fatalf("recipient: %+v", got)
			}
			if err := observer.Stop(); err != nil {
				t.Fatal(err)
			}
		})
	}
}
func TestM1FilterRejectsExtraReport(t *testing.T) {
	result := jailResult{stdout: "socket=ok\nextra=ok\n"}
	if err := validateM1Filter("probe socket-tuple 1 1 0", result); err == nil {
		t.Fatal("accepted undeclared syscall report")
	}
}

func TestM1ListenRequiresAttempt(t *testing.T) {
	for _, test := range []struct {
		output string
		exit   int
		valid  bool
	}{
		{"socket=1\n", 1, false}, {"socket=ok\nlisten=1\n", 3, true}, {"socket=ok\nlisten=ok\n", 0, true}, {"socket=ok\nlisten=22\n", 3, false},
	} {
		if err := validateM1Filter("probe listen unused", jailResult{stdout: test.output, exit: test.exit}); (err == nil) != test.valid {
			t.Fatalf("report %q: %v", test.output, err)
		}
	}
}

func TestM1ShmObserverRejectsErrors(t *testing.T) {
	for _, test := range []struct {
		err           error
		exists, valid bool
	}{{nil, true, true}, {unix.EINVAL, false, true}, {unix.EIDRM, false, true}, {unix.EACCES, false, false}, {unix.EPERM, false, false}, {unix.ENOSYS, false, false}} {
		exists, err := m1ShmPresence(test.err)
		if exists != test.exists || (err == nil) != test.valid {
			t.Fatalf("errno %v: exists=%t err=%v", test.err, exists, err)
		}
	}
}

func TestM1ConnectionObservation(t *testing.T) {
	for _, item := range []struct {
		err              error
		connected, valid bool
	}{
		{nil, true, true}, {os.ErrDeadlineExceeded, false, true}, {os.ErrDeadlineExceeded, true, false}, {nil, false, false}, {errors.New("observer failed"), false, false},
	} {
		if err := validateM1Accept(item.err, item.connected); (err == nil) != item.valid {
			t.Fatalf("%+v: %v", item, err)
		}
	}
}
func TestM1SSFallbackReport(t *testing.T) {
	result := jailResult{stdout: "LISTEN 0 128 127.0.0.1:1234 0.0.0.0:*\n", stderr: "Cannot open netlink socket: Operation not permitted\n"}
	if err := validateM1Filter("ss -H -ltn 'sport = :1234'", result); err != nil {
		t.Fatal(err)
	}
	result.stderr += "observer failed\n"
	if err := validateM1Filter("ss -H -ltn 'sport = :1234'", result); err == nil {
		t.Fatal("accepted unrelated ss diagnostic")
	}
}
