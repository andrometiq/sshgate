package confine

import (
	"fmt"
	"slices"
	"strconv"
	"strings"
	"testing"
)

type m1ModuleObserver struct {
	read            func() ([]string, error)
	restore         func() error
	before, records []string
	mark            ObserverMark
	sealed          bool
	err             error
}

func parseM1Modules(data []byte) ([]string, error) {
	var names []string
	for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
		if line == "" {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 6 || fields[4] != "Live" {
			return nil, fmt.Errorf("incomplete or unsettled module record %q", line)
		}
		for _, field := range fields[1:3] {
			if _, err := strconv.ParseUint(field, 10, 64); err != nil {
				return nil, fmt.Errorf("invalid module record %q", line)
			}
		}
		if slices.Contains(names, fields[0]) {
			return nil, fmt.Errorf("duplicate module %s", fields[0])
		}
		names = append(names, fields[0])
	}
	slices.Sort(names)
	return names, nil
}

func (o *m1ModuleObserver) snapshot() []string {
	names, err := o.read()
	if err != nil && o.err == nil {
		o.err = err
	}
	return names
}
func (o *m1ModuleObserver) Start(t *testing.T) {
	t.Helper()
	o.snapshot()
	if o.err != nil {
		t.Fatalf("SETUP: module observer: %v", o.err)
	}
}
func (o *m1ModuleObserver) Mark() ObserverMark {
	o.mark++
	o.sealed = false
	o.records = nil
	o.before = slices.Clone(o.snapshot())
	return o.mark
}
func (o *m1ModuleObserver) Seal(sync ProducerSync) error {
	if !sync.Complete || sync.Kind != "framed-op-ended" || o.mark == 0 {
		return fmt.Errorf("module producer has not completed")
	}
	after := o.snapshot()
	if o.err != nil {
		return o.err
	}
	for _, name := range after {
		if !slices.Contains(o.before, name) {
			o.records = append(o.records, "+"+name)
		}
	}
	for _, name := range o.before {
		if !slices.Contains(after, name) {
			o.records = append(o.records, "-"+name)
		}
	}
	o.sealed = true
	return nil
}
func (o *m1ModuleObserver) Since(mark ObserverMark) ObservationRecords {
	if o.mark == 0 || mark != 0 && mark != o.mark {
		return ObservationRecords{Err: fmt.Errorf("invalid module observation mark")}
	}
	return ObservationRecords{Records: slices.Clone(o.records), Sealed: o.sealed, Conclusive: o.sealed && o.err == nil, Err: o.err}
}
func (o *m1ModuleObserver) Healthy() error { o.snapshot(); return o.err }
func (o *m1ModuleObserver) Stop() error {
	if err := o.restore(); err != nil && o.err == nil {
		o.err = err
	}
	return o.err
}

func TestM1ModuleObserver(t *testing.T) {
	names := []string{"tcp_diag"}
	o := &m1ModuleObserver{read: func() ([]string, error) { return names, nil }, restore: func() error { return nil }}
	o.Start(t)
	mark := o.Mark()
	if got := o.Since(mark); got.Sealed || got.Conclusive {
		t.Fatal("unsealed modules accepted")
	}
	if err := o.Seal(ProducerSync{}); err == nil {
		t.Fatal("missing completion accepted")
	}
	names = append(names, "raw_diag")
	if err := o.Seal(ProducerSync{Complete: true, Kind: "framed-op-ended"}); err != nil {
		t.Fatal(err)
	}
	names = nil // Later control/restoration must not alter the judged window.
	got := o.Since(mark)
	if all := o.Since(0); !all.Sealed || !all.Conclusive || all.Err != nil {
		t.Fatalf("proof finalizer snapshot invalid: %+v", all)
	}
	if !got.Conclusive || !got.Sealed || !slices.Equal(got.Records, []string{"+raw_diag"}) {
		t.Fatalf("lost effect: %+v", got)
	}
	o.Mark()
	if got := o.Since(mark); got.Conclusive || got.Err == nil {
		t.Fatal("stale mark accepted")
	}
	o.read = func() ([]string, error) { return nil, fmt.Errorf("read failed") }
	if o.Healthy() == nil {
		t.Fatal("read error hidden")
	}
	o.read = func() ([]string, error) { return nil, nil }
	if o.Stop() == nil {
		t.Fatal("latched read error forgotten")
	}
}

func TestM1ModuleRecords(t *testing.T) {
	for _, bad := range []string{"raw_diag", "raw_diag bad 0 - Live 0", "raw_diag 1 0 - Loading 0", "raw_diag 1 0 - Live 0\nraw_diag 1 0 - Live 0"} {
		if _, err := parseM1Modules([]byte(bad)); err == nil {
			t.Fatalf("accepted %q", bad)
		}
	}
	if names, err := parseM1Modules([]byte("raw_diag 16384 0 - Live 0x00000000\n")); err != nil || !slices.Equal(names, []string{"raw_diag"}) {
		t.Fatalf("names=%v error=%v", names, err)
	}
}

func validateM1DiagSS(stdout, stderr string, exit int) error {
	if exit != 0 || !strings.HasSuffix(stdout, "\n") {
		return fmt.Errorf("ss incomplete: exit %d stdout %q", exit, stdout)
	}
	lines := strings.Split(strings.TrimSuffix(stdout, "\n"), "\n")
	if len(lines) == 0 || !strings.HasPrefix(lines[0], "Netid") || !strings.Contains(lines[0], "State") || !strings.Contains(lines[0], "Peer Address:Port") {
		return fmt.Errorf("ss missing table header: %q", stdout)
	}
	for _, line := range lines[1:] {
		fields := strings.Fields(line)
		// iproute2 names a raw IPPROTO_ICMPV6 socket "icmp6" (systemd-networkd holds one).
		if len(fields) < 6 || !slices.Contains([]string{"tcp", "udp", "u_str", "u_dgr", "u_seq", "raw", "icmp6"}, fields[0]) {
			return fmt.Errorf("unexpected ss record %q", line)
		}
	}
	if stderr != "" {
		for _, line := range strings.Split(strings.TrimSuffix(stderr, "\n"), "\n") {
			if line != "Cannot open netlink socket: Operation not permitted" {
				return fmt.Errorf("unexpected ss diagnostic %q", line)
			}
		}
	}
	return nil
}

func TestM1DiagSS(t *testing.T) {
	const header = "Netid State  Recv-Q Send-Q Local Address:Port Peer Address:Port\n"
	const icmp6 = "icmp6 UNCONN 0      0      *%ens3:ipv6-icmp   *:*              \n"
	const denied = "Cannot open netlink socket: Operation not permitted\n"
	for _, item := range []struct {
		stdout, stderr string
		exit           int
		valid          bool
	}{
		{header, "", 0, true},
		{header + "tcp LISTEN 0 4096 127.0.0.1:631 0.0.0.0:*\n", "", 0, true},
		{header + "raw UNCONN 0 0 *:255 *:*\n", denied, 0, true},
		{header + icmp6, "", 0, true},
		{header + "icmp UNCONN 0 0 *:icmp *:*\n", "", 0, false},
		{header + "??? UNCONN 0 0 *:132 *:*\n", "", 0, false},
		{header + "icmp6 UNCONN 0 0 *:ipv6-icmp\n", "", 0, false},
		{header + icmp6, "", 1, false},
		{header + icmp6, "Cannot open netlink socket: Protocol not supported\n", 0, false},
		{icmp6, "", 0, false},
		{header + icmp6[:len(icmp6)-1], "", 0, false},
	} {
		if err := validateM1DiagSS(item.stdout, item.stderr, item.exit); (err == nil) != item.valid {
			t.Errorf("%+v: %v", item, err)
		}
	}
}
