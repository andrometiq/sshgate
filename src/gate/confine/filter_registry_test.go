package confine

import (
	"testing"

	"golang.org/x/sys/unix"
)

import "github.com/karthikeyan5/sshgate/src/gate/confine/jailmut/harness"

func p15Unit(test, name string) harness.Leg {
	return harness.Leg{Name: name, Package: "./src/gate/confine", Names: map[string]string{"native": test + "/" + name, "abi1": test + "/" + name}, Markers: []string{"MUTATION-EFFECT decision"}}
}
func p15Leg(name string, markers ...string) harness.Leg {
	return harness.Leg{Name: name, Package: "./src/gate/confine", Names: map[string]string{"native": "TestJailMatrixP15/native/" + name, "abi1": "TestJailMatrixP15/abi1/" + name}, Markers: markers}
}
func p15Registry() []prot {
	var result []prot
	add := func(id string, legs ...harness.Leg) {
		result = append(result, prot{ID: id, Site: "seccomp / Landlock filters", Class: "direct", DirectLeg: legs[0].Name, MutationSets: []harness.MutationSet{{IDs: []string{id}, Legs: legs}}})
	}
	for _, row := range mutationSeccompRows {
		add("P-SC-"+row, p15Unit("TestSyscallRowDecisions", "U-SC-"+row))
	}
	for _, item := range []struct{ id, leg string }{
		{"P-SC-ARCH", "U-Architecture"}, {"P-SC-X32", "U-X32"}, {"P-SC-TOTAL", "U-UnknownSyscall"},
		{"P-SC-CLONE-MASK", "U-CloneMaskTable"}, {"P-SC-UNSHARE-MASK", "U-UnshareMaskTable"},
		{"P-SC-SOCK-FAM", "U-SocketTupleTable"}, {"P-SC-SOCK-TYPE", "U-SocketTupleTable"}, {"P-SC-NETLINK-PROTO", "U-SocketTupleTable"}, {"P-SC-INET-PROTO", "U-SocketTupleTable"}, {"P-SC-SOCKDIAG", "U-SocketTupleTable"}, {"P-SC-NET", "U-SocketTupleTable"}, {"P-SC-SOCKPAIR", "U-SocketpairTable"},
		{"P-SC-RLIMIT-CORE", "U-RlimitFilterTable"},
		{"P-SC-IOCTL-TIOCSTI", "U-IoctlBlocksLiteral"}, {"P-SC-IOCTL-TIOCLINUX", "U-IoctlBlocksLiteral"}, {"P-SC-IOCTL-FSCRYPT-ADD", "U-IoctlBlocksLiteral"}, {"P-SC-IOCTL-FSCRYPT-REMOVE", "U-IoctlBlocksLiteral"}, {"P-SC-IOCTL-FSCRYPT-REMOVE-ALL", "U-IoctlBlocksLiteral"},
		{"P-LL-RESOLVE-UNIX", "U-HandledByABI"}, {"P-LL-SCOPE-SIGNAL", "U-RulesetAttrScoped"}, {"P-LL-SCOPE-ABSTRACT", "U-RulesetAttrScoped"},
	} {
		add(item.id, p15Unit("TestFilterTables", item.leg))
	}
	add("P-SC-CEILING", p15Unit("TestFilterTables", "U-SyscallCeiling"))
	result[len(result)-1].Partners = []string{"P-SC-TOTAL"}
	result[len(result)-1].MutationSets[0].IDs = []string{"P-SC-CEILING", "P-SC-TOTAL"}

	add("P-CLONE-PID", p15Unit("TestFilterTables", "U-ClonePID"))
	pid := &result[len(result)-1]
	pid.Class = "multi"
	pid.Partners = []string{"P-NSVERIFY", "P-SHIM-PID1", "P-LL-SCOPE-SIGNAL"}
	user := p15Leg("L-SCHED-USER", "MUTATION-EFFECT retuned")
	user.CIOnly = true
	signal := p15Leg("L-SIGNAL")
	signal.ABIMarkers = map[string][]string{"abi1": {"MUTATION-EFFECT signal"}}
	if probeLandlockABI() < 6 {
		signal.Markers = []string{"MUTATION-EFFECT signal"}
	}
	pid.MutationSets = append(pid.MutationSets, harness.MutationSet{IDs: []string{"P-CLONE-PID", "P-NSVERIFY", "P-SHIM-PID1"}, Legs: []harness.Leg{p15Leg("L-SCHED", "MUTATION-EFFECT retuned"), user, signal}})
	add("P-CLONE-IPC", p15Unit("TestFilterTables", "U-CloneIPC"))
	ipc := &result[len(result)-1]
	ipc.Class = "multi"
	ipc.Partners = []string{"P-NSVERIFY"}
	ipc.MutationSets = append(ipc.MutationSets, harness.MutationSet{IDs: []string{"P-CLONE-IPC", "P-NSVERIFY"}, Legs: []harness.Leg{p15Leg("L-IPC-SYSV", "MUTATION-EFFECT removed")}})
	var core unix.Rlimit
	if err := unix.Getrlimit(unix.RLIMIT_CORE, &core); err != nil {
		panic(err)
	}
	for i := range result {
		p := &result[i]
		switch p.ID {
		case "P-SC-CLONE", "P-SC-CLONE-MASK":
			p.MutationSets[0].Legs = append(p.MutationSets[0].Legs, p15Leg("L-NS-CREATE", "MUTATION-EFFECT clone"))
		case "P-SC-UNSHARE", "P-SC-UNSHARE-MASK":
			p.MutationSets[0].Legs = append(p.MutationSets[0].Legs, p15Leg("L-NS-CREATE", "MUTATION-EFFECT unshare"))
		case "P-SC-SETNS":
			p.MutationSets[0].Legs = append(p.MutationSets[0].Legs, p15Leg("L-NS-CREATE"))
		case "P-SC-SOCK-TYPE", "P-SC-NETLINK-PROTO":
			leg := p15Leg("L-SOCK-SWEEP", "MUTATION-EFFECT tuple")
			leg.CIOnly = true
			p.MutationSets[0].Legs = append(p.MutationSets[0].Legs, leg)
		case "P-SC-INET-PROTO":
			leg := p15Leg("L-SOCK-SWEEP-GRANT", "MUTATION-EFFECT tuple")
			leg.CIOnly = true
			p.MutationSets[0].Legs = append(p.MutationSets[0].Legs, leg)
		case "P-SC-NET":
			p.MutationSets[0].Legs = append(p.MutationSets[0].Legs, p15Leg("L-INET-DENY", "MUTATION-EFFECT connected", "MUTATION-EFFECT errno"), p15Leg("L-INET-GRANT"))
		case "P-SC-SOCK-FAM":
			p.Class = "multi"
			p.Partners = []string{"P-LL-RESOLVE-UNIX", "P-LL-SCOPE-ABSTRACT"}
			path := p15Leg("L-UNIX-CONNECT")
			path.ABIMarkers = map[string][]string{"abi1": {"MUTATION-EFFECT connected"}}
			if probeLandlockABI() < 9 {
				path.Markers = []string{"MUTATION-EFFECT connected"}
			}
			abstract := p15Leg("L-UNIX-ABSTRACT")
			abstract.ABIMarkers = map[string][]string{"abi1": {"MUTATION-EFFECT connected"}}
			if probeLandlockABI() < 6 {
				abstract.Markers = []string{"MUTATION-EFFECT connected"}
			}
			p.MutationSets[0].Legs = append(p.MutationSets[0].Legs, path, abstract)
		case "P-SC-IOCTL-TIOCSTI", "P-SC-IOCTL-TIOCLINUX", "P-SC-IOCTL-FSCRYPT-ADD", "P-SC-IOCTL-FSCRYPT-REMOVE", "P-SC-IOCTL-FSCRYPT-REMOVE-ALL":
			p.MutationSets[0].Legs = append(p.MutationSets[0].Legs, p15Leg("L-IOCTL", "MUTATION-EFFECT errno"))
		case "P-SC-KEYCTL", "P-SC-ADD_KEY", "P-SC-REQUEST_KEY":
			p.Class = "single"
			p.MutationSets[0].Legs = append(p.MutationSets[0].Legs, p15Leg("L-KEYRING", "MUTATION-EFFECT keyring", "MUTATION-EFFECT errno"))
		case "P-SC-IO_URING_SETUP":
			p.Class = "multi"
			p.Partners = []string{"P-SC-IO_URING_ENTER", "P-SC-IO_URING_REGISTER"}
			p.MutationSets[0].Legs = append(p.MutationSets[0].Legs, p15Leg("L-IOURING"))
			p.MutationSets = append(p.MutationSets, harness.MutationSet{IDs: []string{"P-SC-IO_URING_SETUP", "P-SC-IO_URING_ENTER", "P-SC-IO_URING_REGISTER"}, Legs: []harness.Leg{p15Leg("L-IOURING", "MUTATION-EFFECT connected")}})
		case "P-SC-FCNTL":
			p.Class = "single"
			p.MutationSets[0].Legs = append(p.MutationSets[0].Legs, p15Unit("TestFilterTables", "U-FcntlCommandTable"), p15Leg("L-FCNTL-PIPESZ", "MUTATION-EFFECT pipe-size", "MUTATION-EFFECT errno"), p15Leg("L-FCNTL-RWHINT", "MUTATION-EFFECT hint", "MUTATION-EFFECT errno"))
		case "P-SC-FLOCK":
			p.Class = "single"
			p.MutationSets[0].Legs = append(p.MutationSets[0].Legs, p15Unit("TestFilterTables", "U-FlockOpTable"), p15Leg("L-FLOCK-EX", "MUTATION-EFFECT exclusive-lock", "MUTATION-EFFECT errno"))
		case "P-SC-RLIMIT-CORE":
			markers := []string{"MUTATION-EFFECT errno", "MUTATION-EFFECT shell", "MUTATION-EFFECT prlimit"}
			if core.Max > 0 {
				markers = append(markers, "MUTATION-EFFECT limit")
			}
			p.MutationSets[0].Legs = append(p.MutationSets[0].Legs, p15Leg("L-RLIMIT-CORE-LOCK", markers...))
			crash := p15Leg("L-CRASH-NO-HELPER", "MUTATION-EFFECT helper-record")
			crash.CIOnly = true
			p.MutationSets[0].Legs = append(p.MutationSets[0].Legs, crash)
		case "P-SC-SYNC":
			p.MutationSets[0].Legs = append(p.MutationSets[0].Legs, p15Leg("L-SC-SYNC-ERRNO", "MUTATION-EFFECT errno"))
		case "P-SC-SYNCFS":
			p.MutationSets[0].Legs = append(p.MutationSets[0].Legs, p15Leg("L-SC-SYNCFS-ERRNO", "MUTATION-EFFECT errno"))
		case "P-SC-LISTEN":
			p.MutationSets[0].Legs = append(p.MutationSets[0].Legs, p15Leg("L-LISTEN", "MUTATION-EFFECT errno"))
		case "P-SC-SOCKDIAG":
			leg := p15Leg("L-SOCKDIAG", "MUTATION-EFFECT errno")
			leg.CIOnly = true
			p.MutationSets[0].Legs = append(p.MutationSets[0].Legs, leg)
		case "P-SC-SOCKPAIR":
			p.Class = "multi"
			p.Partners = []string{"P-LL-RESOLVE-UNIX", "P-LL-SCOPE-ABSTRACT"}
			path := p15Leg("L-DGRAM-SEND")
			path.ABIMarkers = map[string][]string{"abi1": {"MUTATION-EFFECT delivered"}}
			if probeLandlockABI() < 9 {
				path.Markers = []string{"MUTATION-EFFECT delivered"}
			}
			abstract := p15Leg("L-DGRAM-ABSTRACT")
			abstract.ABIMarkers = map[string][]string{"abi1": {"MUTATION-EFFECT delivered"}}
			if probeLandlockABI() < 6 {
				abstract.Markers = []string{"MUTATION-EFFECT delivered"}
			}
			p.MutationSets[0].Legs = append(p.MutationSets[0].Legs, p15Leg("L-SOCKPAIR-SWEEP", "MUTATION-EFFECT errno"), path, abstract)
		case "P-LL-SCOPE-SIGNAL":
			p.Class = "multi"
			p.Partners = []string{"P-CLONE-PID", "P-NSVERIFY", "P-SHIM-PID1"}
			p.MutationSets[0].Legs = append(p.MutationSets[0].Legs, p15Leg("L-SIGNAL"))
			p.MutationSets = append(p.MutationSets, harness.MutationSet{IDs: []string{"P-LL-SCOPE-SIGNAL", "P-CLONE-PID", "P-NSVERIFY", "P-SHIM-PID1"}, Legs: []harness.Leg{p15Leg("L-SIGNAL", "MUTATION-EFFECT signal")}})
		case "P-LL-RESOLVE-UNIX":
			p.Class = "multi"
			p.Partners = []string{"P-SC-SOCKPAIR"}
			p.MutationSets[0].Legs = append(p.MutationSets[0].Legs, p15Leg("L-DGRAM-SEND"))
			p.MutationSets = append(p.MutationSets, harness.MutationSet{IDs: []string{"P-LL-RESOLVE-UNIX", "P-SC-SOCKPAIR"}, Legs: []harness.Leg{p15Unit("TestFilterTables", "U-HandledByABI"), p15Leg("L-DGRAM-SEND", "MUTATION-EFFECT delivered")}})
			p.MutationSets = append(p.MutationSets, harness.MutationSet{IDs: []string{"P-LL-RESOLVE-UNIX", "P-SC-SOCK-FAM"}, Legs: []harness.Leg{p15Leg("L-UNIX-CONNECT", "MUTATION-EFFECT connected")}})
		case "P-LL-SCOPE-ABSTRACT":
			p.Class = "multi"
			p.Partners = []string{"P-SC-SOCKPAIR"}
			p.MutationSets[0].Legs = append(p.MutationSets[0].Legs, p15Leg("L-DGRAM-ABSTRACT"))
			p.MutationSets = append(p.MutationSets, harness.MutationSet{IDs: []string{"P-LL-SCOPE-ABSTRACT", "P-SC-SOCKPAIR"}, Legs: []harness.Leg{p15Unit("TestFilterTables", "U-RulesetAttrScoped"), p15Leg("L-DGRAM-ABSTRACT", "MUTATION-EFFECT delivered")}})
			p.MutationSets = append(p.MutationSets, harness.MutationSet{IDs: []string{"P-LL-SCOPE-ABSTRACT", "P-SC-SOCK-FAM"}, Legs: []harness.Leg{p15Leg("L-UNIX-ABSTRACT", "MUTATION-EFFECT connected")}})
		}
	}
	return result
}

func TestRegistryCIOnlyControls(t *testing.T) {
	controls := map[string]bool{
		"L-SOCKDIAG":         false,
		"L-SOCK-SWEEP":       false,
		"L-SOCK-SWEEP-GRANT": false,
		"L-CRASH-NO-HELPER":  false,
	}
	for _, protection := range p15Registry() {
		for _, set := range protection.MutationSets {
			nonCI, _ := harness.Select(set, true, false)
			ci, omitted := harness.Select(set, true, true)
			if len(ci) != len(set.Legs) || len(omitted) != 0 {
				t.Errorf("%s: CI omitted registered legs", set.Name())
			}
			for _, leg := range set.Legs {
				if _, ok := controls[leg.Name]; !ok {
					continue
				}
				controls[leg.Name] = true
				if !leg.CIOnly {
					t.Errorf("%s: %s requires a CI-only control", set.Name(), leg.Name)
				}
				for _, selected := range nonCI {
					if selected.Name == leg.Name {
						t.Errorf("%s: non-CI selected %s", set.Name(), leg.Name)
					}
				}
			}
		}
	}
	for name, found := range controls {
		if !found {
			t.Errorf("CI-only control %s has no registered leg", name)
		}
	}
}
