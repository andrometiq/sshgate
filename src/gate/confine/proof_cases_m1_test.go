package confine

import "strings"

import "github.com/karthikeyan5/sshgate/src/gate/confine/jailmut/harness"

func proofCasesM1() []harness.Case {
	var cases []harness.Case
	for _, name := range []string{
		"U-CloneIPC",
		"U-FcntlCommandTable",
		"U-FlockOpTable",
		"U-RlimitFilterTable",
		"U-CloneMaskTable",
		"U-UnshareMaskTable",
		"U-SocketTupleTable",
		"U-SocketpairTable",
		"U-IoctlBlocksLiteral",
		"U-RulesetAttrScoped",
		"U-HandledByABI",
		"U-Architecture",
		"U-X32",
		"U-UnknownSyscall",
		"U-SyscallCeiling",
		"U-SC-MOUNT",
		"U-SC-UMOUNT2",
		"U-SC-PIVOT_ROOT",
		"U-SC-OPEN_TREE",
		"U-SC-MOVE_MOUNT",
		"U-SC-FSOPEN",
		"U-SC-FSMOUNT",
		"U-SC-FSPICK",
		"U-SC-MOUNT_SETATTR",
		"U-SC-FSCONFIG",
		"U-SC-OPEN_TREE_ATTR",
		"U-SC-PTRACE",
		"U-SC-PROCESS_VM_READV",
		"U-SC-PROCESS_VM_WRITEV",
		"U-SC-PIDFD_GETFD",
		"U-SC-BPF",
		"U-SC-PERF_EVENT_OPEN",
		"U-SC-USERFAULTFD",
		"U-SC-KEYCTL",
		"U-SC-ADD_KEY",
		"U-SC-REQUEST_KEY",
		"U-SC-IO_URING_SETUP",
		"U-SC-IO_URING_ENTER",
		"U-SC-IO_URING_REGISTER",
		"U-SC-KEXEC_LOAD",
		"U-SC-KEXEC_FILE_LOAD",
		"U-SC-INIT_MODULE",
		"U-SC-FINIT_MODULE",
		"U-SC-DELETE_MODULE",
		"U-SC-REBOOT",
		"U-SC-SWAPON",
		"U-SC-SWAPOFF",
		"U-SC-SETTIMEOFDAY",
		"U-SC-CLOCK_SETTIME",
		"U-SC-CLOCK_ADJTIME",
		"U-SC-ADJTIMEX",
		"U-SC-PERSONALITY",
		"U-SC-OPEN_BY_HANDLE_AT",
		"U-SC-SETNS",
		"U-SC-LISTEN",
		"U-SC-CHMOD",
		"U-SC-FCHMOD",
		"U-SC-FCHMODAT",
		"U-SC-FCHMODAT2",
		"U-SC-CHOWN",
		"U-SC-LCHOWN",
		"U-SC-FCHOWN",
		"U-SC-FCHOWNAT",
		"U-SC-SETXATTR",
		"U-SC-LSETXATTR",
		"U-SC-FSETXATTR",
		"U-SC-SETXATTRAT",
		"U-SC-REMOVEXATTR",
		"U-SC-LREMOVEXATTR",
		"U-SC-FREMOVEXATTR",
		"U-SC-REMOVEXATTRAT",
		"U-SC-UTIME",
		"U-SC-UTIMES",
		"U-SC-FUTIMESAT",
		"U-SC-UTIMENSAT",
		"U-SC-FILE_SETATTR",
		"U-SC-MQ_OPEN",
		"U-SC-MQ_UNLINK",
		"U-SC-MQ_TIMEDSEND",
		"U-SC-MQ_TIMEDRECEIVE",
		"U-SC-MQ_NOTIFY",
		"U-SC-MQ_GETSETATTR",
		"U-SC-SYNC",
		"U-SC-SYNCFS",
		"U-SC-CLONE3",
		"U-SC-USELIB",
		"U-SC-_SYSCTL",
		"U-SC-CREATE_MODULE",
		"U-SC-GET_KERNEL_SYMS",
		"U-SC-QUERY_MODULE",
		"U-SC-NFSSERVCTL",
		"U-SC-GETPMSG",
		"U-SC-PUTPMSG",
		"U-SC-AFS_SYSCALL",
		"U-SC-TUXCALL",
		"U-SC-SECURITY",
		"U-SC-LOOKUP_DCOOKIE",
		"U-SC-EPOLL_CTL_OLD",
		"U-SC-EPOLL_WAIT_OLD",
		"U-SC-VSERVER",
		"U-SC-CLONE",
		"U-SC-UNSHARE",
		"U-SC-SOCKET",
		"U-SC-SOCKETPAIR",
		"U-SC-IOCTL",
		"U-SC-FCNTL",
		"U-SC-FLOCK",
		"U-SC-SETRLIMIT",
		"U-SC-PRLIMIT64",
		"U-SC-PROCESS_MRELEASE",
		"U-SC-KILL",
		"U-SC-TKILL",
		"U-SC-TGKILL",
		"U-SC-RT_SIGQUEUEINFO",
		"U-SC-RT_TGSIGQUEUEINFO",
		"U-SC-PIDFD_SEND_SIGNAL",
		"U-SC-SETPRIORITY",
		"U-SC-IOPRIO_SET",
		"U-SC-SCHED_SETPARAM",
		"U-SC-SCHED_SETSCHEDULER",
		"U-SC-SCHED_SETAFFINITY",
		"U-SC-SCHED_SETATTR",
		"U-SC-MIGRATE_PAGES",
		"U-SC-MOVE_PAGES",
	} {
		cases = append(cases, harness.Case{Name: name, Package: "./src/gate/confine", ABIs: []string{"native", "abi1"}, Kind: "Unit", Obligations: []string{"control:decision"}, Markers: []string{"EFFECT:decision"}})
	}
	cases = append(cases,
		harness.Case{Name: "U-ZgrepControlFires", Package: "./src/gate/confine", ABIs: []string{"native", "abi1"}, Kind: "Unit", Obligations: []string{"control:effect"}},
		harness.Case{Name: "U-CatalogueRouting", Package: "./src/gate/confine", ABIs: []string{"native", "abi1"}, Kind: "Unit", Obligations: []string{"control:routing"}},
		harness.Case{Name: "L-SC-SWEEP", Package: "./src/gate/confine", ABIs: []string{"native", "abi1"}, Kind: "Execution", Mode: Execute, Obligations: []string{"control:distinction", "jailed:sweep"}},
	)
	for _, name := range []string{
		"L-CATALOGUE/sed_inplace_abbrev",
		"L-CATALOGUE/file_compile_bundle",
		"L-CATALOGUE/tree_bundled_output",
		"L-CATALOGUE/awk_include_directive",
		"L-CATALOGUE/zgrep_GREP_injection",
		"L-CATALOGUE/zdiff_DIFF_injection",
		"L-CATALOGUE/git_config_set",
		"L-CATALOGUE/git_branch_new",
		"L-CATALOGUE/git_remote_add",
		"L-CATALOGUE/git_diff_output",
		"L-CATALOGUE/git_show_output",
		"L-CATALOGUE/git_log_output",
		"L-CATALOGUE/git_grep_open_files_in_pager",
		"L-CATALOGUE/file_compile",
		"L-CATALOGUE/command_v_exec",
		"L-CATALOGUE/curl_bundled_output/deny",
		"L-CATALOGUE/curl_bundled_output/grant",
		"L-CATALOGUE/curl_remote_name/deny",
		"L-CATALOGUE/curl_remote_name/grant",
		"L-CATALOGUE/curl_dump_header/deny",
		"L-CATALOGUE/curl_dump_header/grant",
		"L-CATALOGUE/curl_cookie_jar/deny",
		"L-CATALOGUE/curl_cookie_jar/grant",
		"L-CATALOGUE/curl_json_post/deny",
		"L-CATALOGUE/curl_json_post/grant",
		"L-CATALOGUE/mount_inline_options",
		"L-CATALOGUE/mount_source_target",
		"L-CATALOGUE/sysctl_reload_bundle",
		"L-CATALOGUE/sysctl_system",
	} {
		c := harness.Case{Name: name, Package: "./src/gate/confine", ABIs: []string{"native", "abi1"}, Kind: "Effect", Mode: Execute, Obligations: []string{"control:effect", "jailed:command", "observe:effect"}, Omissions: []string{"tool-unavailable"}}
		switch {
		case strings.Contains(name, "/sysctl_"):
			c.Root, c.CIOnly = true, true
			c.Omissions = append(c.Omissions, "root-only", "ci-only")
		case strings.Contains(name, "/mount_"):
		default:
			c.Markers = []string{"EFFECT:file"}
			if strings.HasSuffix(name, "/deny") {
				c.Markers = append(c.Markers, "EFFECT:network")
			}
			c.Characterisation = append([]string(nil), c.Markers...)
			c.CharacterisationOutcome = "catalogue-containment-no-registered-mutation-set"
		}
		cases = append(cases, c)
	}
	cases = append(cases, harness.Case{Name: "L-SOCKDIAG-AUTOLOAD", Package: "./src/gate/confine", ABIs: []string{"native", "abi1"}, Kind: "Effect", Mode: Execute, Obligations: []string{"control:autoload", "jailed:probe", "observe:modules"}, Markers: []string{"EFFECT:module-loaded"}, Root: true, CIOnly: true, Omissions: []string{"root-only", "ci-only", "module-builtin"}})

	for _, item := range []struct {
		name, kind, mode string
		markers          []string
	}{
		{"L-FCNTL-PIPESZ", "Effect", Execute, []string{"EFFECT:pipe-size", "EFFECT:errno"}},
		{"L-FCNTL-RWHINT", "Effect", Execute, []string{"EFFECT:hint", "EFFECT:errno"}},
		{"L-FLOCK-EX", "Effect", Interactive, []string{"EFFECT:exclusive-lock", "EFFECT:errno"}},
		{"L-RLIMIT-CORE-LOCK", "Effect", Execute, []string{"EFFECT:errno", "EFFECT:limit", "EFFECT:shell", "EFFECT:prlimit"}},
		{"L-IPC-SYSV", "Effect", Execute, []string{"EFFECT:removed"}},
		{"L-SCHED", "Effect", Execute, []string{"EFFECT:retuned"}},
		{"L-IOURING", "Effect", Execute, []string{"EFFECT:connected"}},
		{"L-KEYRING", "Effect", Execute, []string{"EFFECT:keyring", "EFFECT:errno"}},
		{"L-DGRAM-SEND", "Effect", Execute, []string{"EFFECT:delivered"}},
		{"L-DGRAM-ABSTRACT", "Effect", Execute, []string{"EFFECT:delivered"}},
		{"L-UNIX-CONNECT", "Effect", Execute, []string{"EFFECT:connected"}},
		{"L-UNIX-ABSTRACT", "Effect", Execute, []string{"EFFECT:connected"}},
		{"L-SOCK-SWEEP", "Effect", Execute, []string{"EFFECT:tuple"}},
		{"L-SOCK-SWEEP-GRANT", "Effect", Execute, []string{"EFFECT:tuple"}},
		{"L-INET-DENY", "Effect", Execute, []string{"EFFECT:connected", "EFFECT:errno"}},
		{"L-INET-GRANT", "Effect", Execute, []string{}},
		{"L-META-ERRNO", "Effect", Execute, []string{"EFFECT:errno"}},
		{"L-SIGNAL", "Effect", Execute, []string{"EFFECT:signal"}},
		{"L-LISTEN", "Execution", Execute, []string{"EFFECT:errno"}},
		{"L-SOCKPAIR-SWEEP", "Execution", Execute, []string{"EFFECT:errno"}},
		{"L-NS-CREATE", "Execution", Execute, []string{"EFFECT:clone", "EFFECT:unshare"}},
		{"L-SS-FALLBACK", "Execution", Execute, []string{}},
		{"L-IOCTL", "Execution", Execute, []string{"EFFECT:errno"}},
		{"L-SC-SYNC-ERRNO", "Execution", Execute, []string{"EFFECT:errno"}},
		{"L-SC-SYNCFS-ERRNO", "Execution", Execute, []string{"EFFECT:errno"}},
		{"L-SOCKDIAG", "Execution", Execute, []string{"EFFECT:errno"}},
		{"L-SC-CEILING", "Execution", Execute, []string{}},
	} {
		c := harness.Case{Name: item.name, Package: "./src/gate/confine", ABIs: []string{"native", "abi1"}, Kind: item.kind, Mode: item.mode, Markers: item.markers, Obligations: []string{"control:fixture", "jailed:probe"}}
		if item.kind == "Effect" {
			c.Obligations = append(c.Obligations, "observe:effects")
		}
		if item.name == "L-SC-CEILING" {
			c.Obligations = []string{"jailed:probe"}
			c.Modes = []string{ExpectedSignal}
		}
		if item.name == "L-SIGNAL" || item.name == "L-SCHED" {
			c.Characterisation = append([]string(nil), c.Markers...)
			c.CharacterisationOutcome = "legacy-host-process-check-no-registered-mutation-set"
		}
		if item.name == "L-SOCK-SWEEP" || item.name == "L-SOCK-SWEEP-GRANT" {
			c.CIOnly = true
			c.Omissions = []string{"ci-only"}
		}
		cases = append(cases, c)
	}

	return cases
}
