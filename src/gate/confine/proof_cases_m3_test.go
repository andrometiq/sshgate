package confine

import "github.com/karthikeyan5/sshgate/src/gate/confine/jailmut/harness"

// Cases migrated by lane M3.
func proofCasesM3() []harness.Case {
	var cases []harness.Case
	add := func(name, kind, mode string, obligations []string, markers ...string) *harness.Case {
		cases = append(cases, harness.Case{Name: name, Package: "./src/gate/confine", ABIs: []string{"native", "abi1"}, Kind: kind, Mode: mode, Obligations: obligations, Markers: markers})
		return &cases[len(cases)-1]
	}
	add("U-SpecRejectsUnknownProfile", "Unit", "", []string{"control:decision"})
	add("U-StatusProtocol", "Unit", "", []string{"control:decision"}, "EFFECT:status")
	for _, stage := range []string{"nsverify", "spec", "cmdread", "mounts", "nnp", "caps", "rlimits", "landlock", "seccomp", "tsync", "fds", "cwd", "selfcheck", "session", "exec"} {
		add("L-FAULT-"+stage, "Abort", SetupAbort, []string{"control:intact", "jailed:attempt"}, "EFFECT:reached-exec").Modes = []string{Execute}
	}
	add("L-INJECT-ERRNO", "Abort", SetupAbort, []string{"control:intact", "jailed:attempt"}, "EFFECT:reached-exec").Modes = []string{Execute}
	add("L-LL-REQUIRED", "Abort", SetupAbort, []string{"control:intact", "jailed:attempt"}, "ABORT:selfcheck").Modes = []string{Execute}
	for _, namespace := range []string{"user", "mnt", "pid", "ipc"} {
		add("L-NSVERIFY-"+namespace, "Abort", SetupAbort, []string{"control:intact", "jailed:attempt", "observe:mounts"}, "EFFECT:reached-exec").Modes = []string{Execute}
	}
	add("L-HOSTMOUNTS-UNCHANGED", "Abort", SetupAbort, []string{"jailed:attempt", "observe:mounts"}, "ABORT:private")
	add("L-SPEC-REJECT", "Abort", SetupAbort, []string{"control:intact", "jailed:attempt", "observe:target"}, "EFFECT:reached-exec").Modes = []string{Execute}
	for _, name := range []string{"L-ROOT-STATE", "L-ROOT-NPROC", "L-ROOT-PROC"} {
		c := add(name, "Execution", Execute, []string{"control:probe", "jailed:probe", "observe:probe"})
		c.Root = true
		c.Omissions = []string{"root-only"}
		if name == "L-ROOT-PROC" {
			c.Kind = "Effect"
			c.CIOnly = true
			c.Omissions = append(c.Omissions, "ci-only")
		}
	}
	add("L-SCRATCH-META", "Effect", Execute, []string{"control:probe", "jailed:probe", "observe:probe"}, "EFFECT:metadata")
	add("L-FILEATTR-ERRNO", "Execution", Execute, []string{"control:probe", "jailed:probe", "observe:probe"}, "EFFECT:fileattr-errno")
	add("L-NNP-LANDLOCK", "Abort", SetupAbort, []string{"control:intact", "jailed:attempt"}, "ABORT:landlock").Modes = []string{Execute}
	add("L-SELFCHECK-CREDS", "Execution", Execute, []string{"jailed:credentials"}, "ABORT:selfcheck", "EFFECT:credentials").Modes = []string{SetupAbort}
	c := add("L-SELFCHECK-LL", "Abort", SetupAbort, []string{"control:intact", "jailed:attempt"}, "EFFECT:reached-exec")
	c.Modes = []string{Execute}
	c.AcceptFactsABI0 = true
	add("L-SETUID", "Execution", Execute, []string{"control:mounts", "jailed:state"}, "EFFECT:nosuid-state")
	c = add("L-NSVERIFY", "Abort", SetupAbort, []string{"control:intact", "jailed:attempt", "observe:mounts"}, "ABORT:private")
	c.Package = "./src/gate"
	c.Modes = []string{Execute}
	c.Names = map[string]string{"native": "TestExecWithRedactionConfineNSVerify/native/L-NSVERIFY", "abi1": "TestExecWithRedactionConfineNSVerify/abi1/L-NSVERIFY"}
	add("L-FAULT-fds-ENOSYS", "Abort", SetupAbort, []string{"control:intact", "jailed:attempt"}, "EFFECT:reached-exec").Modes = []string{Execute}
	add("L-MOUNT-STAGES", "Abort", SetupAbort, []string{"control:intact", "jailed:attempt"}).Modes = []string{Execute}
	add("L-DEVICES", "Execution", Execute, []string{"control:devices", "jailed:devices"})
	add("L-TTY-NODEV", "Effect", Execute, []string{"control:tty", "jailed:tty", "observe:tty"})
	add("L-SCRATCH", "Effect", Execute, []string{"control:scratch", "jailed:scratch", "observe:scratch"})
	add("L-TMP-VISIBLE", "Execution", Execute, []string{"jailed:read"})
	add("L-PS-VISIBLE", "Execution", Execute, []string{"jailed:ps"})
	for _, name := range []string{"L-WRITE-ROOT", "L-WRITE-SUBMOUNT"} {
		add(name, "Effect", Execute, []string{"control:write", "jailed:write", "observe:write"}, "EFFECT:write", "EFFECT:truncate")
	}
	add("L-MQUEUE", "Effect", Execute, []string{"control:queue", "jailed:drain", "observe:queue"}, "EFFECT:queue-drained")
	add("L-MQUEUE-ERRNO", "Execution", Execute, []string{"jailed:errno"}, "EFFECT:mq-errno")
	add("L-WRITE-ERRNO", "Execution", Execute, []string{"jailed:errno"}, "EFFECT:errno")
	for _, name := range []string{"L-META-EROFS", "L-META-ROOT", "L-META-SUBMOUNT"} {
		add(name, "Effect", Execute, []string{"control:metadata", "jailed:metadata", "observe:metadata"}, "EFFECT:metadata-mode", "EFFECT:metadata-mtime", "EFFECT:metadata-flags", "EFFECT:metadata-xattr-set", "EFFECT:metadata-xattr-remove")
	}
	add("L-FIFO-WRITE", "Effect", Execute, []string{"control:fifo", "jailed:fifo", "observe:fifo"}, "EFFECT:delivered")
	return cases
}
