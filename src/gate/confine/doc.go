// Package confine builds the kernel jail that is SSHGate's Tier-1 wall for
// unsigned reads (#22). An unsigned command is run inside a user+mount+pid
// namespace with a read-only, locked view of /, all capabilities dropped, a
// Landlock ruleset and a seccomp filter — so a command the classifier merely
// *thinks* is a read cannot change any file, reach a local daemon over a unix
// socket, or signal other processes. The jail, not the classifier, is what
// makes "this host is read-only" true.
//
// # The rung ladder
//
// Detect probes the host and picks the strongest enforcement tier it supports:
//
//   - Rung1Full:     userns + mount + pid namespaces, read-only /, Landlock,
//     seccomp. The full wall.
//   - Rung2Landlock: no namespaces (userns unavailable), Landlock + seccomp +
//     NNP as the fs/syscall wall, writes only to a scratch dir.
//   - Rung3Unconfined: neither available; no kernel wall (labelled UNCONFINED).
//     confine never runs a command here — the gate passes a nil
//     *Spec and keeps today's /bin/sh path.
//
// # The re-exec model
//
// Go cannot safely unshare(CLONE_NEWUSER) from the already-multithreaded gate
// runtime, so the namespaces are established at clone time by re-execing
// /proc/self/exe with a sentinel argv and SysProcAttr clone flags, bubblewrap
// style. Two sentinels run before any SSH_ORIGINAL_COMMAND handling:
//
//   - __jail     -> RunShim:   pid 1 of the new pid namespace, a tiny reaper
//     that forks the worker (rung 1 only).
//   - __jailexec -> RunWorker: mounts (rung 1), then NNP, capability drop,
//     rlimits, Landlock and seccomp on a single locked
//     OS thread, then execve of /bin/sh -c <cmd>.
//
// Both sentinels only ever ADD restrictions, so a local caller invoking them
// directly gains nothing, and over SSH the forced command passes no argv (the
// client's command arrives in $SSH_ORIGINAL_COMMAND), so the agent can never
// reach them. The command string and a setup-status report travel on two
// private inherited pipes (fd 3 and fd 4), never on argv.
//
// # Fail closed
//
// If any setup step fails, or the rung cannot be determined, the command does
// not run — not jailed, and never "retried unconfined". RunWorker aborts before
// execve on any error; Jailed.Status turns that into a *SetupError the gate maps
// to a deny.
package confine
