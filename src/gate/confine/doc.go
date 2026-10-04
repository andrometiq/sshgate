// Package confine builds SSHGate's ro-v1 kernel jail. Every confined command
// requires fresh user, mount and IPC namespaces with the host PID namespace, read-only mounts, Landlock,
// no_new_privs, capability reduction and seccomp. Detect currently selects
// either the full jail or classifier-only execution; a failed setup never retries.
//
// The mount view preserves host /proc and read-only /tmp and /var/tmp. Only
// private /dev/shm and /dev/null are writable. Unsafe filesystems are covered. Metadata syscalls and generic fileattr setters are denied even
// on scratch. Root SSH retains DAC_READ_SEARCH for file reads. Network access is
// controlled by Spec.Net: only route netlink and optionally TCP/UDP/ping sockets
// are admitted; plain-jail Unix sockets and listen are denied. The total amd64
// syscall table returns ENOSYS for unlisted numbers. Argument allowlists govern
// clone/unshare, socketpair, fcntl, flock and resource limits; ioctl has named
// blocks. Landlock additionally scopes signals and abstract Unix sockets at ABI 6
// and handles pathname Unix resolution at ABI 9. The label remains disabled.
//
// The parent re-execs /proc/self/exe as __jail with namespace clone flags. Its
// subreaper shim starts __jailexec, which verifies namespaces, builds the mount view,
// applies restrictions on a locked OS thread and execs /bin/sh. The command and
// setup report use private pipes on fd 3 and fd 4; no command travels on argv.
// A verified fresh session isolates own-group signals and retunes. Before ABI 6,
// seccomp permits kill only for pid zero or signal zero and denies directed
// signal calls; at ABI 6 Landlock scopes their recipients. Every ABI denies
// process_mrelease, nonzero async owners and retuning explicit PIDs or USERs.
// Fidelity costs are RETUNE-SELF-ONLY, ASYNC-OWNER-ZERO and (below ABI 6)
// SIGNAL-OWN-GROUP, including thread signals, Go asynchronous preemption and
// Go/glibc all-thread credential coordination. Explicit-tid affinity is retuning.
// The shim and gate each own reaping at their level. They enumerate children
// through procfs (falling back to stat parent PIDs), then kill through pidfds.
// Cleanup is best effort with a five-second deadline; cancellation allows a
// grace period before killing the shim and closing inherited output pipes.
// A cleanup error preserves the command status, emits one cleanup diagnostic
// and is recorded as cleanup_error in the audit. R-LIFECYCLE: fatal gate signals,
// repeated forking or cleanup failure can leave jailed descendants running.
// Root is not bounded by NPROC. Surviving descendants remain confined; reads
// have no gate-side execution deadline.
// CPU-clock timers can change another process's timer accounting and tick
// dependency; expiry signals still target the caller. Shared-resource effects
// such as this and page-cache changes are outside the read-only claim.
// Every setup failure becomes a SetupError without executing the command.
package confine
