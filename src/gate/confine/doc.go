// Package confine builds SSHGate's ro-v1 kernel jail. Every confined command
// requires user, mount, PID and IPC namespaces, read-only mounts, Landlock,
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
// pid-1 shim starts __jailexec, which verifies namespaces, builds the mount view,
// applies restrictions on a locked OS thread and execs /bin/sh. The command and
// setup report use private pipes on fd 3 and fd 4; no command travels on argv.
// Every setup failure becomes a SetupError without executing the command.
package confine
