# Source mutation checks

Run `make selftest-srcmut` to check the harness and `make test-srcmut SRCMUT=<IDs>`
to check declared mutation sets.

Patch targets must exist at HEAD, contain `old` exactly once there, and match the
HEAD blob byte for byte in the working tree. Dirty and untracked targets are refused.

The harness clears `GOFLAGS` for module discovery, dependency discovery, wrapper
builds and both test runs, including values supplied in an entry's environment.
Declare build tags with the entry's `tags` field. Only the harness's generated
single-file overlay is used.

An unsuccessful test command triggers process-group cleanup, including when Go's
own test timeout fires before the harness deadline. The outer deadline also kills
the process group. Child wait-status records still determine whether termination
was normal enough to count as mutation detection.
