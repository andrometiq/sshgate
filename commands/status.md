---
description: Show SSHGate health — signer socket + per-server reachability and tier
argument-hint:
allowed-tools: mcp__sshgate__status
---

The user invoked `/sshgate:status`. Print a readable health report for
the local signer socket and every registered server.

Call the MCP tool `mcp__sshgate__status` with an empty input object.
The tool returns:

- `signer_socket`: `{ path, configured, reachable, permission, error }`
  - `configured` is true when the signer socket file exists. On Tier 1
    (no signer installed) it is false, which is normal.
  - `permission` is true when the socket exists but this session was
    refused access to it (not yet in the `sshgatesigner` group).
  - `error` is the dial error, if any.
- `servers`: array of `{ alias, reachable, ping_ms, error, read_only }`,
  sorted by alias. `read_only: true` means the server was added as Tier 1
  (writes are refused at its gate); absent or false means signed writes.
  The tier comes from the local registry, so it is shown even when the
  server is unreachable.

The tool does not report whether a server's reads run in the kernel read
jail. That is checked on the host with `~/.sshgate-gate/gate doctor`.

Format the result as two short sections. Signer first — if its socket is
unreachable, every write will fail.

```
Signer
  socket:    /run/sshgatesigner/sock
  reachable: yes
```

Branch on the signer fields before deciding what to print:

- `configured: false` → most likely a **Tier-1 (read-only)** install: no
  signer daemon exists, so an unreachable socket is EXPECTED. Print it
  as normal, e.g.:

  ```
  Signer
    socket:    /run/sshgatesigner/sock
    status:    not configured (read-only / Tier 1) — writes denied at the gate
  ```

  Do NOT suggest debugging the daemon; suggest `/sshgate:setup` to add a
  signer instead.
- `configured: true` AND `permission: true` → the daemon is fine; this
  session is not yet in the `sshgatesigner` group. The user must log out
  and back in AND relaunch Claude Code (`newgrp` in a side terminal does
  not fix the running session).
- `configured: true` AND `reachable: false` (no `permission`) → a real
  Tier-2 daemon problem. Surface the error verbatim and suggest
  `systemctl status sshgate-signer-telegram` and
  `journalctl -u sshgate-signer-telegram -n 30 --no-pager`. Do not run
  them yourself unless the user asks.

Then a per-server table (use plain text, not markdown tables — they
render poorly in the CLI):

```
Servers
  alias       tier         reachable   ping
  prod-db     read+write   yes         42 ms
  web-1       read-only    yes         38 ms
  staging     read+write   no          —      (dial tcp: i/o timeout)
```

To check a single server without probing all of them, the `ping` tool
takes one alias.

If the registry is empty, say so plainly:

```
No servers registered. A human adds one with `sshgate pubkey` (paste the key into the host), then `sshgate add <alias> <user@host>`.
```

If the tool itself returns an error (not the same as a server being
unreachable — that's data), surface the error and stop. Don't guess
at health.
