---
description: Revoke a registered server — tear down remote gate and drop the alias
argument-hint: <alias>
allowed-tools: mcp__sshgate__revoke_server
---

The user invoked `/sshgate:revoke <alias>`. This is destructive: it
removes SSHGate's `command="..."` line from the remote's
`authorized_keys`, deletes `~/.sshgate-gate/` on the remote, and drops
the alias from the local registry. The gate keeps a backup of the old
file at `~/.ssh/authorized_keys.sshgate-revoke-backup` on the remote.

Parse the first positional argument as `alias`. It must match
`[a-z][a-z0-9-]{0,30}` (the same rule `sshgate add` uses). If it is empty
or malformed, print:

```
Usage: /sshgate:revoke <alias>
Alias must match [a-z][a-z0-9-]{0,30}.
```

…and stop. Do not prompt the user inline; this command is scriptable.

Before calling the tool, tell the user verbatim:

> Revoking `<alias>` issues a signed SSHGATE_REVOKE — you'll get a
> Telegram approval prompt. Approve it to proceed.

(A standing grant never auto-signs a revoke; it always needs a tap.)

Then call `mcp__sshgate__revoke_server` with `{ "alias": "<alias>" }`.

Surface the tool's output:

- `remote_cleaned` (bool) — did the gate confirm `SSHGATE_REVOKED` on the remote?
- `registry_removed` (bool) — was the alias dropped from `~/.config/sshgate/servers.json`?
- `message` — human-readable summary from the tool.

On success (both bools true), print:

```
✓ Revoked '<alias>'.
  Remote cleaned, alias removed from registry.
  Run /sshgate:status to confirm.
```

If the tool returns an error, print it verbatim. Common failure
modes — surface but do not invent fixes:

- **Read-only (Tier 1) server** → refused before any tap. A Tier-1 gate
  has no signer pubkey, so it could never verify a signed revoke. A human
  removes it by hand; `sshgate revoke <alias>` (the human CLI) prints the
  exact steps and changes nothing itself. The error text says the same.
- Telegram approval denied or timed out → say so; ask the user if
  they want to retry.
- Remote unreachable → the registry entry stays; tell the user the
  alias is still listed locally and they can re-run revoke later or
  edit `~/.config/sshgate/servers.json` by hand.
- Alias not registered → surface verbatim; suggest
  `/sshgate:status` to see what is registered.

Do not loop. One attempt per invocation.
