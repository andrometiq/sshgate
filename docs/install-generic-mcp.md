# Use SSHGate with any MCP client

SSHGate ships as a Claude Code plugin, but its agent half is a plain **stdio MCP
server** (`sshgate-mcp`) that works with any MCP-capable client — OpenAI Codex,
Cursor, Gemini CLI, or a hand-written `mcpServers` config.

> **Read this first — the MCP server is only half the system.** `sshgate-mcp`
> classifies commands and runs reads directly, but a **write** needs a valid
> signature from the local **signer daemon**, and every target server must first
> be **provisioned with the gate** (the human-only `sshgate` CLI). Installing the
> MCP server alone gives you read-only operation against already-registered
> servers; writes stay denied until you complete the signer + per-server gate
> setup in [`INSTALL.md`](../INSTALL.md). None of the steps below replace that.

## 1. Build / install `sshgate-mcp`

The MCP server is a Go binary. There are no prebuilt binaries until a release is
tagged, so build from source:

```sh
git clone https://github.com/karthikeyan5/SSHGate
cd SSHGate
make install-local     # puts sshgate-mcp (+ sshgate, sshgate-signer-telegram) on your $PATH via `go install`
```

`make install-local` installs to `$(go env GOPATH)/bin` (usually `~/go/bin`) —
make sure that is on your `PATH`. Confirm:

```sh
sshgate-mcp --version   # e.g. sshgate-mcp v0.1.4
```

Once a release is tagged you can instead `go install` a pinned version directly:

```sh
go install github.com/karthikeyan5/sshgate/src/mcp/cmd/sshgate-mcp@v0.1.4
```

## 2. Generic `mcpServers` snippet (any stdio MCP client)

Point your client at the binary and pass the signer socket via the environment.
This is the same shape as SSHGate's own [`.mcp.json`](../.mcp.json):

```json
{
  "mcpServers": {
    "sshgate": {
      "command": "sshgate-mcp",
      "env": {
        "SSHGATE_SIGNER_SOCK": "/run/sshgatesigner/sock"
      }
    }
  }
}
```

`SSHGATE_SIGNER_SOCK` is the Unix socket of the local signer daemon. Reads never
touch it; writes dial it to get a human Telegram approval. If no signer is
configured yet, the server still starts and serves reads (Tier-1 / read-only).

## 3. OpenAI Codex

Codex reads SSHGate's `.claude-plugin/plugin.json` + `.claude-plugin/marketplace.json`
natively, so installing the whole plugin is two commands (GitHub shorthand is
supported):

```sh
codex plugin marketplace add karthikeyan5/SSHGate
codex plugin add sshgate@sshgate
```

`sshgate@sshgate` is `<plugin-name>@<marketplace-name>` — both are `sshgate`,
from `marketplace.json`. This registers the MCP server and the skills/commands.

Or, for just the bare MCP server without the plugin wrapper:

```sh
codex mcp add sshgate --env SSHGATE_SIGNER_SOCK=/run/sshgatesigner/sock -- sshgate-mcp
```

## 4. Cursor

Cursor installs an MCP server from a deeplink. Use this "Add to Cursor" link
(it encodes exactly the `command` + `SSHGATE_SIGNER_SOCK` env from §2):

```
cursor://anysphere.cursor-deeplink/mcp/install?name=sshgate&config=eyJjb21tYW5kIjoic3NoZ2F0ZS1tY3AiLCJlbnYiOnsiU1NIR0FURV9TSUdORVJfU09DSyI6Ii9ydW4vc3NoZ2F0ZXNpZ25lci9zb2NrIn19
```

(The `config` value is base64 of
`{"command":"sshgate-mcp","env":{"SSHGATE_SIGNER_SOCK":"/run/sshgatesigner/sock"}}`.)
The `sshgate-mcp` binary must already be on your `PATH` from §1.

## 5. Gemini CLI

SSHGate carries a root [`gemini-extension.json`](../gemini-extension.json), so
Gemini CLI can install it as an extension straight from the repo:

```sh
gemini extensions install https://github.com/karthikeyan5/SSHGate
```

The extension launches `sshgate-mcp` with the signer-socket env. Until releases
exist, this installs from source — the `sshgate-mcp` binary still needs to be
built and on your `PATH` (§1); a release-archive path that bundles the binary is
a future improvement.

## 6. The hard caveat, again

Whatever client you use, the same boundary applies:

- **Reads run free.** Reachability + diagnostics work as soon as a server is
  registered.
- **Writes need the signer daemon + a provisioned gate.** Set those up per
  [`INSTALL.md`](../INSTALL.md). Without them, every write is denied at the gate —
  by design, not by bug. The security boundary is the Ed25519 signature checked
  on each host under an OpenSSH forced command; the classifier only routes. See
  [`docs/THREAT-MODEL.md`](THREAT-MODEL.md).
- **Provisioning stays human-only.** A new server is onboarded with the `sshgate`
  CLI, never through the agent — the agent can never expand its own reach.
