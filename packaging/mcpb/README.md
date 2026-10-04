# MCPB bundle (`sshgate-mcp.mcpb`)

This directory is the source for SSHGate's [MCPB](https://github.com/anthropics/mcpb)
bundle — the single-file artifact meant to be listed on the
[Official MCP Registry](https://registry.modelcontextprotocol.io) (via
[`server.json`](../../server.json)) and installable on Smithery and any MCPB-aware
client. **Nothing is published yet:** there is no tagged release, so the bundle
exists only when you build it locally. It bundles **only** the MCP client half
(`sshgate-mcp`); the signer daemon and per-server gate provisioning are still
prerequisites (see [`INSTALL.md`](../../INSTALL.md)).

## Layout

| Path | Committed? | What it is |
|---|---|---|
| `manifest.json` | yes | MCPB manifest template (`manifest_version` 0.3, `server.type` `binary`, 11 tool declarations, `user_config.signer_sock`). Its `version` is re-stamped from the repo `VERSION` at pack time. |
| `server/sshgate-mcp-launch.sh` | yes | Launcher. MCPB `platform_overrides` key on OS only, so this picks the `sshgate-mcp-<os>-<arch>` binary from `server/bin/` at runtime and `exec`s it. |
| `dist/` | no (gitignored) | Build output: the cross-compiled binaries and the packed `sshgate-mcp.mcpb`. |

## Build

Needs Go, `zip` (Info-ZIP) and `jq` on `PATH`.

```sh
make mcpb        # → packaging/mcpb/dist/sshgate-mcp.mcpb
```

The target cross-builds `sshgate-mcp` for linux/darwin × amd64/arm64
(`CGO_ENABLED=0`, deterministic `-trimpath -buildid=`, `VERSION` stamped via
`-X`), stamps the manifest version, and packs a **reproducible** zip (fixed
mtimes via `SOURCE_DATE_EPOCH`, sorted entries, no uid/gid/extra attributes) with
`manifest.json` at the archive root. `make mcpb` run twice produces a
byte-identical bundle — which is what lets `publish-mcp.yml` prove the SHA-256 it
injects into `server.json` matches the GitHub Release asset. `release.yml`
attaches the bundle to the Release; `publish-mcp.yml` publishes the metadata.
The committed `server.json` deliberately carries an all-zero `fileSha256`
placeholder: `publish-mcp.yml` replaces it with the real hash at publish time
and refuses to run if the placeholder is missing.

The documented zip layout is packed directly rather than via `npx
@anthropic-ai/mcpb pack`, because the official packer needs network at build time
and records live mtimes (non-reproducible) — either of which would break the
byte-identical release↔publish cross-check.
