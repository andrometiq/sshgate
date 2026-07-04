# SSHGate integration test target

A throwaway OpenSSH server in a container that real `ssh` clients can connect
to. Used by Go integration tests to exercise SSHGate end-to-end against a live
sshd rather than a mock.

## Boot

```sh
cd tests/integration && docker compose up -d
```

Or from the repo root:

```sh
docker compose -f tests/integration/docker-compose.yml up -d
```

## Tear-down

```sh
docker compose -f tests/integration/docker-compose.yml down -v
```

`-v` removes the anonymous volumes the image creates; keys live on the host
under `fixtures/keys/` and are unaffected.

## Why `linuxserver/openssh-server`

- Rootless: runs sshd as a non-root user (`PUID=1000`).
- Pubkey-auth and a pre-created login user out of the box — set `USER_NAME`
  and point `PUBLIC_KEY_FILE` at a mounted key, no `useradd`/`sshd_config`
  scripting needed.
- Well-maintained, multi-arch, no surprises.

## Notes

- SSH listens on host port **2222** (not 22) to avoid clashing with the host's
  own sshd. The container also listens on 2222 internally — that's the image
  default, no `Port` override needed.
- `fixtures/keys/` is empty in git (just a `.gitkeep`). Test setup code in
  Phase 1 generates a fresh `sshgate_ed25519` keypair into it before bringing
  the container up; tear-down deletes the keys.
- Lifecycle is automated: the Go test helpers (`helpers_test.go`) spawn and
  stop the container via `docker compose` themselves (falling back to
  `docker-compose`, and skipping the suite when neither is available). The
  manual commands above remain useful for debugging a hung container.
