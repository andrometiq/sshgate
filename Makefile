.PHONY: all build install-local test test-integration vet clean sshgate-gate-linux \
	sshgate-mcp-darwin sshgate-signer-telegram-darwin darwin cross sshgate-signer-server \
	preflight e2e smoke gitleaks release-gate verify-dist verify-repro verify-versions mcpb

# ---------------------------------------------------------------------------
# Verified release channel (spec §11)
# ---------------------------------------------------------------------------
# VERSION is the top-level repo/gate version (its own line, e.g. v0.1.4). It
# becomes the gate's build-injected version marker via -X (§11.2). $(shell cat)
# strips the trailing newline; release-gate re-validates the file at recipe time.
VERSION := $(shell cat VERSION 2>/dev/null)

# GATE_BUILD_FLAGS is the SHARED gate build flag set (§11.3, LOW-4): the dev
# `sshgate-gate-linux` target and the strict `release-gate` target use the SAME
# flags so their output cannot drift — they differ ONLY in toolchain env and
# destination. -trimpath strips local paths; -buildid= empties the Go build id;
# -X injects the version marker (§11.2); -buildvcs=false turns vcs stamping OFF
# (the binary is committed in a commit whose hash it cannot contain, and vcs.time
# would break reproducibility, §11.1).
GATE_BUILD_FLAGS := -trimpath -ldflags '-s -w -buildid= -X main.versionMarker=SSHGATE_GATE_VERSION{$(VERSION)}' -buildvcs=false

# The pinned RELEASE toolchain (§11.1), single-sourced from go.mod's `toolchain`
# directive so the two pins can never drift. release-gate forces GOTOOLCHAIN to
# this exact patch so a byte-identical binary comes out on any machine —
# including one whose LOCAL `go` is a custom build (this repo's dev box runs
# go1.26.4-X:nodwarf5, a live instance of the MED-2 trap). Go auto-downloads the
# genuine release toolchain on first use. release-gate asserts the derivation is
# non-empty before compiling.
GATE_RELEASE_TOOLCHAIN := $(shell awk '/^toolchain /{print $$2}' go.mod)

DIST_GATE_DIR := dist/gate
DIST_GATE_BIN := $(DIST_GATE_DIR)/sshgate-gate-linux-amd64

# ---------------------------------------------------------------------------
# Version stamping for the NON-gate binaries (T4)
# ---------------------------------------------------------------------------
# The gate carries a scannable .rodata version MARKER (§11.2, package gatever)
# for downgrade-cue safety. The other binaries have no such constraint, so they
# take a PLAIN -X of their version variable, single-sourced from the same
# VERSION file the gate marker and the plugin-manifest guard already use. The
# source defaults are "dev"; these flags stamp the real version at link time.
# A wrong -X symbol path is SILENTLY IGNORED by the Go linker, so a build that
# looks stamped could still ship "dev" — the `verify-versions` target builds and
# RUNS each binary to prove the stamp actually landed, so the T4 drift (a
# hardcoded 0.2.0 while VERSION said 0.1.4) can never silently return.
MCP_PKG                     := github.com/karthikeyan5/sshgate/src/mcp
MCP_VERSION_FLAGS           := -ldflags '-X $(MCP_PKG).Version=$(VERSION)'
SIGNER_VERSION_FLAGS        := -ldflags '-X main.version=$(VERSION)'
SIGNER_SERVER_VERSION_FLAGS := -ldflags '-X main.version=$(VERSION)'

all: vet test build

build: sshgate-signer-server sshgate-gate-linux
	mkdir -p bin
	go build $(MCP_VERSION_FLAGS)    -o bin/sshgate-mcp              ./src/mcp/cmd/sshgate-mcp
	go build $(SIGNER_VERSION_FLAGS) -o bin/sshgate-signer-telegram  ./src/signer/cmd/sshgate-signer-telegram
	go build -o bin/sshgate-gate             ./src/gate/cmd/sshgate-gate
	go build -o bin/sshgate                  ./src/cli/cmd/sshgate

# sshgate-signer-server: v2 hosted approval daemon (scaffold). Built into
# bin/ alongside the v1 binaries so a single `make build` produces
# every component the operator might deploy. Production VPS installs
# normally use install/deploy.sh, which re-builds at the deploy path;
# this target is for laptop-side dev + cross-compile parity.
sshgate-signer-server:
	mkdir -p bin
	go build $(SIGNER_SERVER_VERSION_FLAGS) -o bin/sshgate-signer-server ./src/signer-server/cmd/sshgate-signer-server

# Cross-compile sshgate-gate for the remote host (linux/amd64) — the DEV build.
# Fast + unpinned: it uses the LOCAL toolchain and writes to bin/, sharing only
# the flag set (GATE_BUILD_FLAGS) with release-gate. It NEVER uses the pinned
# release toolchain env and NEVER writes to dist/ (LOW-4), so a dev build can
# never dirty the committed, CI-verified artifact.
sshgate-gate-linux:
	mkdir -p bin
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
		go build $(GATE_BUILD_FLAGS) \
		-o bin/sshgate-gate-linux-amd64 ./src/gate/cmd/sshgate-gate

# release-gate is the STRICT, reproducible gate build (§11.1). It forces the
# pinned release toolchain + the full deterministic env and writes the committed
# artifact + its sha256 sidecar into dist/gate/. Run twice from a clean state it
# MUST produce a byte-identical binary. This is the ONLY target that touches
# dist/; dev targets (build/preflight/sshgate-gate-linux) never do.
release-gate:
	@# LOW-3: VERSION must be a single clean line — a stray CR/space/comment would
	@# land outside the marker charset and blank every version scan.
	@if [ ! -f VERSION ]; then echo "release-gate: VERSION file is missing" >&2; exit 1; fi
	@# grep -c '' counts LINES (including a final partial line); wc -l counts
	@# newline bytes, which false-rejects a no-trailing-newline single-line file
	@# and false-accepts "v0.1.4\ngarbage".
	@if [ "$$(grep -c '' VERSION)" -ne 1 ]; then echo "release-gate: VERSION must be exactly one line" >&2; exit 1; fi
	@if ! printf '%s' "$$(cat VERSION)" | grep -Eq '^v[0-9A-Za-z._+-]+$$'; then \
		echo "release-gate: VERSION '$$(cat VERSION)' must match ^v[0-9A-Za-z._+-]+\$$ (no CRLF, spaces, or comments)" >&2; exit 1; fi
	@# §11.1 single-source guard: the pin is derived from go.mod's `toolchain`
	@# directive at parse time; an empty derivation means the directive is gone.
	@if [ -z "$(GATE_RELEASE_TOOLCHAIN)" ]; then \
		echo "release-gate: GATE_RELEASE_TOOLCHAIN is empty — go.mod must carry a 'toolchain goX.Y.Z' directive (§11.1 single-source pin)" >&2; exit 1; fi
	@# MED-2: force the genuine release toolchain and ASSERT it before compiling.
	@# The local go here is go1.26.4-X:nodwarf5 (custom); GOTOOLCHAIN pins the real
	@# release build, which Go auto-downloads on first use.
	@have=$$(GOTOOLCHAIN=$(GATE_RELEASE_TOOLCHAIN) go version 2>/dev/null | awk '{print $$3}'); \
	if [ "$$have" != "$(GATE_RELEASE_TOOLCHAIN)" ]; then \
		echo "release-gate: toolchain mismatch: need $(GATE_RELEASE_TOOLCHAIN), have '$$have' — install it or check network (Go auto-downloads the release toolchain; do NOT fall back to a local custom toolchain for the dist artifact)" >&2; exit 1; fi
	mkdir -p $(DIST_GATE_DIR)
	@# MED-1: export the COMPLETE build env, overriding whatever the shell holds
	@# (GOAMD64 microarch, GOEXPERIMENT, a stray GOFLAGS all change emitted bytes).
	GOTOOLCHAIN=$(GATE_RELEASE_TOOLCHAIN) CGO_ENABLED=0 GOOS=linux GOARCH=amd64 GOAMD64= GOEXPERIMENT= GOFLAGS=-mod=readonly \
		go build $(GATE_BUILD_FLAGS) -o $(DIST_GATE_BIN) ./src/gate/cmd/sshgate-gate
	@# Regenerate the sha256sum-compatible sidecar (basename form so `sha256sum -c`
	@# passes when run from inside dist/gate/).
	cd $(DIST_GATE_DIR) && sha256sum sshgate-gate-linux-amd64 > sshgate-gate-linux-amd64.sha256
	@echo "release-gate: built $(DIST_GATE_BIN) (VERSION=$(VERSION), toolchain=$(GATE_RELEASE_TOOLCHAIN))"
	@cat $(DIST_GATE_BIN).sha256

# macOS desktop builds (v1.1 Task C — for users running Claude Code on a Mac).
# sshgate-signer-telegram + sshgate-mcp run on the user's laptop; sshgate-gate is Linux-only
# (it's deployed to remote Linux servers, so no darwin target for it).
# Both archs built: amd64 (Intel Macs) + arm64 (Apple Silicon).
sshgate-mcp-darwin:
	mkdir -p bin
	GOOS=darwin GOARCH=amd64 go build -trimpath -ldflags='-s -w -X $(MCP_PKG).Version=$(VERSION)' -o bin/sshgate-mcp-darwin-amd64 ./src/mcp/cmd/sshgate-mcp
	GOOS=darwin GOARCH=arm64 go build -trimpath -ldflags='-s -w -X $(MCP_PKG).Version=$(VERSION)' -o bin/sshgate-mcp-darwin-arm64 ./src/mcp/cmd/sshgate-mcp

sshgate-signer-telegram-darwin:
	mkdir -p bin
	GOOS=darwin GOARCH=amd64 go build -trimpath -ldflags='-s -w -X main.version=$(VERSION)' -o bin/sshgate-signer-telegram-darwin-amd64 ./src/signer/cmd/sshgate-signer-telegram
	GOOS=darwin GOARCH=arm64 go build -trimpath -ldflags='-s -w -X main.version=$(VERSION)' -o bin/sshgate-signer-telegram-darwin-arm64 ./src/signer/cmd/sshgate-signer-telegram

darwin: sshgate-mcp-darwin sshgate-signer-telegram-darwin
	@echo "darwin builds done; sshgate-gate remains linux-only (deployed to Linux remotes)"

# Full cross-build matrix: linux laptop binaries + linux remote sshgate-gate + darwin laptop binaries.
cross: build darwin

# install-local is the fresh-clone laptop install used by /sshgate:setup
# and INSTALL.md. It depends on `build`, so ONE `make install-local`
# produces everything the install needs:
#   - <clone>/bin/*  (sshgate-mcp, sshgate-signer-telegram, sshgate-gate,
#                     sshgate (human CLI), sshgate-gate-linux-amd64) for dev
#   - $PATH binaries in $(go env GOPATH)/bin via `go install`
#                     (.mcp.json now references the bare `sshgate-mcp`)
#   - the COMMITTED, CI-verified gate (dist/gate/sshgate-gate-linux-amd64)
#     COPIED (never rebuilt, §11.3) into the STABLE config location the MCP
#     hashes + pushes (~/.config/sshgate/bin/). A local rebuild on a
#     slightly-different toolchain would hash to something the §11.5 published
#     check rejects — so the bytes staged for update_gate MUST be the exact
#     published bytes.
# Run from the user's clone (it has src/). Honors $XDG_CONFIG_HOME.
install-local: build
	go install $(MCP_VERSION_FLAGS)    ./src/mcp/cmd/sshgate-mcp
	go install $(SIGNER_VERSION_FLAGS) ./src/signer/cmd/sshgate-signer-telegram
	go install ./src/cli/cmd/sshgate
	@if [ ! -f $(DIST_GATE_BIN) ]; then \
		echo "install-local: $(DIST_GATE_BIN) is missing — it is committed to the repo; run 'make release-gate' to (re)build it, or fetch it from the clean tree" >&2; exit 1; fi
	mkdir -p "$${XDG_CONFIG_HOME:-$$HOME/.config}/sshgate/bin"
	cp $(DIST_GATE_BIN) "$${XDG_CONFIG_HOME:-$$HOME/.config}/sshgate/bin/sshgate-gate-linux-amd64"
	@echo "install-local done:"
	@echo "  <clone>/bin/* -> dev binaries"
	@echo "  sshgate-mcp, sshgate-signer-telegram, sshgate -> $$(go env GOPATH)/bin (must be on PATH)"
	@echo "  COMMITTED $(DIST_GATE_BIN) COPIED -> $${XDG_CONFIG_HOME:-$$HOME/.config}/sshgate/bin/ (the verified bytes update_gate pushes)"

test:
	go test -race ./...

# Phase-1 e2e against a real Docker SSH target. Skipped automatically
# if `docker compose` is unavailable. Excluded from `make test` so
# contributor machines without Docker still get a green per-package
# suite.
test-integration:
	go test -race -tags=integration ./tests/integration/... -timeout=180s -v

# `go vet ./...` errors with "matched no packages" while the module is empty
# (Phase 0). Guard with `go list` so vet is a no-op until source exists.
vet:
	@if [ -n "$$(go list ./... 2>/dev/null)" ]; then \
		go vet ./...; \
	else \
		echo "vet: no packages yet, skipping"; \
	fi

clean:
	rm -rf bin

# ---------------------------------------------------------------------------
# Verification strategy (see docs/E2E-TEST-STRATEGY.md)
#
#   make preflight   run before EVERY push      — fast, no Docker
#   make e2e         run after a large build /  — full end-to-end, needs Docker
#                    before a release
# ---------------------------------------------------------------------------

# preflight: the standing pre-push gate. Format-adjacent vet, the full race
# unit suite, a secret scan of the commits about to be pushed, a clean build,
# the CHEAP verified-release-channel checks, and the two-build reproducibility
# assertion. No Docker, so it runs anywhere in well under a minute.
preflight: vet test gitleaks build verify-dist verify-versions verify-repro
	@echo "preflight: OK — safe to push"

# verify-dist: the FAST verified-release-channel checks (§11). It deliberately
# does NOT do the reproducible rebuild (that needs the pinned-toolchain download
# and is CI's job, verify-gate.yml, §11.4) — it only confirms, locally and in
# milliseconds, that (a) the committed binary still matches its own published
# .sha256 (binary↔sidecar drift) and (b) VERSION is a single clean line. It
# scopes its claim honestly: source↔binary drift is caught ONLY by CI (NIT-1).
verify-dist:
	@if [ ! -f VERSION ]; then echo "verify-dist: VERSION file is missing" >&2; exit 1; fi
	@# grep -c '' counts LINES (incl. a final partial line), not newline bytes.
	@if [ "$$(grep -c '' VERSION)" -ne 1 ]; then echo "verify-dist: VERSION must be exactly one line" >&2; exit 1; fi
	@if ! printf '%s' "$$(cat VERSION)" | grep -Eq '^v[0-9A-Za-z._+-]+$$'; then \
		echo "verify-dist: VERSION '$$(cat VERSION)' must match ^v[0-9A-Za-z._+-]+\$$" >&2; exit 1; fi
	@if [ ! -f $(DIST_GATE_BIN).sha256 ]; then echo "verify-dist: $(DIST_GATE_BIN).sha256 is missing" >&2; exit 1; fi
	@cd $(DIST_GATE_DIR) && sha256sum -c sshgate-gate-linux-amd64.sha256
	@# Manifest↔VERSION drift guard: the plugin manifest version MUST equal the
	@# VERSION file minus its leading 'v'. Nothing else caught this before, so the
	@# two silently diverged (plugin.json lagged VERSION). No jq dependency — the
	@# preflight gate runs anywhere.
	@pv=$$(sed -n 's/.*"version"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' .claude-plugin/plugin.json | head -1); \
	vf=$$(sed 's/^v//' VERSION); \
	if [ -z "$$pv" ]; then echo "verify-dist: could not read version from .claude-plugin/plugin.json" >&2; exit 1; fi; \
	if [ "$$pv" != "$$vf" ]; then \
		echo "verify-dist: plugin.json version '$$pv' != VERSION '$$vf' (manifest must follow VERSION, sans leading v)" >&2; exit 1; fi
	@# Same drift guard for the other published manifests that carry a hand-set
	@# version (server.json for the MCP Registry, gemini-extension.json for the
	@# Gemini gallery). The mcpb manifest is NOT listed here — `make mcpb` stamps
	@# its version from VERSION at pack time, so its committed value is a template.
	@vf=$$(sed 's/^v//' VERSION); \
	for f in server.json gemini-extension.json; do \
		fv=$$(sed -n 's/.*"version"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' "$$f" | head -1); \
		if [ -z "$$fv" ]; then echo "verify-dist: could not read version from $$f" >&2; exit 1; fi; \
		if [ "$$fv" != "$$vf" ]; then \
			echo "verify-dist: $$f version '$$fv' != VERSION '$$vf' (manifest must follow VERSION, sans leading v)" >&2; exit 1; fi; \
	done
	@echo "verify-dist: OK — committed gate matches its .sha256; plugin.json / server.json / gemini-extension.json versions match VERSION (source↔binary is CI's job, §11.4)"

# verify-versions: the T4 version-stamp drift guard. verify-dist proves the
# plugin.json↔VERSION pair; this proves the three -X-stamped Go binaries
# (sshgate-mcp, sshgate-signer-telegram, sshgate-signer-server) report VERSION
# too. It BUILDS each with its version flags and RUNS `--version`, because a
# wrong -X symbol path is silently ignored by the linker — only building+running
# proves the stamp reached the binary. A binary reporting "dev" (stamp did not
# land) or any value != VERSION (a reintroduced hardcode) fails the gate. Kept
# out of verify-dist so that target stays build-free; wired into preflight.
verify-versions:
	@vf=$$(cat VERSION 2>/dev/null); \
	if [ -z "$$vf" ]; then echo "verify-versions: VERSION file is missing/empty" >&2; exit 1; fi; \
	tmpdir=$$(mktemp -d) || exit 1; \
	trap 'rm -rf "$$tmpdir"' EXIT; \
	go build $(MCP_VERSION_FLAGS)           -o "$$tmpdir/sshgate-mcp"             ./src/mcp/cmd/sshgate-mcp || exit 1; \
	go build $(SIGNER_VERSION_FLAGS)        -o "$$tmpdir/sshgate-signer-telegram" ./src/signer/cmd/sshgate-signer-telegram || exit 1; \
	go build $(SIGNER_SERVER_VERSION_FLAGS) -o "$$tmpdir/sshgate-signer-server"   ./src/signer-server/cmd/sshgate-signer-server || exit 1; \
	fail=0; \
	for b in sshgate-mcp sshgate-signer-telegram sshgate-signer-server; do \
		got=$$("$$tmpdir/$$b" --version 2>/dev/null | awk '{print $$NF}'); \
		if [ "$$got" != "$$vf" ]; then \
			echo "verify-versions: FAIL — $$b reports '$$got', expected VERSION '$$vf' (broken -X wiring or a reintroduced hardcoded version)" >&2; \
			fail=1; \
		fi; \
	done; \
	[ $$fail -eq 0 ] || exit 1; \
	echo "verify-versions: OK — sshgate-mcp / signer-telegram / signer-server all report VERSION $$vf"

# verify-repro: the STANDING two-build reproducibility assertion (spec §11.8
# task 14). Builds the gate TWICE with the SHARED flag set (GATE_BUILD_FLAGS)
# on the LOCAL toolchain into throwaway scratch paths — never bin/, never
# dist/ — and fails loudly if the two hashes differ. This catches flag-set
# nondeterminism regressions (a dropped -buildid= / -buildvcs=false, a stray
# env-sensitive flag) at preflight time, before push; CROSS-MACHINE
# reproducibility of the COMMITTED artifact (pinned toolchain, rebuild vs
# committed bytes) stays CI's job (verify-gate.yml, §11.4).
verify-repro:
	@tmpdir=$$(mktemp -d) || exit 1; \
	trap 'rm -rf "$$tmpdir"' EXIT; \
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
		go build $(GATE_BUILD_FLAGS) -o "$$tmpdir/gate-a" ./src/gate/cmd/sshgate-gate || exit 1; \
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
		go build $(GATE_BUILD_FLAGS) -o "$$tmpdir/gate-b" ./src/gate/cmd/sshgate-gate || exit 1; \
	ha=$$(sha256sum "$$tmpdir/gate-a" | awk '{print $$1}'); \
	hb=$$(sha256sum "$$tmpdir/gate-b" | awk '{print $$1}'); \
	if [ "$$ha" != "$$hb" ]; then \
		echo "verify-repro: FAIL — two identical-flag gate builds hashed differently ($$ha vs $$hb): GATE_BUILD_FLAGS has a nondeterminism regression" >&2; exit 1; fi; \
	echo "verify-repro: OK — two local gate builds byte-identical ($$ha) (cross-machine repro vs the committed artifact is CI's job, §11.4)"

# ---------------------------------------------------------------------------
# MCPB bundle — the A2 artifact for Smithery + the Official MCP Registry
# ---------------------------------------------------------------------------
# `make mcpb` packs packaging/mcpb/ into a single sshgate-mcp.mcpb: a zip (the
# documented MCPB format) with manifest.json at the archive ROOT and one
# sshgate-mcp binary per OS+arch under server/bin/, chosen at runtime by
# server/sshgate-mcp-launch.sh (MCPB's platform_overrides key on OS only — there
# is no arch selector in the manifest spec, so a launcher does the arch pick).
#
# Reproducible by construction: CGO-free deterministic Go builds (-trimpath
# -buildid=, VERSION stamped via -X) into a staging tree, then a NORMALIZED zip
# (fixed mtimes via SOURCE_DATE_EPOCH, sorted entries, -X to drop uid/gid/extra
# attrs). release.yml and publish-mcp.yml both call this and MUST get
# byte-identical output, so publish-mcp can prove the Release asset whose sha256
# it injects into server.json IS the reproducible build.
#
# We pack the documented zip layout directly instead of `npx @anthropic-ai/mcpb
# pack`: the official packer needs network at build time and stamps live mtimes
# (non-reproducible), either of which would break that byte-identical cross-check.
MCPB_DIR    := packaging/mcpb
MCPB_OUTDIR := $(MCPB_DIR)/dist
MCPB_STAGE  := $(MCPB_OUTDIR)/bundle
MCPB_BUNDLE := $(MCPB_OUTDIR)/sshgate-mcp.mcpb
# Fixed timestamp for reproducible zips (2020-01-01 UTC; DOS zip can't encode
# pre-1980). Override SOURCE_DATE_EPOCH to pin a different value.
SOURCE_DATE_EPOCH ?= 1577836800
MCPB_MCP_LDFLAGS  := -trimpath -ldflags '-s -w -buildid= -X $(MCP_PKG).Version=$(VERSION)'

mcpb:
	@command -v zip >/dev/null 2>&1 || { echo "mcpb: 'zip' is required (Info-ZIP)" >&2; exit 1; }
	@command -v jq  >/dev/null 2>&1 || { echo "mcpb: 'jq' is required" >&2; exit 1; }
	@if [ -z "$(VERSION)" ]; then echo "mcpb: VERSION is empty" >&2; exit 1; fi
	rm -rf "$(MCPB_STAGE)"
	mkdir -p "$(MCPB_STAGE)/server/bin"
	CGO_ENABLED=0 GOOS=linux  GOARCH=amd64 go build $(MCPB_MCP_LDFLAGS) -o "$(MCPB_STAGE)/server/bin/sshgate-mcp-linux-amd64"  ./src/mcp/cmd/sshgate-mcp
	CGO_ENABLED=0 GOOS=linux  GOARCH=arm64 go build $(MCPB_MCP_LDFLAGS) -o "$(MCPB_STAGE)/server/bin/sshgate-mcp-linux-arm64"  ./src/mcp/cmd/sshgate-mcp
	CGO_ENABLED=0 GOOS=darwin GOARCH=amd64 go build $(MCPB_MCP_LDFLAGS) -o "$(MCPB_STAGE)/server/bin/sshgate-mcp-darwin-amd64" ./src/mcp/cmd/sshgate-mcp
	CGO_ENABLED=0 GOOS=darwin GOARCH=arm64 go build $(MCPB_MCP_LDFLAGS) -o "$(MCPB_STAGE)/server/bin/sshgate-mcp-darwin-arm64" ./src/mcp/cmd/sshgate-mcp
	install -m 0755 "$(MCPB_DIR)/server/sshgate-mcp-launch.sh" "$(MCPB_STAGE)/server/sshgate-mcp-launch.sh"
	@# manifest.json at the archive ROOT, version stamped from VERSION (sans 'v')
	@# so the bundle can never disagree with the repo.
	@vf=$$(sed 's/^v//' VERSION); \
	jq --arg v "$$vf" '.version = $$v' "$(MCPB_DIR)/manifest.json" > "$(MCPB_STAGE)/manifest.json"
	@# Reproducible archive: pin every mtime, then zip sorted entries with no
	@# uid/gid/extra attrs (-X) and no directory entries (-D).
	find "$(MCPB_STAGE)" -exec touch -h -d "@$(SOURCE_DATE_EPOCH)" {} +
	rm -f "$(MCPB_BUNDLE)"
	cd "$(MCPB_STAGE)" && find . -type f | LC_ALL=C sort | sed 's|^\./||' | zip -q -X -D "$(abspath $(MCPB_BUNDLE))" -@
	@echo "mcpb: built $(MCPB_BUNDLE) (VERSION=$(VERSION))"
	@sha256sum "$(MCPB_BUNDLE)"
	@unzip -l "$(MCPB_BUNDLE)" | awk '{print $$4}' | grep -qx 'manifest.json' \
		&& echo "mcpb: OK — manifest.json is at the archive root" \
		|| { echo "mcpb: FAIL — manifest.json is not at the archive root" >&2; exit 1; }

# gitleaks scans the commits that would be pushed (origin/main..HEAD) for
# secrets. Skips with a loud note if gitleaks is not installed — CI must have
# it. Scanning the push delta (not full history) keeps intentional test
# fixtures on other branches from failing an unrelated push.
gitleaks:
	@if command -v gitleaks >/dev/null 2>&1; then \
		if git rev-parse --verify -q origin/main >/dev/null 2>&1; then \
			gitleaks detect --no-banner -c .gitleaks.toml --log-opts="origin/main..HEAD"; \
		else \
			gitleaks detect --no-banner -c .gitleaks.toml; \
		fi; \
	else \
		echo "gitleaks: NOT INSTALLED — install before pushing (https://github.com/gitleaks/gitleaks)"; \
	fi

# e2e: the full end-to-end strategy. Everything in preflight, plus the Docker
# integration suite (real gate deploy + read / write-denial over SSH against a
# live sshd) and the fresh-install keyless-startup smoke. Run this after a
# large build or before cutting a release. Requires Docker.
e2e: preflight test-integration smoke
	@echo "e2e: OK — full end-to-end strategy passed"

# smoke: the headless fresh-user regression — the MCP server must start with
# no config/key (Tier-1 first-run) instead of dying and killing the tool surface.
smoke:
	@bash scripts/smoke-fresh-install.sh
