.PHONY: all build install-local test test-integration vet clean sshgate-gate-linux \
	sshgate-mcp-darwin sshgate-signer-telegram-darwin darwin cross sshgate-signer-server \
	preflight e2e smoke gitleaks release-gate

# ---------------------------------------------------------------------------
# Verified release channel (spec §11)
# ---------------------------------------------------------------------------
# VERSION is the top-level repo/gate version (its own line, e.g. v1.3.0). It
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

# The pinned RELEASE toolchain (§11.1). release-gate forces GOTOOLCHAIN to this
# exact patch so a byte-identical binary comes out on any machine — including one
# whose LOCAL `go` is a custom build (this repo's dev box runs
# go1.26.4-X:nodwarf5, a live instance of the MED-2 trap). Go auto-downloads the
# genuine release toolchain on first use.
GATE_RELEASE_TOOLCHAIN := go1.26.4

DIST_GATE_DIR := dist/gate
DIST_GATE_BIN := $(DIST_GATE_DIR)/sshgate-gate-linux-amd64

all: vet test build

build: sshgate-signer-server sshgate-gate-linux
	mkdir -p bin
	go build -o bin/sshgate-mcp              ./src/mcp/cmd/sshgate-mcp
	go build -o bin/sshgate-signer-telegram  ./src/signer/cmd/sshgate-signer-telegram
	go build -o bin/sshgate-gate             ./src/gate/cmd/sshgate-gate
	go build -o bin/sshgate                  ./src/cli/cmd/sshgate

# sshgate-signer-server: v2 hosted approval daemon (scaffold). Built into
# bin/ alongside the v1 binaries so a single `make build` produces
# every component the operator might deploy. Production VPS installs
# normally use install/deploy.sh, which re-builds at the deploy path;
# this target is for laptop-side dev + cross-compile parity.
sshgate-signer-server:
	mkdir -p bin
	go build -o bin/sshgate-signer-server ./src/signer-server/cmd/sshgate-signer-server

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
	@if [ "$$(wc -l < VERSION)" -ne 1 ]; then echo "release-gate: VERSION must be exactly one line" >&2; exit 1; fi
	@if ! printf '%s' "$$(cat VERSION)" | grep -Eq '^v[0-9A-Za-z._+-]+$$'; then \
		echo "release-gate: VERSION '$$(cat VERSION)' must match ^v[0-9A-Za-z._+-]+\$$ (no CRLF, spaces, or comments)" >&2; exit 1; fi
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
	GOOS=darwin GOARCH=amd64 go build -trimpath -ldflags='-s -w' -o bin/sshgate-mcp-darwin-amd64 ./src/mcp/cmd/sshgate-mcp
	GOOS=darwin GOARCH=arm64 go build -trimpath -ldflags='-s -w' -o bin/sshgate-mcp-darwin-arm64 ./src/mcp/cmd/sshgate-mcp

sshgate-signer-telegram-darwin:
	mkdir -p bin
	GOOS=darwin GOARCH=amd64 go build -trimpath -ldflags='-s -w' -o bin/sshgate-signer-telegram-darwin-amd64 ./src/signer/cmd/sshgate-signer-telegram
	GOOS=darwin GOARCH=arm64 go build -trimpath -ldflags='-s -w' -o bin/sshgate-signer-telegram-darwin-arm64 ./src/signer/cmd/sshgate-signer-telegram

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
	go install ./src/mcp/cmd/sshgate-mcp
	go install ./src/signer/cmd/sshgate-signer-telegram
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
# unit suite, a secret scan of the commits about to be pushed, and a clean
# build. No Docker, so it runs anywhere in well under a minute.
preflight: vet test gitleaks build
	@echo "preflight: OK — safe to push"

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
