`older-a8fc4d5.json` captures the actual handler from `origin/main` revision
`a8fc4d5`, with the policy plane absent and attached using `AttachPolicy`.
Every response is recorded with `httptest.NewRecorder`; no socket is opened.
The capture's unused policy store and custody deliberately panic if invoked:
these non-policy paths must be rejected before reaching either dependency.

Exact capture command, run in the extracted `a8fc4d5` tree:

```sh
GOCACHE="$SHARED_GO_CACHE" GOFLAGS=-mod=readonly GOPROXY=off go run -overlay "$CAPTURE_OVERLAY" -tags fixturecapture ./tests/hostedproxy/internal/capture > "$CURRENT_TREE/tests/hostedproxy/testdata/older-a8fc4d5.json"
```

`CAPTURE_OVERLAY` is a Go overlay JSON with a `Replace` entry mapping
`$OLD_TREE/tests/hostedproxy/internal/capture/main.go` to
`$CURRENT_TREE/tests/hostedproxy/internal/capture/main.go` (expand these to
absolute paths). `SHARED_GO_CACHE` points to the existing module-compatible
build cache. Both fixture cases include all six v2 routes; the JSON preserves
response body bytes, status and headers.

`legacy-a8fc4d5.json` is captured from the same revision's `Service` and
`HostedServerBackend`, with an enrolled test transfer registry and a fake HTTP
transport. It records local request/response bytes and outgoing HTTP requests.
The sequence refuses a grant, lists the still-empty grant map, then signs on
that alias through HTTP; transfer and key registration reach the backend's
existing fail-closed paths. The HTTP sign response is a deterministic denial.

```sh
GOCACHE="$SHARED_GO_CACHE" GOFLAGS=-mod=readonly GOPROXY=off go run -overlay "$LEGACY_CAPTURE_OVERLAY" -tags fixturecapture ./tests/hostedproxy/internal/capturelegacy > "$CURRENT_TREE/tests/hostedproxy/testdata/legacy-a8fc4d5.json"
```

The legacy overlay maps the analogous `internal/capturelegacy/main.go` path
from the old tree to this tree.
