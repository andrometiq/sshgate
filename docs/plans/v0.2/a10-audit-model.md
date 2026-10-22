# A10 hosted audit delivery: model and ruling (2026-10-19)

This is a stop-patch-loop step back after two NO-GO reviews of A10 commit 4 (review note A10-4, -4-2). The the reviewer draft is in review note AUDITSINK (not in the repository). A fresh second-review read said ADOPT-WITH-CHANGES. **This page is binding for the A10-4 rebuild.**

1. **Transport.** There is one blocking stderr writer. It is process-scoped: created in `main` and living for the whole process, not owned by `Server`. Callers hand it a fully encoded frame and wait on their ctx with a 5 s cap. While a write is outstanding, a new submit fails fast with `busy`; there is never a second concurrent write. Files, pipes, journald and Docker all take this same path. **Never set O_NONBLOCK on fd 2 and never use write deadlines.** The O_NONBLOCK flag sits on the shared open file description, so it breaks `log`, panic output and sibling processes. `log.SetOutput`, `http.Server.ErrorLog` and the other diagnostics go through the transport, via a bounded non-blocking queue that counts dropped lines, so no direct fd-2 write can splice into a frame.
2. **Shutdown.** The flusher and worker always join: they stop waiting on cancellation. The process-lifetime writer is not `Server`'s goroutine, so goleak on `Server.Close` stays strict in both modes with no ignore list. Commit 5's goleak acceptance must use the production transport type. The spec needs no amendment.
3. **Framing and ack.** A short successful write continues from its offset. An error after a prefix marks the stream dirty, and a `\n` must be written before the next frame is admitted. A failed separator leaves the frame pending. At startup, a separator is written only when fd 2 is a regular file whose last byte (fstat plus pread) is not `\n`, so journald and Docker never get blank lines. Acknowledgement (Flush advanced, retry evidence deleted) requires the complete line, including its `\n`. A late completion can only produce a duplicate recognizable by `event_key` (at least once, SA-7). With blocking writes, torn lines happen only on a real write error.
4. **Legacy evidence.** Migration 8 adds a versioned legacy-expiry outbox under the store's migration ledger, with no runtime DDL and no trigger. `ExpireLegacy`'s transaction snapshots the terminal time and all votes, with their audit status, into the outbox. Each event has a stable namespaced `event_key`. **No backfill:** the runtime table never shipped, and historical expiries were never promised a line. The one existing flusher delivers both outboxes in bounded batches with its 1 s backoff, and nudges can't bypass that backoff. Clock only expires and nudges, so it never blocks on delivery.
5. **Wire.** The new `AuditCall` legacy-expiry metadata is a wire addition. Record it in E23's notes, `docs/BUILD-PLAN.md:786`, and the frozen-wire checks, which are extended rather than weakened.
6. **Commit split.** Commit 4 covers the transport, migration 8, recovery, the worker and flusher, and standalone tests. It also reverts the `main.go`/README file-rejection change. Commit 5 integrates `Server.Close` and the shutdown tests for both modes. Commit 7 does the final `main.go` wiring and the README.

Acceptance:
- compatibility with regular files, pipes and sockets (no O_NONBLOCK left on fd 2 afterwards; `log` still writes);
- busy-while-outstanding;
- partial-write and failed-separator recovery;
- conditional startup separator;
- an identical `event_key` replayed after a lost ack;
- blocked legacy and v2 delivery mixed, with Clock still on time;
- expiry with unaudited votes;
- migration-7 → 8 upgrade and reopen;
- the race suite, vet and FROZEN-HOSTED.

## Wire note (builder text, for E23 and docs/BUILD-PLAN.md:786; the orchestrator applies it at integration)
A10 adds the trailing optional member `AuditCall.LegacyExpiry` (`legacy_expiry,omitempty`) for legacy-expired lifecycle lines.
- `LegacyExpiryAuditMetadata` encodes `event_key`, `resolved_at` and `votes`.
- Each vote encodes `operator`, `decision`, `authn_method`, `time` and `audited`, including when `audited` is false.
- `event_key` is `legacy-expiry:<lowercase SHA-256 of request_id>:<resolved_at Unix seconds>`.
- Migration 8 captures this evidence atomically with the expiry, with no historical backfill.
- The hosted frozen-wire checks are extended. Existing ordinary, custody, policy and approval encodings are unchanged when the member is absent.

## Commit 7 requirement (from the second-review check of the rebuild)
Route every direct fd-2 writer through the transport:
- `main.go:257` (`NewAppendOnlySink(os.Stderr)`), `main.go:264`, and `logf` at `main.go:884`;
- `fmt.Fprintf(os.Stderr…)` in `custody.go:364,370`, `daemon.go` and `socket.go`, on the hosted process path;
- the engine's `log.Default()` fallback (`approvals_v2_engine.go:104`).

Any writer left in place can splice into audit frames. Commit 7's acceptance includes a test that the hosted process writes to fd 2 only through the transport.

## Ruling (after the reviewer A10-4-3 #2): unreadable regular-file tails
When fd 2 is a regular file whose last byte can't be read (write-only fd, with no read permission to reopen `/proc/self/fd/2`), the transport writes the startup separator unconditionally and starts normally. It never refuses and never needs read permission. A blank line in a plain file is harmless; journald and Docker are never regular files, so they never get it.

## Amendment (after the reviewer A10-4-4 #1): one waiting audit frame
Item 1's "busy while a write is outstanding" is refined:
- **A diagnostic write is outstanding.** At most ONE audit frame may wait, inside its caller's ctx and the 5 s cap, and it is written next, ahead of any queued diagnostics. Further audit submits return `ErrAuditBusy` at once.
- **An audit write is outstanding.** Every new submit returns `ErrAuditBusy` at once, as before.

This is what stops a diagnostic flood from starving audit delivery. It stays bounded and serialized. Required test: an audit submit made while a diagnostic write is blocked. The first waits and wins priority; a second gets busy at once.

## Moved to commit 7
The two README paragraphs from the fix round (reconciliation, reclamation, transport priority, evidence recovery) describe wiring that lands in commit 7. They come out of commit 4 and go back in with commit 7's main.go wiring.
