// Package lifecycle owns local approval storage and the dependency contracts
// used by the single-writer approval engine. State transitions belong to
// approvalplan; transport, rendering and signing adapters belong to callers.
// Legacy callbacks stay on their original engine across v2 reopen. Its audit
// worker, tables, counters, context, assist admission and goroutines belong to
// one legacy service created by New. Its single-slot assist pool is independent
// of the v2 pool. Only service Close cancels and joins these resources.
// Replacement v2 engines do not take over legacy state.
// ReserveLegacy admits a preparing request and waits for its sole assist attempt.
// The caller builds one immutable PreparedLegacyApproval from the returned
// snapshot and render context, then DeliverLegacy compares the notifier copy
// and activates only on AllDelivered while the request is unresolved. Each
// request cancels its delivery context on resolution, including expiry.
// CancelLegacy drops abandoned preparations, including in-flight delivery.
// No legacy state or prepared material is persisted. Rendering, snapshot/input
// validation, network-specific refusal text and message binding stay in adapters.
package lifecycle
