// Package lifecycle owns local approval storage and the dependency contracts
// used by the single-writer approval engine. State transitions belong to
// approvalplan; transport, rendering and signing adapters belong to callers.
// Legacy callbacks stay on their original engine across v2 reopen. Its audit
// worker and dropped-event counter survive Run stopping; service Close cancels
// and joins them. Replacement v2 engines do not take over legacy audit state.
// ReserveLegacy admits a preparing request and waits for its sole assist attempt.
// The caller builds one immutable PreparedLegacyApproval from the returned
// snapshot and render context, then DeliverLegacy compares the notifier copy
// and activates only on AllDelivered. CancelLegacy drops abandoned preparations.
// No legacy state or prepared material is persisted. Rendering, snapshot/input
// validation, network-specific refusal text and message binding stay in adapters.
package lifecycle
