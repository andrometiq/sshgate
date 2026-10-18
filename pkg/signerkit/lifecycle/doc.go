// Package lifecycle owns local approval storage and the dependency contracts
// used by the single-writer approval engine. State transitions belong to
// approvalplan; transport, rendering and signing adapters belong to callers.
// Legacy callbacks stay on their original engine across v2 reopen. Its audit
// worker and dropped-event counter survive Run stopping; service Close cancels
// and joins them. Replacement v2 engines do not take over legacy audit state.
package lifecycle
