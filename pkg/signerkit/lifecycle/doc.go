// Package lifecycle owns local approval storage and the dependency contracts
// used by the single-writer approval engine. State transitions belong to
// approvalplan; transport, rendering and signing adapters belong to callers.
// Admission keeps decision-ordered reclamation indexes alongside its counters.
// Payload pressure visits only full records; count pressure also visits shed
// headers. Confirmed commits update the indexes, and Startup rebuilds them.
// The pure transitions still enforce every reclamation guard. Full records
// retain their immutable reservation until Shed or Delete.
// Storage uncertainty permanently stops a v2 generation under its writer lock.
// Availability and every v2 operation retain that cause until replacement;
// Run joins interrupted effects before returning it. Recovery belongs to callers.
// NewLegacyService creates the independent v1 owner. Pass the same service in
// Config.LegacyService across v2 replacements and route legacy callbacks to it.
// Engine.Close joins only v2 work; the runtime separately closes LegacyService
// at process shutdown, joining its audit worker, assist pool and requests.
// ReserveLegacy admits a preparing request and waits for its sole assist attempt.
// The caller builds one immutable PreparedLegacyApproval from the returned
// snapshot and render context, then DeliverLegacy compares the notifier copy
// and activates only on AllDelivered while the request is unresolved. Each
// request cancels its delivery context on resolution, including expiry.
// CancelLegacy drops abandoned preparations, including in-flight delivery.
// No legacy state or prepared material is persisted. Rendering, snapshot/input
// validation, network-specific refusal text and message binding stay in adapters.
package lifecycle
