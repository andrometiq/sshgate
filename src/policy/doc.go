// Package policy defines SSHGate's authenticated, host-bound policy model.
//
// The package deliberately contains no filesystem or transport behavior. It
// owns only byte-exact command identities, the canonical version-1 base
// manifest and permit-certificate payloads, and their domain-separated
// Ed25519 envelopes. Callers must still enforce custody, rollback protection,
// durable storage, and the gate's recovery ladder.
package policy
