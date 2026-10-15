// Package approvalplan is the v2 approval contract shared by the local signer,
// the hosted signer, the MCP and the executor: the draft and plan types, their
// validators and bounds, the identifiers and storage-key derivations, the
// canonical hashes, and the R1 (approval record) and R2 (executor job) record
// schemas.
//
// It imports the standard library only, so the gate, the MCP and the signers
// can all depend on it without widening any closure. Constants mirrored from
// other packages name their source line and are drift-tested by their owners.
//
// Every encoding here is a stored identity: draft_hash, plan_hash, record keys
// and record bytes are pinned by the goldens in testdata/. Changing one needs a
// version bump, never an edit in place.
package approvalplan
