// Package approvalwire is the v2 approval wire: the six local socket kinds
// (approval_{submit,get,list,wait,claim,report}_v2), the hosted
// /v2/approvals routes, the one response envelope both share, and the typed
// errors their callers classify answers by.
//
// Every frame is versioned by its own approval_proto (the policywire
// precedent), never by sigwire's proto_version, so the frozen v1 socket wire
// and its goldens are untouched. Decoders are strict: one canonical JSON value
// (json.Marshal bytes), no unknown field, no trailing data, every enum from
// approvalplan's closed sets. A local frame never carries requester_sub (the
// local principal comes from SO_PEERCRED); a hosted body may (E19). No
// response carries executor_claim_token_hash or draft_hash (E25).
//
// The package imports approvalplan and the standard library only, so the MCP,
// the local daemon and the hosted server share one definition without
// importing each other. Every shape is frozen by the goldens in testdata/;
// changing one needs a new approval_proto, never an edit in place.
package approvalwire
