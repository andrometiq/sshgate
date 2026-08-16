// Package policystore defines the policy authority's durable domain contract.
//
// It deliberately contains no SQL, filesystem, HTTP, Telegram, or signer
// implementation. Concrete stores implement Store through a distinct adapter.
package policystore
