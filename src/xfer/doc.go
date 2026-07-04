// Package xfer implements the crypto envelope for SSHGate box-to-box
// secret transfer (Mode 2: encrypted pass-through).
//
// The problem it solves: a secret held on server A must reach server B
// without the orchestrating agent or the MCP relay ever seeing its
// plaintext, and without letting a hostile agent substitute either the
// recipient key (to steal the secret) or the payload (to smuggle its own
// content into B under A's provenance). SSHGate's single-choke-point model
// is preserved: the MCP relays an opaque Envelope and is the sole SSH
// client; no server ever reaches another.
//
// The construction is deliberately minimal — one audited encryption
// primitive plus one separate signature:
//
//   - Confidentiality: golang.org/x/crypto/nacl/box SealAnonymous
//     (ephemeral X25519 + XSalsa20-Poly1305). Only the holder of the
//     recipient's box private key can open the sealed bytes; the sender is
//     anonymous at this layer.
//   - Provenance: an ed25519 attestation by the sender's identity key over
//     a domain-separated, length-prefixed message binding the envelope
//     version, transfer id, destination id, and the SHA-256 of the
//     plaintext. This is what defeats the reverse-MITM: a hostile agent can
//     encrypt its own bytes to B's real box key, but it cannot forge A's
//     attestation over those bytes.
//
// This package is LIBRARY code only. It defines and manipulates keys and
// envelopes; it wires nothing — no subcommand, no gate dispatch, no MCP
// surface. Those land in later phases.
//
// Security invariants honored throughout:
//
//   - Plaintext bytes and box private keys are NEVER logged, printed, or
//     folded into an error string. Reject-path errors are generic.
//   - Every failed check is fail-closed: it returns (nil, error) and never
//     partial output.
//   - Open takes the expected sender identity public key as a PARAMETER
//     (it comes from the signer's attestation in a later phase); it never
//     trusts a sender key carried inside the envelope. There is no such
//     field, precisely so it cannot reopen the MITM.
package xfer
