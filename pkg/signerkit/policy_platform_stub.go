//go:build !linux

package signerkit

import (
	"context"
	"errors"
	"io"
)

// The shipped signer and securestate authority journal are Linux-only. Keep
// the public constructor/socket package cross-compilable without pretending a
// weaker pathname-based journal exists on another platform.
type localPolicyJournal struct{}

func openLocalPolicyJournal(string) (*localPolicyJournal, error) {
	return nil, errors.New("policy journal is supported only on Linux")
}

func (*localPolicyJournal) Close() error { return nil }

func (d *Daemon) handleBaseManifestPolicy(context.Context, io.Writer, []byte) error {
	return errors.New("base-manifest policy authority is supported only on Linux")
}

func (d *Daemon) initializePolicyRecovery(context.Context) error { return nil }

func (d *Daemon) stopHostedPolicyRecovery() {}

func (d *Daemon) policyRecoveryStatus() error {
	return errors.Join(d.policyRecoveryErr, d.policyLocalRecoveryErr, d.policyHostedRecoveryErr)
}
