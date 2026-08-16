//go:build !linux

package policyarchive

import "errors"

var errUnsupported = errors.New("policy archive: secure archive and maintenance leases require Linux")

type LeaseMode uint8

const (
	LeaseShared LeaseMode = iota + 1
	LeaseExclusive
)

type MaintenanceLease struct{}

func AcquireMaintenanceLease(string, LeaseMode) (*MaintenanceLease, error) {
	return nil, errUnsupported
}
func (*MaintenanceLease) Path() string      { return "" }
func (*MaintenanceLease) Exclusive() bool   { return false }
func (*MaintenanceLease) Revalidate() error { return errUnsupported }
func (*MaintenanceLease) Close() error      { return nil }

type Archive struct{}

func OpenServing(string, *MaintenanceLease) (*Archive, error)           { return nil, errUnsupported }
func OpenExisting(string, *MaintenanceLease) (*Archive, error)          { return nil, errUnsupported }
func (*Archive) Root() string                                           { return "" }
func (*Archive) PrepareServingShards(*MaintenanceLease) error           { return errUnsupported }
func (*Archive) VerifyShards() error                                    { return errUnsupported }
func (*Archive) PublishBinding(*MaintenanceLease, string, string) error { return errUnsupported }
func (*Archive) VerifyBinding(string, string) error                     { return errUnsupported }
func (*Archive) PublishObject(*MaintenanceLease, []byte) (ObjectRef, error) {
	return ObjectRef{}, errUnsupported
}
func (*Archive) ReadObject(ObjectRef) ([]byte, error) { return nil, errUnsupported }
func (*Archive) CleanupTemporaryObjects(*MaintenanceLease, func(string)) (int, error) {
	return 0, errUnsupported
}
func (*Archive) Close() error { return nil }
