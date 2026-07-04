package backend

import "context"

// StubBackend is the trivial Backend implementation used by the phase-1
// end-to-end test: every Request resolves immediately to StatusDenied.
// Its purpose is to exercise the full cryptographic + socket loop
// (request → backend → audit → response) without needing a human or a
// Telegram bot in the loop. The daemon shipped against StubBackend will
// reject every write, which is exactly the property the phase-1 test
// asserts.
//
// StubBackend has no fields and no state, so the zero value is
// immediately usable and safe for concurrent calls.
type StubBackend struct{}

// Request returns a buffered channel pre-loaded with a Denied result.
// ctx is intentionally ignored — there is no work to cancel.
func (StubBackend) Request(_ context.Context, _ ApprovalRequest) (<-chan Result, error) {
	ch := make(chan Result, 1)
	ch <- Result{Status: StatusDenied}
	close(ch)
	return ch, nil
}

// RequestGrant mirrors Request: every standing-grant request is denied,
// so a daemon shipped against StubBackend mints no grants.
func (StubBackend) RequestGrant(_ context.Context, _ GrantApprovalRequest) (<-chan Result, error) {
	ch := make(chan Result, 1)
	ch <- Result{Status: StatusDenied}
	close(ch)
	return ch, nil
}

// RequestTransfer mirrors Request: every box→box transfer is denied, so a
// daemon shipped against StubBackend signs no transfer legs.
func (StubBackend) RequestTransfer(_ context.Context, _ TransferApprovalRequest) (<-chan Result, error) {
	ch := make(chan Result, 1)
	ch <- Result{Status: StatusDenied}
	close(ch)
	return ch, nil
}

// RequestRegisterKey mirrors Request: every xfer-key registration is denied, so
// a daemon shipped against StubBackend never populates the transfer registry.
func (StubBackend) RequestRegisterKey(_ context.Context, _ RegisterApprovalRequest) (<-chan Result, error) {
	ch := make(chan Result, 1)
	ch <- Result{Status: StatusDenied}
	close(ch)
	return ch, nil
}
