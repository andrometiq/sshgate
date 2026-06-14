package signerserver

// export_test.go exposes unexported internals to the external
// (signerserver_test) test package. It is compiled only under `go test`,
// so it adds nothing to the production binary's surface.

// SetNonceReaderForTest swaps the entropy source used by the Signer's
// nonce generator and returns a restore func. Tests use it to exercise
// the nonce-failure branch of Sign without touching crypto/rand
// globally. The default is reinstated by calling the returned func.
func SetNonceReaderForTest(fn func([]byte) (int, error)) (restore func()) {
	prev := signerNonceRead
	signerNonceRead = fn
	return func() { signerNonceRead = prev }
}
