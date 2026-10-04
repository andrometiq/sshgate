package harness

// Unexpected reports a test failure that can never count as mutation evidence.
func Unexpected(t interface {
	Helper()
	Errorf(string, ...any)
}, format string, args ...any) {
	t.Helper()
	t.Errorf("UNEXPECTED: "+format, args...)
}
