// Package srcmut records an observed source-mutation effect in a test.
package srcmut

import "testing"

func Effect(t testing.TB, marker string) {
	t.Helper()
	t.Log("MUTATION-EFFECT " + marker)
	t.Fail()
}
