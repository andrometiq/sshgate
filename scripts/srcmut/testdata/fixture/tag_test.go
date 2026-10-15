//go:build srcmut_fixture

package fixture

import (
	"github.com/karthikeyan5/sshgate/internal/srcmut"
	"testing"
)

func TestTagged(t *testing.T) {
	if !Guard() {
		srcmut.Effect(t, "red")
	}
}
