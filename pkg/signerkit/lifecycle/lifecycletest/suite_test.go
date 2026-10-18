package lifecycletest_test

import (
	"testing"

	"github.com/karthikeyan5/sshgate/pkg/signerkit/lifecycle"
	"github.com/karthikeyan5/sshgate/pkg/signerkit/lifecycle/lifecycletest"
)

func TestMemStoreConformance(t *testing.T) {
	lifecycletest.Run(t, func(t *testing.T) lifecycle.Store { return &lifecycle.MemStore{} })
}
