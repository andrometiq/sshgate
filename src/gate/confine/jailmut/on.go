//go:build jail_mutation

package jailmut

import "strings"

// IDs is injected by the mutation harness using -ldflags -X.
var IDs string

func On(id string) bool {
	for _, candidate := range strings.Split(IDs, ",") {
		if candidate == id && id != "" {
			return true
		}
	}
	return false
}

// BuildFlags are the go build flags that compile another binary with the same
// mutation hooks on: the selftest binary a test builds for the rehearsal.
func BuildFlags() []string {
	return []string{"-tags=jail_mutation", "-ldflags=-X github.com/karthikeyan5/sshgate/src/gate/confine/jailmut.IDs=" + IDs}
}
