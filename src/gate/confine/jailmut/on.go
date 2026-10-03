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
