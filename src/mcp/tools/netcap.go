package tools

import (
	"bytes"
	"context"
	"encoding/json"

	"github.com/karthikeyan5/sshgate/src/mcp/registry"
)

type hostCap struct {
	V                      int
	Enforcement            string
	Pinned, Net, NetGrants bool
	Label, Reason          string
}

// fetchCap caches even unsupported replies until invalidation. The gate remains
// authoritative; this snapshot only selects the network request route. The
// probe runs unlocked, so a slow host never stalls another host's lookup.
func (r *Runner) fetchCap(ctx context.Context, alias string, entry registry.Entry) *hostCap {
	r.capMu.Lock()
	cap, ok := r.caps[alias]
	generation := r.capGeneration[alias]
	r.capMu.Unlock()
	if !ok {
		stdout, _, exit, err := r.SSH.Run(ctx, entry.Host, entry.User, entry.Port, "SSHGATE_JAIL")
		if err == nil && exit == 0 {
			cap = parseCap(stdout)
		}
		r.capMu.Lock()
		if r.caps == nil {
			r.caps = make(map[string]*hostCap)
		}
		if r.capGeneration[alias] == generation {
			r.caps[alias] = cap
		}
		r.capMu.Unlock()
	}
	if cap == nil {
		return nil
	}
	copy := *cap
	return &copy
}

func (r *Runner) invalidateCap(alias string) {
	r.capMu.Lock()
	defer r.capMu.Unlock()
	delete(r.caps, alias)
	if r.capGeneration == nil {
		r.capGeneration = make(map[string]uint64)
	}
	r.capGeneration[alias]++
}

func parseCap(stdout []byte) *hostCap {
	line := bytes.TrimSuffix(stdout, []byte("\n"))
	if bytes.ContainsAny(line, "\r\n") {
		return nil
	}
	var wire struct {
		V           *int    `json:"v"`
		Enforcement *string `json:"enforcement"`
		Pinned      *bool   `json:"pinned"`
		Net         *bool   `json:"net"`
		NetGrants   *bool   `json:"net_grants"`
		Label       string  `json:"label"`
		Reason      string  `json:"reason"`
	}
	if json.Unmarshal(line, &wire) != nil || wire.V == nil || *wire.V != 1 ||
		wire.Enforcement == nil || wire.Pinned == nil || wire.Net == nil || wire.NetGrants == nil {
		return nil
	}
	switch *wire.Enforcement {
	case "kernel", "classifier", "unavailable":
	default:
		return nil
	}
	return &hostCap{V: *wire.V, Enforcement: *wire.Enforcement, Pinned: *wire.Pinned,
		Net: *wire.Net, NetGrants: *wire.NetGrants, Label: wire.Label, Reason: wire.Reason}
}
