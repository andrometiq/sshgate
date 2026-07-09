package tools

import (
	"context"
	"errors"
	"sort"
	"time"
)

// ListServersInput is the JSON input to the sshgate.list_servers tool.
// The tool takes no parameters; the empty struct keeps the SDK's
// schema-derivation machinery happy.
type ListServersInput struct{}

// ServerInfo is one row in a ListServersOutput. AddedAt and LastSeen
// are RFC3339 strings (omitted when zero) so the structured output is
// directly readable by Claude without an extra time-parsing step.
// ReadOnly surfaces the server's TIER from the registry (true = Tier-1
// read-only, writes denied at the gate; false/absent = signed-write),
// so the agent can tell a server's tier before attempting a write
// (W3-7).
type ServerInfo struct {
	Alias    string `json:"alias"`
	Host     string `json:"host"`
	Port     int    `json:"port"`
	User     string `json:"user"`
	AddedAt  string `json:"added_at"`
	LastSeen string `json:"last_seen,omitempty"`
	ReadOnly bool   `json:"read_only,omitempty"`
}

// ListServersOutput is the structured result of sshgate.list_servers.
// Servers is sorted alphabetically by alias so the order is stable
// across calls — Claude can refer to the same server by index in a
// follow-up.
type ListServersOutput struct {
	Servers []ServerInfo `json:"servers"`
	Total   int          `json:"total"`
}

// ListServers returns every registered alias with its connection
// details. v1 does not track last-seen timestamps; the field is left
// empty and may be populated in v1.1.
func (r *Runner) ListServers(_ context.Context, _ ListServersInput) (ListServersOutput, error) {
	if r.Servers == nil {
		return ListServersOutput{}, errors.New("tools: Servers is nil")
	}
	raw := r.Servers.List()
	aliases := make([]string, 0, len(raw))
	for a := range raw {
		aliases = append(aliases, a)
	}
	sort.Strings(aliases)

	out := ListServersOutput{
		Servers: make([]ServerInfo, 0, len(aliases)),
		Total:   len(aliases),
	}
	for _, alias := range aliases {
		e := raw[alias]
		out.Servers = append(out.Servers, ServerInfo{
			Alias:    alias,
			Host:     e.Host,
			Port:     e.Port,
			User:     e.User,
			AddedAt:  e.AddedAt.UTC().Format(time.RFC3339),
			ReadOnly: e.ReadOnly,
		})
	}
	return out, nil
}
