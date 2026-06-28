package netbird

import (
	"encoding/json"

	"github.com/IPMaze/MazeDNS/internal/store"
)

// ResolversKey is the app_meta key under which the per-node internal DNS resolvers
// are persisted, as a JSON map of node name -> resolver address (ip or ip:port).
// Reverse-DNS for a client uses the resolver of the node that serves it, since
// nodes can be in different sites/LANs.
const ResolversKey = "reverse_dns_resolvers"

// LoadResolvers reads the per-node resolver map (empty map when unset).
func LoadResolvers(st *store.Store) map[string]string {
	m := map[string]string{}
	if raw, err := st.GetMeta(ResolversKey); err == nil && raw != "" {
		_ = json.Unmarshal([]byte(raw), &m)
	}
	return m
}

// SaveResolvers persists the per-node resolver map.
func SaveResolvers(st *store.Store, m map[string]string) error {
	b, err := json.Marshal(m)
	if err != nil {
		return err
	}
	return st.SetMeta(ResolversKey, string(b))
}
