package netbird

import (
	"encoding/json"
	"strings"

	"github.com/IPMaze/MazeDNS/internal/store"
)

// ClientNamesKey is the app_meta key under which operator-assigned static client
// hostnames are persisted, as a JSON map of client IP -> hostname. These take
// priority over NetBird peer names and reverse-DNS, so a static host that isn't a
// NetBird peer and has no PTR record can still be labelled everywhere.
const ClientNamesKey = "client_names"

// LoadClientNames reads the manual client-name map (empty map when unset).
func LoadClientNames(st *store.Store) map[string]string {
	m := map[string]string{}
	if st == nil {
		return m
	}
	if raw, err := st.GetMeta(ClientNamesKey); err == nil && raw != "" {
		_ = json.Unmarshal([]byte(raw), &m)
	}
	return m
}

// SaveClientName sets (or, with an empty name, clears) the manual hostname for a
// client IP and persists the whole map.
func SaveClientName(st *store.Store, ip, name string) error {
	ip = strings.TrimSpace(ip)
	name = strings.TrimSpace(name)
	m := LoadClientNames(st)
	if name == "" {
		delete(m, ip)
	} else {
		m[ip] = name
	}
	b, err := json.Marshal(m)
	if err != nil {
		return err
	}
	return st.SetMeta(ClientNamesKey, string(b))
}
