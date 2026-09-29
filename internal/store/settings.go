package store

import (
	"database/sql"
	"errors"
)

// GetSettings returns the stored operational-settings JSON, or "" if none has
// been saved yet.
func (s *Store) GetSettings() (string, error) {
	var data string
	err := s.read.QueryRow(`SELECT data FROM settings WHERE id=1`).Scan(&data)
	if errors.Is(err, sql.ErrNoRows) {
		return "", nil
	}
	return data, err
}

// clusterSettingsMeta is the app_meta key under which an AGENT persists the
// central resolver settings it last received (raw snapshot JSON), so boot works
// offline with them.
const clusterSettingsMeta = "cluster_settings"

// ClusterSettings returns the central settings JSON persisted on this agent
// ("" on the control plane, on standalone nodes and before the first sync).
func (s *Store) ClusterSettings() (string, error) { return s.GetMeta(clusterSettingsMeta) }

// SetClusterSettings persists the central settings JSON on this agent.
func (s *Store) SetClusterSettings(raw string) error { return s.SetMeta(clusterSettingsMeta, raw) }

// SaveSettings persists the operational-settings JSON as the single settings row.
func (s *Store) SaveSettings(data string) error {
	_, err := s.db.Exec(
		`INSERT INTO settings(id, data) VALUES(1, ?) ON CONFLICT(id) DO UPDATE SET data=excluded.data`,
		data)
	return err
}
