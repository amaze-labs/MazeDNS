package store

import (
	"database/sql"
	"errors"
)

// GetSettings returns the stored operational-settings JSON, or "" if none has
// been saved yet.
func (s *Store) GetSettings() (string, error) {
	var data string
	err := s.db.QueryRow(`SELECT data FROM settings WHERE id=1`).Scan(&data)
	if errors.Is(err, sql.ErrNoRows) {
		return "", nil
	}
	return data, err
}

// SaveSettings persists the operational-settings JSON as the single settings row.
func (s *Store) SaveSettings(data string) error {
	_, err := s.db.Exec(
		`INSERT INTO settings(id, data) VALUES(1, ?) ON CONFLICT(id) DO UPDATE SET data=excluded.data`,
		data)
	return err
}
