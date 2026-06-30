package store

import (
	"errors"
	"strings"
	"time"
)

// Site is a named group of cluster nodes (e.g. an office or region). Roles
// (primary/backup) within a site are advisory labels — every node still serves
// DNS; clients fail over themselves via resolv.conf / DHCP.
type Site struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	CreatedAt   int64  `json:"created_at"`
}

// Valid node roles within a site. An empty role means "in the site, unlabelled".
const (
	RolePrimary = "primary"
	RoleBackup  = "backup"
)

func normalizeRole(role string) string {
	switch strings.ToLower(strings.TrimSpace(role)) {
	case RolePrimary:
		return RolePrimary
	case RoleBackup:
		return RoleBackup
	default:
		return "" // unlabelled
	}
}

// ListSites returns all sites, alphabetically.
func (s *Store) ListSites() ([]Site, error) {
	rows, err := s.read.Query(`SELECT name, description, created_at FROM sites ORDER BY name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Site{}
	for rows.Next() {
		var si Site
		if err := rows.Scan(&si.Name, &si.Description, &si.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, si)
	}
	return out, rows.Err()
}

// CreateSite adds a site (idempotent on name — updates the description).
func (s *Store) CreateSite(name, description string) error {
	name = strings.TrimSpace(name)
	if name == "" {
		return errors.New("site name is required")
	}
	_, err := s.db.Exec(
		`INSERT INTO sites(name, description, created_at) VALUES(?,?,?)
		 ON CONFLICT(name) DO UPDATE SET description = excluded.description`,
		name, strings.TrimSpace(description), time.Now().Unix())
	return err
}

// DeleteSite removes a site and unassigns any nodes that referenced it (workers
// in the table and, if it pointed there, the master's stored assignment).
func (s *Store) DeleteSite(name string) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	if _, err := tx.Exec(`DELETE FROM sites WHERE name=?`, name); err != nil {
		_ = tx.Rollback()
		return err
	}
	if _, err := tx.Exec(`UPDATE nodes SET site='', role='' WHERE site=?`, name); err != nil {
		_ = tx.Rollback()
		return err
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	if s.MasterSite() == name {
		_ = s.SetMasterSite("", "")
	}
	return nil
}

// SetNodeSite assigns a worker node to a site with a role. Setting a node primary
// demotes any existing primary in that site to backup (one primary per site).
func (s *Store) SetNodeSite(name, site, role string) error {
	site = strings.TrimSpace(site)
	role = normalizeRole(role)
	if site == "" {
		role = "" // unassigned nodes carry no role
	}
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	if site != "" && role == RolePrimary {
		if _, err := tx.Exec(`UPDATE nodes SET role=? WHERE site=? AND role=? AND name<>?`,
			RoleBackup, site, RolePrimary, name); err != nil {
			_ = tx.Rollback()
			return err
		}
		// If the master currently holds primary in this site, demote it too.
		if s.MasterSite() == site && s.MasterRole() == RolePrimary && name != "master" {
			_ = s.SetMasterRoleRaw(RoleBackup)
		}
	}
	res, err := tx.Exec(`UPDATE nodes SET site=?, role=? WHERE name=?`, site, role, name)
	if err != nil {
		_ = tx.Rollback()
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		_ = tx.Rollback()
		return errors.New("node not found")
	}
	return tx.Commit()
}

// app_meta keys for the master's own site assignment (the master isn't a nodes
// row — its membership is synthesized in the API, like its maintenance flag).
const (
	masterSiteKey = "master_site"
	masterRoleKey = "master_role"
)

// MasterSite / MasterRole report the master's site assignment.
func (s *Store) MasterSite() string { v, _ := s.GetMeta(masterSiteKey); return v }
func (s *Store) MasterRole() string { v, _ := s.GetMeta(masterRoleKey); return v }

// SetMasterRoleRaw writes the master's role without touching its site (used when
// demoting it to keep one primary per site).
func (s *Store) SetMasterRoleRaw(role string) error {
	return s.SetMeta(masterRoleKey, normalizeRole(role))
}

// SetMasterSite assigns the master to a site with a role. Like SetNodeSite, a
// primary master demotes the site's existing primary worker.
func (s *Store) SetMasterSite(site, role string) error {
	site = strings.TrimSpace(site)
	role = normalizeRole(role)
	if site == "" {
		role = ""
	}
	if site != "" && role == RolePrimary {
		if _, err := s.db.Exec(`UPDATE nodes SET role=? WHERE site=? AND role=?`,
			RoleBackup, site, RolePrimary); err != nil {
			return err
		}
	}
	if err := s.SetMeta(masterSiteKey, site); err != nil {
		return err
	}
	return s.SetMeta(masterRoleKey, role)
}
