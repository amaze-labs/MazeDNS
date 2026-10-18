package store

import (
	"encoding/json"
	"errors"
	"strings"
	"time"
)

// Site is a named group of cluster nodes (e.g. an office or region). Roles
// (primary/secondary/backup) within a site are advisory labels — every node
// still serves DNS; clients fail over themselves via resolv.conf / DHCP.
type Site struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	CreatedAt   int64  `json:"created_at"`
}

// Valid node roles within a site. An empty role means "in the site, unlabelled".
const (
	RolePrimary   = "primary"
	RoleSecondary = "secondary"
	RoleBackup    = "backup"
)

func normalizeRole(role string) string {
	switch strings.ToLower(strings.TrimSpace(role)) {
	case RolePrimary:
		return RolePrimary
	case RoleSecondary:
		return RoleSecondary
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

// ErrSiteExists is returned when renaming a site to a name already in use.
var ErrSiteExists = errors.New("a site with that name already exists")

// UpdateSite renames a site and sets its description. A rename carries
// everything that refers to the site by name: its agents (with their roles),
// the master's assignment, and rewrites and forwarders scoped to it — so a
// renamed site keeps exactly the rules it had. A site known only from its
// agents (no sites row) gets one.
func (s *Store) UpdateSite(oldName, newName, description string) error {
	newName = strings.TrimSpace(newName)
	description = strings.TrimSpace(description)
	if newName == "" {
		return errors.New("site name is required")
	}
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	fail := func(err error) error { _ = tx.Rollback(); return err }
	if newName != oldName {
		var taken int
		if err := tx.QueryRow(
			`SELECT (SELECT COUNT(*) FROM sites WHERE name=?) + (SELECT COUNT(*) FROM nodes WHERE site=?)`,
			newName, newName).Scan(&taken); err != nil {
			return fail(err)
		}
		if taken > 0 || s.MasterSite() == newName {
			return fail(ErrSiteExists)
		}
	}
	res, err := tx.Exec(`UPDATE sites SET name=?, description=? WHERE name=?`, newName, description, oldName)
	if err != nil {
		return fail(err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		var used int
		if err := tx.QueryRow(`SELECT COUNT(*) FROM nodes WHERE site=?`, oldName).Scan(&used); err != nil {
			return fail(err)
		}
		if used == 0 && s.MasterSite() != oldName {
			return fail(errors.New("site not found"))
		}
		if _, err := tx.Exec(`INSERT INTO sites(name, description, created_at) VALUES(?,?,?)`,
			newName, description, time.Now().Unix()); err != nil {
			return fail(err)
		}
	}
	if newName != oldName {
		if _, err := tx.Exec(`UPDATE nodes SET site=? WHERE site=?`, newName, oldName); err != nil {
			return fail(err)
		}
		for _, table := range []string{"rewrites", "forwarders"} {
			if err := renameScopedSite(tx, table, oldName, newName); err != nil {
				return fail(err)
			}
		}
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	if newName != oldName && s.MasterSite() == oldName {
		return s.SetMeta(masterSiteKey, newName)
	}
	return nil
}

// renameScopedSite rewrites the site-scoped entries of table that name
// oldName, keeping each scope canonical (sorted, deduped).
func renameScopedSite(tx *txh, table, oldName, newName string) error {
	rows, err := tx.Query(`SELECT id, scope_values FROM `+table+` WHERE scope_type=?`, ScopeSites)
	if err != nil {
		return err
	}
	type upd struct {
		id   int64
		vals string
	}
	var todo []upd
	for rows.Next() {
		var id int64
		var raw string
		if err := rows.Scan(&id, &raw); err != nil {
			rows.Close()
			return err
		}
		if !scopeContains(raw, oldName) {
			continue
		}
		var vals []string
		_ = json.Unmarshal([]byte(raw), &vals)
		for i, v := range vals {
			if v == oldName {
				vals[i] = newName
			}
		}
		_, canon, err := CanonicalScope(ScopeSites, vals)
		if err != nil {
			rows.Close()
			return err
		}
		todo = append(todo, upd{id, canon})
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}
	for _, u := range todo {
		if _, err := tx.Exec(`UPDATE `+table+` SET scope_values=? WHERE id=?`, u.vals, u.id); err != nil {
			return err
		}
	}
	return nil
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

// SetNodeSite assigns a worker node (by immutable id) to a site with a role.
// Setting a node primary demotes any existing primary in that site to secondary
// (one primary per site).
func (s *Store) SetNodeSite(id, site, role string) error {
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
		if _, err := tx.Exec(`UPDATE nodes SET role=? WHERE site=? AND role=? AND id<>?`,
			RoleSecondary, site, RolePrimary, id); err != nil {
			_ = tx.Rollback()
			return err
		}
		// If the master currently holds primary in this site, demote it too.
		if s.MasterSite() == site && s.MasterRole() == RolePrimary {
			_ = s.SetMasterRoleRaw(RoleSecondary)
		}
	}
	res, err := tx.Exec(`UPDATE nodes SET site=?, role=? WHERE id=?`, site, role, id)
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
			RoleSecondary, site, RolePrimary); err != nil {
			return err
		}
	}
	if err := s.SetMeta(masterSiteKey, site); err != nil {
		return err
	}
	return s.SetMeta(masterRoleKey, role)
}
