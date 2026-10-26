package store

import (
	"fmt"
	"strings"
	"time"

	"github.com/IPMaze/MazeDNS/internal/categories"
)

// CategoryOverride is an operator's category for a registered domain.
type CategoryOverride struct {
	Domain    string `json:"domain"`
	Category  string `json:"category"`
	SetBy     string `json:"set_by"`
	UpdatedAt int64  `json:"updated_at"` // unix secs
}

// SetCategoryOverride records (or replaces) an operator's category for domain.
func (s *Store) SetCategoryOverride(domain, category, setBy string) error {
	_, err := s.db.Exec(
		`INSERT INTO category_overrides(domain, category, set_by, updated_at) VALUES(?,?,?,?)
		 ON CONFLICT(domain) DO UPDATE SET category=excluded.category, set_by=excluded.set_by, updated_at=excluded.updated_at`,
		domain, category, setBy, time.Now().Unix())
	return err
}

// DeleteCategoryOverride removes an operator's category for domain.
func (s *Store) DeleteCategoryOverride(domain string) error {
	_, err := s.db.Exec(`DELETE FROM category_overrides WHERE domain=?`, domain)
	return err
}

// CategoryOverrides returns every override, by domain.
func (s *Store) CategoryOverrides() (map[string]CategoryOverride, error) {
	rows, err := s.read.Query(`SELECT domain, category, set_by, updated_at FROM category_overrides`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]CategoryOverride{}
	for rows.Next() {
		var o CategoryOverride
		if err := rows.Scan(&o.Domain, &o.Category, &o.SetBy, &o.UpdatedAt); err != nil {
			return nil, err
		}
		out[o.Domain] = o
	}
	return out, rows.Err()
}

// VerdictCategories are the classifier's views of the domains it has scored,
// for labelling: an enforced security verdict (auto-blocked or approved) wins
// over the category database; the model's content category fills in for
// domains the database doesn't know.
type VerdictCategories struct {
	Enforced map[string]string // domain -> security category being blocked
	Content  map[string]string // domain -> the model's content category
}

// ClassifierCategories loads VerdictCategories.
func (s *Store) ClassifierCategories() (VerdictCategories, error) {
	vc := VerdictCategories{Enforced: map[string]string{}, Content: map[string]string{}}
	rows, err := s.read.Query(
		`SELECT domain, category, block, status, content_category FROM classifications`)
	if err != nil {
		return vc, err
	}
	defer rows.Close()
	for rows.Next() {
		var domain, cat, status, content string
		var block bool
		if err := rows.Scan(&domain, &cat, &block, &status, &content); err != nil {
			return vc, err
		}
		if block && (status == ClassAuto || status == ClassApproved) {
			vc.Enforced[domain] = cat
		}
		if content != "" {
			vc.Content[domain] = content
		}
	}
	return vc, rows.Err()
}

// SetContentCategory records the model's content category for a scored domain
// ("" = asked, no usable answer) and marks it as asked.
func (s *Store) SetContentCategory(domain, category string) error {
	_, err := s.db.execUntracked(
		`UPDATE classifications SET content_category=?, content_checked=1 WHERE domain=?`, category, domain)
	return err
}

// UncheckedContent returns up to limit scored domains the model hasn't been
// asked to categorise yet (verdicts from before categories existed).
func (s *Store) UncheckedContent(limit int) ([]string, error) {
	rows, err := s.read.Query(
		`SELECT domain FROM classifications WHERE content_checked=0 ORDER BY updated_at DESC LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var d string
		if err := rows.Scan(&d); err != nil {
			return nil, err
		}
		out = append(out, d)
	}
	return out, rows.Err()
}

// ContentCount is query volume for one content category.
type ContentCount struct {
	Category string `json:"category"`
	Count    int64  `json:"count"`
	Blocked  int64  `json:"blocked"`
}

// RollupByCategory returns query volume by content category since sinceMs
// (hour granularity), largest first.
func (s *Store) RollupByCategory(sinceMs int64, nodes []string) ([]ContentCount, error) {
	nf, nargs := nodeFilterSQL(nodes)
	rows, err := s.read.Query(
		`SELECT category, SUM(cnt), SUM(blocked) FROM category_rollup WHERE hour >= ?`+nf+`
		 GROUP BY category ORDER BY SUM(cnt) DESC`,
		append([]any{sinceMs / 3600000}, nargs...)...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []ContentCount{}
	for rows.Next() {
		var c ContentCount
		if err := rows.Scan(&c.Category, &c.Count, &c.Blocked); err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// moveVerdictContentCategories finishes the move of content labels off the
// classifier's verdicts. Before domain categories, a verdict that didn't block
// carried the model's content label (social, streaming, …) as its category, and
// allowing a domain took one too. That now lives in content_category; a
// verdict's category is only ever the reason it blocks, or "other". Idempotent:
// nothing matches once moved.
func (s *Store) moveVerdictContentCategories() error {
	var ids []string
	var args []any
	for _, c := range categories.Content() {
		if c == categories.Other {
			continue
		}
		ids = append(ids, "?")
		args = append(args, c)
	}
	_, err := s.db.Exec(
		`UPDATE classifications
		 SET content_category = CASE WHEN content_category = '' THEN category ELSE content_category END,
		     content_checked = 1,
		     category = 'other'
		 WHERE category IN (`+strings.Join(ids, ",")+`)`, args...)
	return err
}

// UnlabelledQuery is a query-log row still labelled "other" (OtherQueries).
type UnlabelledQuery struct {
	ID     int64
	TS     int64
	Name   string
	Action string
}

// otherQueriesSQL is OtherQueries' statement, with or without the page bound.
// It orders by (ts, id), which the (content_category, ts) index already holds
// (an index ends with the rowid), so a page reads only its own rows: ordering
// by id alone sorted every "other" row in the window for every page.
func otherQueriesSQL(paged bool) string {
	q := `SELECT id, ts, name, action FROM query_log WHERE content_category = ? AND ts >= ?`
	if paged {
		q += ` AND (ts, id) < (?, ?)`
	}
	return q + ` ORDER BY ts DESC, id DESC LIMIT ?`
}

// OtherQueries returns up to limit query-log rows labelled "other" since
// sinceMs, newest first, starting below the (beforeTS, beforeID) of the last
// row of the previous page (beforeID 0 = first page) — a page of the rows
// RelabelContent may move once their domain gets a category.
func (s *Store) OtherQueries(sinceMs, beforeTS, beforeID int64, limit int) ([]UnlabelledQuery, error) {
	args := []any{categories.Other, sinceMs}
	if beforeID > 0 {
		args = append(args, beforeTS, beforeID)
	}
	rows, err := s.read.Query(otherQueriesSQL(beforeID > 0), append(args, limit)...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []UnlabelledQuery
	for rows.Next() {
		var u UnlabelledQuery
		if err := rows.Scan(&u.ID, &u.TS, &u.Name, &u.Action); err != nil {
			return nil, err
		}
		out = append(out, u)
	}
	return out, rows.Err()
}

// relabelChunk bounds the ids in one IN (…) list.
const relabelChunk = 500

// RelabelContent moves query-log rows from "other" to the category each now
// has (id -> category), and the per-hour category rollup with them for rows
// already folded into it, so the dashboard's breakdown changes along with the
// rows. Rows no longer labelled "other" are left alone. Returns how many rows
// moved.
func (s *Store) RelabelContent(labels map[int64]string) (int, error) {
	if len(labels) == 0 {
		return 0, nil
	}
	s.rollupMu.Lock()
	defer s.rollupMu.Unlock()
	cursor, _ := s.GetMetaInt(rollupCursorKey)

	byCat := map[string][]int64{}
	for id, cat := range labels {
		if cat != "" && cat != categories.Other {
			byCat[cat] = append(byCat[cat], id)
		}
	}
	type key struct {
		hour int64
		node string
		cat  string
	}
	type delta struct{ cnt, blocked int64 }
	deltas := map[key]*delta{}
	add := func(k key, cnt, blocked int64) {
		d := deltas[k]
		if d == nil {
			d = &delta{}
			deltas[k] = d
		}
		d.cnt += cnt
		d.blocked += blocked
	}

	tx, err := s.db.Begin()
	if err != nil {
		return 0, err
	}
	fail := func(err error) (int, error) { _ = tx.Rollback(); return 0, err }
	moved := 0
	for cat, ids := range byCat {
		for len(ids) > 0 {
			n := min(len(ids), relabelChunk)
			chunk := ids[:n]
			ids = ids[n:]
			in := strings.TrimSuffix(strings.Repeat("?,", len(chunk)), ",")
			args := make([]any, 0, len(chunk)+2)
			args = append(args, categories.Other)
			for _, id := range chunk {
				args = append(args, id)
			}
			// What the rollup already counts as "other" for these rows.
			rows, err := tx.Query(
				`SELECT ts/3600000, node, COUNT(*), COALESCE(SUM(action='blocked'), 0) FROM query_log
				 WHERE content_category = ? AND id IN (`+in+`) AND id <= ? GROUP BY ts/3600000, node`,
				append(args, cursor)...)
			if err != nil {
				return fail(err)
			}
			for rows.Next() {
				var hour, cnt, blocked int64
				var node string
				if err := rows.Scan(&hour, &node, &cnt, &blocked); err != nil {
					rows.Close()
					return fail(err)
				}
				add(key{hour, node, categories.Other}, -cnt, -blocked)
				add(key{hour, node, cat}, cnt, blocked)
			}
			rows.Close()
			if err := rows.Err(); err != nil {
				return fail(err)
			}
			res, err := tx.Exec(`UPDATE query_log SET content_category = ? WHERE content_category = ? AND id IN (`+in+`)`,
				append([]any{cat}, args...)...)
			if err != nil {
				return fail(err)
			}
			n64, _ := res.RowsAffected()
			moved += int(n64)
		}
	}
	for k, d := range deltas {
		if d.cnt == 0 {
			continue
		}
		if _, err := tx.Exec(
			`INSERT INTO category_rollup(hour, node, category, cnt, blocked) VALUES(?,?,?,?,?)
			 ON CONFLICT(hour, node, category) DO UPDATE SET
			   cnt = category_rollup.cnt + excluded.cnt, blocked = category_rollup.blocked + excluded.blocked`,
			k.hour, k.node, k.cat, d.cnt, d.blocked); err != nil {
			return fail(fmt.Errorf("move rollup counts: %w", err))
		}
	}
	if _, err := tx.Exec(`DELETE FROM category_rollup WHERE category = ? AND cnt <= 0`, categories.Other); err != nil {
		return fail(err)
	}
	return moved, tx.Commit()
}
