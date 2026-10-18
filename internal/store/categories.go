package store

import (
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
