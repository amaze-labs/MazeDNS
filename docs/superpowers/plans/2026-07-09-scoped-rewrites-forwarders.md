# Scoped Rewrites & Central Conditional Forwarders Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Rewrites and (new) centrally-managed conditional forwarders can be scoped to all nodes, specific nodes, or sites; the control plane filters per node at snapshot-serve time so agents stay scope-free.

**Architecture:** Scope metadata (`scope_type` + `scope_values`) lives only in the control plane's DB. The authenticated `/api/cluster/snapshot` handler filters rewrites/forwarders per calling node and computes a per-node content hash. Agents persist received forwarders as an `app_meta` JSON blob, include it in their own hash (drift detection unchanged), and merge central forwarders over local settings (central wins per suffix) at apply time only.

**Tech Stack:** Go 1.x (`modernc.org/sqlite` + optional Postgres via dialect adapter), React/TypeScript UI in `web/`, plain `net/http` mux API.

**Spec:** `docs/superpowers/specs/2026-07-09-scoped-rewrites-forwarders-design.md`

## Global Constraints

- Scope types are exactly `'all' | 'nodes' | 'sites'`; `scope_values` is a canonically sorted, deduped JSON array stored as TEXT.
- Precedence: node-scoped > site-scoped > all. Same-specificity overlaps (intersecting node lists / intersecting site lists for the same domain+rrtype or suffix) are rejected at write time with HTTP 409.
- Agents receive scope-free entries; agent DB schema and `ApplySnapshot` rewrites path stay unchanged. Old agents must keep working when no central forwarders exist.
- Hash line formats: `R|action|domain|category|enabled`, `W|domain|rrtype|value|enabled` (both unchanged), new `F|suffix|up1,up2` (enabled-only forwarders; disabled entries are excluded from serving AND hashing).
- The control plane never serves DNS; nothing applies to itself.
- All SQL must go through the dialect-aware `s.db`/`s.read` handles (`?` placeholders; translated for Postgres automatically).
- Run `go test ./...` from the repo root; it must pass before every commit. Also `go vet ./...`.
- Commit messages follow the repo style (`feat(store): …`, `feat(api): …`, etc.) and end with `Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>`.

---

### Task 1: Scope primitives (`internal/store/scope.go`)

**Files:**
- Create: `internal/store/scope.go`
- Test: `internal/store/scope_test.go`

**Interfaces:**
- Consumes: nothing (pure functions + one type).
- Produces (used by Tasks 2–4, 7, 8):
  - `const ScopeAll = "all"; ScopeNodes = "nodes"; ScopeSites = "sites"`
  - `func CanonicalScope(scopeType string, values []string) (string, string, error)` → normalized type, canonical JSON array string, error
  - `func ScopeMatches(scopeType, valuesJSON, nodeName, nodeSite string) bool`
  - `func scopeRank(scopeType string) int` (all=1, sites=2, nodes=3)
  - `func scopeValuesIntersect(aJSON, bJSON string) bool`
  - `type ForwardSpec struct { Suffix string; Upstreams []string }`

- [ ] **Step 1: Write the failing test**

Create `internal/store/scope_test.go`:

```go
package store

import "testing"

func TestCanonicalScope(t *testing.T) {
	// Empty type defaults to all; values are ignored for 'all'.
	st, vals, err := CanonicalScope("", nil)
	if err != nil || st != ScopeAll || vals != "[]" {
		t.Fatalf("default: got (%q,%q,%v), want (all,[],nil)", st, vals, err)
	}
	// Values are trimmed, deduped, sorted -> canonical JSON.
	st, vals, err = CanonicalScope("nodes", []string{" b ", "a", "b", ""})
	if err != nil || st != ScopeNodes || vals != `["a","b"]` {
		t.Fatalf("canonical: got (%q,%q,%v), want (nodes,[\"a\",\"b\"],nil)", st, vals, err)
	}
	// A scoped type with no values is an error.
	if _, _, err := CanonicalScope("sites", []string{"  "}); err == nil {
		t.Fatal("sites with no values should error")
	}
	// Unknown types are errors.
	if _, _, err := CanonicalScope("bogus", []string{"x"}); err == nil {
		t.Fatal("unknown scope type should error")
	}
}

func TestScopeMatches(t *testing.T) {
	cases := []struct {
		st, vals, name, site string
		want                 bool
	}{
		{ScopeAll, "[]", "n1", "", true},
		{ScopeNodes, `["n1","n2"]`, "n1", "", true},
		{ScopeNodes, `["n2"]`, "n1", "", false},
		{ScopeSites, `["office"]`, "n1", "office", true},
		{ScopeSites, `["office"]`, "n1", "lab", false},
		{ScopeSites, `["office"]`, "n1", "", false}, // unassigned node matches no site scope
	}
	for _, c := range cases {
		if got := ScopeMatches(c.st, c.vals, c.name, c.site); got != c.want {
			t.Errorf("ScopeMatches(%q,%q,%q,%q) = %v, want %v", c.st, c.vals, c.name, c.site, got, c.want)
		}
	}
}

func TestScopeValuesIntersect(t *testing.T) {
	if !scopeValuesIntersect(`["a","b"]`, `["b","c"]`) {
		t.Fatal("expected intersection on b")
	}
	if scopeValuesIntersect(`["a"]`, `["b"]`) {
		t.Fatal("expected no intersection")
	}
}

func TestScopeRank(t *testing.T) {
	if !(scopeRank(ScopeNodes) > scopeRank(ScopeSites) && scopeRank(ScopeSites) > scopeRank(ScopeAll)) {
		t.Fatal("rank order must be nodes > sites > all")
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/store/ -run 'TestCanonicalScope|TestScopeMatches|TestScopeValuesIntersect|TestScopeRank' -v`
Expected: FAIL (compile error: `CanonicalScope` undefined).

- [ ] **Step 3: Write the implementation**

Create `internal/store/scope.go`:

```go
package store

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
)

// Scope types for rewrites and forwarders. Scope metadata exists only on the
// control plane: agents receive per-node pre-filtered, scope-free entries.
const (
	ScopeAll   = "all"   // every node
	ScopeNodes = "nodes" // an explicit list of node names
	ScopeSites = "sites" // one or more sites (named node groups)
)

// ForwardSpec is the lean forwarder shape replicated to agents and hashed into
// the config version: just the routing fact, no scope, no enabled flag
// (disabled entries are never served).
type ForwardSpec struct {
	Suffix    string   `json:"suffix"`
	Upstreams []string `json:"upstreams"`
}

// CanonicalScope validates a scope and returns its normalized type plus the
// canonical JSON encoding of its values (trimmed, deduped, sorted — so equal
// scopes always serialize identically, which the UNIQUE constraints rely on).
func CanonicalScope(scopeType string, values []string) (string, string, error) {
	switch scopeType {
	case "", ScopeAll:
		return ScopeAll, "[]", nil
	case ScopeNodes, ScopeSites:
	default:
		return "", "", fmt.Errorf("scope_type must be all, nodes, or sites")
	}
	seen := map[string]bool{}
	out := make([]string, 0, len(values))
	for _, v := range values {
		v = strings.TrimSpace(v)
		if v == "" || seen[v] {
			continue
		}
		seen[v] = true
		out = append(out, v)
	}
	if len(out) == 0 {
		return "", "", fmt.Errorf("scope_values required for scope_type %q", scopeType)
	}
	sort.Strings(out)
	b, err := json.Marshal(out)
	if err != nil {
		return "", "", err
	}
	return scopeType, string(b), nil
}

// scopeRank orders scopes by specificity: node-scoped beats site-scoped beats all.
func scopeRank(scopeType string) int {
	switch scopeType {
	case ScopeNodes:
		return 3
	case ScopeSites:
		return 2
	default:
		return 1
	}
}

// ScopeMatches reports whether an entry with the given scope applies to a node.
func ScopeMatches(scopeType, valuesJSON, nodeName, nodeSite string) bool {
	switch scopeType {
	case ScopeNodes:
		return scopeContains(valuesJSON, nodeName)
	case ScopeSites:
		return nodeSite != "" && scopeContains(valuesJSON, nodeSite)
	default: // "" or "all"
		return true
	}
}

func scopeContains(valuesJSON, want string) bool {
	var vals []string
	if json.Unmarshal([]byte(valuesJSON), &vals) != nil {
		return false
	}
	for _, v := range vals {
		if v == want {
			return true
		}
	}
	return false
}

// scopeValuesIntersect reports whether two canonical value lists share a member —
// the write-time overlap check that keeps same-specificity winners unique.
func scopeValuesIntersect(aJSON, bJSON string) bool {
	var a, b []string
	if json.Unmarshal([]byte(aJSON), &a) != nil || json.Unmarshal([]byte(bJSON), &b) != nil {
		return false
	}
	set := make(map[string]bool, len(a))
	for _, v := range a {
		set[v] = true
	}
	for _, v := range b {
		if set[v] {
			return true
		}
	}
	return false
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/store/ -run 'TestCanonicalScope|TestScopeMatches|TestScopeValuesIntersect|TestScopeRank' -v`
Expected: PASS (4 tests).

- [ ] **Step 5: Commit**

```bash
git add internal/store/scope.go internal/store/scope_test.go
git commit -m "feat(store): scope primitives for node/site-scoped config"
```

---

### Task 2: Rewrites schema migration + scoped CRUD

**Files:**
- Modify: `internal/store/store.go` (Rewrite struct ~line 39; `rewrites` DDL ~line 125; `migrate()` ~line 276; ListRewrites/AddRewrite/AddRewritesBulk ~lines 406–469)
- Test: `internal/store/scope_test.go` (append), `internal/store/store_test.go` is untouched but must keep passing

**Interfaces:**
- Consumes: `CanonicalScope`, `ScopeAll` (Task 1).
- Produces (used by Tasks 4, 7, 10):
  - `Rewrite` gains `ScopeType string \`json:"scope_type,omitempty"\`` and `ScopeValues []string \`json:"scope_values,omitempty"\``
  - `func (s *Store) AddRewriteScoped(domain, rrtype, value, scopeType string, scopeValues []string) (int64, error)`
  - `func (s *Store) AddRewrite(domain, rrtype, value string) (int64, error)` — unchanged signature, now = scoped add with `ScopeAll`
  - `func (s *Store) UpdateRewrite(id int64, value string, enabled bool, scopeType string, scopeValues []string) error`
  - `func (s *Store) RewriteScopeConflict(domain, rrtype, scopeType, valuesJSON string, excludeID int64) (bool, error)`
  - `ListRewrites()` now returns scope fields populated.

- [ ] **Step 1: Write the failing tests** (append to `internal/store/scope_test.go`)

```go
package store // (already declared; append below existing tests)

import (
	"database/sql"
	"path/filepath"
	"testing"
)
// NOTE: merge these imports into the existing import block.

func TestScopedRewritesSplitHorizon(t *testing.T) {
	s, err := Open(filepath.Join(t.TempDir(), "t.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	// Same domain+rrtype under two different site scopes must coexist.
	if _, err := s.AddRewriteScoped("nas.home", "A", "10.0.0.5", ScopeSites, []string{"site-a"}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.AddRewriteScoped("nas.home", "A", "192.168.1.5", ScopeSites, []string{"site-b"}); err != nil {
		t.Fatalf("split-horizon insert rejected: %v", err)
	}
	// Re-adding the same domain+scope upserts (no third row).
	if _, err := s.AddRewriteScoped("nas.home", "A", "10.0.0.6", ScopeSites, []string{"site-a"}); err != nil {
		t.Fatal(err)
	}
	rws, err := s.ListRewrites()
	if err != nil || len(rws) != 2 {
		t.Fatalf("want 2 rewrites, got %d (err=%v)", len(rws), err)
	}
	// Scope fields round-trip through ListRewrites.
	found := false
	for _, r := range rws {
		if r.Value == "10.0.0.6" {
			found = true
			if r.ScopeType != ScopeSites || len(r.ScopeValues) != 1 || r.ScopeValues[0] != "site-a" {
				t.Fatalf("scope not round-tripped: %+v", r)
			}
		}
	}
	if !found {
		t.Fatal("upserted value not found")
	}

	// Legacy AddRewrite still works and lands in scope 'all'.
	if _, err := s.AddRewrite("printer.lan", "A", "10.0.0.9"); err != nil {
		t.Fatal(err)
	}

	// UpdateRewrite edits value/enabled/scope in place.
	id := rws[0].ID
	if err := s.UpdateRewrite(id, "10.9.9.9", false, ScopeNodes, []string{"n1"}); err != nil {
		t.Fatal(err)
	}
	rws, _ = s.ListRewrites()
	var got *Rewrite
	for i := range rws {
		if rws[i].ID == id {
			got = &rws[i]
		}
	}
	if got == nil || got.Value != "10.9.9.9" || got.Enabled || got.ScopeType != ScopeNodes {
		t.Fatalf("update not applied: %+v", got)
	}
}

func TestRewriteScopeConflict(t *testing.T) {
	s, err := Open(filepath.Join(t.TempDir(), "t.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	id, err := s.AddRewriteScoped("app.corp", "A", "10.1.1.1", ScopeSites, []string{"a", "b"})
	if err != nil {
		t.Fatal(err)
	}
	// Intersecting site lists at the same specificity conflict.
	if c, _ := s.RewriteScopeConflict("app.corp", "A", ScopeSites, `["b","c"]`, 0); !c {
		t.Fatal("expected conflict on intersecting site lists")
	}
	// Disjoint lists don't.
	if c, _ := s.RewriteScopeConflict("app.corp", "A", ScopeSites, `["c"]`, 0); c {
		t.Fatal("disjoint site lists must not conflict")
	}
	// Different specificity doesn't conflict (precedence resolves it).
	if c, _ := s.RewriteScopeConflict("app.corp", "A", ScopeNodes, `["b"]`, 0); c {
		t.Fatal("node scope must not conflict with site scope")
	}
	// The row itself is excluded when editing.
	if c, _ := s.RewriteScopeConflict("app.corp", "A", ScopeSites, `["a","b"]`, id); c {
		t.Fatal("row must not conflict with itself when excluded")
	}
}

// An existing pre-scope database is rebuilt in place: rows preserved, scope
// defaulted to 'all', and the relaxed unique key allows split-horizon rows.
func TestRewritesScopeMigration(t *testing.T) {
	path := filepath.Join(t.TempDir(), "old.db")
	raw, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := raw.Exec(`CREATE TABLE rewrites (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		domain TEXT NOT NULL, rrtype TEXT NOT NULL, value TEXT NOT NULL,
		enabled INTEGER NOT NULL DEFAULT 1, updated_at INTEGER NOT NULL,
		UNIQUE(domain, rrtype))`); err != nil {
		t.Fatal(err)
	}
	if _, err := raw.Exec(`INSERT INTO rewrites(domain, rrtype, value, enabled, updated_at) VALUES('old.lan','A','1.2.3.4',1,42)`); err != nil {
		t.Fatal(err)
	}
	raw.Close()

	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	rws, err := s.ListRewrites()
	if err != nil || len(rws) != 1 || rws[0].Domain != "old.lan" || rws[0].ScopeType != ScopeAll {
		t.Fatalf("migrated row wrong: %+v err=%v", rws, err)
	}
	// The relaxed key now permits a second scope for the same domain+rrtype.
	if _, err := s.AddRewriteScoped("old.lan", "A", "5.6.7.8", ScopeNodes, []string{"n1"}); err != nil {
		t.Fatalf("post-migration split-horizon insert failed: %v", err)
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./internal/store/ -run 'TestScopedRewrites|TestRewriteScopeConflict|TestRewritesScopeMigration' -v`
Expected: FAIL (compile error: `AddRewriteScoped` undefined).

- [ ] **Step 3: Implement**

In `internal/store/store.go`:

3a. Extend the `Rewrite` struct (~line 39):

```go
// Rewrite is a local DNS record override. Scope fields exist only on the
// control plane (agents receive pre-filtered, scope-free entries): ScopeType
// is all|nodes|sites and ScopeValues the node/site names it applies to.
type Rewrite struct {
	ID          int64    `json:"id"`
	Domain      string   `json:"domain"`
	RRType      string   `json:"rrtype"` // "A" | "AAAA" | "CNAME"
	Value       string   `json:"value"`
	Enabled     bool     `json:"enabled"`
	UpdatedAt   int64    `json:"updated_at"`
	ScopeType   string   `json:"scope_type,omitempty"`
	ScopeValues []string `json:"scope_values,omitempty"`
}
```

3b. Replace the `rewrites` DDL inside `sqliteSchema` (~line 125) with:

```sql
CREATE TABLE IF NOT EXISTS rewrites (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	domain TEXT NOT NULL,
	rrtype TEXT NOT NULL,
	value TEXT NOT NULL,
	enabled INTEGER NOT NULL DEFAULT 1,
	updated_at INTEGER NOT NULL,
	scope_type TEXT NOT NULL DEFAULT 'all',
	scope_values TEXT NOT NULL DEFAULT '[]',
	UNIQUE(domain, rrtype, scope_type, scope_values)
);
```

3c. In `migrate()` (~line 276), right after the schema loop and BEFORE the additive-ALTER loop, add:

```go
	if err := s.migrateRewritesScope(); err != nil {
		return err
	}
```

and add the method:

```go
// migrateRewritesScope relaxes the pre-scope UNIQUE(domain, rrtype) key to
// UNIQUE(domain, rrtype, scope_type, scope_values). SQLite can't alter a
// table constraint, so the table is rebuilt in place; Postgres swaps the
// constraint directly. Detected by probing for the scope_type column.
func (s *Store) migrateRewritesScope() error {
	if _, err := s.db.Exec(`SELECT scope_type FROM rewrites LIMIT 1`); err == nil {
		return nil // already migrated (or fresh schema)
	}
	var stmts []string
	if s.db.pg {
		stmts = []string{
			`ALTER TABLE rewrites ADD COLUMN scope_type TEXT NOT NULL DEFAULT 'all'`,
			`ALTER TABLE rewrites ADD COLUMN scope_values TEXT NOT NULL DEFAULT '[]'`,
			`ALTER TABLE rewrites DROP CONSTRAINT IF EXISTS rewrites_domain_rrtype_key`,
			`ALTER TABLE rewrites ADD CONSTRAINT rewrites_domain_rrtype_scope_key UNIQUE (domain, rrtype, scope_type, scope_values)`,
		}
	} else {
		stmts = []string{
			`CREATE TABLE rewrites_new (
				id INTEGER PRIMARY KEY AUTOINCREMENT,
				domain TEXT NOT NULL,
				rrtype TEXT NOT NULL,
				value TEXT NOT NULL,
				enabled INTEGER NOT NULL DEFAULT 1,
				updated_at INTEGER NOT NULL,
				scope_type TEXT NOT NULL DEFAULT 'all',
				scope_values TEXT NOT NULL DEFAULT '[]',
				UNIQUE(domain, rrtype, scope_type, scope_values))`,
			`INSERT INTO rewrites_new(id, domain, rrtype, value, enabled, updated_at)
				SELECT id, domain, rrtype, value, enabled, updated_at FROM rewrites`,
			`DROP TABLE rewrites`,
			`ALTER TABLE rewrites_new RENAME TO rewrites`,
		}
	}
	for _, q := range stmts {
		if _, err := s.db.Exec(q); err != nil {
			return fmt.Errorf("migrate rewrites scope: %w", err)
		}
	}
	return nil
}
```

3d. Update `ListRewrites` to scan the scope columns:

```go
// ListRewrites returns all rewrites ordered by domain.
func (s *Store) ListRewrites() ([]Rewrite, error) {
	rows, err := s.read.Query(`SELECT id, domain, rrtype, value, enabled, updated_at, scope_type, scope_values FROM rewrites ORDER BY domain`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Rewrite
	for rows.Next() {
		var r Rewrite
		var valsJSON string
		if err := rows.Scan(&r.ID, &r.Domain, &r.RRType, &r.Value, &r.Enabled, &r.UpdatedAt, &r.ScopeType, &valsJSON); err != nil {
			return nil, err
		}
		_ = json.Unmarshal([]byte(valsJSON), &r.ScopeValues)
		out = append(out, r)
	}
	return out, rows.Err()
}
```

(add `"encoding/json"` to store.go's imports.)

3e. Replace `AddRewrite` and add the scoped variants:

```go
// AddRewriteScoped inserts or updates a rewrite under a specific scope and
// returns its id. The scope is canonicalized so equal scopes hit the same row.
func (s *Store) AddRewriteScoped(domain, rrtype, value, scopeType string, scopeValues []string) (int64, error) {
	st, vals, err := CanonicalScope(scopeType, scopeValues)
	if err != nil {
		return 0, err
	}
	now := time.Now().Unix()
	if _, err := s.db.Exec(
		`INSERT INTO rewrites(domain, rrtype, value, enabled, updated_at, scope_type, scope_values) VALUES(?,?,?,1,?,?,?)
		 ON CONFLICT(domain, rrtype, scope_type, scope_values) DO UPDATE SET value=excluded.value, enabled=1, updated_at=excluded.updated_at`,
		domain, rrtype, value, now, st, vals,
	); err != nil {
		return 0, err
	}
	var id int64
	err = s.read.QueryRow(`SELECT id FROM rewrites WHERE domain=? AND rrtype=? AND scope_type=? AND scope_values=?`,
		domain, rrtype, st, vals).Scan(&id)
	return id, err
}

// AddRewrite inserts or updates a cluster-wide ('all' scope) rewrite.
func (s *Store) AddRewrite(domain, rrtype, value string) (int64, error) {
	return s.AddRewriteScoped(domain, rrtype, value, ScopeAll, nil)
}

// UpdateRewrite edits a rewrite's value, enabled flag, and scope in place.
func (s *Store) UpdateRewrite(id int64, value string, enabled bool, scopeType string, scopeValues []string) error {
	st, vals, err := CanonicalScope(scopeType, scopeValues)
	if err != nil {
		return err
	}
	res, err := s.db.Exec(`UPDATE rewrites SET value=?, enabled=?, scope_type=?, scope_values=?, updated_at=? WHERE id=?`,
		value, boolToInt(enabled), st, vals, time.Now().Unix(), id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return errors.New("rewrite not found")
	}
	return nil
}

// RewriteScopeConflict reports whether another rewrite for the same
// domain+rrtype at the SAME specificity would match an overlapping set of
// nodes — precedence can't break that tie, so writes must reject it.
// valuesJSON must already be canonical (from CanonicalScope). excludeID
// skips the row being edited.
func (s *Store) RewriteScopeConflict(domain, rrtype, scopeType, valuesJSON string, excludeID int64) (bool, error) {
	if scopeType == ScopeAll {
		return false, nil // the UNIQUE key already enforces a single 'all' row
	}
	rows, err := s.read.Query(
		`SELECT id, scope_values FROM rewrites WHERE domain=? AND rrtype=? AND scope_type=?`,
		domain, rrtype, scopeType)
	if err != nil {
		return false, err
	}
	defer rows.Close()
	for rows.Next() {
		var id int64
		var vals string
		if err := rows.Scan(&id, &vals); err != nil {
			return false, err
		}
		if id != excludeID && vals != valuesJSON && scopeValuesIntersect(vals, valuesJSON) {
			return true, nil
		}
	}
	return false, rows.Err()
}
```

(`boolToInt` already exists in the store package — it's used by `SetNodeMaintenance`. Add `"errors"` to store.go's imports if missing.)

3f. Update `AddRewritesBulk` to carry scope (bundle import path):

```go
// AddRewritesBulk inserts/updates many rewrites in one transaction, returning the count applied.
func (s *Store) AddRewritesBulk(rws []Rewrite) (int, error) {
	if len(rws) == 0 {
		return 0, nil
	}
	tx, err := s.db.Begin()
	if err != nil {
		return 0, err
	}
	stmt, err := tx.Prepare(
		`INSERT INTO rewrites(domain, rrtype, value, enabled, updated_at, scope_type, scope_values) VALUES(?,?,?,1,?,?,?)
		 ON CONFLICT(domain, rrtype, scope_type, scope_values) DO UPDATE SET value=excluded.value, enabled=1, updated_at=excluded.updated_at`)
	if err != nil {
		_ = tx.Rollback()
		return 0, err
	}
	defer stmt.Close()
	now := time.Now().Unix()
	n := 0
	for _, r := range rws {
		st, vals, cerr := CanonicalScope(r.ScopeType, r.ScopeValues)
		if cerr != nil {
			st, vals = ScopeAll, "[]" // tolerate malformed imported scopes: fall back to cluster-wide
		}
		if _, err := stmt.Exec(r.Domain, r.RRType, r.Value, now, st, vals); err != nil {
			_ = tx.Rollback()
			return 0, err
		}
		n++
	}
	if err := tx.Commit(); err != nil {
		return 0, err
	}
	return n, nil
}
```

- [ ] **Step 4: Run the store tests**

Run: `go test ./internal/store/ -v`
Expected: PASS, including the pre-existing `TestRulesRewritesAndLog` (legacy `AddRewrite` upsert semantics preserved) and the three new tests.

- [ ] **Step 5: Run the full suite** (ApplySnapshot and boot still compile/pass)

Run: `go test ./... 2>&1 | tail -20`
Expected: all packages PASS (the `Rewrite` struct change is additive; ApplySnapshot inserts without scope columns and gets the defaults).

- [ ] **Step 6: Commit**

```bash
git add internal/store/store.go internal/store/scope_test.go
git commit -m "feat(store): scoped rewrites schema, migration, and CRUD"
```

---

### Task 3: Forwarders table + CRUD + agent-side blob

**Files:**
- Create: `internal/store/forwarders.go`
- Modify: `internal/store/store.go` (append `forwarders` DDL to `sqliteSchema`)
- Test: `internal/store/forwarders_test.go`

**Interfaces:**
- Consumes: `CanonicalScope`, `ForwardSpec`, `scopeValuesIntersect` (Task 1); `GetMeta`/`SetMeta` (existing).
- Produces (used by Tasks 4, 5, 8, 10):
  - `type Forwarder struct { ID int64; Suffix string; Upstreams []string; ScopeType string; ScopeValues []string; Enabled bool; UpdatedAt int64 }` (JSON tags: `id, suffix, upstreams, scope_type, scope_values, enabled, updated_at`)
  - `func (s *Store) ListForwarders() ([]Forwarder, error)`
  - `func (s *Store) AddForwarder(suffix string, upstreams []string, scopeType string, scopeValues []string) (int64, error)`
  - `func (s *Store) AddForwardersBulk(fws []Forwarder) (int, error)`
  - `func (s *Store) UpdateForwarder(id int64, upstreams []string, enabled bool, scopeType string, scopeValues []string) error`
  - `func (s *Store) DeleteForwarder(id int64) error`
  - `func (s *Store) ClearForwarders() error`
  - `func (s *Store) ForwarderScopeConflict(suffix, scopeType, valuesJSON string, excludeID int64) (bool, error)`
  - `func (s *Store) ClusterForwarders() ([]ForwardSpec, error)` / `func (s *Store) SetClusterForwarders(fws []ForwardSpec) error` (agent-side persisted blob)

- [ ] **Step 1: Write the failing test**

Create `internal/store/forwarders_test.go`:

```go
package store

import (
	"path/filepath"
	"testing"
)

func TestForwardersCRUD(t *testing.T) {
	s, err := Open(filepath.Join(t.TempDir(), "t.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	id, err := s.AddForwarder("corp.internal", []string{"10.0.0.2:53"}, ScopeAll, nil)
	if err != nil {
		t.Fatal(err)
	}
	// Same suffix under a different scope coexists (split-horizon).
	if _, err := s.AddForwarder("corp.internal", []string{"10.9.0.2:53"}, ScopeSites, []string{"lab"}); err != nil {
		t.Fatalf("scoped duplicate suffix rejected: %v", err)
	}
	// Same suffix+scope upserts.
	if _, err := s.AddForwarder("corp.internal", []string{"10.0.0.3:53"}, ScopeAll, nil); err != nil {
		t.Fatal(err)
	}
	fws, err := s.ListForwarders()
	if err != nil || len(fws) != 2 {
		t.Fatalf("want 2 forwarders, got %d (err=%v)", len(fws), err)
	}

	if err := s.UpdateForwarder(id, []string{"10.0.0.4:53"}, false, ScopeAll, nil); err != nil {
		t.Fatal(err)
	}
	fws, _ = s.ListForwarders()
	for _, f := range fws {
		if f.ID == id && (f.Enabled || f.Upstreams[0] != "10.0.0.4:53") {
			t.Fatalf("update not applied: %+v", f)
		}
	}

	// Overlap: same suffix, same specificity, intersecting sites -> conflict.
	if c, _ := s.ForwarderScopeConflict("corp.internal", ScopeSites, `["lab","dc"]`, 0); !c {
		t.Fatal("expected forwarder scope conflict")
	}
	if c, _ := s.ForwarderScopeConflict("corp.internal", ScopeSites, `["dc"]`, 0); c {
		t.Fatal("disjoint sites must not conflict")
	}

	if err := s.DeleteForwarder(id); err != nil {
		t.Fatal(err)
	}
	if err := s.ClearForwarders(); err != nil {
		t.Fatal(err)
	}
	if fws, _ := s.ListForwarders(); len(fws) != 0 {
		t.Fatalf("clear left %d rows", len(fws))
	}
}

func TestClusterForwardersBlob(t *testing.T) {
	s, err := Open(filepath.Join(t.TempDir(), "t.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if fws, err := s.ClusterForwarders(); err != nil || len(fws) != 0 {
		t.Fatalf("empty blob: got %v, %v", fws, err)
	}
	in := []ForwardSpec{{Suffix: "corp.internal", Upstreams: []string{"10.0.0.2:53", "10.0.0.3:53"}}}
	if err := s.SetClusterForwarders(in); err != nil {
		t.Fatal(err)
	}
	out, err := s.ClusterForwarders()
	if err != nil || len(out) != 1 || out[0].Suffix != "corp.internal" || len(out[0].Upstreams) != 2 {
		t.Fatalf("blob round-trip failed: %+v err=%v", out, err)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/store/ -run 'TestForwarders|TestClusterForwardersBlob' -v`
Expected: FAIL (compile error: `AddForwarder` undefined).

- [ ] **Step 3: Implement**

3a. Append to `sqliteSchema` in `internal/store/store.go` (before the closing backtick):

```sql
CREATE TABLE IF NOT EXISTS forwarders (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	suffix TEXT NOT NULL,
	upstreams TEXT NOT NULL,
	scope_type TEXT NOT NULL DEFAULT 'all',
	scope_values TEXT NOT NULL DEFAULT '[]',
	enabled INTEGER NOT NULL DEFAULT 1,
	updated_at INTEGER NOT NULL,
	UNIQUE(suffix, scope_type, scope_values)
);
```

3b. Create `internal/store/forwarders.go`:

```go
package store

import (
	"encoding/json"
	"errors"
	"time"
)

// Forwarder is a centrally-managed conditional forwarder: a domain suffix
// routed to specific upstreams, scoped to all nodes, a node list, or sites.
// It lives only on the control plane; agents receive pre-filtered ForwardSpecs.
type Forwarder struct {
	ID          int64    `json:"id"`
	Suffix      string   `json:"suffix"`
	Upstreams   []string `json:"upstreams"`
	ScopeType   string   `json:"scope_type"`
	ScopeValues []string `json:"scope_values"`
	Enabled     bool     `json:"enabled"`
	UpdatedAt   int64    `json:"updated_at"`
}

// ListForwarders returns all forwarders ordered by suffix.
func (s *Store) ListForwarders() ([]Forwarder, error) {
	rows, err := s.read.Query(`SELECT id, suffix, upstreams, scope_type, scope_values, enabled, updated_at FROM forwarders ORDER BY suffix`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Forwarder{}
	for rows.Next() {
		var f Forwarder
		var ups, vals string
		if err := rows.Scan(&f.ID, &f.Suffix, &ups, &f.ScopeType, &vals, &f.Enabled, &f.UpdatedAt); err != nil {
			return nil, err
		}
		_ = json.Unmarshal([]byte(ups), &f.Upstreams)
		_ = json.Unmarshal([]byte(vals), &f.ScopeValues)
		out = append(out, f)
	}
	return out, rows.Err()
}

// AddForwarder inserts or updates a forwarder (upsert key: suffix + scope).
func (s *Store) AddForwarder(suffix string, upstreams []string, scopeType string, scopeValues []string) (int64, error) {
	st, vals, err := CanonicalScope(scopeType, scopeValues)
	if err != nil {
		return 0, err
	}
	ups, err := json.Marshal(upstreams)
	if err != nil {
		return 0, err
	}
	now := time.Now().Unix()
	if _, err := s.db.Exec(
		`INSERT INTO forwarders(suffix, upstreams, scope_type, scope_values, enabled, updated_at) VALUES(?,?,?,?,1,?)
		 ON CONFLICT(suffix, scope_type, scope_values) DO UPDATE SET upstreams=excluded.upstreams, enabled=1, updated_at=excluded.updated_at`,
		suffix, string(ups), st, vals, now,
	); err != nil {
		return 0, err
	}
	var id int64
	err = s.read.QueryRow(`SELECT id FROM forwarders WHERE suffix=? AND scope_type=? AND scope_values=?`, suffix, st, vals).Scan(&id)
	return id, err
}

// AddForwardersBulk upserts many forwarders (config-bundle import), honoring
// each entry's enabled flag. Returns the count applied.
func (s *Store) AddForwardersBulk(fws []Forwarder) (int, error) {
	n := 0
	for _, f := range fws {
		id, err := s.AddForwarder(f.Suffix, f.Upstreams, f.ScopeType, f.ScopeValues)
		if err != nil {
			return n, err
		}
		if !f.Enabled {
			if err := s.UpdateForwarder(id, f.Upstreams, false, f.ScopeType, f.ScopeValues); err != nil {
				return n, err
			}
		}
		n++
	}
	return n, nil
}

// UpdateForwarder edits a forwarder's upstreams, enabled flag, and scope.
func (s *Store) UpdateForwarder(id int64, upstreams []string, enabled bool, scopeType string, scopeValues []string) error {
	st, vals, err := CanonicalScope(scopeType, scopeValues)
	if err != nil {
		return err
	}
	ups, err := json.Marshal(upstreams)
	if err != nil {
		return err
	}
	res, err := s.db.Exec(`UPDATE forwarders SET upstreams=?, enabled=?, scope_type=?, scope_values=?, updated_at=? WHERE id=?`,
		string(ups), boolToInt(enabled), st, vals, time.Now().Unix(), id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return errors.New("forwarder not found")
	}
	return nil
}

// DeleteForwarder removes a forwarder by id.
func (s *Store) DeleteForwarder(id int64) error {
	_, err := s.db.Exec(`DELETE FROM forwarders WHERE id=?`, id)
	return err
}

// ClearForwarders removes every forwarder (used by a "replace" config import).
func (s *Store) ClearForwarders() error {
	_, err := s.db.Exec(`DELETE FROM forwarders`)
	return err
}

// ForwarderScopeConflict mirrors RewriteScopeConflict for forwarder suffixes.
func (s *Store) ForwarderScopeConflict(suffix, scopeType, valuesJSON string, excludeID int64) (bool, error) {
	if scopeType == ScopeAll {
		return false, nil
	}
	rows, err := s.read.Query(`SELECT id, scope_values FROM forwarders WHERE suffix=? AND scope_type=?`, suffix, scopeType)
	if err != nil {
		return false, err
	}
	defer rows.Close()
	for rows.Next() {
		var id int64
		var vals string
		if err := rows.Scan(&id, &vals); err != nil {
			return false, err
		}
		if id != excludeID && vals != valuesJSON && scopeValuesIntersect(vals, valuesJSON) {
			return true, nil
		}
	}
	return false, rows.Err()
}

// clusterForwardersMeta is the app_meta key under which an AGENT persists the
// central forwarders it last received, so boot works offline and the agent's
// ConfigVersion hash covers them (drift detection).
const clusterForwardersMeta = "cluster_forwarders"

// ClusterForwarders returns the centrally-pushed forwarders persisted on this
// agent (empty on the control plane and on standalone nodes).
func (s *Store) ClusterForwarders() ([]ForwardSpec, error) {
	raw, err := s.GetMeta(clusterForwardersMeta)
	if err != nil || raw == "" {
		return nil, err
	}
	var out []ForwardSpec
	if err := json.Unmarshal([]byte(raw), &out); err != nil {
		return nil, err
	}
	return out, nil
}

// SetClusterForwarders persists the centrally-pushed forwarders on this agent.
func (s *Store) SetClusterForwarders(fws []ForwardSpec) error {
	if fws == nil {
		fws = []ForwardSpec{}
	}
	b, err := json.Marshal(fws)
	if err != nil {
		return err
	}
	return s.SetMeta(clusterForwardersMeta, string(b))
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/store/ -run 'TestForwarders|TestClusterForwardersBlob' -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/store/store.go internal/store/forwarders.go internal/store/forwarders_test.go
git commit -m "feat(store): forwarders table, CRUD, and agent-side cluster blob"
```

---

### Task 4: Per-node filtering + per-node config hash

**Files:**
- Modify: `internal/store/cluster.go` (`ConfigVersion` ~line 55)
- Test: `internal/store/scope_test.go` (append)

**Interfaces:**
- Consumes: `ScopeMatches`, `scopeRank`, `ForwardSpec` (Task 1); forwarders CRUD + `ClusterForwarders` (Task 3).
- Produces (used by Tasks 5, 9):
  - `func (s *Store) ListRewritesForNode(nodeName, nodeSite string) ([]Rewrite, error)` — filtered, precedence-resolved, scope fields zeroed
  - `func (s *Store) ListForwardersForNode(nodeName, nodeSite string) ([]ForwardSpec, error)` — enabled-only, filtered, precedence-resolved
  - `func (s *Store) ConfigVersionForNode(nodeName, nodeSite string) (string, error)`
  - `ConfigVersion()` unchanged signature, now also hashes the agent-side `ClusterForwarders()` blob.

- [ ] **Step 1: Write the failing test** (append to `internal/store/scope_test.go`)

```go
func TestPerNodeFilteringAndHash(t *testing.T) {
	s, err := Open(filepath.Join(t.TempDir(), "t.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	// nas.home: global fallback, site override, node override.
	if _, err := s.AddRewriteScoped("nas.home", "A", "1.1.1.1", ScopeAll, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := s.AddRewriteScoped("nas.home", "A", "2.2.2.2", ScopeSites, []string{"office"}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.AddRewriteScoped("nas.home", "A", "3.3.3.3", ScopeNodes, []string{"n1"}); err != nil {
		t.Fatal(err)
	}

	check := func(name, site, wantVal string) {
		t.Helper()
		rws, err := s.ListRewritesForNode(name, site)
		if err != nil || len(rws) != 1 {
			t.Fatalf("%s/%s: want 1 rewrite, got %d (%v)", name, site, len(rws), err)
		}
		if rws[0].Value != wantVal {
			t.Fatalf("%s/%s: got %s, want %s", name, site, rws[0].Value, wantVal)
		}
		if rws[0].ScopeType != "" || rws[0].ScopeValues != nil {
			t.Fatalf("scope must be zeroed in the served set: %+v", rws[0])
		}
	}
	check("n1", "office", "3.3.3.3") // node beats site beats all
	check("n2", "office", "2.2.2.2") // site beats all
	check("n3", "", "1.1.1.1")       // fallback

	// Forwarders: only enabled entries are served; site scope filters.
	fid, err := s.AddForwarder("corp.internal", []string{"10.0.0.2:53"}, ScopeSites, []string{"office"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.AddForwarder("lab.internal", []string{"10.9.0.2:53"}, ScopeAll, nil); err != nil {
		t.Fatal(err)
	}
	fws, err := s.ListForwardersForNode("n1", "office")
	if err != nil || len(fws) != 2 {
		t.Fatalf("n1 forwarders: want 2, got %d (%v)", len(fws), err)
	}
	if fws, _ := s.ListForwardersForNode("n3", ""); len(fws) != 1 || fws[0].Suffix != "lab.internal" {
		t.Fatalf("n3 forwarders: want only lab.internal, got %+v", fws)
	}
	// Disabling removes it from the served set (and the hash).
	if err := s.UpdateForwarder(fid, []string{"10.0.0.2:53"}, false, ScopeSites, []string{"office"}); err != nil {
		t.Fatal(err)
	}
	if fws, _ := s.ListForwardersForNode("n1", "office"); len(fws) != 1 {
		t.Fatalf("disabled forwarder still served: %+v", fws)
	}

	// Per-node hashes: different content -> different hash; same node -> stable.
	h1a, err := s.ConfigVersionForNode("n1", "office")
	if err != nil || h1a == "" {
		t.Fatal(err)
	}
	h1b, _ := s.ConfigVersionForNode("n1", "office")
	h3, _ := s.ConfigVersionForNode("n3", "")
	if h1a != h1b {
		t.Fatal("per-node hash must be deterministic")
	}
	if h1a == h3 {
		t.Fatal("nodes with different content must hash differently")
	}
}

// The agent recomputes the master's per-node hash from its own local state:
// the applied (filtered) rewrites plus the persisted forwarders blob.
func TestAgentHashMatchesMasterPerNodeHash(t *testing.T) {
	master, err := Open(filepath.Join(t.TempDir(), "m.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer master.Close()
	agent, err := Open(filepath.Join(t.TempDir(), "a.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer agent.Close()

	if _, err := master.AddRule("deny", "ads.test", "ads"); err != nil {
		t.Fatal(err)
	}
	if _, err := master.AddRewriteScoped("nas.home", "A", "2.2.2.2", ScopeSites, []string{"office"}); err != nil {
		t.Fatal(err)
	}
	if _, err := master.AddForwarder("corp.internal", []string{"10.0.0.2:53"}, ScopeSites, []string{"office"}); err != nil {
		t.Fatal(err)
	}

	rules, _ := master.ReplicatedRules()
	rws, _ := master.ListRewritesForNode("n1", "office")
	fws, _ := master.ListForwardersForNode("n1", "office")
	if err := agent.ApplySnapshot(rules, rws); err != nil {
		t.Fatal(err)
	}
	if err := agent.SetClusterForwarders(fws); err != nil {
		t.Fatal(err)
	}

	want, _ := master.ConfigVersionForNode("n1", "office")
	got, _ := agent.ConfigVersion()
	if want == "" || got != want {
		t.Fatalf("agent hash %q != master per-node hash %q", got, want)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/store/ -run 'TestPerNodeFiltering|TestAgentHashMatches' -v`
Expected: FAIL (compile error: `ListRewritesForNode` undefined).

- [ ] **Step 3: Implement** in `internal/store/cluster.go`

3a. Refactor `ConfigVersion` into a shared line-hasher and extend it with `F|` lines:

```go
// configHash is the shared content hash both sides compute from their own
// data: the master over a node's filtered view, the agent over its local
// tables + persisted forwarders blob. Line formats are frozen (R|, W|, F|) —
// changing them desynchronizes every agent at once.
func configHash(rules []Rule, rewrites []Rewrite, fws []ForwardSpec) string {
	lines := make([]string, 0, len(rules)+len(rewrites)+len(fws))
	for _, r := range rules {
		lines = append(lines, fmt.Sprintf("R|%s|%s|%s|%t", r.Action, r.Domain, r.Category, r.Enabled))
	}
	for _, rw := range rewrites {
		lines = append(lines, fmt.Sprintf("W|%s|%s|%s|%t", rw.Domain, rw.RRType, rw.Value, rw.Enabled))
	}
	for _, f := range fws {
		lines = append(lines, fmt.Sprintf("F|%s|%s", f.Suffix, strings.Join(f.Upstreams, ",")))
	}
	sort.Strings(lines) // order-independent: same content -> same hash on every node
	sum := sha256.Sum256([]byte(strings.Join(lines, "\n")))
	return hex.EncodeToString(sum[:])[:12]
}

// ConfigVersion returns a short content hash of the replicated config this
// node holds (rules + rewrites + centrally-pushed forwarders). A worker
// detects drift by comparing its own hash to the per-node hash the master
// advertises — no monotonic counter needed.
func (s *Store) ConfigVersion() (string, error) {
	rules, err := s.ReplicatedRules()
	if err != nil {
		return "", err
	}
	rewrites, err := s.ListRewrites()
	if err != nil {
		return "", err
	}
	fws, err := s.ClusterForwarders()
	if err != nil {
		return "", err
	}
	return configHash(rules, rewrites, fws), nil
}

// ConfigVersionForNode is the master-side counterpart of an agent's
// ConfigVersion: the hash of exactly the content served to that node.
func (s *Store) ConfigVersionForNode(nodeName, nodeSite string) (string, error) {
	rules, err := s.ReplicatedRules()
	if err != nil {
		return "", err
	}
	rws, err := s.ListRewritesForNode(nodeName, nodeSite)
	if err != nil {
		return "", err
	}
	fws, err := s.ListForwardersForNode(nodeName, nodeSite)
	if err != nil {
		return "", err
	}
	return configHash(rules, rws, fws), nil
}
```

(keep the existing imports; `sort`, `fmt`, `strings`, `crypto/sha256`, `encoding/hex` are already imported by cluster.go for the old ConfigVersion.)

Note the agent-side subtlety this preserves: an agent's local rewrites all sit in scope `'all'` (ApplySnapshot inserts defaults) and the `W|` lines never mention scope, so agent and master hash identical strings.

3b. Add the per-node filtered views:

```go
// ListRewritesForNode returns the rewrites that apply to one node, precedence
// resolved (nodes > sites > all) to a single winner per domain+rrtype, with
// scope fields zeroed — the served set is scope-free by design, so agents
// need no scope logic and old agents keep working.
func (s *Store) ListRewritesForNode(nodeName, nodeSite string) ([]Rewrite, error) {
	all, err := s.ListRewrites()
	if err != nil {
		return nil, err
	}
	type key struct{ domain, rrtype string }
	best := map[key]Rewrite{}
	rank := map[key]int{}
	for _, rw := range all {
		valsJSON := "[]"
		if len(rw.ScopeValues) > 0 {
			b, _ := json.Marshal(rw.ScopeValues)
			valsJSON = string(b)
		}
		if !ScopeMatches(rw.ScopeType, valsJSON, nodeName, nodeSite) {
			continue
		}
		k := key{rw.Domain, rw.RRType}
		if r := scopeRank(rw.ScopeType); r > rank[k] {
			rank[k] = r
			rw.ScopeType, rw.ScopeValues = "", nil
			best[k] = rw
		}
	}
	out := make([]Rewrite, 0, len(best))
	for _, rw := range best {
		out = append(out, rw)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Domain != out[j].Domain {
			return out[i].Domain < out[j].Domain
		}
		return out[i].RRType < out[j].RRType
	})
	return out, nil
}

// ListForwardersForNode returns the enabled forwarders that apply to one node,
// precedence resolved to a single winner per suffix, as lean ForwardSpecs.
func (s *Store) ListForwardersForNode(nodeName, nodeSite string) ([]ForwardSpec, error) {
	all, err := s.ListForwarders()
	if err != nil {
		return nil, err
	}
	best := map[string]ForwardSpec{}
	rank := map[string]int{}
	for _, f := range all {
		if !f.Enabled {
			continue
		}
		valsJSON := "[]"
		if len(f.ScopeValues) > 0 {
			b, _ := json.Marshal(f.ScopeValues)
			valsJSON = string(b)
		}
		if !ScopeMatches(f.ScopeType, valsJSON, nodeName, nodeSite) {
			continue
		}
		if r := scopeRank(f.ScopeType); r > rank[f.Suffix] {
			rank[f.Suffix] = r
			best[f.Suffix] = ForwardSpec{Suffix: f.Suffix, Upstreams: f.Upstreams}
		}
	}
	out := make([]ForwardSpec, 0, len(best))
	for _, f := range best {
		out = append(out, f)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Suffix < out[j].Suffix })
	return out, nil
}
```

(add `"encoding/json"` to cluster.go's imports.)

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/store/ -v`
Expected: PASS (all store tests, old and new).

- [ ] **Step 5: Commit**

```bash
git add internal/store/cluster.go internal/store/scope_test.go
git commit -m "feat(store): per-node filtered views and per-node config hash"
```

---

### Task 5: Snapshot field + agent sync (persist blob, apply settings hook)

**Files:**
- Modify: `internal/cluster/snapshot.go`
- Modify: `internal/cluster/agent.go` (struct ~line 23, `syncOnce` ~line 178)
- Test: `internal/cluster/agent_test.go` (extend `TestAgentSync`)

**Interfaces:**
- Consumes: `store.ForwardSpec`, `SetClusterForwarders` (Task 3), agent-side `ConfigVersion` (Task 4).
- Produces (used by Tasks 6, 9):
  - `cluster.Snapshot` gains `Forwarders []store.ForwardSpec \`json:"forwarders,omitempty"\``
  - `func (a *Agent) SetApplySettings(fn func())` — called after every applied snapshot so the node re-merges local + central settings.

- [ ] **Step 1: Extend the test** — in `internal/cluster/agent_test.go`, update `TestAgentSync`:

Replace the `snap := Snapshot{...}` literal with:

```go
	snap := Snapshot{
		Version:  "pending", // any value != the worker's empty-config hash triggers the first apply
		Rules:    []store.Rule{{Action: "deny", Domain: "ads.test", Enabled: true, UpdatedAt: 1}},
		Rewrites: []store.Rewrite{{Domain: "nas.lan", RRType: "A", Value: "10.0.0.5", Enabled: true, UpdatedAt: 1}},
		Forwarders: []store.ForwardSpec{
			{Suffix: "corp.internal", Upstreams: []string{"10.0.0.2:53"}},
		},
	}
```

Replace the `ag := NewAgent(...)` + assertions section (lines 36–54) with:

```go
	reloaded := false
	settingsApplied := false
	ag := NewAgent(ts.URL, "", "tok", "", time.Second, st, func() error { reloaded = true; return nil }, func() store.NodeStats { return store.NodeStats{} }, nil, nil)
	ag.SetApplySettings(func() { settingsApplied = true })
	ag.syncOnce(context.Background())

	rules, _ := st.ListRules()
	if len(rules) != 1 || rules[0].Domain != "ads.test" {
		t.Fatalf("rules not applied: %+v", rules)
	}
	rws, _ := st.ListRewrites()
	if len(rws) != 1 || rws[0].Value != "10.0.0.5" {
		t.Fatalf("rewrites not applied: %+v", rws)
	}
	fws, _ := st.ClusterForwarders()
	if len(fws) != 1 || fws[0].Suffix != "corp.internal" {
		t.Fatalf("forwarders not persisted: %+v", fws)
	}
	if !reloaded {
		t.Fatal("reload was not called after a change")
	}
	if !settingsApplied {
		t.Fatal("applySettings was not called after a change")
	}
	applied, _ := st.ConfigVersion()
	if applied == "" {
		t.Fatal("config version should be a non-empty content hash")
	}
```

And after the existing "no-op when versions match" block, add:

```go
	// An emptied central forwarder list clears the persisted blob on the agent.
	snap.Version = "changed-again"
	snap.Forwarders = nil
	settingsApplied = false
	ag.syncOnce(context.Background())
	if fws, _ := st.ClusterForwarders(); len(fws) != 0 {
		t.Fatalf("forwarders blob not cleared: %+v", fws)
	}
	if !settingsApplied {
		t.Fatal("applySettings must fire when forwarders are removed")
	}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/cluster/ -run TestAgentSync -v`
Expected: FAIL (compile error: unknown field `Forwarders` / `SetApplySettings` undefined).

- [ ] **Step 3: Implement**

3a. `internal/cluster/snapshot.go` — replace the Snapshot struct:

```go
// Snapshot is the replicated configuration the master serves to a worker.
// It is computed PER NODE: rewrites and forwarders are pre-filtered to the
// entries that apply to the requesting node (scope metadata never leaves the
// control plane), and Version is the content hash of exactly this payload.
type Snapshot struct {
	Version     string              `json:"version"`
	Rules       []store.Rule        `json:"rules"`
	Rewrites    []store.Rewrite     `json:"rewrites"`
	Forwarders  []store.ForwardSpec `json:"forwarders,omitempty"`
	PausedUntil int64               `json:"paused_until"` // cluster-wide block pause deadline (unix)
	Maintenance bool                `json:"maintenance"`  // this node is drained (answers SERVFAIL)
}
```

3b. `internal/cluster/agent.go` — add the hook field to the `Agent` struct (after `setMaintenance`):

```go
	applySettings  func() // re-merge local + central settings after an applied snapshot (may be nil)
```

Add the setter next to `SetReenroll`:

```go
// SetApplySettings installs a callback invoked after every applied snapshot,
// so the node rebuilds its effective settings (local settings + centrally
// pushed forwarders, central winning per suffix).
func (a *Agent) SetApplySettings(fn func()) { a.applySettings = fn }
```

Update `syncOnce` — replace the apply block:

```go
	cur, _ := a.store.ConfigVersion()
	if snap.Version == cur {
		return // rules already up to date
	}
	// Persist the central forwarders first: they are part of this node's
	// ConfigVersion, so the next poll's drift check sees the full payload.
	if err := a.store.SetClusterForwarders(snap.Forwarders); err != nil {
		slog.Warn("cluster apply failed (forwarders)", "err", err)
		return
	}
	if err := a.store.ApplySnapshot(snap.Rules, snap.Rewrites); err != nil {
		slog.Warn("cluster apply failed", "err", err)
		return
	}
	if a.applySettings != nil {
		a.applySettings()
	}
	if a.reload != nil {
		_ = a.reload()
	}
	slog.Info("cluster synced", "version", snap.Version, "rules", len(snap.Rules), "rewrites", len(snap.Rewrites), "forwarders", len(snap.Forwarders))
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/cluster/ -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/cluster/snapshot.go internal/cluster/agent.go internal/cluster/agent_test.go
git commit -m "feat(cluster): replicate per-node forwarders; agent persists and applies them"
```

---

### Task 6: Effective settings merge + dns-agent wiring

**Files:**
- Modify: `internal/boot/boot.go` (after `LoadOrSeedSettings`, ~line 150)
- Modify: `cmd/dns-agent/main.go` (line 88 and `startAgent` ~line 265)
- Test: `internal/boot/boot_test.go` (create)

**Interfaces:**
- Consumes: `store.ForwardSpec`, `ClusterForwarders` (Task 3); `SetApplySettings` (Task 5); existing `LoadOrSeedSettings`, `resolver.Settings`, `filter.Normalize`.
- Produces:
  - `func MergeForwarders(s resolver.Settings, central []store.ForwardSpec) resolver.Settings` (in `boot`)
  - `func EffectiveSettings(st *store.Store, cfg config.Config) resolver.Settings` (in `boot`)

- [ ] **Step 1: Write the failing test**

Create `internal/boot/boot_test.go`:

```go
package boot

import (
	"testing"

	"github.com/IPMaze/MazeDNS/internal/resolver"
	"github.com/IPMaze/MazeDNS/internal/store"
)

func TestMergeForwarders(t *testing.T) {
	local := resolver.Settings{
		Upstreams: []string{"1.1.1.1:53"},
		Forwarders: []resolver.ForwardGroup{
			{Suffix: "corp.internal", Upstreams: []string{"10.0.0.9:53"}}, // shadowed by central
			{Suffix: "printers.lan", Upstreams: []string{"10.0.0.8:53"}},  // survives
		},
	}
	central := []store.ForwardSpec{
		{Suffix: "CORP.Internal.", Upstreams: []string{"10.0.0.2:53"}}, // wins despite case/dot
		{Suffix: "lab.internal", Upstreams: []string{"10.9.0.2:53"}},
	}
	got := MergeForwarders(local, central)
	if len(got.Forwarders) != 3 {
		t.Fatalf("want 3 merged forwarders, got %d: %+v", len(got.Forwarders), got.Forwarders)
	}
	byName := map[string][]string{}
	for _, f := range got.Forwarders {
		byName[f.Suffix] = f.Upstreams
	}
	if ups := byName["corp.internal"]; len(ups) != 1 || ups[0] != "10.0.0.2:53" {
		t.Fatalf("central must win for corp.internal: %+v", byName)
	}
	if _, ok := byName["printers.lan"]; !ok {
		t.Fatal("non-conflicting local forwarder must survive")
	}
	// The input settings must not be mutated; other fields pass through.
	if got.Upstreams[0] != "1.1.1.1:53" || len(local.Forwarders) != 2 {
		t.Fatal("merge must not mutate inputs or drop other settings")
	}
	// No central entries -> unchanged local settings.
	same := MergeForwarders(local, nil)
	if len(same.Forwarders) != 2 {
		t.Fatalf("nil central must be a no-op, got %+v", same.Forwarders)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/boot/ -run TestMergeForwarders -v`
Expected: FAIL (compile error: `MergeForwarders` undefined).

- [ ] **Step 3: Implement** — append to `internal/boot/boot.go` (after `LoadOrSeedSettings`):

```go
// MergeForwarders overlays centrally-pushed conditional forwarders onto a
// node's local settings. The central entry wins when both define the same
// normalized suffix; non-conflicting local entries survive. The merge happens
// at apply time only — central entries are never persisted into the node's
// saved settings, so deleting one centrally restores local behavior.
func MergeForwarders(s resolver.Settings, central []store.ForwardSpec) resolver.Settings {
	if len(central) == 0 {
		return s
	}
	merged := make([]resolver.ForwardGroup, 0, len(central)+len(s.Forwarders))
	taken := make(map[string]bool, len(central))
	for _, f := range central {
		key := filter.Normalize(f.Suffix)
		if key == "" || taken[key] {
			continue
		}
		taken[key] = true
		merged = append(merged, resolver.ForwardGroup{Suffix: key, Upstreams: f.Upstreams})
	}
	for _, g := range s.Forwarders {
		if !taken[filter.Normalize(g.Suffix)] {
			merged = append(merged, g)
		}
	}
	s.Forwarders = merged
	return s
}

// EffectiveSettings returns what the resolver should actually run: the node's
// local (seeded/DB) settings with the centrally-pushed forwarders merged in.
func EffectiveSettings(st *store.Store, cfg config.Config) resolver.Settings {
	s := LoadOrSeedSettings(st, cfg)
	fws, err := st.ClusterForwarders()
	if err != nil {
		slog.Warn("load cluster forwarders", "err", err)
		return s
	}
	return MergeForwarders(s, fws)
}
```

Check boot.go's imports include `"log/slog"` and `"github.com/IPMaze/MazeDNS/internal/filter"`; add them if missing.

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/boot/ -v`
Expected: PASS.

- [ ] **Step 5: Wire the dns-agent**

In `cmd/dns-agent/main.go`:

Line 88, replace:

```go
	res.ApplySettings(boot.LoadOrSeedSettings(st, cfg))
```

with:

```go
	res.ApplySettings(boot.EffectiveSettings(st, cfg))
```

In `startAgent`, right after `ag := cluster.NewAgent(...)` (~line 268), add:

```go
	ag.SetApplySettings(func() { res.ApplySettings(boot.EffectiveSettings(st, cfg)) })
```

- [ ] **Step 6: Verify the whole tree builds and tests pass**

Run: `go build ./... && go test ./... 2>&1 | tail -5`
Expected: build OK, all PASS.

- [ ] **Step 7: Commit**

```bash
git add internal/boot/boot.go internal/boot/boot_test.go cmd/dns-agent/main.go
git commit -m "feat(agent): merge central forwarders over local settings (central wins)"
```

---

### Task 7: API — scoped rewrites (POST scope fields, PUT, 409 on overlap)

**Files:**
- Modify: `internal/api/api.go` (routes ~line 120; `addRewrite` ~line 1105)
- Test: `internal/api/rewrites_test.go` (create)

**Interfaces:**
- Consumes: `store.CanonicalScope`, `AddRewriteScoped`, `UpdateRewrite`, `RewriteScopeConflict` (Tasks 1–2).
- Produces: `POST /api/rewrites` accepts `scope_type` + `scope_values`; new `PUT /api/rewrites/{id}` with body `{value, enabled, scope_type, scope_values}`; both return 409 `{"error": ...}` on same-specificity overlap.

- [ ] **Step 1: Write the failing test**

Create `internal/api/rewrites_test.go`:

```go
package api

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/IPMaze/MazeDNS/internal/store"
)

func newRewriteServer(t *testing.T) (*Server, *store.Store) {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	return &Server{store: st}, st
}

func TestAddRewriteScoped(t *testing.T) {
	s, st := newRewriteServer(t)
	post := func(body string) *httptest.ResponseRecorder {
		rr := httptest.NewRecorder()
		s.addRewrite(rr, httptest.NewRequest(http.MethodPost, "/api/rewrites", strings.NewReader(body)))
		return rr
	}

	// Default scope is 'all' (legacy body unchanged).
	if rr := post(`{"domain":"nas.lan","rrtype":"A","value":"10.0.0.5"}`); rr.Code != http.StatusCreated {
		t.Fatalf("legacy add: %d %s", rr.Code, rr.Body.String())
	}
	// Site-scoped split-horizon value for the same domain.
	if rr := post(`{"domain":"nas.lan","rrtype":"A","value":"192.168.1.5","scope_type":"sites","scope_values":["office"]}`); rr.Code != http.StatusCreated {
		t.Fatalf("scoped add: %d %s", rr.Code, rr.Body.String())
	}
	// Overlapping site list at the same specificity -> 409.
	if rr := post(`{"domain":"nas.lan","rrtype":"A","value":"172.16.0.5","scope_type":"sites","scope_values":["office","lab"]}`); rr.Code != http.StatusConflict {
		t.Fatalf("overlap: got %d, want 409 (%s)", rr.Code, rr.Body.String())
	}
	// Bad scope type -> 400.
	if rr := post(`{"domain":"x.lan","rrtype":"A","value":"1.2.3.4","scope_type":"bogus"}`); rr.Code != http.StatusBadRequest {
		t.Fatalf("bad scope: got %d, want 400", rr.Code)
	}
	if rws, _ := st.ListRewrites(); len(rws) != 2 {
		t.Fatalf("want 2 rewrites, got %+v", rws)
	}
}

func TestUpdateRewrite(t *testing.T) {
	s, st := newRewriteServer(t)
	id, err := st.AddRewriteScoped("nas.lan", "A", "10.0.0.5", store.ScopeAll, nil)
	if err != nil {
		t.Fatal(err)
	}
	put := func(id int64, body string) *httptest.ResponseRecorder {
		rr := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPut, fmt.Sprintf("/api/rewrites/%d", id), strings.NewReader(body))
		req.SetPathValue("id", fmt.Sprint(id))
		s.updateRewrite(rr, req)
		return rr
	}
	if rr := put(id, `{"value":"10.0.0.6","enabled":false,"scope_type":"nodes","scope_values":["n1"]}`); rr.Code != http.StatusOK {
		t.Fatalf("update: %d %s", rr.Code, rr.Body.String())
	}
	rws, _ := st.ListRewrites()
	if len(rws) != 1 || rws[0].Value != "10.0.0.6" || rws[0].Enabled || rws[0].ScopeType != store.ScopeNodes {
		t.Fatalf("update not applied: %+v", rws)
	}
	if rr := put(9999, `{"value":"1.1.1.1","enabled":true}`); rr.Code != http.StatusNotFound {
		t.Fatalf("missing id: got %d, want 404", rr.Code)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/api/ -run 'TestAddRewriteScoped|TestUpdateRewrite' -v`
Expected: FAIL (compile error: `updateRewrite` undefined).

- [ ] **Step 3: Implement**

3a. In `internal/api/api.go`, after the existing rewrites routes (~line 122), add:

```go
		mux.HandleFunc("PUT /api/rewrites/{id}", s.requireRole(roleAdmin, s.updateRewrite))
```

3b. Replace `addRewrite` (~line 1105):

```go
func (s *Server) addRewrite(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Domain      string   `json:"domain"`
		RRType      string   `json:"rrtype"`
		Value       string   `json:"value"`
		ScopeType   string   `json:"scope_type"`
		ScopeValues []string `json:"scope_values"`
	}
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON")
		return
	}
	switch in.RRType {
	case "A", "AAAA", "CNAME":
	default:
		writeError(w, http.StatusBadRequest, "rrtype must be A, AAAA, or CNAME")
		return
	}
	domain := filter.Normalize(in.Domain)
	if domain == "" || in.Value == "" {
		writeError(w, http.StatusBadRequest, "domain and value required")
		return
	}
	// Wildcards are allowed only as a single leading "*." label.
	if strings.Contains(domain, "*") && (!strings.HasPrefix(domain, "*.") || strings.Contains(domain[2:], "*")) {
		writeError(w, http.StatusBadRequest, "wildcards must be a single leading label, e.g. *.example.com")
		return
	}
	scopeType, valsJSON, err := store.CanonicalScope(in.ScopeType, in.ScopeValues)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if conflict, err := s.store.RewriteScopeConflict(domain, in.RRType, scopeType, valsJSON, 0); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	} else if conflict {
		writeError(w, http.StatusConflict, "another rewrite for this domain already targets overlapping "+scopeType)
		return
	}
	id, err := s.store.AddRewriteScoped(domain, in.RRType, in.Value, scopeType, in.ScopeValues)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.afterChange()
	writeJSON(w, http.StatusCreated, map[string]any{"id": id, "domain": domain, "rrtype": in.RRType, "value": in.Value, "scope_type": scopeType, "scope_values": in.ScopeValues})
}

// updateRewrite edits a rewrite's value, enabled flag, and scope in place, so
// re-scoping doesn't require delete-and-recreate.
func (s *Server) updateRewrite(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid id")
		return
	}
	var in struct {
		Value       string   `json:"value"`
		Enabled     bool     `json:"enabled"`
		ScopeType   string   `json:"scope_type"`
		ScopeValues []string `json:"scope_values"`
	}
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON")
		return
	}
	if in.Value == "" {
		writeError(w, http.StatusBadRequest, "value required")
		return
	}
	scopeType, valsJSON, err := store.CanonicalScope(in.ScopeType, in.ScopeValues)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	// The domain+rrtype being edited are needed for the overlap check.
	rws, err := s.store.ListRewrites()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	var cur *store.Rewrite
	for i := range rws {
		if rws[i].ID == id {
			cur = &rws[i]
			break
		}
	}
	if cur == nil {
		writeError(w, http.StatusNotFound, "rewrite not found")
		return
	}
	if conflict, err := s.store.RewriteScopeConflict(cur.Domain, cur.RRType, scopeType, valsJSON, id); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	} else if conflict {
		writeError(w, http.StatusConflict, "another rewrite for this domain already targets overlapping "+scopeType)
		return
	}
	if err := s.store.UpdateRewrite(id, in.Value, in.Enabled, scopeType, in.ScopeValues); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.afterChange()
	writeJSON(w, http.StatusOK, map[string]any{"id": id, "value": in.Value, "enabled": in.Enabled, "scope_type": scopeType, "scope_values": in.ScopeValues})
}
```

(Note: `UpdateRewrite` returning "rewrite not found" can no longer happen after the `cur == nil` check, which already 404s — the double check is fine.)

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/api/ -v`
Expected: PASS (including pre-existing api tests).

- [ ] **Step 5: Commit**

```bash
git add internal/api/api.go internal/api/rewrites_test.go
git commit -m "feat(api): scope fields on rewrites + PUT endpoint with overlap 409"
```

---

### Task 8: API — forwarders CRUD

**Files:**
- Create: `internal/api/forwarders.go`
- Modify: `internal/api/api.go` (routes, after the rewrites block ~line 123)
- Test: `internal/api/forwarders_test.go` (create)

**Interfaces:**
- Consumes: store forwarder CRUD + `ForwarderScopeConflict` (Task 3); `resolver.ParseUpstream` (existing, `internal/resolver/upstream.go:77`); `filter.Normalize`.
- Produces: `GET/POST /api/forwarders`, `PUT/DELETE /api/forwarders/{id}`. POST/PUT body: `{suffix, upstreams: [], scope_type, scope_values, enabled?}`.

- [ ] **Step 1: Write the failing test**

Create `internal/api/forwarders_test.go`:

```go
package api

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/IPMaze/MazeDNS/internal/store"
)

func TestForwardersAPI(t *testing.T) {
	st, err := store.Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	s := &Server{store: st}

	post := func(body string) *httptest.ResponseRecorder {
		rr := httptest.NewRecorder()
		s.addForwarder(rr, httptest.NewRequest(http.MethodPost, "/api/forwarders", strings.NewReader(body)))
		return rr
	}

	// Valid add.
	if rr := post(`{"suffix":"corp.internal","upstreams":["10.0.0.2:53"],"scope_type":"sites","scope_values":["office"]}`); rr.Code != http.StatusCreated {
		t.Fatalf("add: %d %s", rr.Code, rr.Body.String())
	}
	// Missing upstreams -> 400.
	if rr := post(`{"suffix":"x.internal","upstreams":[]}`); rr.Code != http.StatusBadRequest {
		t.Fatalf("no upstreams: got %d, want 400", rr.Code)
	}
	// Unparseable upstream -> 400.
	if rr := post(`{"suffix":"x.internal","upstreams":["not a real upstream::"]}`); rr.Code != http.StatusBadRequest {
		t.Fatalf("bad upstream: got %d, want 400 (%s)", rr.Code, rr.Body.String())
	}
	// Wildcards make no sense in a suffix -> 400.
	if rr := post(`{"suffix":"*.corp.internal","upstreams":["10.0.0.2:53"]}`); rr.Code != http.StatusBadRequest {
		t.Fatalf("wildcard suffix: got %d, want 400", rr.Code)
	}
	// Overlapping sites for the same suffix -> 409.
	if rr := post(`{"suffix":"corp.internal","upstreams":["10.1.1.1:53"],"scope_type":"sites","scope_values":["office","lab"]}`); rr.Code != http.StatusConflict {
		t.Fatalf("overlap: got %d, want 409 (%s)", rr.Code, rr.Body.String())
	}

	// List returns the row with its scope.
	rr := httptest.NewRecorder()
	s.listForwarders(rr, httptest.NewRequest(http.MethodGet, "/api/forwarders", nil))
	if rr.Code != http.StatusOK || !strings.Contains(rr.Body.String(), `"corp.internal"`) {
		t.Fatalf("list: %d %s", rr.Code, rr.Body.String())
	}

	// Update + delete round-trip.
	fws, _ := st.ListForwarders()
	id := fws[0].ID
	prr := httptest.NewRecorder()
	preq := httptest.NewRequest(http.MethodPut, fmt.Sprintf("/api/forwarders/%d", id),
		strings.NewReader(`{"upstreams":["10.0.0.3:53"],"enabled":false,"scope_type":"sites","scope_values":["office"]}`))
	preq.SetPathValue("id", fmt.Sprint(id))
	s.updateForwarder(prr, preq)
	if prr.Code != http.StatusOK {
		t.Fatalf("update: %d %s", prr.Code, prr.Body.String())
	}
	fws, _ = st.ListForwarders()
	if fws[0].Enabled || fws[0].Upstreams[0] != "10.0.0.3:53" {
		t.Fatalf("update not applied: %+v", fws[0])
	}
	drr := httptest.NewRecorder()
	dreq := httptest.NewRequest(http.MethodDelete, fmt.Sprintf("/api/forwarders/%d", id), nil)
	dreq.SetPathValue("id", fmt.Sprint(id))
	s.deleteForwarder(drr, dreq)
	if drr.Code != http.StatusNoContent {
		t.Fatalf("delete: %d", drr.Code)
	}
	if fws, _ := st.ListForwarders(); len(fws) != 0 {
		t.Fatalf("row not deleted: %+v", fws)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/api/ -run TestForwardersAPI -v`
Expected: FAIL (compile error: `addForwarder` undefined).

- [ ] **Step 3: Implement**

3a. Create `internal/api/forwarders.go`:

```go
package api

import (
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/IPMaze/MazeDNS/internal/filter"
	"github.com/IPMaze/MazeDNS/internal/resolver"
	"github.com/IPMaze/MazeDNS/internal/store"
)

// Centrally-managed conditional forwarders: suffix -> upstreams, scoped to
// all nodes / a node list / sites. Agents receive their filtered set through
// the cluster snapshot; there is nothing to apply on the control plane itself
// (it serves no DNS), so mutations only need afterChange() to bump the
// content hash agents poll.

func (s *Server) listForwarders(w http.ResponseWriter, _ *http.Request) {
	fws, err := s.store.ListForwarders()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, fws)
}

// validateForwarderInput normalizes and validates the shared POST/PUT fields.
// Returns (suffix, scopeType, valuesJSON, ok); on !ok the response is written.
func (s *Server) validateForwarderInput(w http.ResponseWriter, suffix string, upstreams []string, scopeType string, scopeValues []string) (string, string, string, bool) {
	sfx := filter.Normalize(suffix)
	if sfx == "" {
		writeError(w, http.StatusBadRequest, "suffix required")
		return "", "", "", false
	}
	if strings.Contains(sfx, "*") {
		writeError(w, http.StatusBadRequest, "a forwarder suffix already matches all subdomains; wildcards are not allowed")
		return "", "", "", false
	}
	if len(upstreams) == 0 {
		writeError(w, http.StatusBadRequest, "at least one upstream is required")
		return "", "", "", false
	}
	for _, u := range upstreams {
		if _, err := resolver.ParseUpstream(u, 5*time.Second); err != nil {
			writeError(w, http.StatusBadRequest, "invalid upstream "+u+": "+err.Error())
			return "", "", "", false
		}
	}
	st, valsJSON, err := store.CanonicalScope(scopeType, scopeValues)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return "", "", "", false
	}
	return sfx, st, valsJSON, true
}

func (s *Server) addForwarder(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Suffix      string   `json:"suffix"`
		Upstreams   []string `json:"upstreams"`
		ScopeType   string   `json:"scope_type"`
		ScopeValues []string `json:"scope_values"`
	}
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON")
		return
	}
	suffix, scopeType, valsJSON, ok := s.validateForwarderInput(w, in.Suffix, in.Upstreams, in.ScopeType, in.ScopeValues)
	if !ok {
		return
	}
	if conflict, err := s.store.ForwarderScopeConflict(suffix, scopeType, valsJSON, 0); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	} else if conflict {
		writeError(w, http.StatusConflict, "another forwarder for this suffix already targets overlapping "+scopeType)
		return
	}
	id, err := s.store.AddForwarder(suffix, in.Upstreams, scopeType, in.ScopeValues)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.afterChange()
	writeJSON(w, http.StatusCreated, map[string]any{"id": id, "suffix": suffix, "upstreams": in.Upstreams, "scope_type": scopeType, "scope_values": in.ScopeValues})
}

func (s *Server) updateForwarder(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid id")
		return
	}
	var in struct {
		Upstreams   []string `json:"upstreams"`
		Enabled     bool     `json:"enabled"`
		ScopeType   string   `json:"scope_type"`
		ScopeValues []string `json:"scope_values"`
	}
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON")
		return
	}
	fws, err := s.store.ListForwarders()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	var cur *store.Forwarder
	for i := range fws {
		if fws[i].ID == id {
			cur = &fws[i]
			break
		}
	}
	if cur == nil {
		writeError(w, http.StatusNotFound, "forwarder not found")
		return
	}
	suffix, scopeType, valsJSON, ok := s.validateForwarderInput(w, cur.Suffix, in.Upstreams, in.ScopeType, in.ScopeValues)
	if !ok {
		return
	}
	if conflict, err := s.store.ForwarderScopeConflict(suffix, scopeType, valsJSON, id); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	} else if conflict {
		writeError(w, http.StatusConflict, "another forwarder for this suffix already targets overlapping "+scopeType)
		return
	}
	if err := s.store.UpdateForwarder(id, in.Upstreams, in.Enabled, scopeType, in.ScopeValues); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.afterChange()
	writeJSON(w, http.StatusOK, map[string]any{"id": id, "upstreams": in.Upstreams, "enabled": in.Enabled, "scope_type": scopeType, "scope_values": in.ScopeValues})
}

func (s *Server) deleteForwarder(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid id")
		return
	}
	if err := s.store.DeleteForwarder(id); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.afterChange()
	w.WriteHeader(http.StatusNoContent)
}
```

3b. Register routes in `internal/api/api.go`, directly after the `PUT /api/rewrites/{id}` route added in Task 7:

```go
		mux.HandleFunc("GET /api/forwarders", s.requireRole(roleReadonly, s.listForwarders))
		mux.HandleFunc("POST /api/forwarders", s.requireRole(roleAdmin, s.addForwarder))
		mux.HandleFunc("PUT /api/forwarders/{id}", s.requireRole(roleAdmin, s.updateForwarder))
		mux.HandleFunc("DELETE /api/forwarders/{id}", s.requireRole(roleAdmin, s.deleteForwarder))
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/api/ -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/api/forwarders.go internal/api/forwarders_test.go internal/api/api.go
git commit -m "feat(api): centrally-managed conditional forwarders CRUD"
```

---

### Task 9: API — per-node snapshot + expected_version on the nodes list

**Files:**
- Modify: `internal/api/api.go` (`clusterSnapshot` ~line 311, `clusterNodes` ~line 416)
- Test: `internal/api/cluster_test.go` (append)

**Interfaces:**
- Consumes: `ListRewritesForNode`, `ListForwardersForNode`, `ConfigVersionForNode` (Task 4); `Snapshot.Forwarders` (Task 5).
- Produces: `/api/cluster/snapshot` responses are per-node filtered; `GET /api/cluster/nodes` items gain `"expected_version"`.

- [ ] **Step 1: Write the failing test** (append to `internal/api/cluster_test.go`)

```go
// Two enrolled nodes in different sites receive different filtered snapshots,
// each self-consistent with its per-node version hash.
func TestClusterSnapshotPerNodeScoping(t *testing.T) {
	s, st := newEnrollServer(t, "s3cr3t", false)

	enroll := func(name string) string {
		rr := httptest.NewRecorder()
		s.clusterEnroll(rr, httptest.NewRequest(http.MethodPost, "/api/cluster/enroll",
			strings.NewReader(`{"name":"`+name+`","token":"s3cr3t"}`)))
		if rr.Code != http.StatusCreated {
			t.Fatalf("enroll %s: %d %s", name, rr.Code, rr.Body.String())
		}
		var out struct {
			Key string `json:"key"`
		}
		if err := json.Unmarshal(rr.Body.Bytes(), &out); err != nil {
			t.Fatal(err)
		}
		return out.Key
	}
	keyA, keyB := enroll("node-a"), enroll("node-b")
	if err := st.SetNodeSite("node-a", "office", ""); err != nil {
		t.Fatal(err)
	}

	if _, err := st.AddRewriteScoped("nas.home", "A", "1.1.1.1", store.ScopeAll, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := st.AddRewriteScoped("nas.home", "A", "2.2.2.2", store.ScopeSites, []string{"office"}); err != nil {
		t.Fatal(err)
	}
	if _, err := st.AddForwarder("corp.internal", []string{"10.0.0.2:53"}, store.ScopeSites, []string{"office"}); err != nil {
		t.Fatal(err)
	}

	fetch := func(key string) cluster.Snapshot {
		rr := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/api/cluster/snapshot", nil)
		req.Header.Set("Authorization", "Bearer "+key)
		s.clusterSnapshot(rr, req)
		if rr.Code != http.StatusOK {
			t.Fatalf("snapshot: %d %s", rr.Code, rr.Body.String())
		}
		var snap cluster.Snapshot
		if err := json.Unmarshal(rr.Body.Bytes(), &snap); err != nil {
			t.Fatal(err)
		}
		return snap
	}

	a, b := fetch(keyA), fetch(keyB)
	if len(a.Rewrites) != 1 || a.Rewrites[0].Value != "2.2.2.2" {
		t.Fatalf("node-a must get the site override: %+v", a.Rewrites)
	}
	if len(b.Rewrites) != 1 || b.Rewrites[0].Value != "1.1.1.1" {
		t.Fatalf("node-b must get the global value: %+v", b.Rewrites)
	}
	if len(a.Forwarders) != 1 || len(b.Forwarders) != 0 {
		t.Fatalf("forwarder scoping wrong: a=%+v b=%+v", a.Forwarders, b.Forwarders)
	}
	if a.Version == b.Version {
		t.Fatal("nodes with different content must advertise different versions")
	}
	if wantA, _ := st.ConfigVersionForNode("node-a", "office"); a.Version != wantA {
		t.Fatalf("snapshot version %q != per-node hash %q", a.Version, wantA)
	}
}

// The nodes listing carries each node's expected (per-node) config version so
// the UI can flag drift individually.
func TestClusterNodesExpectedVersion(t *testing.T) {
	s, st := newEnrollServer(t, "s3cr3t", false)
	rr := httptest.NewRecorder()
	s.clusterEnroll(rr, httptest.NewRequest(http.MethodPost, "/api/cluster/enroll",
		strings.NewReader(`{"name":"node-a","token":"s3cr3t"}`)))
	if rr.Code != http.StatusCreated {
		t.Fatal(rr.Body.String())
	}
	if _, err := st.AddRewrite("nas.lan", "A", "10.0.0.5"); err != nil {
		t.Fatal(err)
	}
	nrr := httptest.NewRecorder()
	s.clusterNodes(nrr, httptest.NewRequest(http.MethodGet, "/api/cluster/nodes", nil))
	if nrr.Code != http.StatusOK {
		t.Fatal(nrr.Body.String())
	}
	var nodes []struct {
		Name            string `json:"name"`
		ExpectedVersion string `json:"expected_version"`
	}
	if err := json.Unmarshal(nrr.Body.Bytes(), &nodes); err != nil {
		t.Fatal(err)
	}
	want, _ := st.ConfigVersionForNode("node-a", "")
	if len(nodes) != 1 || nodes[0].ExpectedVersion != want || want == "" {
		t.Fatalf("expected_version missing/wrong: %+v (want %q)", nodes, want)
	}
}
```

Add `"encoding/json"` and `"github.com/IPMaze/MazeDNS/internal/cluster"` to the test file's imports.

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/api/ -run 'TestClusterSnapshotPerNode|TestClusterNodesExpected' -v`
Expected: FAIL — node-b receives 2 rewrites (unfiltered) / `expected_version` is empty.

- [ ] **Step 3: Implement**

3a. In `clusterSnapshot` (~line 348), replace the rewrites+version block:

```go
	rewrites, err := s.store.ListRewritesForNode(node.Name, node.Site)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	forwarders, err := s.store.ListForwardersForNode(node.Name, node.Site)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	version, _ := s.store.ConfigVersionForNode(node.Name, node.Site)
	pausedUntil, _ := s.store.GetBlockPausedUntil()
	if rules == nil {
		rules = []store.Rule{}
	}
	if rewrites == nil {
		rewrites = []store.Rewrite{}
	}
	writeJSON(w, http.StatusOK, cluster.Snapshot{Version: version, Rules: rules, Rewrites: rewrites, Forwarders: forwarders, PausedUntil: pausedUntil, Maintenance: node.Maintenance})
```

3b. Replace `clusterNodes` (~line 416):

```go
// clusterNodes lists the enrolled DNS agents. The control plane itself is not a
// resolver, so it does not appear here — the cluster view is the data plane only.
// Each node carries its expected (per-node) config version: scoped rewrites and
// forwarders mean there is no single cluster-wide version to compare against.
func (s *Server) clusterNodes(w http.ResponseWriter, _ *http.Request) {
	nodes, err := s.store.ListNodes()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	type nodeStatus struct {
		store.Node
		ExpectedVersion string `json:"expected_version"`
	}
	out := make([]nodeStatus, 0, len(nodes))
	for _, n := range nodes {
		ev, _ := s.store.ConfigVersionForNode(n.Name, n.Site)
		out = append(out, nodeStatus{Node: n, ExpectedVersion: ev})
	}
	writeJSON(w, http.StatusOK, out)
}
```

- [ ] **Step 4: Run the full suite**

Run: `go test ./... 2>&1 | tail -5`
Expected: all PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/api/api.go internal/api/cluster_test.go
git commit -m "feat(api): per-node filtered snapshots and expected_version per node"
```

---

### Task 10: Config bundle export/import carries forwarders

**Files:**
- Modify: `internal/api/config.go`
- Test: `internal/api/config_test.go` (create)

**Interfaces:**
- Consumes: `ListForwarders`, `AddForwardersBulk`, `ClearForwarders` (Task 3).
- Produces: `ConfigBundle` gains `Forwarders []store.Forwarder \`json:"forwarders,omitempty"\`` (bundle version stays 1 — the field is additive and old bundles import unchanged).

- [ ] **Step 1: Write the failing test**

Create `internal/api/config_test.go`:

```go
package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/IPMaze/MazeDNS/internal/store"
)

func TestConfigBundleForwardersRoundTrip(t *testing.T) {
	st, err := store.Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	s := &Server{store: st}

	if _, err := st.AddForwarder("corp.internal", []string{"10.0.0.2:53"}, store.ScopeSites, []string{"office"}); err != nil {
		t.Fatal(err)
	}
	if _, err := st.AddRewriteScoped("nas.lan", "A", "10.0.0.5", store.ScopeNodes, []string{"n1"}); err != nil {
		t.Fatal(err)
	}

	// Export includes forwarders and rewrite scopes.
	rr := httptest.NewRecorder()
	s.exportConfig(rr, httptest.NewRequest(http.MethodGet, "/api/config/export", nil))
	if rr.Code != http.StatusOK {
		t.Fatal(rr.Body.String())
	}
	var b ConfigBundle
	if err := json.Unmarshal(rr.Body.Bytes(), &b); err != nil {
		t.Fatal(err)
	}
	if len(b.Forwarders) != 1 || b.Forwarders[0].Suffix != "corp.internal" || b.Forwarders[0].ScopeType != store.ScopeSites {
		t.Fatalf("forwarders not exported: %+v", b.Forwarders)
	}
	if len(b.Rewrites) != 1 || b.Rewrites[0].ScopeType != store.ScopeNodes {
		t.Fatalf("rewrite scope not exported: %+v", b.Rewrites)
	}

	// Replace-import into an empty store restores both, with scopes.
	st2, err := store.Open(filepath.Join(t.TempDir(), "test2.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st2.Close() })
	s2 := &Server{store: st2}
	irr := httptest.NewRecorder()
	s2.importConfig(irr, httptest.NewRequest(http.MethodPost, "/api/config/import?mode=replace", strings.NewReader(rr.Body.String())))
	if irr.Code != http.StatusOK {
		t.Fatal(irr.Body.String())
	}
	fws, _ := st2.ListForwarders()
	if len(fws) != 1 || fws[0].Suffix != "corp.internal" || fws[0].ScopeType != store.ScopeSites || !fws[0].Enabled {
		t.Fatalf("forwarders not imported: %+v", fws)
	}
	rws, _ := st2.ListRewrites()
	if len(rws) != 1 || rws[0].ScopeType != store.ScopeNodes {
		t.Fatalf("rewrite scope not imported: %+v", rws)
	}
}
```

Note: `importConfig` calls `s.res.ApplySettings` only when `b.Settings != nil`; the exported bundle here has no settings row, so `s2.res` being nil is fine. If the export DID include settings (a real CP always has one after first boot), the test store has no settings row → `bundle.Settings` stays nil. No resolver needed.

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/api/ -run TestConfigBundleForwarders -v`
Expected: FAIL (compile error: `b.Forwarders` undefined).

- [ ] **Step 3: Implement** in `internal/api/config.go`

3a. Extend the struct:

```go
type ConfigBundle struct {
	Version    int                `json:"version"`
	ExportedAt int64              `json:"exported_at"`
	Settings   *resolver.Settings `json:"settings,omitempty"`
	Rules      []store.Rule       `json:"rules"`
	Rewrites   []store.Rewrite    `json:"rewrites"`
	Forwarders []store.Forwarder  `json:"forwarders,omitempty"`
}
```

3b. In `exportConfig`, after the rewrites block (~line 62), add:

```go
	fws, err := s.store.ListForwarders()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	bundle.Forwarders = fws
```

3c. In `importConfig`:
- In the `mode == "replace"` block, after `ClearRewrites()`:

```go
		if err := s.store.ClearForwarders(); err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
```

- After the `AddRewritesBulk` call:

```go
	nf, err := s.store.AddForwardersBulk(b.Forwarders)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
```

- Add `"forwarders": nf,` to the final `writeJSON` map.

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/api/ -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/api/config.go internal/api/config_test.go
git commit -m "feat(api): config bundle carries forwarders and rewrite scopes"
```

---

### Task 11: Web UI — scope picker, scoped rewrites, forwarders section

**Files:**
- Modify: `web/src/api.ts` (Rewrite interface ~line 33; api object rewrites section ~line 506)
- Create: `web/src/components/ScopePicker.tsx`
- Modify: `web/src/components/Rewrites.tsx` (full rewrite below)

**Interfaces:**
- Consumes: API endpoints from Tasks 7–8; existing `api.clusterNodes()`, `api.clusterSites()`.
- Produces: UI for scoped rewrites + a "Conditional forwarders (cluster)" section on the same page.

- [ ] **Step 1: Extend `web/src/api.ts`**

Replace the `Rewrite` interface:

```ts
export interface Rewrite {
  id: number
  domain: string
  rrtype: string
  value: string
  enabled: boolean
  updated_at: number
  scope_type?: string
  scope_values?: string[]
}

export interface Forwarder {
  id: number
  suffix: string
  upstreams: string[]
  scope_type: string
  scope_values: string[]
  enabled: boolean
  updated_at: number
}
```

Replace the rewrites entries in the `api` object and add forwarders:

```ts
  rewrites: () => fetch('/api/rewrites').then(j<Rewrite[]>),
  addRewrite: (domain: string, rrtype: string, value: string, scopeType = 'all', scopeValues: string[] = []) =>
    fetch('/api/rewrites', {
      method: 'POST',
      headers: jsonHeaders,
      body: JSON.stringify({ domain, rrtype, value, scope_type: scopeType, scope_values: scopeValues }),
    }).then(j),
  updateRewrite: (id: number, value: string, enabled: boolean, scopeType: string, scopeValues: string[]) =>
    fetch(`/api/rewrites/${id}`, {
      method: 'PUT',
      headers: jsonHeaders,
      body: JSON.stringify({ value, enabled, scope_type: scopeType, scope_values: scopeValues }),
    }).then(j),
  deleteRewrite: (id: number) => fetch(`/api/rewrites/${id}`, { method: 'DELETE' }),

  // Centrally-managed conditional forwarders (pushed to agents via the snapshot).
  forwarders: () => fetch('/api/forwarders').then(j<Forwarder[]>),
  addForwarder: (suffix: string, upstreams: string[], scopeType = 'all', scopeValues: string[] = []) =>
    fetch('/api/forwarders', {
      method: 'POST',
      headers: jsonHeaders,
      body: JSON.stringify({ suffix, upstreams, scope_type: scopeType, scope_values: scopeValues }),
    }).then(j),
  updateForwarder: (id: number, upstreams: string[], enabled: boolean, scopeType: string, scopeValues: string[]) =>
    fetch(`/api/forwarders/${id}`, {
      method: 'PUT',
      headers: jsonHeaders,
      body: JSON.stringify({ upstreams, enabled, scope_type: scopeType, scope_values: scopeValues }),
    }).then(j),
  deleteForwarder: (id: number) => fetch(`/api/forwarders/${id}`, { method: 'DELETE' }),
```

- [ ] **Step 2: Create `web/src/components/ScopePicker.tsx`**

```tsx
import { type ReactNode } from 'react'

export interface Scope {
  scope_type: string
  scope_values: string[]
}

export const ALL_SCOPE: Scope = { scope_type: 'all', scope_values: [] }

// Human-readable badge for a stored scope ("all nodes", "2 nodes: a, b", …).
export function scopeBadge(scopeType?: string, scopeValues?: string[], known?: string[]): ReactNode {
  const st = scopeType || 'all'
  if (st === 'all') return <span className="muted">all nodes</span>
  const vals = scopeValues || []
  const label = st === 'nodes' ? 'node' : 'site'
  const missing = known ? vals.filter((v) => !known.includes(v)) : []
  return (
    <span title={vals.join(', ')}>
      {vals.length === 1 ? `${label}: ${vals[0]}` : `${vals.length} ${label}s: ${vals.join(', ')}`}
      {missing.length > 0 && (
        <span className="muted" title={`unknown ${label}(s): ${missing.join(', ')} — this entry currently matches nothing`}>
          {' '}
          ⚠
        </span>
      )}
    </span>
  )
}

// Scope selector: "all nodes" or a checkbox list of nodes / sites. Options come
// from the cluster endpoints; when the cluster is empty the picker collapses to
// "all nodes" only.
export default function ScopePicker({
  value,
  onChange,
  nodes,
  sites,
}: {
  value: Scope
  onChange: (s: Scope) => void
  nodes: string[]
  sites: string[]
}) {
  const options = value.scope_type === 'nodes' ? nodes : value.scope_type === 'sites' ? sites : []
  const toggle = (name: string) => {
    const has = value.scope_values.includes(name)
    onChange({
      ...value,
      scope_values: has ? value.scope_values.filter((v) => v !== name) : [...value.scope_values, name],
    })
  }
  return (
    <span className="scope-picker">
      <select
        value={value.scope_type}
        onChange={(e) => onChange({ scope_type: e.target.value, scope_values: [] })}
      >
        <option value="all">All nodes</option>
        {nodes.length > 0 && <option value="nodes">Specific nodes</option>}
        {sites.length > 0 && <option value="sites">Sites</option>}
      </select>
      {value.scope_type !== 'all' &&
        options.map((name) => (
          <label key={name} className="scope-chip">
            <input type="checkbox" checked={value.scope_values.includes(name)} onChange={() => toggle(name)} />
            {name}
          </label>
        ))}
    </span>
  )
}
```

- [ ] **Step 3: Rewrite `web/src/components/Rewrites.tsx`**

```tsx
import { useEffect, useState, type FormEvent } from 'react'
import { api, type Forwarder, type Rewrite } from '../api'
import ScopePicker, { ALL_SCOPE, scopeBadge, type Scope } from './ScopePicker'

export default function Rewrites() {
  const [rows, setRows] = useState<Rewrite[]>([])
  const [domain, setDomain] = useState('')
  const [rrtype, setRrtype] = useState('A')
  const [value, setValue] = useState('')
  const [scope, setScope] = useState<Scope>(ALL_SCOPE)
  const [err, setErr] = useState('')

  const [fwds, setFwds] = useState<Forwarder[]>([])
  const [suffix, setSuffix] = useState('')
  const [upstreams, setUpstreams] = useState('')
  const [fwdScope, setFwdScope] = useState<Scope>(ALL_SCOPE)
  const [fwdErr, setFwdErr] = useState('')

  const [nodes, setNodes] = useState<string[]>([])
  const [sites, setSites] = useState<string[]>([])

  const load = () => {
    api.rewrites().then(setRows).catch((e) => setErr(e.message))
    api.forwarders().then(setFwds).catch(() => setFwds([]))
  }
  useEffect(() => {
    load()
    // Cluster lists feed the scope pickers; on a standalone control plane the
    // calls fail and scoping simply collapses to "all nodes".
    api.clusterNodes().then((ns) => setNodes(ns.map((n) => n.name))).catch(() => {})
    api.clusterSites().then((ss) => setSites(ss.map((s) => s.name))).catch(() => {})
  }, [])

  const add = async (e: FormEvent) => {
    e.preventDefault()
    if (!domain.trim() || !value.trim()) return
    try {
      await api.addRewrite(domain.trim(), rrtype, value.trim(), scope.scope_type, scope.scope_values)
      setDomain('')
      setValue('')
      setScope(ALL_SCOPE)
      setErr('')
      load()
    } catch (e: any) {
      setErr(e.message)
    }
  }

  const del = async (id: number) => {
    await api.deleteRewrite(id)
    load()
  }

  const addFwd = async (e: FormEvent) => {
    e.preventDefault()
    const ups = upstreams
      .split(',')
      .map((u) => u.trim())
      .filter(Boolean)
    if (!suffix.trim() || ups.length === 0) return
    try {
      await api.addForwarder(suffix.trim(), ups, fwdScope.scope_type, fwdScope.scope_values)
      setSuffix('')
      setUpstreams('')
      setFwdScope(ALL_SCOPE)
      setFwdErr('')
      load()
    } catch (e: any) {
      setFwdErr(e.message)
    }
  }

  const toggleFwd = async (f: Forwarder) => {
    try {
      await api.updateForwarder(f.id, f.upstreams, !f.enabled, f.scope_type, f.scope_values)
      load()
    } catch (e: any) {
      setFwdErr(e.message)
    }
  }

  const delFwd = async (id: number) => {
    await api.deleteForwarder(id)
    load()
  }

  return (
    <div>
      <h2>Local DNS rewrites</h2>
      <p className="muted">
        Use <code>*.example.com</code> to match every subdomain. The wildcard does not cover the bare
        <code> example.com</code> — add a separate entry for the apex if you need it. Scope an entry to
        nodes or sites for split-horizon answers; the most specific scope wins (node &gt; site &gt; all).
      </p>
      {err && <div className="error">{err}</div>}
      <form className="row" onSubmit={add}>
        <input placeholder="domain (e.g. nas.lan or *.lab.lan)" value={domain} onChange={(e) => setDomain(e.target.value)} />
        <select value={rrtype} onChange={(e) => setRrtype(e.target.value)}>
          <option>A</option>
          <option>AAAA</option>
          <option>CNAME</option>
        </select>
        <input placeholder="value (IP or target)" value={value} onChange={(e) => setValue(e.target.value)} />
        <ScopePicker value={scope} onChange={setScope} nodes={nodes} sites={sites} />
        <button type="submit">Add</button>
      </form>
      <table>
        <thead>
          <tr>
            <th>Domain</th>
            <th>Type</th>
            <th>Value</th>
            <th>Scope</th>
            <th></th>
          </tr>
        </thead>
        <tbody>
          {rows.map((r) => (
            <tr key={r.id}>
              <td>{r.domain}</td>
              <td>{r.rrtype}</td>
              <td>{r.value}</td>
              <td>
                {scopeBadge(
                  r.scope_type,
                  r.scope_values,
                  r.scope_type === 'nodes' ? nodes : r.scope_type === 'sites' ? sites : undefined,
                )}
              </td>
              <td>
                <button className="del" onClick={() => del(r.id)}>
                  ✕
                </button>
              </td>
            </tr>
          ))}
          {rows.length === 0 && (
            <tr>
              <td colSpan={5} className="muted">
                No rewrites
              </td>
            </tr>
          )}
        </tbody>
      </table>

      <h2>Conditional forwarders (cluster)</h2>
      <p className="muted">
        Send a domain suffix to specific upstreams. Entries here are pushed to the scoped agents
        automatically and override a node's own forwarder for the same suffix.
      </p>
      {fwdErr && <div className="error">{fwdErr}</div>}
      <form className="row" onSubmit={addFwd}>
        <input placeholder="suffix (e.g. corp.internal)" value={suffix} onChange={(e) => setSuffix(e.target.value)} />
        <input
          placeholder="upstreams, comma-separated (e.g. 10.0.0.2:53)"
          value={upstreams}
          onChange={(e) => setUpstreams(e.target.value)}
        />
        <ScopePicker value={fwdScope} onChange={setFwdScope} nodes={nodes} sites={sites} />
        <button type="submit">Add</button>
      </form>
      <table>
        <thead>
          <tr>
            <th>Suffix</th>
            <th>Upstreams</th>
            <th>Scope</th>
            <th>Enabled</th>
            <th></th>
          </tr>
        </thead>
        <tbody>
          {fwds.map((f) => (
            <tr key={f.id} className={f.enabled ? '' : 'muted'}>
              <td>{f.suffix}</td>
              <td>{f.upstreams.join(', ')}</td>
              <td>
                {scopeBadge(
                  f.scope_type,
                  f.scope_values,
                  f.scope_type === 'nodes' ? nodes : f.scope_type === 'sites' ? sites : undefined,
                )}
              </td>
              <td>
                <button onClick={() => toggleFwd(f)}>{f.enabled ? 'On' : 'Off'}</button>
              </td>
              <td>
                <button className="del" onClick={() => delFwd(f.id)}>
                  ✕
                </button>
              </td>
            </tr>
          ))}
          {fwds.length === 0 && (
            <tr>
              <td colSpan={5} className="muted">
                No cluster forwarders
              </td>
            </tr>
          )}
        </tbody>
      </table>
    </div>
  )
}
```

- [ ] **Step 4: Add minimal styles** — append to `web/src/styles.css`:

```css
/* Scope picker: inline chips next to the type select */
.scope-picker { display: inline-flex; align-items: center; gap: 0.4rem; flex-wrap: wrap; }
.scope-chip { display: inline-flex; align-items: center; gap: 0.2rem; font-size: 0.85em; padding: 0.1rem 0.4rem; border: 1px solid var(--border, #4444); border-radius: 999px; cursor: pointer; }
```

- [ ] **Step 5: Build the frontend**

Run: `make web`
Expected: build completes without TypeScript errors; `web/dist/` is regenerated.

- [ ] **Step 6: Commit**

```bash
git add web/src/api.ts web/src/components/ScopePicker.tsx web/src/components/Rewrites.tsx web/src/styles.css web/dist
git commit -m "feat(web): scope pickers for rewrites + cluster forwarders section"
```

---

### Task 12: Web UI — per-node drift on the cluster page + settings note

**Files:**
- Modify: `web/src/api.ts` (Node interface)
- Modify: `web/src/components/Cluster.tsx` (~line 356 and detail panel ~line 470)
- Modify: `web/src/components/Settings.tsx` (~line 453)

**Interfaces:**
- Consumes: `expected_version` from Task 9.
- Produces: visual drift flag per node; a note that central forwarders override local ones.

- [ ] **Step 1: Extend the `Node` interface in `web/src/api.ts`** — add one field:

```ts
  expected_version?: string
```

- [ ] **Step 2: Show drift in `web/src/components/Cluster.tsx`**

At ~line 356, replace:

```tsx
                  <td>{n.version ? <code>{n.version}</code> : <span className="muted">pending</span>}</td>
```

with:

```tsx
                  <td>
                    {n.version ? (
                      n.expected_version && n.version !== n.expected_version ? (
                        <code title={`syncing: node has ${n.version}, expects ${n.expected_version}`}>{n.version} ⟳</code>
                      ) : (
                        <code>{n.version}</code>
                      )
                    ) : (
                      <span className="muted">pending</span>
                    )}
                  </td>
```

At ~line 470 (detail panel), replace:

```tsx
        <div><dt>Version</dt><dd>{node.version ? <code>{node.version}</code> : '—'}</dd></div>
```

with:

```tsx
        <div><dt>Version</dt><dd>{node.version ? <code>{node.version}</code> : '—'}{node.expected_version && node.version && node.version !== node.expected_version ? <span className="muted"> (expects <code>{node.expected_version}</code>)</span> : null}</dd></div>
```

(If the surrounding markup differs slightly, keep the existing structure and add only the drift comparison — the behavior to preserve: show the reported version, and flag when it differs from `expected_version`.)

- [ ] **Step 3: Add the precedence note in `web/src/components/Settings.tsx`** — inside the `<details>` whose `<summary>` is `Conditional forwarders` (~line 453), directly after the summary line, add:

```tsx
        <p className="muted">
          These forwarders are this control plane's local settings. Cluster-wide forwarders for the
          DNS agents are managed on the <b>Rewrites</b> tab and override a node's local entry for the
          same suffix.
        </p>
```

- [ ] **Step 4: Build and verify**

Run: `make web`
Expected: clean build.

- [ ] **Step 5: Commit**

```bash
git add web/src/api.ts web/src/components/Cluster.tsx web/src/components/Settings.tsx web/dist
git commit -m "feat(web): per-node version drift flag + forwarder precedence note"
```

---

### Task 13: Documentation

**Files:**
- Modify: `docs/user-guide.md` (rewrites + forwarders sections)
- Modify: `docs/configuration.md` (forwarders row, ~line 123)

**Interfaces:** none (prose only).

- [ ] **Step 1: Update `docs/user-guide.md`**

In the "Conditional forwarders" bullet under "Upstreams, cache, and DNS behavior" (~line 37), replace the bullet with:

```markdown
- **Conditional forwarders** — send a domain suffix to specific upstreams
  (split-horizon), e.g. `corp.internal` → your internal resolver. Cluster-wide
  forwarders are managed on the **Rewrites** tab, can be scoped to specific
  nodes or sites, and are pushed to the agents automatically; they override a
  node's own (YAML-seeded) forwarder for the same suffix.
```

Find the section describing local DNS rewrites (search for "rewrites" headings) and add after its existing description:

```markdown
Rewrites can be **scoped**: to every node (default), to specific nodes, or to
one or more sites. The same domain may carry different values under different
scopes — the classic split-horizon setup where `nas.home` resolves to a
different address per site. When several entries match a node, the most
specific wins (node > site > all); creating two entries that would tie at the
same specificity is rejected. Entries scoped to a node or site that no longer
exists are kept but match nothing (flagged with ⚠ in the UI).

The **Conditional forwarders (cluster)** section on the same tab manages
suffix → upstream routing with identical scoping. Agents pick changes up on
their next config poll; the cluster page shows a per-node sync flag (⟳) until
each node has applied its own expected version.
```

- [ ] **Step 2: Update `docs/configuration.md`** — replace the `forwarders` table row (~line 123):

```markdown
| `forwarders` | Split-horizon per suffix: `- { suffix: "corp.internal", upstreams: [...] }`. Seeds this node's local forwarders; cluster-wide scoped forwarders managed in the UI override a local entry with the same suffix. |
```

- [ ] **Step 3: Commit**

```bash
git add docs/user-guide.md docs/configuration.md
git commit -m "docs: scoped rewrites and centrally managed conditional forwarders"
```

---

### Final verification (after all tasks)

- [ ] `go build ./... && go vet ./... && go test ./...` — everything green.
- [ ] `make web` — frontend builds.
- [ ] Manual smoke (optional but recommended): `make compose-dev` (or `make run-cp` + `make run-agent`), add a site-scoped rewrite and a forwarder in the UI, and confirm the agent log line `cluster synced ... forwarders=1` plus a `dig` against the agent returning the scoped value.
