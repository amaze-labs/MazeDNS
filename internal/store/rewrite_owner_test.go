package store

import (
	"database/sql"
	"errors"
	"path/filepath"
	"testing"
)

// A database from before rewrite ownership migrates to all-manual rows, and
// the config hashes agents compare against don't move: adding the columns
// must not resync any agent.
func TestRewriteOwnershipMigrationKeepsConfigHash(t *testing.T) {
	path := filepath.Join(t.TempDir(), "old.db")
	raw, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	// The rewrites table exactly as releases before #38 created it.
	if _, err := raw.Exec(`CREATE TABLE rewrites (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		domain TEXT NOT NULL,
		rrtype TEXT NOT NULL,
		value TEXT NOT NULL,
		enabled INTEGER NOT NULL DEFAULT 1,
		updated_at INTEGER NOT NULL,
		scope_type TEXT NOT NULL DEFAULT 'all',
		scope_values TEXT NOT NULL DEFAULT '[]',
		UNIQUE(domain, rrtype, scope_type, scope_values))`); err != nil {
		t.Fatal(err)
	}
	if _, err := raw.Exec(`INSERT INTO rewrites(domain, rrtype, value, enabled, updated_at, scope_type, scope_values) VALUES
		('nas.example.lan', 'A', '192.0.2.10', 1, 42, 'all', '[]'),
		('nas.example.lan', 'A', '198.51.100.10', 1, 42, 'sites', '["site-a"]'),
		('nas.example.lan', 'AAAA', '2001:db8::10', 0, 42, 'all', '[]'),
		('www.example.lan', 'CNAME', 'nas.example.lan', 1, 42, 'nodes', '["agent-01"]')`); err != nil {
		t.Fatal(err)
	}
	raw.Close()

	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	for _, rw := range mustListRewrites(t, s) {
		if rw.Source != "" || rw.ExternalID != "" {
			t.Fatalf("migrated row is not manual: %+v", rw)
		}
	}

	// Golden values: the hashes main (0c8b902) computes for these rows. The
	// global one hashes every row, the per-node one the node's filtered view.
	const wantGlobal, wantAgent01 = "bb4635602b55", "3e1a9b6439a6"
	all := []Rewrite{
		{Domain: "nas.example.lan", RRType: "A", Value: "192.0.2.10", Enabled: true},
		{Domain: "nas.example.lan", RRType: "A", Value: "198.51.100.10", Enabled: true},
		{Domain: "nas.example.lan", RRType: "AAAA", Value: "2001:db8::10", Enabled: false},
		{Domain: "www.example.lan", RRType: "CNAME", Value: "nas.example.lan", Enabled: true},
	}
	agent01 := []Rewrite{all[0], all[2], all[3]}
	if got := legacyConfigHash(nil, all, nil); got != wantGlobal {
		t.Fatalf("legacy global hash = %q, golden %q", got, wantGlobal)
	}
	if got := legacyConfigHash(nil, agent01, nil); got != wantAgent01 {
		t.Fatalf("legacy agent-01 hash = %q, golden %q", got, wantAgent01)
	}
	if v, err := s.ConfigVersion(); err != nil || v != wantGlobal {
		t.Fatalf("ConfigVersion = %q (%v), want %q", v, err, wantGlobal)
	}
	if v, err := s.ConfigVersionForNode("agent-01", ""); err != nil || v != wantAgent01 {
		t.Fatalf("ConfigVersionForNode = %q (%v), want %q", v, err, wantAgent01)
	}

	// Reopening runs the migration again as a no-op.
	s.Close()
	if s, err = Open(path); err != nil {
		t.Fatalf("reopen: %v", err)
	}
	if v, err := s.ConfigVersion(); err != nil || v != wantGlobal {
		t.Fatalf("ConfigVersion after reopen = %q (%v), want %q", v, err, wantGlobal)
	}
}

// Who owns a row never reaches the hash or the agents' view.
func TestRewriteOwnerNotHashedNorServed(t *testing.T) {
	s := openTestStore(t)
	id, err := s.UpsertRewrite(Rewrite{Domain: "srv-01.example.lan", RRType: "A", Value: "192.0.2.20",
		Source: "ipmaze", ExternalID: "host:1"})
	if err != nil {
		t.Fatal(err)
	}
	owned, err := s.ConfigVersionForNode("agent-01", "")
	if err != nil {
		t.Fatal(err)
	}
	served, err := s.ListRewritesForNode("agent-01", "")
	if err != nil {
		t.Fatal(err)
	}
	for _, rw := range served {
		if rw.Source != "" || rw.ExternalID != "" {
			t.Fatalf("agent view carries the owner: %+v", rw)
		}
	}
	if err := s.DetachRewrite(id); err != nil {
		t.Fatal(err)
	}
	if manual, _ := s.ConfigVersionForNode("agent-01", ""); manual != owned {
		t.Fatalf("detach moved the hash: %q -> %q", owned, manual)
	}
	if rw, ok, _ := s.GetRewrite(id); !ok || rw.Source != "" || rw.ExternalID != "" {
		t.Fatalf("detached row = %+v (found %v)", rw, ok)
	}
}

func TestUpsertRewriteOwnership(t *testing.T) {
	s := openTestStore(t)
	conflict := func(err error, owner string) {
		t.Helper()
		var ce *RewriteConflictError
		if !errors.As(err, &ce) || ce.Source != owner {
			t.Fatalf("err = %v, want a conflict with owner %q", err, owner)
		}
	}

	manual, err := s.AddRewrite("nas.example.lan", "A", "192.0.2.10")
	if err != nil {
		t.Fatal(err)
	}
	// An integration never takes over a manual row...
	_, err = s.UpsertRewrite(Rewrite{Domain: "nas.example.lan", RRType: "A", Value: "192.0.2.99", Source: "ipmaze"})
	conflict(err, "")
	if rw, _, _ := s.GetRewrite(manual); rw.Value != "192.0.2.10" || rw.Source != "" {
		t.Fatalf("manual row changed: %+v", rw)
	}

	// ...nor a manual write, or another integration, an owned one.
	owned, err := s.UpsertRewrite(Rewrite{Domain: "srv-01.example.lan", RRType: "A", Value: "192.0.2.20",
		Source: "ipmaze", ExternalID: "host:1"})
	if err != nil {
		t.Fatal(err)
	}
	_, err = s.AddRewrite("srv-01.example.lan", "A", "192.0.2.99")
	conflict(err, "ipmaze")
	_, err = s.UpsertRewrite(Rewrite{Domain: "srv-01.example.lan", RRType: "A", Value: "192.0.2.99", Source: "other"})
	conflict(err, "ipmaze")

	// The owner upserts in place but keeps the operator's enabled flag.
	if err := s.UpdateRewrite(owned, "192.0.2.20", false, ScopeAll, nil); err != nil {
		t.Fatal(err)
	}
	id, err := s.UpsertRewrite(Rewrite{Domain: "srv-01.example.lan", RRType: "A", Value: "192.0.2.21",
		Source: "ipmaze", ExternalID: "host:1"})
	if err != nil || id != owned {
		t.Fatalf("owner upsert: id %d (want %d) err %v", id, owned, err)
	}
	if rw, _, _ := s.GetRewrite(owned); rw.Value != "192.0.2.21" || rw.Enabled {
		t.Fatalf("owner upsert = %+v, want new value and still disabled", rw)
	}

	// (source, external_id, rrtype) is unique: another name for the same
	// object is refused, another type for it is not.
	_, err = s.UpsertRewrite(Rewrite{Domain: "srv-02.example.lan", RRType: "A", Value: "192.0.2.22",
		Source: "ipmaze", ExternalID: "host:1"})
	conflict(err, "ipmaze")
	if _, err := s.UpsertRewrite(Rewrite{Domain: "srv-01.example.lan", RRType: "AAAA", Value: "2001:db8::20",
		Source: "ipmaze", ExternalID: "host:1"}); err != nil {
		t.Fatalf("same object, other type: %v", err)
	}
}

// A config import restores owners, makes an unusable source manual, and
// drops an external id another row of the same source already holds.
func TestAddRewritesBulkOwnership(t *testing.T) {
	s := openTestStore(t)
	if _, err := s.UpsertRewrite(Rewrite{Domain: "srv-01.example.lan", RRType: "A", Value: "192.0.2.20",
		Source: "ipmaze", ExternalID: "host:1"}); err != nil {
		t.Fatal(err)
	}
	n, err := s.AddRewritesBulk([]Rewrite{
		{Domain: "srv-02.example.lan", RRType: "A", Value: "192.0.2.21", Source: "ipmaze", ExternalID: "host:2"},
		{Domain: "srv-03.example.lan", RRType: "A", Value: "192.0.2.22", Source: "ipmaze", ExternalID: "host:1"},
		{Domain: "srv-04.example.lan", RRType: "A", Value: "192.0.2.23", Source: "Not A Slug", ExternalID: "x"},
	})
	if err != nil || n != 3 {
		t.Fatalf("import n=%d err=%v", n, err)
	}
	got := map[string]Rewrite{}
	for _, rw := range mustListRewrites(t, s) {
		got[rw.Domain] = rw
	}
	for domain, want := range map[string][2]string{
		"srv-01.example.lan": {"ipmaze", "host:1"},
		"srv-02.example.lan": {"ipmaze", "host:2"},
		"srv-03.example.lan": {"ipmaze", ""},
		"srv-04.example.lan": {"", ""},
	} {
		if rw := got[domain]; rw.Source != want[0] || rw.ExternalID != want[1] {
			t.Errorf("%s: source %q external_id %q, want %q %q", domain, rw.Source, rw.ExternalID, want[0], want[1])
		}
	}
}
