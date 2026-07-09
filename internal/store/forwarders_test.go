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

	// A forwarder never conflicts with itself when its own id is excluded. Use
	// a different-but-intersecting value list (not identical to the row's own
	// ["lab"]) so the self-skip is actually exercised via excludeID — an
	// identical list would pass this assertion via the "vals != valuesJSON"
	// shortcut even if excludeID were ignored entirely.
	var sitesID int64 = -1
	for _, f := range fws {
		if f.ScopeType == ScopeSites {
			sitesID = f.ID
		}
	}
	if sitesID == -1 {
		t.Fatal("expected a sites-scoped forwarder in list")
	}
	if c, _ := s.ForwarderScopeConflict("corp.internal", ScopeSites, `["dc","lab"]`, sitesID); c {
		t.Fatal("forwarder must not conflict with itself when excludeID is its own id")
	}
	if c, _ := s.ForwarderScopeConflict("corp.internal", ScopeSites, `["dc","lab"]`, 0); !c {
		t.Fatal("expected conflict when excludeID does not match the row")
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

func TestAddForwardersBulk(t *testing.T) {
	s, err := Open(filepath.Join(t.TempDir(), "t.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	in := []Forwarder{
		{Suffix: "corp.internal", Upstreams: []string{"10.0.0.2:53"}, ScopeType: ScopeAll, Enabled: true},
		{Suffix: "lab.internal", Upstreams: []string{"10.9.0.2:53"}, ScopeType: ScopeSites, ScopeValues: []string{"lab"}, Enabled: false},
	}
	n, err := s.AddForwardersBulk(in)
	if err != nil {
		t.Fatal(err)
	}
	if n != 2 {
		t.Fatalf("want 2 applied, got %d", n)
	}

	fws, err := s.ListForwarders()
	if err != nil || len(fws) != 2 {
		t.Fatalf("want 2 forwarders, got %d (err=%v)", len(fws), err)
	}
	for _, f := range fws {
		switch f.Suffix {
		case "corp.internal":
			if !f.Enabled {
				t.Fatalf("corp.internal should be enabled: %+v", f)
			}
		case "lab.internal":
			// The disabled entry must persist as disabled immediately -
			// no transient enabled state from a bulk import.
			if f.Enabled {
				t.Fatalf("lab.internal should be disabled: %+v", f)
			}
		default:
			t.Fatalf("unexpected forwarder: %+v", f)
		}
	}

	// Re-importing the same suffix+scope upserts rather than duplicating rows.
	in2 := []Forwarder{
		{Suffix: "corp.internal", Upstreams: []string{"10.0.0.3:53"}, ScopeType: ScopeAll, Enabled: false},
		{Suffix: "lab.internal", Upstreams: []string{"10.9.0.3:53"}, ScopeType: ScopeSites, ScopeValues: []string{"lab"}, Enabled: true},
	}
	n2, err := s.AddForwardersBulk(in2)
	if err != nil {
		t.Fatal(err)
	}
	if n2 != 2 {
		t.Fatalf("want 2 applied on re-import, got %d", n2)
	}

	fws, err = s.ListForwarders()
	if err != nil || len(fws) != 2 {
		t.Fatalf("want still 2 forwarders after upsert, got %d (err=%v)", len(fws), err)
	}
	for _, f := range fws {
		switch f.Suffix {
		case "corp.internal":
			if f.Enabled || f.Upstreams[0] != "10.0.0.3:53" {
				t.Fatalf("corp.internal not upserted: %+v", f)
			}
		case "lab.internal":
			if !f.Enabled || f.Upstreams[0] != "10.9.0.3:53" {
				t.Fatalf("lab.internal not upserted: %+v", f)
			}
		default:
			t.Fatalf("unexpected forwarder: %+v", f)
		}
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
