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
