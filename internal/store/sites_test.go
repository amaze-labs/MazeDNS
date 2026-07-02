package store

import (
	"path/filepath"
	"testing"
)

func TestSitesAssignment(t *testing.T) {
	s, err := Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })

	id := map[string]string{}
	for _, n := range []string{"node-a", "node-b", "node-c"} {
		nid, err := s.CreateNode(n, "h"+n, "p")
		if err != nil {
			t.Fatal(err)
		}
		id[n] = nid
	}
	if err := s.CreateSite("office", "HQ"); err != nil {
		t.Fatal(err)
	}

	if err := s.SetNodeSite(id["node-a"], "office", "primary"); err != nil {
		t.Fatal(err)
	}
	if err := s.SetNodeSite(id["node-b"], "office", "backup"); err != nil {
		t.Fatal(err)
	}

	roleOf := func(name string) (site, role string) {
		nodes, _ := s.ListNodes()
		for _, n := range nodes {
			if n.Name == name {
				return n.Site, n.Role
			}
		}
		return "", ""
	}

	if si, r := roleOf("node-a"); si != "office" || r != "primary" {
		t.Fatalf("node-a = %s/%s, want office/primary", si, r)
	}

	// Promoting node-b to primary must demote node-a (one primary per site).
	if err := s.SetNodeSite(id["node-b"], "office", "primary"); err != nil {
		t.Fatal(err)
	}
	if _, r := roleOf("node-a"); r != "backup" {
		t.Errorf("node-a should be demoted to backup, got %q", r)
	}
	if _, r := roleOf("node-b"); r != "primary" {
		t.Errorf("node-b should be primary, got %q", r)
	}

	// A primary in a DIFFERENT site is unaffected.
	if err := s.CreateSite("branch", ""); err != nil {
		t.Fatal(err)
	}
	if err := s.SetNodeSite(id["node-c"], "branch", "primary"); err != nil {
		t.Fatal(err)
	}
	if _, r := roleOf("node-b"); r != "primary" {
		t.Errorf("node-b (office) should stay primary when branch gets one, got %q", r)
	}

	// Deleting a site unassigns its members.
	if err := s.DeleteSite("office"); err != nil {
		t.Fatal(err)
	}
	if si, r := roleOf("node-b"); si != "" || r != "" {
		t.Errorf("node-b after site delete = %s/%s, want empty", si, r)
	}
	sites, _ := s.ListSites()
	if len(sites) != 1 || sites[0].Name != "branch" {
		t.Errorf("sites after delete = %+v, want [branch]", sites)
	}
}

func TestMasterSiteSinglePrimary(t *testing.T) {
	s, err := Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })

	idA, err := s.CreateNode("node-a", "h", "p")
	if err != nil {
		t.Fatal(err)
	}
	if err := s.SetNodeSite(idA, "office", "primary"); err != nil {
		t.Fatal(err)
	}
	// Master taking primary in the same site demotes the worker primary.
	if err := s.SetMasterSite("office", "primary"); err != nil {
		t.Fatal(err)
	}
	nodes, _ := s.ListNodes()
	if nodes[0].Role != "backup" {
		t.Errorf("node-a should be demoted by master primary, got %q", nodes[0].Role)
	}
	if s.MasterSite() != "office" || s.MasterRole() != "primary" {
		t.Errorf("master = %s/%s, want office/primary", s.MasterSite(), s.MasterRole())
	}
}
