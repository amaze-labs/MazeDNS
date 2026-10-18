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
	if _, r := roleOf("node-a"); r != "secondary" {
		t.Errorf("node-a should be demoted to secondary, got %q", r)
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
	if nodes[0].Role != "secondary" {
		t.Errorf("node-a should be demoted by master primary, got %q", nodes[0].Role)
	}
	if s.MasterSite() != "office" || s.MasterRole() != "primary" {
		t.Errorf("master = %s/%s, want office/primary", s.MasterSite(), s.MasterRole())
	}
}

// Renaming a site carries its agents (and their roles), the rules scoped to it
// and the master's assignment; the new name must be free.
func TestUpdateSiteRename(t *testing.T) {
	s, err := Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })

	a, _ := s.CreateNode("agent-a", "ha", "p")
	if _, err := s.CreateNode("agent-b", "hb", "p"); err != nil {
		t.Fatal(err)
	}
	for _, n := range []string{"office", "lab", "zoo"} {
		if err := s.CreateSite(n, ""); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.SetNodeSite(a, "office", "primary"); err != nil {
		t.Fatal(err)
	}
	if err := s.SetMasterSite("office", "backup"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.AddRewriteScoped("nas.lan", "A", "192.0.2.1", ScopeSites, []string{"office", "zoo"}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.AddForwarder("corp.internal", []string{"10.0.0.2:53"}, ScopeSites, []string{"office"}); err != nil {
		t.Fatal(err)
	}
	before, _ := s.ListRewritesForNode("agent-a", "office")

	if err := s.UpdateSite("office", "lab", ""); err != ErrSiteExists {
		t.Fatalf("rename onto an existing site: err = %v, want ErrSiteExists", err)
	}
	if err := s.UpdateSite("office", "hq", "Head office"); err != nil {
		t.Fatal(err)
	}

	sites, _ := s.ListSites()
	got := map[string]string{}
	for _, si := range sites {
		got[si.Name] = si.Description
	}
	if _, old := got["office"]; old || got["hq"] != "Head office" {
		t.Errorf("sites = %v", got)
	}
	nodes, _ := s.ListNodes()
	for _, n := range nodes {
		if n.Name == "agent-a" && (n.Site != "hq" || n.Role != "primary") {
			t.Errorf("agent-a = %s/%s, want hq/primary", n.Site, n.Role)
		}
	}
	if s.MasterSite() != "hq" || s.MasterRole() != "backup" {
		t.Errorf("master = %s/%s", s.MasterSite(), s.MasterRole())
	}
	rws, _ := s.ListRewrites()
	if len(rws) != 1 || len(rws[0].ScopeValues) != 2 || rws[0].ScopeValues[0] != "hq" || rws[0].ScopeValues[1] != "zoo" {
		t.Errorf("rewrite scope = %v, want [hq zoo] (canonical order)", rws[0].ScopeValues)
	}
	fws, _ := s.ListForwarders()
	if len(fws) != 1 || len(fws[0].ScopeValues) != 1 || fws[0].ScopeValues[0] != "hq" {
		t.Errorf("forwarder scope = %v", fws[0].ScopeValues)
	}
	after, _ := s.ListRewritesForNode("agent-a", "hq")
	if len(before) != 1 || len(after) != 1 {
		t.Errorf("agent-a's rewrites: %d before, %d after the rename", len(before), len(after))
	}

	// Description only.
	if err := s.UpdateSite("hq", "hq", "HQ, floor 2"); err != nil {
		t.Fatal(err)
	}
	if err := s.UpdateSite("nowhere", "x", ""); err == nil {
		t.Error("updating a site that doesn't exist must fail")
	}
}
