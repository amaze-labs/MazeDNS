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
