package classifier

import (
	"path/filepath"
	"reflect"
	"testing"

	"github.com/IPMaze/MazeDNS/internal/store"
)

func TestNormalizeExcludes(t *testing.T) {
	got := NormalizeExcludes([]string{" Example.COM. ", "*.lab.example.net", "example.com", "", "bad name!", "corp.internal"})
	want := []string{"example.com", "lab.example.net", "corp.internal"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("NormalizeExcludes = %v, want %v", got, want)
	}
}

// Names under an excluded domain or a conditional forwarder's domain never
// reach the queue; anything else does.
func TestEnqueueSkipsExcluded(t *testing.T) {
	st, err := store.Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	if _, err := st.AddForwarder("corp.acme-widgets.net", []string{"10.0.0.53:53"}, store.ScopeAll, nil); err != nil {
		t.Fatal(err)
	}
	s := Settings{Enabled: true, Mode: "suggest", ExcludeDomains: []string{"amaze-labs.com"}}
	w := NewWorker(st, func() Settings { return s }, func() error { return nil })

	for _, name := range []string{"nas.amaze-labs.com.", "amaze-labs.com", "git.corp.acme-widgets.net."} {
		w.Enqueue(name)
	}
	if n := len(w.queue); n != 0 {
		t.Fatalf("excluded names queued: %d", n)
	}
	w.Enqueue("www.acme-widgets.net.") // a public name of the same registered domain
	w.Enqueue("news.ycombinator.com.")
	if n := len(w.queue); n != 2 {
		t.Errorf("queued %d, want 2", n)
	}
	if !w.Excluded("x.amaze-labs.com") || w.Excluded("notamaze-labs.com") {
		t.Error("suffix matching is per label")
	}
}
