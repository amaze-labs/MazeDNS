package resolver

import (
	"testing"
	"time"

	"github.com/miekg/dns"

	"github.com/IPMaze/MazeDNS/internal/categories"
	"github.com/IPMaze/MazeDNS/internal/filter"
)

func categoryResolver(t *testing.T, s Settings, allow ...string) *Resolver {
	t.Helper()
	var b categories.Builder
	b.Add("adult.example", "adult")
	b.Add("social.example", "social")
	b.Add("override-out.example", "adult")
	r := New(Options{Timeout: 200 * time.Millisecond})
	r.SetCategoryDB(categories.NewLoadedHolder(b.Build()))
	al := filter.New()
	for _, d := range allow {
		al.Add(d, "")
	}
	r.SetPolicy(&Policy{Block: filter.New(), Allow: al})
	s.Upstreams = []string{"127.0.0.1:1"} // nothing answers: an unblocked name errors
	r.ApplySettings(s)
	return r
}

func resolveName(r *Resolver, name string) (string, string) {
	req := new(dns.Msg)
	req.SetQuestion(dns.Fqdn(name), dns.TypeA)
	_, action, cat := r.Resolve(req, "10.0.0.1")
	return action, cat
}

func TestBlockedCategories(t *testing.T) {
	r := categoryResolver(t, Settings{
		BlockedCategories: []string{"adult", "gambling"},
		CategoryDomains: map[string]string{
			"override-out.example": "education", // an operator moved it out of adult
			"model-bet.example":    "gambling",  // the model's label, unknown to the database
		},
	}, "allowed.adult.example")

	for name, want := range map[string][2]string{
		"adult.example":         {"blocked", "adult"},
		"www.adult.example":     {"blocked", "adult"},    // subdomains too
		"model-bet.example":     {"blocked", "gambling"}, // the correction blocks
		"cdn.model-bet.example": {"blocked", "gambling"},
		"social.example":        {"error", ""}, // a category not blocked
		"override-out.example":  {"error", ""}, // the override exempts it
		"allowed.adult.example": {"error", ""}, // an allow rule wins
		"unknown.example":       {"error", ""},
	} {
		action, cat := resolveName(r, name)
		if action != want[0] || cat != want[1] {
			t.Errorf("%s: %s (%s), want %s (%s)", name, action, cat, want[0], want[1])
		}
	}

	r.SetBlockPausedUntil(time.Now().Add(time.Minute).Unix())
	if action, _ := resolveName(r, "adult.example"); action == "blocked" {
		t.Error("a block pause must also pause category blocking")
	}
}

// With no category blocked, nothing is blocked by category, whatever the
// database holds.
func TestNoBlockedCategories(t *testing.T) {
	r := categoryResolver(t, Settings{})
	if action, _ := resolveName(r, "adult.example"); action == "blocked" {
		t.Error("blocked with no category blocked")
	}
}

// An unchanged cache and unchanged upstreams survive a settings apply, so a
// change elsewhere (a category override, say) doesn't empty every agent's cache
// or drop their warm upstream connections.
func TestApplySettingsReusesCacheAndUpstreams(t *testing.T) {
	r := New(Options{Timeout: time.Second})
	s := Settings{Upstreams: []string{"tls://192.0.2.1:853", "192.0.2.2:53"}, Cache: CacheSettings{Enabled: true, MaxEntries: 100}}
	r.ApplySettings(s)
	rt1 := r.rt.Load()

	s.BlockedCategories = []string{"adult"}
	r.ApplySettings(s)
	rt2 := r.rt.Load()
	if rt2.cache != rt1.cache {
		t.Error("cache rebuilt although its settings didn't change")
	}
	if rt2.defaultUpstreams[0] != rt1.defaultUpstreams[0] || rt2.defaultUpstreams[1] != rt1.defaultUpstreams[1] {
		t.Error("upstreams rebuilt although they didn't change")
	}

	s.Cache.MaxEntries = 200
	s.Upstreams = []string{"tls://192.0.2.1:853", "192.0.2.3:53"}
	r.ApplySettings(s)
	rt3 := r.rt.Load()
	if rt3.cache == rt2.cache {
		t.Error("cache kept although its size changed")
	}
	if rt3.defaultUpstreams[0] != rt2.defaultUpstreams[0] {
		t.Error("the unchanged upstream was rebuilt")
	}
	if rt3.defaultUpstreams[1] == rt2.defaultUpstreams[1] {
		t.Error("the changed upstream was kept")
	}
	if len(r.upstreams) != 2 {
		t.Errorf("kept %d upstreams, want only the 2 in use", len(r.upstreams))
	}
}
