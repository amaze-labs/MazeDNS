package resolver

import (
	"testing"
	"time"

	"github.com/miekg/dns"

	"github.com/IPMaze/MazeDNS/internal/categories"
	"github.com/IPMaze/MazeDNS/internal/filter"
)

func TestScheduleActiveAt(t *testing.T) {
	rome, _ := time.LoadLocation("Europe/Rome")
	at := func(day time.Weekday, hh, mm int) time.Time {
		// 2026-11-22 is a Sunday.
		return time.Date(2026, 11, 22+int(day), hh, mm, 0, 0, rome)
	}
	compile := func(days []int, start, end string) compiledSchedule {
		cs := compileSchedules([]BlockSchedule{{Name: "s", Enabled: true, Domains: []string{"x.test"},
			Days: days, Start: start, End: end, TimeZone: "Europe/Rome"}}, nil)
		if len(cs) != 1 {
			t.Fatal("not compiled")
		}
		return cs[0]
	}
	night := compile([]int{1, 2, 3, 4, 5}, "22:00", "06:00") // school nights, Mon–Fri evenings
	cases := []struct {
		name string
		s    compiledSchedule
		t    time.Time
		want bool
	}{
		{"monday evening", night, at(time.Monday, 22, 0), true},
		{"before start", night, at(time.Monday, 21, 59), false},
		{"tuesday early morning (after monday night)", night, at(time.Tuesday, 5, 59), true},
		{"tuesday at end", night, at(time.Tuesday, 6, 0), false},
		{"saturday morning (after friday night)", night, at(time.Saturday, 3, 0), true},
		{"saturday evening (not listed)", night, at(time.Saturday, 23, 0), false},
		{"monday early morning (sunday not listed)", night, at(time.Monday, 3, 0), false},
		{"same-day window inside", compile([]int{3}, "15:00", "17:30"), at(time.Wednesday, 16, 0), true},
		{"same-day window other day", compile([]int{3}, "15:00", "17:30"), at(time.Thursday, 16, 0), false},
		{"whole day", compile([]int{0}, "00:00", "00:00"), at(time.Sunday, 13, 0), true},
		{"time zone respected", night, at(time.Monday, 22, 30).In(time.UTC), true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.s.activeAt(tc.t); got != tc.want {
				t.Fatalf("activeAt(%s) = %v, want %v", tc.t.In(rome).Format("Mon 15:04"), got, tc.want)
			}
		})
	}
}

// scheduleResolver blocks "snapchat.com" and the social category for the Kids
// group (10.0.20.0/24 and 192.168.1.50) all day every day, plus "games.test"
// for everyone.
func scheduleResolver(t *testing.T, allow ...string) *Resolver {
	t.Helper()
	var b categories.Builder
	b.Add("social.example", "social")
	r := New(Options{Timeout: 200 * time.Millisecond})
	r.SetCategoryDB(categories.NewLoadedHolder(b.Build()))
	al := filter.New()
	for _, d := range allow {
		al.Add(d, "")
	}
	r.SetPolicy(&Policy{Block: filter.New(), Allow: al})
	every := []int{0, 1, 2, 3, 4, 5, 6}
	r.ApplySettings(Settings{
		Upstreams:    []string{"127.0.0.1:1"},
		ClientGroups: []ClientGroup{{Name: "Kids", Members: []string{"10.0.20.0/24", "192.168.1.50"}}},
		Schedules: []BlockSchedule{
			{Name: "Bedtime", Enabled: true, Domains: []string{"snapchat.com"}, Categories: []string{"social"},
				Days: every, Start: "00:00", End: "00:00", Groups: []string{"Kids"}},
			{Name: "Everyone", Enabled: true, Domains: []string{"games.test"}, Days: every, Start: "00:00", End: "00:00"},
			{Name: "Off", Enabled: false, Domains: []string{"off.test"}, Days: every, Start: "00:00", End: "00:00"},
		},
	})
	return r
}

func resolveFrom(r *Resolver, name, client string) (string, string) {
	req := new(dns.Msg)
	req.SetQuestion(dns.Fqdn(name), dns.TypeA)
	_, action, cat := r.Resolve(req, client)
	return action, cat
}

func TestScheduledBlocking(t *testing.T) {
	r := scheduleResolver(t, "allowed.social.example")
	cases := []struct {
		name, client, wantAction, wantCat string
	}{
		{"www.snapchat.com", "10.0.20.15", "blocked", ScheduleCategory},
		{"snapchat.com", "192.168.1.50", "blocked", ScheduleCategory},
		{"snapchat.com", "::ffff:192.168.1.50", "blocked", ScheduleCategory},
		{"snapchat.com", "192.168.1.51", "error", ""}, // not in the group: forwarded (nothing answers)
		{"m.social.example", "10.0.20.15", "blocked", "social"},
		{"m.social.example", "10.0.30.1", "error", ""},
		{"allowed.social.example", "10.0.20.15", "error", ""}, // allow rule wins
		{"games.test", "203.0.113.9", "blocked", ScheduleCategory},
		{"off.test", "10.0.20.15", "error", ""}, // disabled schedule
	}
	for _, tc := range cases {
		action, cat := resolveFrom(r, tc.name, tc.client)
		if action != tc.wantAction || cat != tc.wantCat {
			t.Errorf("%s from %s: %s/%q, want %s/%q", tc.name, tc.client, action, cat, tc.wantAction, tc.wantCat)
		}
	}
	// Pausing blocking pauses schedules too.
	r.SetBlockPausedUntil(time.Now().Add(time.Hour).Unix())
	if action, _ := resolveFrom(r, "games.test", "203.0.113.9"); action == "blocked" {
		t.Fatal("schedule blocked while blocking is paused")
	}
}

func TestTraceReportsSchedule(t *testing.T) {
	r := scheduleResolver(t)
	tr := r.Trace(traceQ("snapchat.com"), nil, TraceOptions{Client: "10.0.20.15"})
	if tr.Decision != "blocked" || tr.Schedule != "Bedtime" || tr.Category != ScheduleCategory {
		t.Fatalf("kid: %+v", tr)
	}
	// No client given: group schedules don't apply, everyone-schedules do.
	if tr := r.Trace(traceQ("snapchat.com"), nil, TraceOptions{}); tr.Decision == "blocked" {
		t.Fatalf("unknown client blocked by a group schedule: %+v", tr)
	}
	if tr := r.Trace(traceQ("games.test"), nil, TraceOptions{}); tr.Schedule != "Everyone" {
		t.Fatalf("everyone schedule: %+v", tr)
	}
	// Outside the window (Bedtime made a one-hour slot that isn't now).
	now := time.Now()
	shut := now.Add(3 * time.Hour)
	r.ApplySettings(Settings{
		Upstreams:    []string{"127.0.0.1:1"},
		ClientGroups: []ClientGroup{{Name: "Kids", Members: []string{"10.0.20.0/24"}}},
		Schedules: []BlockSchedule{{Name: "Bedtime", Enabled: true, Domains: []string{"snapchat.com"},
			Days: []int{int(shut.Weekday())}, Start: shut.Format("15:04"), End: shut.Add(time.Hour).Format("15:04"), Groups: []string{"Kids"}}},
	})
	if tr := r.Trace(traceQ("snapchat.com"), nil, TraceOptions{Client: "10.0.20.15", Now: now}); tr.Decision == "blocked" {
		t.Fatalf("blocked outside the window: %+v", tr)
	}
	if tr := r.Trace(traceQ("snapchat.com"), nil, TraceOptions{Client: "10.0.20.15", Now: shut.Add(time.Minute)}); tr.Schedule != "Bedtime" {
		t.Fatalf("not blocked inside the window: %+v", tr)
	}
}

func TestScheduleSkipsInvalidAndEmptyGroups(t *testing.T) {
	cs := compileSchedules([]BlockSchedule{
		{Name: "bad-tz", Enabled: true, Domains: []string{"a.test"}, Days: []int{1}, Start: "01:00", End: "02:00", TimeZone: "Mars/Olympus"},
		{Name: "bad-time", Enabled: true, Domains: []string{"a.test"}, Days: []int{1}, Start: "25:00", End: "02:00"},
		{Name: "empty-group", Enabled: true, Domains: []string{"a.test"}, Days: []int{1}, Start: "01:00", End: "02:00", Groups: []string{"Nobody"}},
		{Name: "ok", Enabled: true, Domains: []string{"a.test"}, Days: []int{1}, Start: "01:00", End: "02:00"},
	}, nil)
	if len(cs) != 1 || cs[0].name != "ok" {
		t.Fatalf("compiled %d schedules, want only ok", len(cs))
	}
}
