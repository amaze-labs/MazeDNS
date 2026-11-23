package resolver

import (
	"fmt"
	"log/slog"
	"net/netip"
	"strconv"
	"strings"
	"time"
	_ "time/tzdata" // schedules name IANA time zones; resolvers may run without a zoneinfo database

	"github.com/IPMaze/MazeDNS/internal/categories"
	"github.com/IPMaze/MazeDNS/internal/filter"
)

// ClientGroup names a set of client addresses: single IPs or CIDR ranges.
// Schedules target groups by name.
type ClientGroup struct {
	Name    string   `json:"name"`
	Members []string `json:"members"`
}

// BlockSchedule blocks domains and/or categories during a weekly time window,
// for everyone or only the clients in some groups ("downtime").
type BlockSchedule struct {
	Name    string `json:"name"`
	Enabled bool   `json:"enabled"`
	// Domains block the name and all its subdomains; Categories are category
	// ids (social, games, …) looked up like the network-wide category blocks.
	Domains    []string `json:"domains,omitempty"`
	Categories []string `json:"categories,omitempty"`
	// Days the window starts on (0 = Sunday … 6 = Saturday). Start and End are
	// "HH:MM"; an End at or before Start runs past midnight into the next day
	// (22:00–06:00), and Start == End covers the whole day.
	Days  []int  `json:"days"`
	Start string `json:"start"`
	End   string `json:"end"`
	// TimeZone is an IANA zone ("Europe/Rome"); empty = the resolver's local time.
	TimeZone string `json:"time_zone,omitempty"`
	// Groups are the client groups it applies to; empty = everyone.
	Groups []string `json:"groups,omitempty"`
}

// ScheduleCategory is the block category reported for a name a schedule
// blocks by domain (a category block reports the name's own category).
const ScheduleCategory = "scheduled"

// compiledSchedule is a BlockSchedule ready for the query path.
type compiledSchedule struct {
	name       string
	domains    *filter.Engine
	cats       map[string]bool
	days       [7]bool
	start, end int // minutes after midnight
	loc        *time.Location
	everyone   bool
	clients    []netip.Prefix
}

// ParseClock parses "HH:MM" into minutes after midnight.
func ParseClock(s string) (int, error) {
	h, m, ok := strings.Cut(strings.TrimSpace(s), ":")
	if !ok {
		return 0, fmt.Errorf("time %q is not HH:MM", s)
	}
	hh, err1 := strconv.Atoi(h)
	mm, err2 := strconv.Atoi(m)
	if err1 != nil || err2 != nil || len(m) != 2 || hh < 0 || hh > 23 || mm < 0 || mm > 59 {
		return 0, fmt.Errorf("time %q is not HH:MM", s)
	}
	return hh*60 + mm, nil
}

// ParseClientMember parses a client group member: an IP or a CIDR range.
func ParseClientMember(s string) (netip.Prefix, error) {
	s = strings.TrimSpace(s)
	if strings.Contains(s, "/") {
		p, err := netip.ParsePrefix(s)
		if err != nil {
			return netip.Prefix{}, fmt.Errorf("%q is not an IP address or CIDR range", s)
		}
		return p.Masked(), nil
	}
	a, err := netip.ParseAddr(s)
	if err != nil {
		return netip.Prefix{}, fmt.Errorf("%q is not an IP address or CIDR range", s)
	}
	a = a.Unmap()
	return netip.PrefixFrom(a, a.BitLen()), nil
}

// compileSchedules turns the enabled schedules into their query-path form.
// Entries that don't parse are skipped with a warning (the API validates
// before saving, so this only guards against hand-edited settings).
func compileSchedules(scheds []BlockSchedule, groups []ClientGroup) []compiledSchedule {
	members := make(map[string][]netip.Prefix, len(groups))
	for _, g := range groups {
		for _, m := range g.Members {
			if p, err := ParseClientMember(m); err == nil {
				members[g.Name] = append(members[g.Name], p)
			}
		}
	}
	var out []compiledSchedule
	for _, s := range scheds {
		if !s.Enabled {
			continue
		}
		start, err1 := ParseClock(s.Start)
		end, err2 := ParseClock(s.End)
		loc := time.Local
		var err3 error
		if s.TimeZone != "" {
			loc, err3 = time.LoadLocation(s.TimeZone)
		}
		if err1 != nil || err2 != nil || err3 != nil {
			slog.Warn("schedule skipped", "name", s.Name, "err", firstErr(err1, err2, err3))
			continue
		}
		c := compiledSchedule{name: s.Name, start: start, end: end, loc: loc, everyone: len(s.Groups) == 0}
		for _, d := range s.Days {
			if d >= 0 && d < 7 {
				c.days[d] = true
			}
		}
		if len(s.Domains) > 0 {
			c.domains = filter.New()
			for _, d := range s.Domains {
				c.domains.Add(d, ScheduleCategory)
			}
			c.domains.Seal()
		}
		if len(s.Categories) > 0 {
			c.cats = make(map[string]bool, len(s.Categories))
			for _, cat := range s.Categories {
				c.cats[cat] = true
			}
		}
		for _, g := range s.Groups {
			c.clients = append(c.clients, members[g]...)
		}
		if !c.everyone && len(c.clients) == 0 {
			continue // its groups are empty: it applies to no one
		}
		out = append(out, c)
	}
	return out
}

func firstErr(errs ...error) error {
	for _, e := range errs {
		if e != nil {
			return e
		}
	}
	return nil
}

// activeAt reports whether the window is open at t.
func (c *compiledSchedule) activeAt(t time.Time) bool {
	t = t.In(c.loc)
	day := int(t.Weekday())
	m := t.Hour()*60 + t.Minute()
	switch {
	case c.start == c.end: // the whole day
		return c.days[day]
	case c.start < c.end:
		return c.days[day] && m >= c.start && m < c.end
	default: // past midnight: the evening of a listed day, or the morning after one
		return (c.days[day] && m >= c.start) || (c.days[(day+6)%7] && m < c.end)
	}
}

// appliesTo reports whether the schedule covers this client.
func (c *compiledSchedule) appliesTo(client netip.Addr, ok bool) bool {
	if c.everyone {
		return true
	}
	if !ok {
		return false
	}
	for _, p := range c.clients {
		if p.Contains(client) {
			return true
		}
	}
	return false
}

// scheduledBlock reports whether an open schedule blocks name for client at
// now: the schedule's name and the block category (the name's category for a
// category block, ScheduleCategory for a domain block).
func scheduledBlock(rt *runtime, db *categories.Holder, name, client string, now time.Time) (sched, cat string, blocked bool) {
	if len(rt.schedules) == 0 {
		return "", "", false
	}
	var (
		addr     netip.Addr
		addrOK   bool
		parsed   bool
		nameCat  string
		catKnown bool
	)
	for i := range rt.schedules {
		s := &rt.schedules[i]
		if !s.activeAt(now) {
			continue
		}
		if !s.everyone && !parsed {
			parsed = true
			if a, err := netip.ParseAddr(client); err == nil {
				addr, addrOK = a.Unmap(), true
			}
		}
		if !s.appliesTo(addr, addrOK) {
			continue
		}
		if s.domains != nil {
			if _, hit := s.domains.MatchNormalized(name); hit {
				return s.name, ScheduleCategory, true
			}
		}
		if len(s.cats) > 0 {
			if !catKnown {
				catKnown = true
				nameCat, _ = categoryOf(rt, db, name)
			}
			if nameCat != "" && s.cats[nameCat] {
				return s.name, nameCat, true
			}
		}
	}
	return "", "", false
}

// categoryOf is the category of name: a per-domain correction first (walking
// up the parents), then the category database.
func categoryOf(rt *runtime, db *categories.Holder, name string) (string, bool) {
	if len(rt.catDomains) > 0 {
		for rest := name; ; {
			if cat, ok := rt.catDomains[rest]; ok {
				return cat, true
			}
			i := strings.IndexByte(rest, '.')
			if i < 0 {
				break
			}
			rest = rest[i+1:]
		}
	}
	if db != nil {
		return db.Lookup(name)
	}
	return "", false
}

// ScheduleCategories is every category a schedule may block, so a resolver
// loads them from the category database alongside the network-wide ones.
func ScheduleCategories(s Settings) []string {
	var out []string
	for _, sc := range s.Schedules {
		if sc.Enabled {
			out = append(out, sc.Categories...)
		}
	}
	return out
}
