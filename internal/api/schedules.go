package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/miekg/dns"

	"github.com/IPMaze/MazeDNS/internal/categories"
	"github.com/IPMaze/MazeDNS/internal/filter"
	"github.com/IPMaze/MazeDNS/internal/resolver"
	"github.com/IPMaze/MazeDNS/internal/store"
)

// Limits that keep a schedule set reviewable (and the settings payload every
// resolver receives small).
const (
	maxClientGroups  = 100
	maxGroupMembers  = 256
	maxSchedules     = 100
	maxScheduleNames = 500 // domains per schedule
	maxNameLen       = 64
)

type schedulesBody struct {
	ClientGroups []resolver.ClientGroup   `json:"client_groups"`
	Schedules    []resolver.BlockSchedule `json:"schedules"`
}

// getSchedules returns the client groups and time-window blocks
// (GET /api/schedules).
func (s *Server) getSchedules(w http.ResponseWriter, _ *http.Request) {
	set, err := s.loadSettings()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	out := schedulesBody{ClientGroups: set.ClientGroups, Schedules: set.Schedules}
	if out.ClientGroups == nil {
		out.ClientGroups = []resolver.ClientGroup{}
	}
	if out.Schedules == nil {
		out.Schedules = []resolver.BlockSchedule{}
	}
	writeJSON(w, http.StatusOK, out)
}

// putSchedules replaces the client groups and schedules (PUT /api/schedules).
// They travel to the resolvers with the settings and apply live.
func (s *Server) putSchedules(w http.ResponseWriter, r *http.Request) {
	var in schedulesBody
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&in); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON")
		return
	}
	groups, scheds, err := cleanSchedules(in.ClientGroups, in.Schedules)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	set, err := s.loadSettings()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	before := scheduleSummary(set.ClientGroups, set.Schedules)
	set.ClientGroups, set.Schedules = groups, scheds
	set.CategoryDomains = nil // computed when replicating, never stored
	b, err := json.Marshal(set)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if err := s.store.SaveSettings(string(b)); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if s.res != nil {
		s.res.ApplySettings(set)
	}
	_ = s.store.AppendAudit(store.AuditEntry{User: auditUser(s, r), Action: "schedules",
		Detail: fmt.Sprintf("%s -> %s", before, scheduleSummary(groups, scheds))})
	writeJSON(w, http.StatusOK, schedulesBody{ClientGroups: groups, Schedules: scheds})
}

func scheduleSummary(groups []resolver.ClientGroup, scheds []resolver.BlockSchedule) string {
	names := make([]string, 0, len(scheds))
	for _, sc := range scheds {
		n := sc.Name
		if !sc.Enabled {
			n += " (off)"
		}
		names = append(names, n)
	}
	return fmt.Sprintf("%d groups, schedules [%s]", len(groups), strings.Join(names, ", "))
}

// cleanSchedules validates and normalizes client groups and schedules: unique
// names, members that parse, valid domains/categories/days/times/zones, and
// groups that exist.
func cleanSchedules(groups []resolver.ClientGroup, scheds []resolver.BlockSchedule) ([]resolver.ClientGroup, []resolver.BlockSchedule, error) {
	if len(groups) > maxClientGroups {
		return nil, nil, fmt.Errorf("at most %d client groups", maxClientGroups)
	}
	if len(scheds) > maxSchedules {
		return nil, nil, fmt.Errorf("at most %d schedules", maxSchedules)
	}
	outG := make([]resolver.ClientGroup, 0, len(groups))
	seenG := map[string]bool{}
	for _, g := range groups {
		name := strings.TrimSpace(g.Name)
		if err := checkName("client group", name, seenG); err != nil {
			return nil, nil, err
		}
		if len(g.Members) == 0 {
			return nil, nil, fmt.Errorf("client group %q has no members", name)
		}
		if len(g.Members) > maxGroupMembers {
			return nil, nil, fmt.Errorf("client group %q: at most %d members", name, maxGroupMembers)
		}
		members := make([]string, 0, len(g.Members))
		for _, m := range g.Members {
			p, err := resolver.ParseClientMember(m)
			if err != nil {
				return nil, nil, fmt.Errorf("client group %q: %v", name, err)
			}
			v := p.String()
			if p.IsSingleIP() {
				v = p.Addr().String()
			}
			if !slices.Contains(members, v) {
				members = append(members, v)
			}
		}
		outG = append(outG, resolver.ClientGroup{Name: name, Members: members})
	}

	outS := make([]resolver.BlockSchedule, 0, len(scheds))
	seenS := map[string]bool{}
	for _, sc := range scheds {
		name := strings.TrimSpace(sc.Name)
		if err := checkName("schedule", name, seenS); err != nil {
			return nil, nil, err
		}
		c := resolver.BlockSchedule{Name: name, Enabled: sc.Enabled, TimeZone: strings.TrimSpace(sc.TimeZone)}
		if len(sc.Domains) > maxScheduleNames {
			return nil, nil, fmt.Errorf("schedule %q: at most %d domains", name, maxScheduleNames)
		}
		for _, d := range sc.Domains {
			d = filter.Normalize(strings.TrimPrefix(strings.TrimSpace(d), "*."))
			if d == "" {
				continue
			}
			if _, ok := dns.IsDomainName(d); !ok || !strings.Contains(d, ".") {
				return nil, nil, fmt.Errorf("schedule %q: %q is not a domain", name, d)
			}
			if !slices.Contains(c.Domains, d) {
				c.Domains = append(c.Domains, d)
			}
		}
		for _, cat := range sc.Categories {
			cat = strings.TrimSpace(cat)
			if cat == categories.Other || cat == categories.Local || !categories.Valid(cat) {
				return nil, nil, fmt.Errorf("schedule %q: can't block category %q", name, cat)
			}
			if !slices.Contains(c.Categories, cat) {
				c.Categories = append(c.Categories, cat)
			}
		}
		if len(c.Domains) == 0 && len(c.Categories) == 0 {
			return nil, nil, fmt.Errorf("schedule %q blocks nothing: add domains or categories", name)
		}
		for _, d := range sc.Days {
			if d < 0 || d > 6 {
				return nil, nil, fmt.Errorf("schedule %q: day %d is not 0 (Sunday) to 6", name, d)
			}
			if !slices.Contains(c.Days, d) {
				c.Days = append(c.Days, d)
			}
		}
		if len(c.Days) == 0 {
			return nil, nil, fmt.Errorf("schedule %q has no days", name)
		}
		slices.Sort(c.Days)
		start, err := resolver.ParseClock(sc.Start)
		if err != nil {
			return nil, nil, fmt.Errorf("schedule %q: %v", name, err)
		}
		end, err := resolver.ParseClock(sc.End)
		if err != nil {
			return nil, nil, fmt.Errorf("schedule %q: %v", name, err)
		}
		c.Start, c.End = clock(start), clock(end)
		if c.TimeZone != "" {
			if _, err := time.LoadLocation(c.TimeZone); err != nil {
				return nil, nil, fmt.Errorf("schedule %q: unknown time zone %q", name, c.TimeZone)
			}
		}
		for _, g := range sc.Groups {
			g = strings.TrimSpace(g)
			if !seenG[g] {
				return nil, nil, fmt.Errorf("schedule %q: no client group %q", name, g)
			}
			if !slices.Contains(c.Groups, g) {
				c.Groups = append(c.Groups, g)
			}
		}
		outS = append(outS, c)
	}
	return outG, outS, nil
}

func checkName(kind, name string, seen map[string]bool) error {
	if name == "" {
		return fmt.Errorf("a %s needs a name", kind)
	}
	if len(name) > maxNameLen {
		return fmt.Errorf("%s name %q is too long", kind, name)
	}
	if seen[name] {
		return fmt.Errorf("two %ss are named %q", kind, name)
	}
	seen[name] = true
	return nil
}

func clock(min int) string { return fmt.Sprintf("%02d:%02d", min/60, min%60) }
