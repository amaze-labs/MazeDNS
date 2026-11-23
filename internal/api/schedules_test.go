package api

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/IPMaze/MazeDNS/internal/resolver"
)

const kidsSchedules = `{
  "client_groups": [{"name": "Kids", "members": ["10.0.20.0/24", " 192.168.1.50 ", "192.168.1.50"]}],
  "schedules": [{"name": "Bedtime", "enabled": true, "domains": ["Snapchat.com.", "*.tiktok.com"],
    "categories": ["social"], "days": [5, 1, 1, 2, 3, 4], "start": "22:00", "end": "6:00",
    "time_zone": "Europe/Rome", "groups": ["Kids"]}]
}`

// Issue #95: schedules and client groups are validated, normalized, kept apart
// from the settings page, and replicated to the resolvers.
func TestSchedulesEndpoint(t *testing.T) {
	s, st := newCategoryServer(t)
	if err := st.SaveSettings(`{"upstreams":["192.0.2.1:53"]}`); err != nil {
		t.Fatal(err)
	}
	rr := call(t, s.putSchedules, http.MethodPut, "/", kidsSchedules)
	if rr.Code != http.StatusOK {
		t.Fatal(rr.Body.String())
	}
	var got schedulesBody
	if err := json.Unmarshal(call(t, s.getSchedules, http.MethodGet, "/", "").Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	g, sc := got.ClientGroups[0], got.Schedules[0]
	if strings.Join(g.Members, ",") != "10.0.20.0/24,192.168.1.50" {
		t.Fatalf("members = %v", g.Members)
	}
	if strings.Join(sc.Domains, ",") != "snapchat.com,tiktok.com" || sc.Start != "22:00" || sc.End != "06:00" {
		t.Fatalf("schedule = %+v", sc)
	}
	if len(sc.Days) != 5 || sc.Days[0] != 1 || sc.Days[4] != 5 {
		t.Fatalf("days = %v", sc.Days)
	}

	// A settings save that doesn't mention them keeps them.
	if rr := call(t, s.putSettings, http.MethodPut, "/", `{"upstreams":["192.0.2.9:53"]}`); rr.Code != http.StatusOK {
		t.Fatal(rr.Body.String())
	}
	set, _ := s.loadSettings()
	if len(set.Schedules) != 1 || len(set.ClientGroups) != 1 {
		t.Fatalf("settings save dropped schedules: %+v", set)
	}

	// They reach the resolvers with the settings, with the category corrections
	// for the categories they block.
	raw, err := s.replicatedSettings()
	if err != nil {
		t.Fatal(err)
	}
	var rep resolver.Settings
	if err := json.Unmarshal(raw, &rep); err != nil {
		t.Fatal(err)
	}
	if len(rep.Schedules) != 1 || rep.Schedules[0].Groups[0] != "Kids" || rep.CategoryDomains["instagram.com"] != "social" {
		t.Fatalf("replicated: schedules %+v, category domains %v", rep.Schedules, rep.CategoryDomains)
	}
}

func TestSchedulesValidation(t *testing.T) {
	s, st := newCategoryServer(t)
	if err := st.SaveSettings(`{"upstreams":["192.0.2.1:53"]}`); err != nil {
		t.Fatal(err)
	}
	sched := func(extra string) string {
		return `{"client_groups":[{"name":"Kids","members":["10.0.0.1"]}],"schedules":[{"name":"S","enabled":true,` + extra + `}]}`
	}
	for name, body := range map[string]string{
		"bad member":      `{"client_groups":[{"name":"Kids","members":["10.0.0.300"]}],"schedules":[]}`,
		"empty group":     `{"client_groups":[{"name":"Kids","members":[]}],"schedules":[]}`,
		"duplicate group": `{"client_groups":[{"name":"K","members":["10.0.0.1"]},{"name":"K","members":["10.0.0.2"]}],"schedules":[]}`,
		"blocks nothing":  sched(`"days":[1],"start":"22:00","end":"06:00"`),
		"bad domain":      sched(`"domains":["not a domain"],"days":[1],"start":"22:00","end":"06:00"`),
		"bad category":    sched(`"categories":["other"],"days":[1],"start":"22:00","end":"06:00"`),
		"no days":         sched(`"domains":["a.test"],"days":[],"start":"22:00","end":"06:00"`),
		"bad day":         sched(`"domains":["a.test"],"days":[7],"start":"22:00","end":"06:00"`),
		"bad time":        sched(`"domains":["a.test"],"days":[1],"start":"24:00","end":"06:00"`),
		"bad zone":        sched(`"domains":["a.test"],"days":[1],"start":"22:00","end":"06:00","time_zone":"Mars/Olympus"`),
		"unknown group":   sched(`"domains":["a.test"],"days":[1],"start":"22:00","end":"06:00","groups":["Teens"]`),
	} {
		if rr := call(t, s.putSchedules, http.MethodPut, "/", body); rr.Code != http.StatusBadRequest {
			t.Errorf("%s: code %d, want 400 (%s)", name, rr.Code, rr.Body.String())
		}
	}
}

// The test tool evaluates schedules for a given client.
func TestTestQueryClientSchedule(t *testing.T) {
	s := testQueryServer(t)
	if err := s.store.SaveSettings(`{"upstreams":["127.0.0.1:1"]}`); err != nil {
		t.Fatal(err)
	}
	body := `{"client_groups":[{"name":"Kids","members":["10.0.20.0/24"]}],"schedules":[{"name":"Always","enabled":true,
	  "domains":["snapchat.com"],"days":[0,1,2,3,4,5,6],"start":"00:00","end":"00:00","groups":["Kids"]}]}`
	if rr := call(t, s.putSchedules, http.MethodPut, "/", body); rr.Code != http.StatusOK {
		t.Fatal(rr.Body.String())
	}
	if _, out := runTestQuery(t, s, `{"name":"snapchat.com","client":"10.0.20.7"}`); out.Decision != "blocked" || out.Schedule != "Always" || out.Client != "10.0.20.7" {
		t.Fatalf("kid: %+v", out)
	}
	if _, out := runTestQuery(t, s, `{"name":"snapchat.com","client":"10.0.30.7"}`); out.Decision == "blocked" {
		t.Fatalf("other client blocked: %+v", out)
	}
	if code, _ := runTestQuery(t, s, `{"name":"snapchat.com","client":"nope"}`); code != http.StatusBadRequest {
		t.Fatalf("bad client: %d", code)
	}
}

// A schedule's category covers the domains the resolvers know only through a
// per-domain correction, in a test as on the resolvers.
func TestTestQueryScheduleCategoryCorrections(t *testing.T) {
	s, st := newCategoryServer(t)
	s.testQueryLimit = userLimiter{limit: testQueryLimit, window: testQueryWindow}
	if err := st.SaveSettings(`{"upstreams":["127.0.0.1:1"]}`); err != nil {
		t.Fatal(err)
	}
	body := `{"client_groups":[],"schedules":[{"name":"Social","enabled":true,"categories":["social"],
	  "days":[0,1,2,3,4,5,6],"start":"00:00","end":"00:00"}]}`
	if rr := call(t, s.putSchedules, http.MethodPut, "/", body); rr.Code != http.StatusOK {
		t.Fatal(rr.Body.String())
	}
	if _, out := runTestQuery(t, s, `{"name":"www.instagram.com"}`); out.Decision != "blocked" || out.Schedule != "Social" {
		t.Fatalf("corrected domain under a schedule: %+v", out)
	}
}
