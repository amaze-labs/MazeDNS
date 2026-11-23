package classifier

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
	"time"
)

func TestNRDSet(t *testing.T) {
	week, err := parseNRD(strings.NewReader("# header\nnew-scam.xyz\nNew-Scam.xyz.\nfresh.shop\n"))
	if err != nil || len(week) != 2 {
		t.Fatalf("parsed %d %v, want 2 (deduplicated, normalized)", len(week), err)
	}
	older, _ := parseNRD(strings.NewReader("older.site\n"))
	set := &nrdSet{bands: []nrdBand{{"a", 7}, {"b", 14}}, sets: [][]uint64{week, older}}
	for d, want := range map[string]int{"new-scam.xyz": 7, "fresh.shop": 7, "older.site": 14, "google.com": 0} {
		if got := set.days(d); got != want {
			t.Errorf("days(%s) = %d, want %d", d, got, want)
		}
	}
	var nilSet *nrdSet
	if nilSet.days("x.com") != 0 {
		t.Error("nil set")
	}
}

func TestNetRep(t *testing.T) {
	h := &netrepHolder{
		resolve: func(_ context.Context, d string) string {
			return map[string]string{"bad.example": "45.138.16.9", "badnet.example": "203.0.113.5", "ok.example": "198.51.100.7"}[d]
		},
		asnOf: func(_ context.Context, ip netip.Addr) uint32 {
			if ip.String() == "203.0.113.5" {
				return 64666
			}
			return 13335
		},
	}
	if r := h.check(context.Background(), "bad.example"); r.Checked {
		t.Fatal("checked without lists")
	}
	h.lists.Store(&netrepLists{prefixes: []netip.Prefix{netip.MustParsePrefix("45.138.16.0/24")}, asns: map[uint32]string{64666: "EVIL-AS"}})
	if r := h.check(context.Background(), "bad.example"); r.DropCIDR != "45.138.16.0/24" || !r.Listed() {
		t.Fatalf("DROP netblock: %+v", r)
	}
	if r := h.check(context.Background(), "badnet.example"); !r.DropASN || r.ASName != "EVIL-AS" {
		t.Fatalf("ASN-DROP: %+v", r)
	}
	if r := h.check(context.Background(), "ok.example"); r.Listed() || !r.Checked || r.ASN != 13335 {
		t.Fatalf("clean: %+v", r)
	}
	if r := h.check(context.Background(), "nxdomain.example"); r.Checked {
		t.Fatalf("unresolvable: %+v", r)
	}
	if parseCymru("13335 | 1.1.1.0/24 | US | apnic | 2011-08-11") != 13335 || parseCymru("701 1239 | 1.2.3.0/24") != 701 || parseCymru("") != 0 {
		t.Fatal("parseCymru")
	}
}

func TestCertTransparency(t *testing.T) {
	first := time.Now().Add(-3 * 24 * time.Hour).UTC().Format("2006-01-02T15:04:05")
	calls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		switch r.URL.Query().Get("q") {
		case "new.example":
			fmt.Fprintf(w, `[{"not_before":"2099-01-01T00:00:00"},{"not_before":%q}]`, first)
		case "nocert.example":
			_, _ = w.Write([]byte(`[]`))
		default:
			http.Error(w, "bad gateway", http.StatusBadGateway)
		}
	}))
	defer srv.Close()
	c := newCTCache()
	c.base = srv.URL + "/"
	ctx := context.Background()
	if a := c.firstCertAge(ctx, "new.example"); a != 3 {
		t.Fatalf("new: %d, want 3", a)
	}
	if a := c.firstCertAge(ctx, "nocert.example"); a != 0 {
		t.Fatalf("no certificate: %d", a)
	}
	if a := c.firstCertAge(ctx, "busy.example"); a != -1 {
		t.Fatalf("crt.sh down: %d, want -1", a)
	}
	n := calls
	c.firstCertAge(ctx, "new.example") // cached
	if calls != n {
		t.Fatal("not cached")
	}
}

func TestScoreOpenDataFactors(t *testing.T) {
	has := func(s Score, label string, delta int) bool {
		for _, f := range s.Factors {
			if f.Label == label && f.Delta == delta {
				return true
			}
		}
		return false
	}
	if s := computeScore(ScoreInput{Domain: "x.example", NRDDays: 7}); !has(s, "Domain age", -45) {
		t.Fatalf("NRD 7: %+v", s.Factors)
	}
	if s := computeScore(ScoreInput{Domain: "x.example", NRDDays: 14}); !has(s, "Domain age", -35) {
		t.Fatalf("NRD 14: %+v", s.Factors)
	}
	// RDAP's own age wins over the lists.
	if s := computeScore(ScoreInput{Domain: "x.example", NRDDays: 7, Whois: WhoisInfo{AgeDays: 4000, Source: "rdap"}}); has(s, "Domain age", -45) {
		t.Fatal("NRD overrode a known registration date")
	}
	if s := computeScore(ScoreInput{Domain: "x.example", CertAgeDays: 2}); !has(s, "Site age", -30) {
		t.Fatalf("new certificate: %+v", s.Factors)
	}
	if s := computeScore(ScoreInput{Domain: "x.example", CertAgeDays: ctOld}); !has(s, "Site age", 6) {
		t.Fatalf("many certificates: %+v", s.Factors)
	}
	s := computeScore(ScoreInput{Domain: "x.example", Net: NetRep{Checked: true, IP: "45.138.16.9", DropCIDR: "45.138.16.0/24"}})
	if !has(s, "Spamhaus DROP", -50) || !(ScoreInput{Net: NetRep{DropASN: true}}).StrongThreat() {
		t.Fatalf("DROP: %+v", s.Factors)
	}
}
