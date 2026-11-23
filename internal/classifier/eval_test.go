package classifier

import (
	"context"
	"math"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestAUC(t *testing.T) {
	rows := []scored{{legit: 10, malicious: true}, {legit: 20, malicious: true}, {legit: 80}, {legit: 90}}
	if a := auc(rows, func(r scored) float64 { return float64(-r.legit) }); a != 1 {
		t.Fatalf("perfect separation: %v", a)
	}
	if a := auc(rows, func(r scored) float64 { return float64(r.legit) }); a != 0 {
		t.Fatalf("inverted: %v", a)
	}
	ties := []scored{{legit: 50, malicious: true}, {legit: 50}}
	if a := auc(ties, func(r scored) float64 { return float64(-r.legit) }); a != 0.5 {
		t.Fatalf("ties: %v", a)
	}
}

func TestLoadRanked(t *testing.T) {
	p := filepath.Join(t.TempDir(), "list.csv")
	if err := os.WriteFile(p, []byte("1,a.com\n2,www.a.com\n3,b.com\n4,c.org\n5,d.net\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	got, err := LoadRanked(p, 1, 2) // skip a.com (www.a.com is the same domain), take 2
	if err != nil || strings.Join(got, ",") != "b.com,c.org" {
		t.Fatalf("got %v %v", got, err)
	}
}

// A factor that only fires on malicious samples gets a positive (malicious)
// regression weight and a high likelihood ratio; the report renders.
func TestEvaluate(t *testing.T) {
	var samples []Sample
	for i := 0; i < 200; i++ {
		samples = append(samples, Sample{Domain: "site" + itoa(i) + ".xyz", Malicious: true, Source: "feed"}) // risky TLD
		samples = append(samples, Sample{Domain: "site" + itoa(i) + ".com", Source: "popular tail"})
	}
	res := Evaluate(context.Background(), samples, EvalOptions{Seed: 1})
	if res.Pos != 200 || res.Neg != 200 || res.AUC < 0.99 {
		t.Fatalf("result: pos %d neg %d auc %.3f", res.Pos, res.Neg, res.AUC)
	}
	var tld *FactorStat
	for i := range res.Factors {
		if res.Factors[i].Key == "Risky TLD" {
			tld = &res.Factors[i]
		}
	}
	if tld == nil || tld.Coef <= 0 || tld.PosRate != 1 || tld.NegRate != 0 || tld.Suggested >= 0 {
		t.Fatalf("risky TLD stat: %+v", tld)
	}
	if math.IsNaN(res.FittedAUC) || !strings.Contains(res.Report("t", 0), "| Risky TLD | -15 |") {
		t.Fatalf("report:\n%s", res.Report("t", 0))
	}
}

func itoa(i int) string {
	const d = "abcdefghij"
	s := ""
	for {
		s = string(d[i%10]) + s
		i /= 10
		if i == 0 {
			return s
		}
	}
}
