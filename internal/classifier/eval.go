package classifier

import (
	"context"
	"fmt"
	"math"
	"math/rand"
	"sort"
	"strings"
	"time"
)

// This file measures how well the legitimacy score separates malicious from
// legitimate domains, on labelled samples built from open data (threat feeds,
// the long tail of a popularity list, the operator's own review decisions):
// how often each factor fires on each side, the ROC AUC, the error rates at
// the thresholds, and a logistic regression fitted on the same factors to
// show which weights the data supports.
//
// Only signals the sample can't have leaked into are scored: the threat feeds
// themselves (they are where the malicious labels come from), reputation
// services and the model are left out. So the numbers measure the static
// analysis that has to catch what no list knows yet.

// Sample is one labelled domain.
type Sample struct {
	Domain    string
	Malicious bool
	Source    string // where the label comes from (a feed, "popular", "review")
}

// EvalOptions are the signals available to an evaluation.
type EvalOptions struct {
	Lex *Lexicon
	// Whois looks up registration data (nil = none: domain age and the
	// registration factors don't fire). WhoisLimit caps lookups per class.
	Whois      func(ctx context.Context, domain string) (WhoisInfo, error)
	WhoisLimit int
	Seed       int64
	// Progress, when set, is called every 250 samples.
	Progress func(done, total int)
}

// ThresholdStat is how the score does with "legitimacy < Threshold" as the
// malicious call.
type ThresholdStat struct {
	Threshold int
	TPR       float64 // share of malicious samples caught (recall)
	FPR       float64 // share of legitimate samples flagged
	Precision float64 // at the sample's own mix of classes
}

// FactorStat is one factor's behaviour on the two classes.
type FactorStat struct {
	Key        string  // factor label, with its points when they vary
	Delta      int     // current points
	PosRate    float64 // share of malicious samples it fires on
	NegRate    float64 // share of legitimate samples it fires on
	Likelihood float64 // PosRate / NegRate (smoothed): >1 points to malicious
	Coef       float64 // logistic-regression weight (log-odds of malicious)
	Suggested  int     // points the regression supports, on the current scale
}

// EvalResult is the evaluation report's data.
type EvalResult struct {
	Pos, Neg    int
	Sources     map[string]int
	AUC         float64 // the current score
	FittedAUC   float64 // the regression, on held-out samples
	CurrentTest float64 // the current score on the same held-out samples
	Thresholds  []ThresholdStat
	Factors     []FactorStat
	WhoisPos    int // lookups that returned data
	WhoisNeg    int
}

type scored struct {
	legit     int
	malicious bool
	keys      []string
}

// factorKey names a factor for the statistics: the label, plus the points
// when one label comes in several strengths (domain age brackets).
func factorKey(f Factor, varying map[string]bool) string {
	if varying[f.Label] {
		return fmt.Sprintf("%s (%+d)", f.Label, f.Delta)
	}
	return f.Label
}

// varyingLabels are the factors whose points depend on the detail.
var varyingLabels = map[string]bool{"Domain age": true}

// Evaluate scores every sample and builds the report.
func Evaluate(ctx context.Context, samples []Sample, opt EvalOptions) EvalResult {
	rng := rand.New(rand.NewSource(opt.Seed))
	res := EvalResult{Sources: map[string]int{}}
	deltas := map[string]int{}
	whoisLeft := map[bool]int{true: opt.WhoisLimit, false: opt.WhoisLimit}
	var rows []scored
	for i, s := range samples {
		if ctx.Err() != nil {
			break
		}
		if opt.Progress != nil && i > 0 && i%250 == 0 {
			opt.Progress(i, len(samples))
		}
		in := ScoreInput{Domain: s.Domain, Platform: HostingPlatform(s.Domain), Lex: opt.Lex}
		if opt.Whois != nil && whoisLeft[s.Malicious] > 0 && in.Platform == "" {
			whoisLeft[s.Malicious]--
			if w, err := opt.Whois(ctx, s.Domain); err == nil {
				in.Whois = w
				if s.Malicious {
					res.WhoisPos++
				} else {
					res.WhoisNeg++
				}
			}
		}
		sc := computeScore(in)
		r := scored{legit: sc.Legitimacy, malicious: s.Malicious}
		for _, f := range sc.Factors {
			if f.Delta == 0 || f.Label == "Trust cap" || strings.HasSuffix(f.Label, "floor") {
				continue // informational, or a cap/floor rather than evidence
			}
			k := factorKey(f, varyingLabels)
			deltas[k] = f.Delta
			r.keys = append(r.keys, k)
		}
		rows = append(rows, r)
		res.Sources[s.Source]++
		if s.Malicious {
			res.Pos++
		} else {
			res.Neg++
		}
	}
	if res.Pos == 0 || res.Neg == 0 {
		return res
	}
	res.AUC = auc(rows, func(r scored) float64 { return float64(-r.legit) })
	for _, t := range []int{35, 50, 65, 75} {
		var tp, fp int
		for _, r := range rows {
			if r.legit < t {
				if r.malicious {
					tp++
				} else {
					fp++
				}
			}
		}
		ts := ThresholdStat{Threshold: t, TPR: float64(tp) / float64(res.Pos), FPR: float64(fp) / float64(res.Neg)}
		if tp+fp > 0 {
			ts.Precision = float64(tp) / float64(tp+fp)
		}
		res.Thresholds = append(res.Thresholds, ts)
	}

	// Per-factor rates.
	keys := make([]string, 0, len(deltas))
	for k := range deltas {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	idx := map[string]int{}
	for i, k := range keys {
		idx[k] = i
	}
	pos := make([]int, len(keys))
	neg := make([]int, len(keys))
	for _, r := range rows {
		for _, k := range r.keys {
			if r.malicious {
				pos[idx[k]]++
			} else {
				neg[idx[k]]++
			}
		}
	}

	// Logistic regression on factor presence, trained on 70%, tested on 30%.
	perm := rng.Perm(len(rows))
	cut := len(rows) * 7 / 10
	train := make([]scored, 0, cut)
	test := make([]scored, 0, len(rows)-cut)
	for i, p := range perm {
		if i < cut {
			train = append(train, rows[p])
		} else {
			test = append(test, rows[p])
		}
	}
	w, b := fitLogistic(train, idx, len(keys))
	predict := func(r scored) float64 {
		z := b
		for _, k := range r.keys {
			z += w[idx[k]]
		}
		return z
	}
	res.FittedAUC = auc(test, predict)
	res.CurrentTest = auc(test, func(r scored) float64 { return float64(-r.legit) })

	// Map the regression's weights onto the current point scale: the factor
	// whose weight the data supports more (or less) than its points stands out.
	var num, den float64
	for i, k := range keys {
		num += float64(-deltas[k]) * w[i]
		den += w[i] * w[i]
	}
	scale := 0.0
	if den > 0 {
		scale = num / den
	}
	for i, k := range keys {
		pr := float64(pos[i]) / float64(res.Pos)
		nr := float64(neg[i]) / float64(res.Neg)
		res.Factors = append(res.Factors, FactorStat{
			Key: k, Delta: deltas[k], PosRate: pr, NegRate: nr,
			Likelihood: (float64(pos[i]) + 1) / float64(res.Pos+2) / ((float64(neg[i]) + 1) / float64(res.Neg+2)),
			Coef:       w[i], Suggested: int(math.Round(-scale * w[i])),
		})
	}
	sort.Slice(res.Factors, func(i, j int) bool { return res.Factors[i].Likelihood > res.Factors[j].Likelihood })
	return res
}

// fitLogistic fits P(malicious) = σ(b + Σ w·x) on binary features with L2
// regularization, by batch gradient descent.
func fitLogistic(rows []scored, idx map[string]int, n int) ([]float64, float64) {
	w := make([]float64, n)
	b := 0.0
	const (
		iters  = 600
		rate   = 0.5
		lambda = 1e-3
	)
	m := float64(len(rows))
	if m == 0 {
		return w, b
	}
	gw := make([]float64, n)
	for it := 0; it < iters; it++ {
		for i := range gw {
			gw[i] = lambda * w[i]
		}
		gb := 0.0
		for _, r := range rows {
			z := b
			for _, k := range r.keys {
				z += w[idx[k]]
			}
			p := 1 / (1 + math.Exp(-z))
			y := 0.0
			if r.malicious {
				y = 1
			}
			g := (p - y) / m
			gb += g
			for _, k := range r.keys {
				gw[idx[k]] += g
			}
		}
		b -= rate * gb
		for i := range w {
			w[i] -= rate * gw[i]
		}
	}
	return w, b
}

// auc is the ROC AUC of a score where higher means more likely malicious
// (Mann–Whitney, ties counted half).
func auc(rows []scored, score func(scored) float64) float64 {
	type pt struct {
		s float64
		y bool
	}
	pts := make([]pt, len(rows))
	var npos, nneg float64
	for i, r := range rows {
		pts[i] = pt{score(r), r.malicious}
		if r.malicious {
			npos++
		} else {
			nneg++
		}
	}
	if npos == 0 || nneg == 0 {
		return 0
	}
	sort.Slice(pts, func(i, j int) bool { return pts[i].s < pts[j].s })
	var rankSum float64
	for i := 0; i < len(pts); {
		j := i
		for j < len(pts) && pts[j].s == pts[i].s {
			j++
		}
		avg := float64(i+j+1) / 2 // 1-based average rank of the tie group
		for k := i; k < j; k++ {
			if pts[k].y {
				rankSum += avg
			}
		}
		i = j
	}
	return (rankSum - npos*(npos+1)/2) / (npos * nneg)
}

// Report renders the result as Markdown.
func (r EvalResult) Report(title string, took time.Duration) string {
	var b strings.Builder
	fmt.Fprintf(&b, "# %s\n\n", title)
	fmt.Fprintf(&b, "%d malicious and %d legitimate domains (", r.Pos, r.Neg)
	srcs := make([]string, 0, len(r.Sources))
	for s := range r.Sources {
		srcs = append(srcs, s)
	}
	sort.Strings(srcs)
	for i, s := range srcs {
		if i > 0 {
			b.WriteString(", ")
		}
		fmt.Fprintf(&b, "%s %d", s, r.Sources[s])
	}
	fmt.Fprintf(&b, "), scored in %s.", took.Round(time.Second))
	if r.WhoisPos+r.WhoisNeg > 0 {
		fmt.Fprintf(&b, " Registration data for %d malicious and %d legitimate.", r.WhoisPos, r.WhoisNeg)
	}
	b.WriteString(" Threat feeds, reputation services and the model are left out: the score here is the static analysis alone.\n\n")
	fmt.Fprintf(&b, "**ROC AUC:** %.3f for the current score. On a 30%% held-out split: current %.3f, fitted regression %.3f.\n\n", r.AUC, r.CurrentTest, r.FittedAUC)
	b.WriteString("| Legitimacy below | Malicious caught | Legitimate flagged | Precision (this mix) |\n|---|---|---|---|\n")
	for _, t := range r.Thresholds {
		fmt.Fprintf(&b, "| %d | %.1f%% | %.1f%% | %.1f%% |\n", t.Threshold, 100*t.TPR, 100*t.FPR, 100*t.Precision)
	}
	b.WriteString("\n## Factors\n\nSorted by how strongly they point to malicious (likelihood ratio). *Suggested* maps the regression's weight onto the current point scale.\n\n")
	b.WriteString("| Factor | Points now | Malicious | Legitimate | Likelihood ratio | Suggested points |\n|---|---|---|---|---|---|\n")
	for _, f := range r.Factors {
		fmt.Fprintf(&b, "| %s | %+d | %.1f%% | %.1f%% | %.2f | %+d |\n", f.Key, f.Delta, 100*f.PosRate, 100*f.NegRate, f.Likelihood, f.Suggested)
	}
	return b.String()
}
