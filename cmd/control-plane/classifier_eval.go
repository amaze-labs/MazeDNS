package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"math/rand"
	"os"
	"os/signal"
	"strings"
	"time"

	"github.com/IPMaze/MazeDNS/internal/boot"
	"github.com/IPMaze/MazeDNS/internal/classifier"
	"github.com/IPMaze/MazeDNS/internal/config"
	"github.com/IPMaze/MazeDNS/internal/store"
)

// classifierEvalCmd measures the legitimacy score on labelled domains built
// from open data, and prints a Markdown report:
//
//	control-plane classifier-eval [--n 2000] [--rdap 300] [--config path] [--out report.md]
//
// Malicious samples come from the built-in threat feeds; legitimate ones from
// the long tail of the popularity list (past the part trusted outright, so the
// score is what decides them); with --config, the operator's review decisions
// (approved = malicious, rejected = legitimate) are added. --rdap looks up
// registration data (free RDAP) for that many samples of each class, slowly.
func classifierEvalCmd(args []string) {
	fs := flag.NewFlagSet("classifier-eval", flag.ExitOnError)
	popular := fs.String("popular", classifier.DefaultTrustedURL, "popularity list (file or URL, ranked)")
	trustedTop := fs.Int("trusted-top", classifier.DefaultTrustedTopN, "how much of the popularity list is trusted (and trains the lexicon)")
	tailFrom := fs.Int("tail-from", 0, "legitimate samples start at this rank (default: trusted-top + 50000)")
	n := fs.Int("n", 2000, "samples per class")
	feeds := fs.String("feeds", strings.Join(classifier.DefaultThreatFeeds, ","), "threat feeds for malicious samples (keys, comma-separated)")
	rdap := fs.Int("rdap", 0, "look up registration data for this many samples per class (free RDAP, ~2 per second)")
	nrd := fs.Bool("nrd", false, "use the free newly-registered-domains lists (downloads ~90 MB)")
	cfgPath := fs.String("config", "", "config file: also use this control plane's review decisions as labels")
	out := fs.String("out", "", "write the report here instead of stdout")
	seed := fs.Int64("seed", 1, "sampling seed")
	_ = fs.Parse(args)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	start := time.Now()
	rng := rand.New(rand.NewSource(*seed))
	fail := func(what string, err error) {
		slog.Error(what, "err", err)
		os.Exit(1)
	}

	slog.Info("loading the popularity list", "source", *popular)
	trusted, err := classifier.LoadTrusted(*popular, *trustedTop)
	if err != nil {
		fail("popularity list", err)
	}
	lex := classifier.BuildLexicon(trusted)
	from := *tailFrom
	if from <= 0 {
		from = *trustedTop + 50000
	}
	tail, err := classifier.LoadRanked(*popular, from, *n*5)
	if err != nil {
		fail("popularity list tail", err)
	}
	rng.Shuffle(len(tail), func(i, j int) { tail[i], tail[j] = tail[j], tail[i] })
	var samples []classifier.Sample
	legit := map[string]bool{}
	for _, d := range tail {
		if len(legit) >= *n {
			break
		}
		legit[d] = true
		samples = append(samples, classifier.Sample{Domain: d, Source: "popular tail"})
	}

	// Malicious: an even share from every feed, never a trusted or legitimate
	// sample (the trusted shortcut would decide those, not the score).
	keys := strings.Split(*feeds, ",")
	per := *n / max(1, len(keys))
	mal := map[string]bool{}
	for _, k := range keys {
		k = strings.TrimSpace(k)
		url, ok := classifier.ThreatFeedURLFor(k)
		if !ok {
			slog.Warn("unknown feed", "feed", k)
			continue
		}
		slog.Info("loading feed", "feed", k)
		set, err := classifier.LoadTrusted(url, 0)
		if err != nil {
			slog.Warn("feed failed", "feed", k, "err", err)
			continue
		}
		var ds []string
		set.Each(func(d string) {
			if !trusted.Has(d) && !legit[d] && !mal[d] {
				ds = append(ds, d)
			}
		})
		rng.Shuffle(len(ds), func(i, j int) { ds[i], ds[j] = ds[j], ds[i] })
		for _, d := range ds[:min(per, len(ds))] {
			mal[d] = true
			samples = append(samples, classifier.Sample{Domain: d, Malicious: true, Source: k})
		}
	}

	if *cfgPath != "" {
		cfg, err := config.Load(*cfgPath)
		if err != nil {
			fail("config", err)
		}
		st, err := boot.OpenStore(cfg)
		if err != nil {
			fail("open store", err)
		}
		for status, bad := range map[string]bool{store.ClassApproved: true, store.ClassRejected: false} {
			cs, err := st.ListClassifications(status, "", 100000, 0)
			if err != nil {
				fail("review decisions", err)
			}
			for _, c := range cs {
				samples = append(samples, classifier.Sample{Domain: c.Domain, Malicious: bad, Source: "review"})
			}
		}
		st.Close()
	}

	rng.Shuffle(len(samples), func(i, j int) { samples[i], samples[j] = samples[j], samples[i] })
	opt := classifier.EvalOptions{Lex: lex, Seed: *seed, Progress: func(done, total int) {
		slog.Info("scoring", "done", done, "of", total)
	}}
	if *rdap > 0 {
		cache := classifier.NewWhoisCache()
		opt.WhoisLimit = *rdap
		opt.Whois = func(ctx context.Context, d string) (classifier.WhoisInfo, error) {
			select { // stay polite to the registries' RDAP servers
			case <-ctx.Done():
				return classifier.WhoisInfo{}, ctx.Err()
			case <-time.After(500 * time.Millisecond):
			}
			lctx, cancel := context.WithTimeout(ctx, 10*time.Second)
			defer cancel()
			return cache.Lookup(lctx, d)
		}
	}
	if *nrd {
		slog.Info("loading the newly-registered-domains lists")
		lists, err := classifier.LoadNRDLists(ctx)
		if err != nil {
			fail("newly-registered-domains lists", err)
		}
		opt.NRD = lists
	}
	slog.Info("scoring", "samples", len(samples), "rdap_per_class", *rdap)
	res := classifier.Evaluate(ctx, samples, opt)
	report := res.Report("Classifier evaluation", time.Since(start))
	if *out == "" {
		fmt.Print(report)
		return
	}
	if err := os.WriteFile(*out, []byte(report), 0o644); err != nil {
		fail("write report", err)
	}
	slog.Info("report written", "path", *out)
}
