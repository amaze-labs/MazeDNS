package store

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"testing"
)

// TestWriteCostReport measures how many database pages each recurring write
// costs, by counting the frames it appends to the WAL with automatic
// checkpoints off. Each page is written once more when a checkpoint copies it
// into the database, so the disk cost is about twice what is reported here.
// The per-day column multiplies by how often the operation runs.
//
//	MAZEDNS_WRITECOST=1 go test ./internal/store -run TestWriteCostReport -v
//
// It is a measurement, not a check, so it only runs when asked.
func TestWriteCostReport(t *testing.T) {
	if os.Getenv("MAZEDNS_WRITECOST") == "" {
		t.Skip("set MAZEDNS_WRITECOST=1 to run")
	}
	const (
		qps       = 6      // steady load on one resolver
		logRows   = 200000 // rows already in the log (B-tree depth)
		rules     = 369000
		clients   = 60
		perDay    = 86400
		shipEvery = 30 // seconds, the agent's sync interval
	)

	type result struct {
		name    string
		pages   int64
		perDay  int64 // runs per day
		comment string
	}
	var results []result
	add := func(name string, pages, runs int64, comment string) {
		results = append(results, result{name, pages, runs, comment})
	}

	logEntry := func(i int) QueryLogEntry {
		action, cat := "forward", ""
		if i%5 == 0 {
			action, cat = "blocked", "ads"
		}
		return QueryLogEntry{
			TS: int64(1_700_000_000_000 + i*1000/qps), Client: fmt.Sprintf("c%d", i%clients),
			Name: fmt.Sprintf("n%d.example", i%2000), QType: "A", Action: action, Category: cat,
			Rcode: "NOERROR", ElapsedMS: 1.5, ContentCategory: []string{"", "news", "video", "other"}[i%4],
		}
	}
	batch := func(from, n int) []QueryLogEntry {
		out := make([]QueryLogEntry, n)
		for i := range out {
			out[i] = logEntry(from + i)
		}
		return out
	}

	// ---- Agent ----
	for _, tc := range []struct {
		label string
		opts  []Option
	}{
		{"with the 4 indexes", nil},
		{"without indexes", []Option{WithoutQueryLogIndexes()}},
	} {
		s, wal := openMeasured(t, tc.opts...)
		if err := s.InsertQueryLogBatch(batch(0, logRows)); err != nil {
			t.Fatal(err)
		}
		n := logRows
		// Old writer: one commit per second holding that second's queries.
		p := wal(func() {
			for i := 0; i < 60; i++ {
				_ = s.InsertQueryLogBatch(batch(n, qps))
				n += qps
			}
		})
		add("agent: 1-second commits, "+tc.label, p/60, perDay, fmt.Sprintf("%d queries per commit (before)", qps))
		// The same queries spilled in one batch per ship interval.
		p = wal(func() { _ = s.InsertQueryLogBatch(batch(n, qps*shipEvery)); n += qps * shipEvery })
		add("agent: one batch per 30 s, "+tc.label, p, perDay/shipEvery, "if the buffer spilled every cycle")
		_ = s.Close()
	}
	{
		s, wal := openMeasured(t)
		_ = s.SetMetaInt("shipped_log_id", 1)
		p := wal(func() { _ = s.SetMetaInt("shipped_log_id", 2) })
		add("agent: ship cursor update", p, perDay/shipEvery, "per cycle with entries from the database")

		big := make([]Rule, rules)
		for i := range big {
			big[i] = Rule{Action: "deny", Domain: fmt.Sprintf("blocked%d.example", i), Category: "ads", Enabled: true}
		}
		if err := s.ApplySnapshot(big, nil); err != nil {
			t.Fatal(err)
		}
		big = append(big, Rule{Action: "deny", Domain: "one-more.example", Category: "custom", Enabled: true})
		p = wal(func() { _ = s.ApplySnapshot(big, nil) })
		add("agent: apply, one rule added", p, 0, fmt.Sprintf("of %d rules (after)", rules))
		for i := range big {
			big[i].Category = "malware" // every row changes: the old full rewrite
		}
		p = wal(func() { _ = s.ApplySnapshot(big, nil) })
		add("agent: apply rewriting every rule", p, 0, "what any change cost before")
		_ = s.Close()
	}

	// ---- Control plane ----
	{
		s, wal := openMeasured(t)
		if err := s.InsertNodeQueryLog("r1", batch(0, logRows)); err != nil {
			t.Fatal(err)
		}
		if _, err := s.RollupAdvance(logRows + 1); err != nil {
			t.Fatal(err)
		}
		n := logRows
		p := wal(func() { _ = s.InsertNodeQueryLog("r1", batch(n, qps*shipEvery)); n += qps * shipEvery })
		add("control plane: ingest one ship batch", p, perDay/shipEvery, fmt.Sprintf("%d entries, 4 indexes", qps*shipEvery))
		p = wal(func() { _, _ = s.RollupAdvance(50000) })
		add("control plane: rollup advance", p, perDay/shipEvery, "once per ingested batch")
		// The same traffic arriving in fewer, larger batches: index leaf
		// pages (one per active client, category, action) are rewritten once
		// per commit, however many rows the commit adds to them.
		p = wal(func() { _ = s.InsertNodeQueryLog("r1", batch(n, qps*120)); n += qps * 120 })
		add("control plane: ingest 2 minutes in one batch", p, perDay/120, fmt.Sprintf("%d entries, 4 indexes", qps*120))
		p = wal(func() { _, _ = s.RollupAdvance(50000) })
		add("control plane: rollup advance, 2-minute batch", p, perDay/120, "")
		id, _ := s.CreateNode("r1", "h", "p")
		p = wal(func() { _ = s.TouchNode(id, "addr", "v", "a", NodeStats{Total: 1}) })
		add("control plane: node heartbeat write", p, perDay/int64(heartbeatFlush.Seconds()), "per resolver, every 5 minutes")
		p = wal(func() { _ = s.TouchNode(id, "addr", "v", "a", NodeStats{Total: 2}) })
		add("control plane: routine heartbeat", p, perDay/shipEvery, "per resolver, held in memory")

		// Relabelling "other" queries the category database now knows.
		others, err := s.OtherQueries(0, 0, 0, 100)
		if err != nil {
			t.Fatal(err)
		}
		p = wal(func() { _, _ = s.RelabelContent(nil) })
		add("control plane: relabel, nothing new", p, perDay/300, "every 5 minutes")
		labels := map[int64]string{}
		for _, q := range others {
			labels[q.ID] = "news"
		}
		p = wal(func() { _, _ = s.RelabelContent(labels) })
		add(fmt.Sprintf("control plane: relabel of %d queries", len(labels)), p, 0, "when the category database learns their domains")

		p = wal(func() { _, _ = s.PruneQueryLog(int64(1_700_000_000_000 + 3600*1000)) })
		add("control plane: hourly prune", p, 24, fmt.Sprintf("removes an hour of rows (%d)", 3600*qps))
		_ = s.Close()
	}
	{
		// The classifier: one verdict per newly seen domain, plus the usage
		// counters of the lookups behind it.
		s, wal := openMeasured(t)
		for i := 0; i < 20000; i++ {
			_, _ = s.InsertClassification(Classification{Domain: fmt.Sprintf("seen%d.example", i), Category: "clean", Status: ClassClean})
		}
		p := wal(func() {
			_, _ = s.InsertClassification(Classification{Domain: "new.example", Category: "clean", Status: ClassClean})
		})
		add("classifier: verdict for a new domain", p, 0, "per newly seen domain, 20k verdicts held")
		_ = s.RecordReputationUsage("svc", false, false, 1, 1)
		p = wal(func() { _ = s.RecordReputationUsage("svc", false, false, 1, 1) })
		add("classifier: reputation usage counter", p, 0, "per reputation lookup")
		_ = s.RecordLLMUsage(false, 1, 1, 1)
		p = wal(func() { _ = s.RecordLLMUsage(false, 1, 1, 1) })
		add("classifier: model usage counter", p, 0, "per model call")
		_ = s.Close()
	}

	// ---- Control plane: 10 minutes of a three-resolver cluster ----
	// One busy resolver and two quiet ones, one of them on an older build
	// that still ships every 30 s, each with its own clients. Ingested as
	// one commit per shipped batch, or coalesced into one commit for all
	// resolvers per interval; each commit is followed by a rollup advance.
	type node struct {
		name           string
		qps            float64
		clients, every int // distinct clients, ship interval (s)
		offset         int // first ship (s)
	}
	cluster := []node{{"busy", 9, 150, 120, 0}, {"quiet", 1, 20, 120, 60}, {"old-build", 0.5, 10, 30, 10}}
	type ship struct {
		at    int
		batch NodeQueryLog
	}
	var ships []ship
	for _, nd := range cluster {
		last := 0
		for at := nd.offset; at <= 600; at += nd.every {
			n := int(float64(at-last) * nd.qps)
			es := make([]QueryLogEntry, n)
			for i := range es {
				ts := int64(1_800_000_000_000 + (last*1000 + i*int(1000/nd.qps)))
				action, cat := "forward", ""
				if i%5 == 0 {
					action, cat = "blocked", "ads"
				}
				es[i] = QueryLogEntry{TS: ts, Client: fmt.Sprintf("%s-c%d", nd.name, i%nd.clients),
					Name: fmt.Sprintf("n%d.example", i%3000), QType: "A", Action: action, Category: cat, Rcode: "NOERROR",
					ElapsedMS: 1, ContentCategory: fmt.Sprintf("cat%d", i%12)}
			}
			ships = append(ships, ship{at, NodeQueryLog{nd.name, es}})
			last = at
		}
	}
	sort.Slice(ships, func(i, j int) bool { return ships[i].at < ships[j].at })
	for _, mode := range []struct {
		label string
		every int // 0 = one commit per shipped batch
	}{{"one commit per shipped batch", 0}, {"coalesced, one commit per minute", 60}, {"coalesced, one commit per 2 minutes", 120}} {
		s, wal := openMeasured(t)
		if err := s.InsertNodeQueryLog("busy", batch(0, logRows)); err != nil {
			t.Fatal(err)
		}
		_, _ = s.RollupAdvance(logRows + 1)
		commits := 0
		p := wal(func() {
			var pending []NodeQueryLog
			flush := func() {
				if len(pending) > 0 {
					_ = s.InsertNodeQueryLogs(pending)
					_, _ = s.RollupAdvance(50000)
					commits++
					pending = nil
				}
			}
			next := mode.every
			for _, sh := range ships {
				for mode.every > 0 && sh.at >= next {
					flush()
					next += mode.every
				}
				pending = append(pending, sh.batch)
				if mode.every == 0 {
					flush()
				}
			}
			flush()
		})
		add("cluster, 10 min: "+mode.label, p, perDay/600, fmt.Sprintf("%d commits", commits))
		_ = s.Close()
	}

	t.Logf("%-46s %10s %12s  %s", "operation", "WAL KiB", "MiB/day ×2", "")
	for _, r := range results {
		kib := float64(r.pages*4096) / 1024
		day := ""
		if r.perDay > 0 {
			day = fmt.Sprintf("%.1f", 2*float64(r.pages*4096*r.perDay)/(1<<20))
		}
		t.Logf("%-46s %10.1f %12s  %s", r.name, kib, day, r.comment)
	}
}

// openMeasured opens a store with automatic checkpoints off and returns a
// function that runs fn and reports how many pages it appended to the WAL.
func openMeasured(t *testing.T, opts ...Option) (*Store, func(fn func()) int64) {
	t.Helper()
	return openMeasuredAt(t, filepath.Join(t.TempDir(), "cost.db"), opts...)
}

// openMeasuredAt is openMeasured on the database at path.
func openMeasuredAt(t *testing.T, path string, opts ...Option) (*Store, func(fn func()) int64) {
	t.Helper()
	s, err := Open(path, opts...)
	if err != nil {
		t.Fatal(err)
	}
	if s.db.pg {
		t.Skip("WAL frame counting is SQLite-only")
	}
	if _, err := s.db.Exec(`PRAGMA wal_autocheckpoint=0`); err != nil {
		t.Fatal(err)
	}
	frames := func() int64 {
		fi, err := os.Stat(path + "-wal")
		if err != nil {
			return 0
		}
		return max((fi.Size()-32)/(4096+24), 0)
	}
	return s, func(fn func()) int64 {
		if _, err := s.db.Exec(`PRAGMA wal_checkpoint(TRUNCATE)`); err != nil {
			t.Fatal(err)
		}
		before := frames()
		fn()
		return frames() - before
	}
}
