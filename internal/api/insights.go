package api

import (
	"sort"

	"github.com/IPMaze/MazeDNS/internal/store"
)

// nodeQueries is one node's windowed query volume (the master included).
type nodeQueries struct {
	Node    string `json:"node"`
	Total   int64  `json:"total"`
	Blocked int64  `json:"blocked"`
}

func sumTypes(ts []store.TypeStat) int64 {
	var n int64
	for _, t := range ts {
		n += t.Count
	}
	return n
}

func sumDomains(ds []store.DomainStat) int64 {
	var n int64
	for _, d := range ds {
		n += d.Count
	}
	return n
}

// byNodeQueries builds the per-node query distribution over the same window as
// the rest of the insights (the master first), so magnitudes are comparable.
// Total is exact (sum of query types); Blocked is an approximation from the
// node's top blocked domains.
func byNodeQueries(local store.Insights, nodes map[string]store.Insights) []nodeQueries {
	out := []nodeQueries{{Node: "master", Total: sumTypes(local.QTypes), Blocked: sumDomains(local.TopBlocked)}}
	for name, in := range nodes {
		out = append(out, nodeQueries{Node: name, Total: sumTypes(in.QTypes), Blocked: sumDomains(in.TopBlocked)})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Total > out[j].Total })
	return out
}

// mergeInsights combines this node's insights with each worker's reported
// insights into a single cluster-wide view, re-ranked to the top `topN`.
func mergeInsights(local store.Insights, nodes map[string]store.Insights, topN int) store.Insights {
	clientTotal := map[string]int64{}
	clientBlocked := map[string]int64{}
	queried := map[string]int64{}
	blocked := map[string]int64{}
	qtypes := map[string]int64{}
	var latSum float64
	var latWeight int64

	add := func(in store.Insights) {
		for _, c := range in.Clients {
			clientTotal[c.Client] += c.Total
			clientBlocked[c.Client] += c.Blocked
		}
		for _, d := range in.TopQueried {
			queried[d.Name] += d.Count
		}
		for _, d := range in.TopBlocked {
			blocked[d.Name] += d.Count
		}
		var total int64
		for _, t := range in.QTypes {
			qtypes[t.QType] += t.Count
			total += t.Count
		}
		if total > 0 { // weight each source's mean latency by its query volume
			latSum += in.AvgLatencyMS * float64(total)
			latWeight += total
		}
	}
	add(local)
	for _, in := range nodes {
		add(in)
	}

	out := store.Insights{
		Clients:       topClients(clientTotal, clientBlocked, topN),
		TopQueried:    topDomains(queried, topN),
		TopBlocked:    topDomains(blocked, topN),
		QTypes:        sortedTypes(qtypes),
		UniqueClients: int64(len(clientTotal)),
	}
	if latWeight > 0 {
		out.AvgLatencyMS = latSum / float64(latWeight)
	}
	return out
}

func topClients(total, blocked map[string]int64, n int) []store.ClientStat {
	out := make([]store.ClientStat, 0, len(total))
	for c, t := range total {
		out = append(out, store.ClientStat{Client: c, Total: t, Blocked: blocked[c]})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Total > out[j].Total })
	if n > 0 && len(out) > n {
		out = out[:n]
	}
	return out
}

func topDomains(m map[string]int64, n int) []store.DomainStat {
	out := make([]store.DomainStat, 0, len(m))
	for name, c := range m {
		out = append(out, store.DomainStat{Name: name, Count: c})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Count > out[j].Count })
	if n > 0 && len(out) > n {
		out = out[:n]
	}
	return out
}

func sortedTypes(m map[string]int64) []store.TypeStat {
	out := make([]store.TypeStat, 0, len(m))
	for q, c := range m {
		out = append(out, store.TypeStat{QType: q, Count: c})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Count > out[j].Count })
	return out
}
