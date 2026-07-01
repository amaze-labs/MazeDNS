package metrics

import "testing"

// BenchmarkIncQuery measures the per-query counter increment on the record path
// using the pre-resolved action counters.
func BenchmarkIncQuery(b *testing.B) {
	m := New()
	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			m.IncQuery("cache")
		}
	})
}

// BenchmarkIncQueryWithLabelValues measures the previous approach (label lookup
// on every query) for comparison.
func BenchmarkIncQueryWithLabelValues(b *testing.B) {
	m := New()
	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			m.Queries.WithLabelValues("cache").Inc()
		}
	})
}
