package store

import "testing"

// sqliteOnly skips a test that exercises SQLite itself (EXPLAIN QUERY PLAN, a
// legacy schema written with the raw sqlite driver) when the suite runs on
// PostgreSQL (-tags pgtest).
func sqliteOnly(tb testing.TB) {
	tb.Helper()
	if openOverride != nil {
		tb.Skip("SQLite-specific test (running on PostgreSQL with -tags pgtest)")
	}
}
