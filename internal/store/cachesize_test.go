package store

import (
	"context"
	"database/sql"
	"path/filepath"
	"testing"
)

// Every connection — the writer and each one in the read pool — gets the page
// cache Open was given: DefaultCacheMiB unless WithCacheMiB says otherwise.
// It is per connection, so a pool that held the old 64 MiB on each one could
// reach ~1 GiB outside the Go heap.
func TestCacheSizeOnEveryConnection(t *testing.T) {
	for _, tc := range []struct {
		name string
		opts []Option
		kib  int
	}{
		{"default", nil, 8 * 1024},
		{"custom", []Option{WithCacheMiB(32)}, 32 * 1024},
		{"zero keeps the default", []Option{WithCacheMiB(0)}, 8 * 1024},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s, err := Open(filepath.Join(t.TempDir(), "cache.db"), tc.opts...)
			if err != nil {
				t.Fatal(err)
			}
			defer s.Close()
			if s.db.pg {
				t.Skip("SQLite-only")
			}
			check := func(who string, q interface {
				QueryRowContext(context.Context, string, ...any) *sql.Row
			}) {
				t.Helper()
				var n int
				if err := q.QueryRowContext(context.Background(), `PRAGMA cache_size`).Scan(&n); err != nil {
					t.Fatalf("%s: %v", who, err)
				}
				if n != -tc.kib {
					t.Errorf("%s: cache_size = %d, want %d (KiB)", who, n, -tc.kib)
				}
			}
			check("writer", s.db.DB)
			// Hold several readers at once so the pool opens distinct connections.
			ctx := context.Background()
			for i := 0; i < 4; i++ {
				c, err := s.read.Conn(ctx)
				if err != nil {
					t.Fatal(err)
				}
				defer c.Close()
				check("reader", c)
			}
		})
	}
}
