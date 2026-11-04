//go:build pgtest

package store

import (
	"crypto/sha256"
	"encoding/hex"
	"net/url"
	"os"
)

// Built only with -tags pgtest: every Open(path) (i.e. every store test) runs on
// the PostgreSQL server in MAZEDNS_TEST_PG_DSN (URL form) instead of SQLite.
// Each path gets its own schema, and reopening the same path reopens the same
// schema, so the reopen/migration tests keep their meaning. Use a throwaway
// database: schemas are left behind.
//
//	MAZEDNS_TEST_PG_DSN='postgres://u:p@host:5432/mazedns_ci?sslmode=disable' \
//	  go test -tags pgtest -p 1 ./internal/store/
func init() {
	dsn := os.Getenv("MAZEDNS_TEST_PG_DSN")
	if dsn == "" {
		panic("pgtest build: set MAZEDNS_TEST_PG_DSN to a throwaway PostgreSQL database (URL form)")
	}
	openOverride = func(path string) (*Store, error) {
		sum := sha256.Sum256([]byte(path))
		schema := "t_" + hex.EncodeToString(sum[:8])
		admin, err := openPostgres(dsn)
		if err != nil {
			return nil, err
		}
		_, err = admin.Exec("CREATE SCHEMA IF NOT EXISTS " + schema)
		_ = admin.Close()
		if err != nil {
			return nil, err
		}
		u, err := url.Parse(dsn)
		if err != nil {
			return nil, err
		}
		q := u.Query()
		q.Set("search_path", schema)
		u.RawQuery = q.Encode()
		return OpenWith("pgx", u.String())
	}
}
