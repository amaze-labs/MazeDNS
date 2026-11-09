package store

import (
	"context"
	"database/sql"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/stdlib"
)

// openPostgres opens a pgx-backed pool whose connections encode a Go bool bound
// to an integer column as 0/1.
//
// MazeDNS stores every boolean in an INTEGER 0/1 column (see dialect.go) and
// passes Go bools straight to Exec, sometimes through prepared statements that
// bypass the dialect wrapper. pgx refuses that ("unable to encode false into
// binary format for int4"), so on Postgres those writes failed (toggling a list,
// applying a config snapshot, …). The fallback only applies when the target
// type cannot take a bool natively; a real BOOLEAN column still gets a boolean.
func openPostgres(dsn string) (*sql.DB, error) {
	cfg, err := pgx.ParseConfig(dsn)
	if err != nil {
		return nil, err
	}
	return stdlib.OpenDB(*cfg, stdlib.OptionAfterConnect(func(_ context.Context, c *pgx.Conn) error {
		m := c.TypeMap()
		m.TryWrapEncodePlanFuncs = append([]pgtype.TryWrapEncodePlanFunc{tryWrapBoolAsInt}, m.TryWrapEncodePlanFuncs...)
		return nil
	})), nil
}

// tryWrapBoolAsInt is consulted by pgx only after the target codec found no
// direct plan for the value: it re-plans a bool as an int64 0/1.
func tryWrapBoolAsInt(value any) (pgtype.WrappedEncodePlanNextSetter, any, bool) {
	if _, ok := value.(bool); !ok {
		return nil, nil, false
	}
	return &boolAsIntEncodePlan{}, int64(0), true
}

type boolAsIntEncodePlan struct{ next pgtype.EncodePlan }

func (p *boolAsIntEncodePlan) SetNext(next pgtype.EncodePlan) { p.next = next }

func (p *boolAsIntEncodePlan) Encode(value any, buf []byte) ([]byte, error) {
	var i int64
	if value.(bool) {
		i = 1
	}
	return p.next.Encode(i, buf)
}
