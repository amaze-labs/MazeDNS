package store

import (
	"context"
	"path/filepath"
	"testing"
	"time"
)

// ClientsForDomain matches the domain and its subdomains (with or without the
// trailing dot), counts blocked queries, and ignores entries before the window.
func TestClientsForDomainWindow(t *testing.T) {
	s, err := Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })

	now := time.Now().UnixMilli()
	day := int64(24 * time.Hour / time.Millisecond)
	if err := s.InsertQueryLogBatch([]QueryLogEntry{
		{TS: now, Client: "10.0.0.1", Name: "evil.com.", QType: "A", Action: "blocked", Rcode: "NXDOMAIN"},
		{TS: now, Client: "10.0.0.1", Name: "cdn.evil.com.", QType: "A", Action: "allowed", Rcode: "NOERROR"},
		{TS: now, Client: "10.0.0.2", Name: "evil.com", QType: "A", Action: "allowed", Rcode: "NOERROR"},
		{TS: now, Client: "10.0.0.3", Name: "notevil.com.", QType: "A", Action: "allowed", Rcode: "NOERROR"},
		{TS: now - 30*day, Client: "10.0.0.4", Name: "evil.com.", QType: "A", Action: "allowed", Rcode: "NOERROR"},
	}); err != nil {
		t.Fatal(err)
	}

	got, err := s.ClientsForDomain(context.Background(), "evil.com", now-7*day, 100)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Fatalf("clients = %+v, want 10.0.0.1 and 10.0.0.2 only", got)
	}
	if got[0].Client != "10.0.0.1" || got[0].Count != 2 || got[0].Blocked != 1 {
		t.Errorf("top client = %+v, want 10.0.0.1 with 2 queries, 1 blocked", got[0])
	}
	if got[1].Client != "10.0.0.2" || got[1].Count != 1 {
		t.Errorf("second client = %+v, want 10.0.0.2 with 1 query", got[1])
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := s.ClientsForDomain(ctx, "evil.com", 0, 100); err == nil {
		t.Error("a cancelled context should abort the lookup")
	}
}
