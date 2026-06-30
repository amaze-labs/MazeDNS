package store

import (
	"path/filepath"
	"testing"
	"time"
)

func TestReputationUsage(t *testing.T) {
	s, err := Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })

	// Two clean VT calls (quota unknown), then one rate-limited; one AbuseIPDB call
	// that reports its quota via headers.
	if err := s.RecordReputationUsage("virustotal", false, false, -1, -1); err != nil {
		t.Fatal(err)
	}
	if err := s.RecordReputationUsage("virustotal", false, false, -1, -1); err != nil {
		t.Fatal(err)
	}
	if err := s.RecordReputationUsage("virustotal", true, true, -1, -1); err != nil {
		t.Fatal(err)
	}
	if err := s.RecordReputationUsage("abuseipdb", false, false, 987, 1000); err != nil {
		t.Fatal(err)
	}

	rows, err := s.ReputationUsage(14)
	if err != nil {
		t.Fatal(err)
	}
	today := time.Now().UTC().Format("2006-01-02")
	var vt, abuse *ReputationUsageDay
	for i := range rows {
		if rows[i].Day != today {
			t.Errorf("unexpected day %q", rows[i].Day)
		}
		switch rows[i].Service {
		case "virustotal":
			vt = &rows[i]
		case "abuseipdb":
			abuse = &rows[i]
		}
	}
	if vt == nil || abuse == nil {
		t.Fatalf("missing service rows: %+v", rows)
	}

	if vt.Calls != 3 || vt.Errors != 1 || vt.RateLimited != 1 {
		t.Errorf("vt = %+v, want calls 3 / errors 1 / rate_limited 1", *vt)
	}
	// VT reported no quota, so it stays unknown.
	if vt.Remaining != -1 || vt.Limit != -1 {
		t.Errorf("vt quota = %d/%d, want -1/-1", vt.Remaining, vt.Limit)
	}
	if abuse.Calls != 1 || abuse.Remaining != 987 || abuse.Limit != 1000 {
		t.Errorf("abuse = %+v, want calls 1 / remaining 987 / limit 1000", *abuse)
	}

	// A later call without quota headers must NOT wipe the known reading.
	if err := s.RecordReputationUsage("abuseipdb", false, false, -1, -1); err != nil {
		t.Fatal(err)
	}
	rows, _ = s.ReputationUsage(14)
	for _, r := range rows {
		if r.Service == "abuseipdb" && (r.Remaining != 987 || r.Limit != 1000) {
			t.Errorf("abuse quota overwritten: %+v", r)
		}
	}
}
