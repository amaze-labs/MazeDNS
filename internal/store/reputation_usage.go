package store

import "time"

// ReputationUsageDay is one day's call accounting for a single reputation service
// (VirusTotal / AbuseIPDB), so the UI can show how close the configured key is to
// its daily quota.
type ReputationUsageDay struct {
	Day         string `json:"day"`
	Service     string `json:"service"`
	Calls       int64  `json:"calls"`
	Errors      int64  `json:"errors"`
	RateLimited int64  `json:"rate_limited"`
	Remaining   int64  `json:"remaining"` // last API-reported quota remaining (-1 = unknown)
	Limit       int64  `json:"limit"`     // last API-reported daily limit (-1 = unknown)
}

// RecordReputationUsage adds one API call to today's row for a service. remaining
// and limit are the values the API last reported (pass -1 when unknown); they
// overwrite the stored value only when known, so a later call without headers
// doesn't wipe a good reading.
func (s *Store) RecordReputationUsage(service string, errored, rateLimited bool, remaining, limit int) error {
	day := time.Now().UTC().Format("2006-01-02")
	errs, rl := 0, 0
	if errored {
		errs = 1
	}
	if rateLimited {
		rl = 1
	}
	_, err := s.db.Exec(
		`INSERT INTO reputation_usage(day, service, calls, errors, rate_limited, remaining, limit_total)
		 VALUES(?,?,1,?,?,?,?)
		 ON CONFLICT(day, service) DO UPDATE SET
		   calls = calls + 1,
		   errors = errors + excluded.errors,
		   rate_limited = rate_limited + excluded.rate_limited,
		   remaining = CASE WHEN excluded.remaining >= 0 THEN excluded.remaining ELSE remaining END,
		   limit_total = CASE WHEN excluded.limit_total >= 0 THEN excluded.limit_total ELSE limit_total END`,
		day, service, errs, rl, remaining, limit)
	return err
}

// ReputationUsage returns the most recent daily rows across both services, newest
// day first (then service), capped at `days` distinct days.
func (s *Store) ReputationUsage(days int) ([]ReputationUsageDay, error) {
	if days <= 0 || days > 365 {
		days = 30
	}
	rows, err := s.read.Query(
		`SELECT day, service, calls, errors, rate_limited, remaining, limit_total
		 FROM reputation_usage
		 WHERE day IN (SELECT DISTINCT day FROM reputation_usage ORDER BY day DESC LIMIT ?)
		 ORDER BY day DESC, service ASC`, days)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []ReputationUsageDay
	for rows.Next() {
		var d ReputationUsageDay
		if err := rows.Scan(&d.Day, &d.Service, &d.Calls, &d.Errors, &d.RateLimited, &d.Remaining, &d.Limit); err != nil {
			return nil, err
		}
		out = append(out, d)
	}
	return out, rows.Err()
}
