package store

import "time"

// LLMUsageDay is the classifier's model usage for one UTC day.
type LLMUsageDay struct {
	Day              string `json:"day"`
	Calls            int64  `json:"calls"`
	Errors           int64  `json:"errors"`
	PromptTokens     int64  `json:"prompt_tokens"`
	CompletionTokens int64  `json:"completion_tokens"`
	LatencyMsTotal   int64  `json:"latency_ms_total"`
}

// RecordLLMUsage adds one model call to today's usage row (created on demand).
func (s *Store) RecordLLMUsage(errored bool, promptTokens, completionTokens, latencyMs int) error {
	day := time.Now().UTC().Format("2006-01-02")
	errs := 0
	if errored {
		errs = 1
	}
	_, err := s.db.Exec(
		`INSERT INTO llm_usage(day, calls, errors, prompt_tokens, completion_tokens, latency_ms_total)
		 VALUES(?,1,?,?,?,?)
		 ON CONFLICT(day) DO UPDATE SET
		   calls = calls + 1,
		   errors = errors + excluded.errors,
		   prompt_tokens = prompt_tokens + excluded.prompt_tokens,
		   completion_tokens = completion_tokens + excluded.completion_tokens,
		   latency_ms_total = latency_ms_total + excluded.latency_ms_total`,
		day, errs, promptTokens, completionTokens, latencyMs)
	return err
}

// LLMUsage returns the last `days` daily rows, newest first.
func (s *Store) LLMUsage(days int) ([]LLMUsageDay, error) {
	if days <= 0 || days > 365 {
		days = 30
	}
	rows, err := s.db.Query(
		`SELECT day, calls, errors, prompt_tokens, completion_tokens, latency_ms_total
		 FROM llm_usage ORDER BY day DESC LIMIT ?`, days)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []LLMUsageDay
	for rows.Next() {
		var d LLMUsageDay
		if err := rows.Scan(&d.Day, &d.Calls, &d.Errors, &d.PromptTokens, &d.CompletionTokens, &d.LatencyMsTotal); err != nil {
			return nil, err
		}
		out = append(out, d)
	}
	return out, rows.Err()
}

// LLMUsageTotals sums usage across all retained days.
func (s *Store) LLMUsageTotals() (LLMUsageDay, error) {
	var d LLMUsageDay
	d.Day = "all"
	err := s.db.QueryRow(
		`SELECT COALESCE(SUM(calls),0), COALESCE(SUM(errors),0), COALESCE(SUM(prompt_tokens),0),
		        COALESCE(SUM(completion_tokens),0), COALESCE(SUM(latency_ms_total),0) FROM llm_usage`,
	).Scan(&d.Calls, &d.Errors, &d.PromptTokens, &d.CompletionTokens, &d.LatencyMsTotal)
	return d, err
}
