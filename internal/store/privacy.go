package store

import "strings"

// Query-log scrubbing for the privacy levels (internal/privacy). Each helper
// works on a time range so the scrub can walk history a day at a time and
// re-run over the same range without effect.

// HideQueryLogNames replaces every name in [fromMs, toMs) with hidden.
func (s *Store) HideQueryLogNames(fromMs, toMs int64, hidden string) (int64, error) {
	res, err := s.db.Exec(`UPDATE query_log SET name = ? WHERE ts >= ? AND ts < ? AND name <> ?`,
		hidden, fromMs, toMs, hidden)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

// PseudonymizeQueryLog replaces each client in [fromMs, toMs) that does not
// start with prefix by pseudonym(client, dayStartMs), one UTC day at a time.
func (s *Store) PseudonymizeQueryLog(fromMs, toMs int64, prefix string, pseudonym func(client string, dayStartMs int64) string) (int64, error) {
	type clientDay struct {
		client, to string
		day        int64
	}
	rows, err := s.read.Query(
		`SELECT DISTINCT client, ts/86400000 FROM query_log
		 WHERE ts >= ? AND ts < ? AND client <> '' AND client NOT LIKE ?`,
		fromMs, toMs, prefix+"%")
	if err != nil {
		return 0, err
	}
	var todo []clientDay
	for rows.Next() {
		var cd clientDay
		if err := rows.Scan(&cd.client, &cd.day); err != nil {
			rows.Close()
			return 0, err
		}
		todo = append(todo, cd)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return 0, err
	}
	if len(todo) == 0 {
		return 0, nil
	}
	// Outside the transaction: pseudonym may itself write (a new day key), and
	// the transaction holds the only write connection.
	for i := range todo {
		todo[i].to = pseudonym(todo[i].client, todo[i].day*86400000)
	}
	tx, err := s.db.Begin()
	if err != nil {
		return 0, err
	}
	var n int64
	for _, cd := range todo {
		dayStart := cd.day * 86400000
		lo, hi := max(fromMs, dayStart), min(toMs, dayStart+86400000)
		res, err := tx.Exec(`UPDATE query_log SET client = ? WHERE client = ? AND ts >= ? AND ts < ?`,
			cd.to, cd.client, lo, hi)
		if err != nil {
			_ = tx.Rollback()
			return 0, err
		}
		c, _ := res.RowsAffected()
		n += c
	}
	return n, tx.Commit()
}

// DeleteRolledUpQueryLog deletes the entries before beforeMs that the rollups
// have already counted (the rest go once they are counted).
func (s *Store) DeleteRolledUpQueryLog(beforeMs int64) (int64, error) {
	cursor, err := s.GetMetaInt(rollupCursorKey)
	if err != nil {
		return 0, err
	}
	res, err := s.db.Exec(`DELETE FROM query_log WHERE ts < ? AND id <= ?`, beforeMs, cursor)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

// RekeyClientRollup replaces each client_rollup client in hours fromHour
// through throughHour that does not start with prefix by rekey(client,
// hourStartMs), merging counts into an existing row; an empty result drops the
// row.
func (s *Store) RekeyClientRollup(fromHour, throughHour int64, prefix string, rekey func(client string, hourStartMs int64) string) error {
	s.rollupMu.Lock()
	defer s.rollupMu.Unlock()
	type row struct {
		hour             int64
		node, client, to string
		cnt, blocked     int64
	}
	rows, err := s.db.Query(
		`SELECT hour, node, client, cnt, blocked FROM client_rollup
		 WHERE hour >= ? AND hour <= ? AND client NOT LIKE ?`, fromHour, throughHour, prefix+"%")
	if err != nil {
		return err
	}
	var todo []row
	for rows.Next() {
		var r row
		if err := rows.Scan(&r.hour, &r.node, &r.client, &r.cnt, &r.blocked); err != nil {
			rows.Close()
			return err
		}
		todo = append(todo, r)
	}
	rows.Close()
	if err := rows.Err(); err != nil || len(todo) == 0 {
		return err
	}
	for i := range todo { // outside the transaction, as in PseudonymizeQueryLog
		todo[i].to = rekey(todo[i].client, todo[i].hour*3600000)
	}
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	for _, r := range todo {
		if _, err := tx.Exec(`DELETE FROM client_rollup WHERE hour = ? AND node = ? AND client = ?`,
			r.hour, r.node, r.client); err != nil {
			_ = tx.Rollback()
			return err
		}
		if r.to == "" {
			continue
		}
		if _, err := tx.Exec(
			`INSERT INTO client_rollup(hour, node, client, cnt, blocked) VALUES(?, ?, ?, ?, ?)
			 ON CONFLICT(hour, node, client) DO UPDATE SET
			   cnt = cnt + excluded.cnt, blocked = blocked + excluded.blocked`,
			r.hour, r.node, r.to, r.cnt, r.blocked); err != nil {
			_ = tx.Rollback()
			return err
		}
	}
	return tx.Commit()
}

// DeleteQueryLogThrough deletes the entries with id up to and including id (an
// agent's already-shipped buffer).
func (s *Store) DeleteQueryLogThrough(id int64) error {
	_, err := s.db.Exec(`DELETE FROM query_log WHERE id <= ?`, id)
	return err
}

// DeleteClientRollup drops every client_rollup row up to and including hour
// throughHour.
func (s *Store) DeleteClientRollup(throughHour int64) error {
	s.rollupMu.Lock()
	defer s.rollupMu.Unlock()
	_, err := s.db.Exec(`DELETE FROM client_rollup WHERE hour <= ?`, throughHour)
	return err
}

// OldestQueryLogTS returns the earliest entry's timestamp (0 when empty).
func (s *Store) OldestQueryLogTS() (int64, error) {
	var ts int64
	err := s.read.QueryRow(`SELECT COALESCE(MIN(ts), 0) FROM query_log`).Scan(&ts)
	return ts, err
}

// ReduceQueryLogNames replaces each name in [fromMs, toMs) (other than hidden)
// by keep(name, ts) where that differs.
func (s *Store) ReduceQueryLogNames(fromMs, toMs int64, hidden string, keep func(name string, ts int64) string) (int64, error) {
	rows, err := s.read.Query(`SELECT id, name, ts FROM query_log WHERE ts >= ? AND ts < ? AND name <> ?`,
		fromMs, toMs, hidden)
	if err != nil {
		return 0, err
	}
	type entry struct {
		id, ts int64
		name   string
	}
	var all []entry
	for rows.Next() {
		var e entry
		if err := rows.Scan(&e.id, &e.name, &e.ts); err != nil {
			rows.Close()
			return 0, err
		}
		all = append(all, e)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return 0, err
	}
	// Decided after the scan: keep may read the store itself.
	changes := map[string][]int64{} // new name -> ids
	for _, e := range all {
		if to := keep(e.name, e.ts); to != e.name {
			changes[to] = append(changes[to], e.id)
		}
	}
	if len(changes) == 0 {
		return 0, nil
	}
	tx, err := s.db.Begin()
	if err != nil {
		return 0, err
	}
	var n int64
	for to, ids := range changes {
		for len(ids) > 0 {
			chunk := ids[:min(len(ids), 500)]
			ids = ids[len(chunk):]
			args := make([]any, 0, len(chunk)+1)
			args = append(args, to)
			for _, id := range chunk {
				args = append(args, id)
			}
			res, err := tx.Exec(`UPDATE query_log SET name = ? WHERE id IN (?`+strings.Repeat(",?", len(chunk)-1)+`)`, args...)
			if err != nil {
				_ = tx.Rollback()
				return 0, err
			}
			c, _ := res.RowsAffected()
			n += c
		}
	}
	return n, tx.Commit()
}

// QueryLogDayPairs calls each with every distinct (name, client) stored for
// the UTC day starting at dayStartMs.
func (s *Store) QueryLogDayPairs(dayStartMs int64, each func(name, client string)) error {
	rows, err := s.read.Query(`SELECT DISTINCT name, client FROM query_log WHERE ts >= ? AND ts < ?`,
		dayStartMs, dayStartMs+86400000)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var name, client string
		if err := rows.Scan(&name, &client); err != nil {
			return err
		}
		each(name, client)
	}
	return rows.Err()
}
