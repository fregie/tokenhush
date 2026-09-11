package audit

import (
	"database/sql"
	"errors"
	"fmt"
	"time"
)

// Prune applies the configured retention window.
func (s *Store) Prune() (int64, error) {
	days := s.retention
	if days <= 0 {
		days = defaultRetentionDays
	}
	return s.PruneBefore(s.now().AddDate(0, 0, -days))
}

// PruneBefore deletes rows older than cutoff and maintains the append-only
// anchor history. The new anchor is written and fsynced BEFORE the delete, so a
// crash in between leaves extra (still-chainable) rows, never a re-anchored gap:
// a crash before the anchor write changes nothing, and a crash after the delete
// has the anchor already on disk.
//
// The newest row is always retained as the chain tip, so retention never
// removes the tip the witness and high-water refer to. Returns rows deleted.
func (s *Store) PruneBefore(cutoff time.Time) (int64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return 0, ErrClosed
	}

	var maxOld sql.NullInt64
	if err := s.db.QueryRow(`SELECT MAX(id) FROM requests WHERE ts < ?`, cutoff.UnixMilli()).Scan(&maxOld); err != nil {
		return 0, fmt.Errorf("audit: find retention boundary: %w", err)
	}
	if !maxOld.Valid || maxOld.Int64 < 1 {
		return 0, nil
	}

	var maxRowID int64
	if err := s.db.QueryRow(`SELECT COALESCE(MAX(id), 0) FROM requests`).Scan(&maxRowID); err != nil {
		return 0, fmt.Errorf("audit: read chain tip id: %w", err)
	}
	deleteThrough := maxOld.Int64
	if deleteThrough >= maxRowID {
		deleteThrough = maxRowID - 1
	}
	if deleteThrough < 1 {
		return 0, nil
	}

	var (
		targetID   int64
		targetHash []byte
	)
	err := s.db.QueryRow(
		`SELECT id, hash FROM requests WHERE id > ? ORDER BY id ASC LIMIT 1`, deleteThrough,
	).Scan(&targetID, &targetHash)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, nil
	}
	if err != nil {
		return 0, fmt.Errorf("audit: read re-anchor row: %w", err)
	}

	if _, err := s.anchors.append(targetID, targetHash); err != nil {
		return 0, err
	}

	res, err := s.db.Exec(`DELETE FROM requests WHERE id <= ?`, deleteThrough)
	if err != nil {
		return 0, fmt.Errorf("audit: delete expired rows: %w", err)
	}
	deleted, err := res.RowsAffected()
	if err != nil {
		return 0, fmt.Errorf("audit: count expired rows: %w", err)
	}
	return deleted, nil
}
