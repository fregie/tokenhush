package audit

import (
	"bytes"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"

	"github.com/fregie/tokenhush/pkg/platform"
)

// Verify authenticates the whole store: it re-runs the ≤1 crash-window
// reconciliation (healing a benign window, refusing a larger gap or a
// rollback) and then walks the row chain forward from the newest retention
// anchor, re-deriving every row hash.
//
// A benign crash window is one missing witness for the newest append. A
// forged key, a re-written anchor, a truncated tip, or a rollback of either the
// witness file or the secret-store high-water always fails with ErrTampered.
func (s *Store) Verify() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return ErrClosed
	}
	if err := s.anchors.reload(); err != nil {
		return err
	}
	if err := s.witness.reload(); err != nil {
		return err
	}
	if err := s.reconcile(); err != nil {
		return err
	}
	return s.verifyRows()
}

// reconcile applies the two documented crash-window protocols between the three
// counters: requests max, witness-file tip and secret-store high-water. It
// heals a difference of at most one append (re-witnessing / re-publishing) and
// refuses anything larger or in the rollback direction.
func (s *Store) reconcile() error {
	wTip, hasW := s.witness.tip()
	hw, hasHW, err := s.readHighWater()
	if err != nil {
		return err
	}

	switch {
	case hasW && hasHW:
		switch {
		case hw.RowID > wTip.RowID:
			return fmt.Errorf("%w: high-water is ahead of the witness log", ErrTampered)
		case wTip.RowID-hw.RowID > 1:
			return fmt.Errorf("%w: witness tip exceeds the high-water by more than one entry", ErrTampered)
		case wTip.RowID > hw.RowID:
			// Witness written, high-water write crashed: re-publish the tip.
			if err := s.publishHighWater(wTip); err != nil {
				return err
			}
		}
	case hasW && !hasHW:
		if wTip.RowID > 1 {
			return fmt.Errorf("%w: witness log present without a matching high-water", ErrTampered)
		}
		if err := s.publishHighWater(wTip); err != nil {
			return err
		}
	case !hasW && hasHW:
		return fmt.Errorf("%w: high-water present without a witness log", ErrTampered)
	}

	maxID, maxHash, hasMax, err := s.chainTip()
	if err != nil {
		return err
	}
	if !hasMax {
		if hasW {
			return fmt.Errorf("%w: witness tip present but the requests table is empty", ErrTampered)
		}
		return s.verifyAnchorBoundary()
	}
	if !hasW {
		if maxID > 1 {
			return fmt.Errorf("%w: requests table has more than one unwitnessed append", ErrTampered)
		}
		// Row committed, witness write crashed: re-witness the observed tip.
		if err := s.witnessAndPublish(maxID, maxHash); err != nil {
			return err
		}
		return s.verifyAnchorBoundary()
	}

	switch {
	case maxID > wTip.RowID:
		if maxID-wTip.RowID > 1 {
			return fmt.Errorf("%w: requests tip exceeds the witness by more than one append", ErrTampered)
		}
		if err := s.witnessAndPublish(maxID, maxHash); err != nil {
			return err
		}
	case maxID < wTip.RowID:
		return fmt.Errorf("%w: requests tip was truncated below the witness", ErrTampered)
	default:
		want, err := hex.DecodeString(wTip.RowHash)
		if err != nil || !bytes.Equal(want, maxHash) {
			return fmt.Errorf("%w: requests tip hash does not match the witness", ErrTampered)
		}
	}
	return s.verifyAnchorBoundary()
}

// verifyAnchorBoundary checks the newest retention anchor against the rows that
// still exist: rows below it may only survive as an in-flight delete, its own
// row must still be present with the recorded hash, and the requests table must
// not be empty.
func (s *Store) verifyAnchorBoundary() error {
	aTip, hasA := s.anchors.tip()
	if !hasA {
		return nil
	}
	oldestID, oldestHash, has, err := s.oldestRow()
	if err != nil {
		return err
	}
	if !has {
		return fmt.Errorf("%w: an anchor exists but the requests table is empty", ErrTampered)
	}
	if oldestID > aTip.RowID {
		return fmt.Errorf("%w: rows below the newest anchor were deleted without re-anchoring", ErrTampered)
	}
	want, err := hex.DecodeString(aTip.RowHash)
	if err != nil {
		return fmt.Errorf("%w: anchor hash is malformed", ErrTampered)
	}
	if oldestID == aTip.RowID {
		if !bytes.Equal(want, oldestHash) {
			return fmt.Errorf("%w: newest anchor row hash does not match", ErrTampered)
		}
		return nil
	}

	var rowHash []byte
	err = s.db.QueryRow(`SELECT hash FROM requests WHERE id = ?`, aTip.RowID).Scan(&rowHash)
	if errors.Is(err, sql.ErrNoRows) {
		return fmt.Errorf("%w: newest anchor row is missing", ErrTampered)
	}
	if err != nil {
		return fmt.Errorf("audit: read anchor row: %w", err)
	}
	if !bytes.Equal(want, rowHash) {
		return fmt.Errorf("%w: newest anchor row hash does not match", ErrTampered)
	}
	return nil
}

// verifyRows walks the chain from the newest retention anchor (or genesis when
// no retention has run) and re-derives every row hash. Invalid or missing rows
// fail closed.
func (s *Store) verifyRows() error {
	aTip, hasA := s.anchors.tip()
	startID := int64(0)
	var anchorHash []byte
	if hasA {
		startID = aTip.RowID
		h, err := hex.DecodeString(aTip.RowHash)
		if err != nil {
			return fmt.Errorf("%w: anchor hash is malformed", ErrTampered)
		}
		anchorHash = h
	}

	rows, err := s.db.Query(
		`SELECT id, ts, provider, path, method, status, req_bytes, resp_bytes, redactions, detectors, client, prev_hash, hash
		 FROM requests WHERE id >= ? ORDER BY id ASC`, startID)
	if err != nil {
		return fmt.Errorf("audit: verify query: %w", err)
	}
	defer rows.Close()

	var prev []byte
	first := true
	for rows.Next() {
		f, rowID, prevHash, hash, err := scanChainRow(rows)
		if err != nil {
			return err
		}
		switch {
		case first && hasA:
			if !bytes.Equal(hash, anchorHash) {
				return fmt.Errorf("%w: first verified row does not match the anchor", ErrTampered)
			}
		case first:
			if !bytes.Equal(prevHash, make([]byte, sha256.Size)) {
				return fmt.Errorf("%w: chain does not start at genesis", ErrTampered)
			}
		default:
			if !bytes.Equal(prevHash, prev) {
				return fmt.Errorf("%w: row %d does not chain to its predecessor", ErrTampered, rowID)
			}
		}
		if !bytes.Equal(hash, s.rowHash(prevHash, f)) {
			return fmt.Errorf("%w: row %d hash does not match its contents", ErrTampered, rowID)
		}
		prev = hash
		first = false
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("audit: verify rows: %w", err)
	}
	return nil
}

// scanChainRow reads one row into its canonical form plus the chain fields.
func scanChainRow(rows *sql.Rows) (canonicalRowFields, int64, []byte, []byte, error) {
	var (
		f         canonicalRowFields
		rowID     int64
		prevHash  []byte
		hash      []byte
		status    sql.NullInt64
		reqBytes  sql.NullInt64
		respBytes sql.NullInt64
		redacts   sql.NullInt64
		detectors sql.NullString
		client    sql.NullString
	)
	if err := rows.Scan(
		&rowID, &f.TS, &f.Provider, &f.Path, &f.Method,
		&status, &reqBytes, &respBytes, &redacts,
		&detectors, &client, &prevHash, &hash,
	); err != nil {
		return canonicalRowFields{}, 0, nil, nil, fmt.Errorf("audit: verify scan: %w", err)
	}
	f.Status = int(status.Int64)
	f.ReqBytes = reqBytes.Int64
	f.RespBytes = respBytes.Int64
	f.Redactions = int(redacts.Int64)
	f.Detectors = detectors.String
	f.Client = client.String
	return f, rowID, prevHash, hash, nil
}

// publishHighWater caches the witness tip as a bounded, MAC'd single value in
// the platform secret store.
func (s *Store) publishHighWater(e chainEntry) error {
	hw := highWater{Seq: e.Seq, RowID: e.RowID, RowHash: e.RowHash}
	if err := s.secrets.Set(secretService, highWaterKey, hw.encode(s.anchorKey)); err != nil {
		return fmt.Errorf("audit: persist high-water: %w", err)
	}
	return nil
}

// readHighWater loads and authenticates the cached tip, reporting absence as
// (zero, false, nil) so the caller can distinguish it from tampering.
func (s *Store) readHighWater() (highWater, bool, error) {
	value, err := s.secrets.Get(secretService, highWaterKey)
	if errors.Is(err, platform.ErrNotFound) {
		return highWater{}, false, nil
	}
	if err != nil {
		return highWater{}, false, fmt.Errorf("audit: read high-water: %w", err)
	}
	hw, err := decodeHighWater(value, s.anchorKey)
	if err != nil {
		return highWater{}, false, err
	}
	return hw, true, nil
}

// witnessAndPublish appends a tip entry and then publishes it, preserving the
// witness-file-before-high-water ordering.
func (s *Store) witnessAndPublish(id int64, hash []byte) error {
	entry, err := s.witness.append(id, hash)
	if err != nil {
		return err
	}
	return s.publishHighWater(entry)
}
