package audit

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/fregie/tokenhush/pkg/platform"
	_ "modernc.org/sqlite" // pure-Go, CGO-free SQLite driver
)

const (
	// defaultRetentionDays is the docs/13 §6 default; the configured value is
	// clamped to the documented 7–30 day band.
	defaultRetentionDays = 14
	minRetentionDays     = 7
	maxRetentionDays     = 30

	// defaultQueryLimit bounds an unfiltered Query when the caller leaves
	// Limit unset, mirroring the control-API's own cap.
	defaultQueryLimit = 1000

	// anchorSuffix and witnessSuffix name the two protected files that live
	// outside the requests database.
	anchorSuffix  = ".anchors"
	witnessSuffix = ".witness"
)

// Store-level sentinels. Every error path wraps one of these where a caller
// could reasonably branch on it.
var (
	// ErrClosed reports use of a Store after Close.
	ErrClosed = errors.New("audit: store is closed")
	// ErrPathRequired reports an empty StoreConfig.Path.
	ErrPathRequired = errors.New("audit: store path is required")
	// ErrSecretStoreRequired reports a missing key source when keys were not
	// injected: the high-water tip must be persisted somewhere durable.
	ErrSecretStoreRequired = errors.New("audit: a secret store is required")
)

// StoreConfig opens a metadata-only audit Store.
//
// Path is the SQLite database file; the witness and anchor logs are derived
// from it by suffix. Secrets is the platform secret store used to derive the
// two independent audit keys and to persist the bounded high-water tip.
// HashKey/AnchorKey and Now are test seams.
type StoreConfig struct {
	Path          string
	Secrets       platform.SecretStore
	HashKey       []byte
	AnchorKey     []byte
	RetentionDays int
	Now           func() time.Time
}

// Store is the metadata-only SQLite audit store: an append-only requests table
// with a keyed row chain, a retention policy anchored in a protected external
// log, and a per-append tip witness whose head is also cached as a bounded,
// non-rollback high-water in the platform secret store.
//
// It implements AuditSink and AuditQuerier. Records carry metadata only: no
// column ever holds request or response content.
type Store struct {
	db        *sql.DB
	path      string
	secrets   platform.SecretStore
	hashKey   []byte
	anchorKey []byte
	retention int
	now       func() time.Time

	mu      sync.Mutex
	anchors *chainLog
	witness *chainLog
	closed  bool
}

var (
	_ AuditSink    = (*Store)(nil)
	_ AuditQuerier = (*Store)(nil)
)

// OpenStore opens (creating if needed) the audit store at cfg.Path and runs the
// crash-recovery reconciliation before returning. A tampered or inconsistent
// state is refused, never silently repaired beyond the documented ≤1 window.
func OpenStore(cfg StoreConfig) (*Store, error) {
	path := strings.TrimSpace(cfg.Path)
	if path == "" {
		return nil, ErrPathRequired
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, fmt.Errorf("audit: create store dir: %w", err)
	}

	hashKey, anchorKey := cfg.HashKey, cfg.AnchorKey
	if cfg.Secrets == nil {
		return nil, ErrSecretStoreRequired
	}
	var err error
	if len(hashKey) == 0 {
		if hashKey, err = loadOrCreateKey(cfg.Secrets, hmacKeyName); err != nil {
			return nil, err
		}
	}
	if len(anchorKey) == 0 {
		if anchorKey, err = loadOrCreateKey(cfg.Secrets, anchorKeyName); err != nil {
			return nil, err
		}
	}

	db, err := openSQLite(path)
	if err != nil {
		return nil, err
	}
	anchors, err := loadChainLog(path+anchorSuffix, "anchor", anchorKey)
	if err != nil {
		_ = db.Close()
		return nil, err
	}
	witness, err := loadChainLog(path+witnessSuffix, "witness", anchorKey)
	if err != nil {
		_ = db.Close()
		return nil, err
	}

	now := cfg.Now
	if now == nil {
		now = time.Now
	}
	s := &Store{
		db:        db,
		path:      path,
		secrets:   cfg.Secrets,
		hashKey:   hashKey,
		anchorKey: anchorKey,
		retention: clampRetentionDays(cfg.RetentionDays),
		now:       now,
		anchors:   anchors,
		witness:   witness,
	}
	if err := s.reconcile(); err != nil {
		_ = db.Close()
		return nil, err
	}
	return s, nil
}

// OpenDefaultStore opens the store under the platform data directory using the
// selected platform secret store.
func OpenDefaultStore() (*Store, error) {
	dir, err := platform.DataDir()
	if err != nil {
		return nil, err
	}
	secrets, err := platform.OpenSecretStore()
	if err != nil {
		return nil, err
	}
	return OpenStore(StoreConfig{
		Path:    filepath.Join(dir, "audit.db"),
		Secrets: secrets,
	})
}

// Path returns the SQLite database path.
func (s *Store) Path() string { return s.path }

// RetentionDays returns the clamped retention window in days.
func (s *Store) RetentionDays() int { return s.retention }

// Close flushes and releases the store. It is idempotent.
func (s *Store) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil
	}
	s.closed = true
	return s.db.Close()
}

// Record appends one metadata-only row and witnesses the new chain tip.
//
// Ordering is fixed and crash-safe:
//  1. insert the row and commit (the chain hash is computed inside),
//  2. append the tip witness to the protected witness log,
//  3. publish the witness tip to the secret-store high-water.
//
// A crash between steps leaves at most one unwitnessed append; reconcile heals
// exactly that window. A larger gap, or a rollback, is refused.
func (s *Store) Record(rec Record) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return ErrClosed
	}
	id, hash, err := s.insertRow(rec)
	if err != nil {
		return err
	}
	entry, err := s.witness.append(id, hash)
	if err != nil {
		return err
	}
	return s.publishHighWater(entry)
}

// insertRow commits one row and returns its id and chain hash. The caller must
// hold s.mu. It is split out from Record so tests can simulate the documented
// row-commit / witness-write crash window.
func (s *Store) insertRow(rec Record) (int64, []byte, error) {
	ts := rec.TS
	if ts == 0 {
		ts = s.now().UnixMilli()
	}
	detectors := encodeDetectors(rec.Detectors)

	prevHash := make([]byte, sha256.Size)
	_, tipHash, ok, err := s.chainTip()
	if err != nil {
		return 0, nil, err
	}
	if ok {
		prevHash = tipHash
	}
	hash := s.rowHash(prevHash, canonicalRowFields{
		TS:         ts,
		Provider:   rec.Provider,
		Path:       rec.Path,
		Method:     rec.Method,
		Status:     rec.Status,
		ReqBytes:   rec.ReqBytes,
		RespBytes:  rec.RespBytes,
		Redactions: rec.Redactions,
		Detectors:  detectors,
		Client:     rec.Client,
	})

	res, err := s.db.Exec(
		`INSERT INTO requests
		 (ts, provider, path, method, status, req_bytes, resp_bytes, redactions, detectors, client, prev_hash, hash)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		ts, rec.Provider, rec.Path, rec.Method, rec.Status, rec.ReqBytes, rec.RespBytes,
		rec.Redactions, detectors, rec.Client, prevHash, hash,
	)
	if err != nil {
		return 0, nil, fmt.Errorf("audit: insert row: %w", err)
	}
	id, err := res.LastInsertId()
	if err != nil {
		return 0, nil, fmt.Errorf("audit: row id: %w", err)
	}
	return id, hash, nil
}

// rowHash computes HMAC(hashKey, prevHash || canonical row bytes).
func (s *Store) rowHash(prevHash []byte, f canonicalRowFields) []byte {
	m := hmac.New(sha256.New, s.hashKey)
	m.Write(prevHash)
	m.Write(canonicalBytes(f))
	return m.Sum(nil)
}

// canonicalRowFields is the deterministic serialization hashed into the row
// chain. The stored detectors text is reused verbatim so append and verify
// agree without re-marshalling.
type canonicalRowFields struct {
	TS         int64  `json:"ts"`
	Provider   string `json:"provider"`
	Path       string `json:"path"`
	Method     string `json:"method"`
	Status     int    `json:"status"`
	ReqBytes   int64  `json:"req_bytes"`
	RespBytes  int64  `json:"resp_bytes"`
	Redactions int    `json:"redactions"`
	Detectors  string `json:"detectors"`
	Client     string `json:"client"`
}

// canonicalBytes serializes the canonical row.
func canonicalBytes(f canonicalRowFields) []byte {
	b, err := json.Marshal(f)
	if err != nil {
		return nil
	}
	return b
}

// encodeDetectors stores detector ids as the JSON array docs/13 §6 mandates,
// using [] rather than null for an empty set.
func encodeDetectors(detectors []string) string {
	if len(detectors) == 0 {
		return "[]"
	}
	b, err := json.Marshal(detectors)
	if err != nil {
		return "[]"
	}
	return string(b)
}

// decodeDetectors parses a stored detectors column, tolerating NULL and blank.
func decodeDetectors(text string) []string {
	if text == "" {
		return nil
	}
	var out []string
	if err := json.Unmarshal([]byte(text), &out); err != nil {
		return nil
	}
	return out
}

// chainTip returns the newest row's id and hash.
func (s *Store) chainTip() (int64, []byte, bool, error) {
	var id int64
	var hash []byte
	err := s.db.QueryRow(`SELECT id, hash FROM requests ORDER BY id DESC LIMIT 1`).Scan(&id, &hash)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, nil, false, nil
	}
	if err != nil {
		return 0, nil, false, fmt.Errorf("audit: read chain tip: %w", err)
	}
	return id, hash, true, nil
}

// oldestRow returns the oldest row's id and hash.
func (s *Store) oldestRow() (int64, []byte, bool, error) {
	var id int64
	var hash []byte
	err := s.db.QueryRow(`SELECT id, hash FROM requests ORDER BY id ASC LIMIT 1`).Scan(&id, &hash)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, nil, false, nil
	}
	if err != nil {
		return 0, nil, false, fmt.Errorf("audit: read oldest row: %w", err)
	}
	return id, hash, true, nil
}

// Query returns metadata-only rows matching q, oldest first.
func (s *Store) Query(ctx context.Context, q Query) ([]Record, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil, ErrClosed
	}

	where := make([]string, 0, 3)
	args := make([]any, 0, 4)
	if !q.Since.IsZero() {
		where = append(where, "ts >= ?")
		args = append(args, q.Since.UnixMilli())
	}
	if !q.Until.IsZero() {
		where = append(where, "ts <= ?")
		args = append(args, q.Until.UnixMilli())
	}
	if q.Provider != "" {
		where = append(where, "provider = ?")
		args = append(args, q.Provider)
	}
	limit := q.Limit
	if limit <= 0 {
		limit = defaultQueryLimit
	}

	var b strings.Builder
	b.WriteString(`SELECT id, ts, provider, path, method, status, req_bytes, resp_bytes, redactions, detectors, client, prev_hash, hash FROM requests`)
	if len(where) > 0 {
		b.WriteString(" WHERE ")
		b.WriteString(strings.Join(where, " AND "))
	}
	b.WriteString(" ORDER BY id ASC LIMIT ?")
	args = append(args, limit)

	rows, err := s.db.QueryContext(ctx, b.String(), args...)
	if err != nil {
		return nil, fmt.Errorf("audit: query rows: %w", err)
	}
	defer rows.Close()

	records := make([]Record, 0)
	for rows.Next() {
		var (
			rec       Record
			status    sql.NullInt64
			reqBytes  sql.NullInt64
			respBytes sql.NullInt64
			redacts   sql.NullInt64
			detectors sql.NullString
			client    sql.NullString
		)
		if err := rows.Scan(
			&rec.ID, &rec.TS, &rec.Provider, &rec.Path, &rec.Method,
			&status, &reqBytes, &respBytes, &redacts,
			&detectors, &client, &rec.PrevHash, &rec.Hash,
		); err != nil {
			return nil, fmt.Errorf("audit: scan row: %w", err)
		}
		rec.Status = int(status.Int64)
		rec.ReqBytes = reqBytes.Int64
		rec.RespBytes = respBytes.Int64
		rec.Redactions = int(redacts.Int64)
		rec.Detectors = decodeDetectors(detectors.String)
		rec.Client = client.String
		records = append(records, rec)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("audit: iterate rows: %w", err)
	}
	return records, nil
}

// openSQLite opens the database with WAL journaling and a busy timeout, then
// installs the docs/13 §6 schema.
func openSQLite(path string) (*sql.DB, error) {
	params := url.Values{}
	params.Add("_pragma", "journal_mode(WAL)")
	params.Add("_pragma", "busy_timeout(5000)")
	params.Add("_pragma", "synchronous(NORMAL)")
	dsn := path + "?" + params.Encode()

	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("audit: open sqlite: %w", err)
	}
	// A single writer keeps WAL writers from racing and makes the append
	// ordering deterministic; audit traffic is low-volume.
	db.SetMaxOpenConns(1)
	if err := db.Ping(); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("audit: open sqlite: %w", err)
	}
	if _, err := db.Exec(schemaSQL); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("audit: create schema: %w", err)
	}
	return db, nil
}

// schemaSQL is the exact requests table from docs/13 §6.
const schemaSQL = `
CREATE TABLE IF NOT EXISTS requests (
  id          INTEGER PRIMARY KEY AUTOINCREMENT,
  ts          INTEGER NOT NULL,
  provider    TEXT    NOT NULL,
  path        TEXT    NOT NULL,
  method      TEXT    NOT NULL,
  status      INTEGER,
  req_bytes   INTEGER,
  resp_bytes  INTEGER,
  redactions  INTEGER,
  detectors   TEXT,
  client      TEXT,
  prev_hash   BLOB    NOT NULL,
  hash        BLOB    NOT NULL
);`

// clampRetentionDays applies the documented 7–30 day band, defaulting to 14.
func clampRetentionDays(days int) int {
	switch {
	case days == 0:
		return defaultRetentionDays
	case days < minRetentionDays:
		return minRetentionDays
	case days > maxRetentionDays:
		return maxRetentionDays
	default:
		return days
	}
}
