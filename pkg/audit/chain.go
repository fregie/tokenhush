package audit

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/fregie/tokenhush/pkg/platform"
)

// Secret-store coordinates for the audit subsystem (docs/13 §3.2, §6.1). The
// row chain and the anchor/witness chain use two independent keys so a leak of
// one never authenticates the other.
const (
	secretService = "tokenhush/audit"
	hmacKeyName   = "hmac-key"
	anchorKeyName = "anchor-key"
	highWaterKey  = "witness-tip"
	keyLen        = 32
)

// Chain-log entry kinds. A regular entry chains to its predecessor; a seal is
// the compacted head of a rewritten log and carries the predecessor it removed.
const (
	entryKind = "entry"
	sealKind  = "seal"
)

// Compaction bounds: the on-disk anchor/witness logs stay append-only until the
// threshold is crossed, then compact down to keep entries, preserving the
// dropped tail through a MAC'd seal. The plan forbids unbounded logs because
// the same tip must also fit platform.SecretStore value limits (§6.1).
const (
	chainCompactThreshold = 4096
	chainCompactKeep      = 2048
)

// genesisMAC is the all-zero predecessor digest every fresh chain roots at.
var genesisMAC = make([]byte, sha256.Size)

// ErrTampered reports that a chain log failed authentication, that the request
// database disagrees with a witness, or that a cross-store rollback was seen.
// Every Verify failure wraps it, so callers can classify with errors.Is.
var ErrTampered = errors.New("audit: tamper detected")

// chainEntry is one small, MAC'd, hash-chained log record. RowHash is the hex
// of the requests-row hash the entry witnesses. PrevMAC is the previous entry's
// MAC (or genesisMAC at the origin); MAC authenticates every field above.
type chainEntry struct {
	Kind    string `json:"kind"`
	Seq     uint64 `json:"seq"`
	RowID   int64  `json:"row_id"`
	RowHash string `json:"row_hash"`
	PrevMAC string `json:"prev_mac"`
	MAC     string `json:"mac"`
}

// macInput is the canonical, unambiguous byte string each entry MAC covers.
func (e chainEntry) macInput() []byte {
	return []byte(strings.Join([]string{
		e.Kind,
		strconv.FormatUint(e.Seq, 10),
		strconv.FormatInt(e.RowID, 10),
		e.RowHash,
		e.PrevMAC,
	}, "|"))
}

// computeMAC derives the entry MAC with the independent anchor key.
func (e chainEntry) computeMAC(key []byte) []byte {
	m := hmac.New(sha256.New, key)
	m.Write(e.macInput())
	return m.Sum(nil)
}

// validMAC reports whether the stored MAC matches the recomputed one.
func (e chainEntry) validMAC(key []byte) bool {
	want, err := hex.DecodeString(e.MAC)
	if err != nil {
		return false
	}
	return hmac.Equal(want, e.computeMAC(key))
}

// chainLog is an append-only, hash-chained, MAC'd log of small entries. It is
// the protected anchor history and the per-append tip witness, both persisted
// outside the requests database so deleting rows cannot rewrite them.
//
// Appends are serialized by the owning Store, so the cached tip is safe to
// trust between calls. The whole log is authenticated by the anchor key, which
// is independent of the row-chain HMAC key: neither key can forge the other.
type chainLog struct {
	path  string
	name  string
	key   []byte
	last  chainEntry
	count int
}

// loadChainLog reads and verifies an existing log (or starts an empty one).
func loadChainLog(path, name string, key []byte) (*chainLog, error) {
	l := &chainLog{path: path, name: name, key: key}
	entries, err := l.read()
	if err != nil {
		return nil, err
	}
	if len(entries) > 0 {
		l.last = entries[len(entries)-1]
		l.count = len(entries)
	}
	return l, nil
}

// read parses and verifies every entry currently on disk.
func (l *chainLog) read() ([]chainEntry, error) {
	data, err := os.ReadFile(l.path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("audit: read %s log: %w", l.name, err)
	}
	entries := make([]chainEntry, 0, bytes.Count(data, []byte("\n"))+1)
	for i, line := range bytes.Split(data, []byte("\n")) {
		if len(bytes.TrimSpace(line)) == 0 {
			continue
		}
		var e chainEntry
		if err := json.Unmarshal(line, &e); err != nil {
			return nil, fmt.Errorf("%w: %s log line %d is not valid JSON", ErrTampered, l.name, i+1)
		}
		entries = append(entries, e)
	}
	if err := verifyChain(l.name, entries, l.key); err != nil {
		return nil, err
	}
	return entries, nil
}

// verifyChain authenticates the MAC of every entry and the link between them.
// The first entry is the chain origin: a regular entry must root at genesis, a
// seal carries the tail MAC of the prefix it compacted away.
func verifyChain(name string, entries []chainEntry, key []byte) error {
	prevMAC := ""
	for i, e := range entries {
		if !e.validMAC(key) {
			return fmt.Errorf("%w: %s entry %d failed authentication", ErrTampered, name, i+1)
		}
		switch i {
		case 0:
			if e.Kind == entryKind && e.PrevMAC != hex.EncodeToString(genesisMAC) {
				return fmt.Errorf("%w: %s log origin is not genesis", ErrTampered, name)
			}
			if e.Kind != entryKind && e.Kind != sealKind {
				return fmt.Errorf("%w: %s entry %d has unknown kind %q", ErrTampered, name, i+1, e.Kind)
			}
		default:
			want := prevMAC
			if i == 1 && entries[0].Kind == sealKind {
				// The seal carries the predecessor of the first kept entry.
				want = entries[0].PrevMAC
			}
			if e.PrevMAC != want {
				return fmt.Errorf("%w: %s entry %d does not chain to its predecessor", ErrTampered, name, i+1)
			}
		}
		prevMAC = e.MAC
	}
	return nil
}

// append writes one entry that witnesses (rowID, rowHash) and returns it. The
// entry is fsynced before append returns so a crash cannot leave a torn line.
func (l *chainLog) append(rowID int64, rowHash []byte) (chainEntry, error) {
	prev := hex.EncodeToString(genesisMAC)
	seq := uint64(1)
	if l.count > 0 {
		prev = l.last.MAC
		seq = l.last.Seq + 1
	}
	e := chainEntry{
		Kind:    entryKind,
		Seq:     seq,
		RowID:   rowID,
		RowHash: hex.EncodeToString(rowHash),
		PrevMAC: prev,
	}
	e.MAC = hex.EncodeToString(e.computeMAC(l.key))

	line, err := json.Marshal(e)
	if err != nil {
		return chainEntry{}, fmt.Errorf("audit: encode %s entry: %w", l.name, err)
	}
	line = append(line, '\n')

	f, err := os.OpenFile(l.path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return chainEntry{}, fmt.Errorf("audit: open %s log: %w", l.name, err)
	}
	if _, err := f.Write(line); err != nil {
		_ = f.Close()
		return chainEntry{}, fmt.Errorf("audit: append %s log: %w", l.name, err)
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		return chainEntry{}, fmt.Errorf("audit: sync %s log: %w", l.name, err)
	}
	if err := f.Close(); err != nil {
		return chainEntry{}, fmt.Errorf("audit: close %s log: %w", l.name, err)
	}

	l.last = e
	l.count++
	if l.count > chainCompactThreshold {
		if err := l.compact(chainCompactKeep); err != nil {
			return chainEntry{}, err
		}
	}
	return e, nil
}

// tip returns the newest entry, or false when the log is empty.
func (l *chainLog) tip() (chainEntry, bool) {
	if l.count == 0 {
		return chainEntry{}, false
	}
	return l.last, true
}

// reload re-reads and re-authenticates the log from disk, refreshing the cached
// tip. Verify uses it so tampering with a log file after Open is detected
// rather than masked by a stale in-memory tip.
func (l *chainLog) reload() error {
	entries, err := l.read()
	if err != nil {
		return err
	}
	l.count = len(entries)
	if len(entries) > 0 {
		l.last = entries[len(entries)-1]
	} else {
		l.last = chainEntry{}
	}
	return nil
}

// compact rewrites the log to keep only the newest entries, prefixed by a
// MAC'd seal that records the tail it dropped. Re-anchoring stays detectable
// because the seal and every kept entry are authenticated and the kept first
// entry still chains to the dropped tail through the seal's PrevMAC.
func (l *chainLog) compact(keep int) error {
	entries, err := l.read()
	if err != nil {
		return err
	}
	if len(entries) <= keep {
		return nil
	}
	dropped := entries[0 : len(entries)-keep]
	kept := entries[len(entries)-keep:]
	tail := dropped[len(dropped)-1]

	seal := chainEntry{
		Kind:    sealKind,
		Seq:     tail.Seq,
		RowID:   tail.RowID,
		RowHash: tail.RowHash,
		PrevMAC: tail.MAC,
	}
	seal.MAC = hex.EncodeToString(seal.computeMAC(l.key))

	compacted := make([]chainEntry, 0, keep+1)
	compacted = append(compacted, seal)
	compacted = append(compacted, kept...)
	if err := writeChainFile(l.path, compacted); err != nil {
		return err
	}
	l.count = len(compacted)
	return nil
}

// writeChainFile atomically replaces a chain log with entries.
func writeChainFile(path string, entries []chainEntry) error {
	var buf bytes.Buffer
	for _, e := range entries {
		line, err := json.Marshal(e)
		if err != nil {
			return fmt.Errorf("audit: encode compacted chain: %w", err)
		}
		buf.Write(line)
		buf.WriteByte('\n')
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".chain-*")
	if err != nil {
		return fmt.Errorf("audit: create compacted chain: %w", err)
	}
	tmpName := tmp.Name()
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		_ = os.Remove(tmpName)
		return fmt.Errorf("audit: protect compacted chain: %w", err)
	}
	if _, err := tmp.Write(buf.Bytes()); err != nil {
		_ = tmp.Close()
		_ = os.Remove(tmpName)
		return fmt.Errorf("audit: write compacted chain: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		_ = os.Remove(tmpName)
		return fmt.Errorf("audit: sync compacted chain: %w", err)
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(tmpName)
		return fmt.Errorf("audit: close compacted chain: %w", err)
	}
	if err := os.Rename(tmpName, path); err != nil {
		_ = os.Remove(tmpName)
		return fmt.Errorf("audit: install compacted chain: %w", err)
	}
	return nil
}

// loadOrCreateKey returns the named audit key, generating and persisting it on
// first use. A malformed existing value is treated as tampering, never as
// absent, so a damaged key is surfaced instead of silently regenerated.
func loadOrCreateKey(secrets platform.SecretStore, key string) ([]byte, error) {
	value, err := secrets.Get(secretService, key)
	if err == nil {
		raw, derr := hex.DecodeString(value)
		if derr != nil || len(raw) != keyLen {
			return nil, fmt.Errorf("%w: %s is malformed", ErrTampered, key)
		}
		return raw, nil
	}
	if !errors.Is(err, platform.ErrNotFound) {
		return nil, fmt.Errorf("audit: read %s: %w", key, err)
	}
	raw := make([]byte, keyLen)
	if _, err := rand.Read(raw); err != nil {
		return nil, fmt.Errorf("audit: generate %s: %w", key, err)
	}
	if err := secrets.Set(secretService, key, hex.EncodeToString(raw)); err != nil {
		return nil, fmt.Errorf("audit: persist %s: %w", key, err)
	}
	return raw, nil
}

// highWater is the bounded, non-rollback tip cached in platform.SecretStore.
type highWater struct {
	Seq     uint64
	RowID   int64
	RowHash string
	MAC     string
}

// highWaterMAC authenticates the tip with the anchor key.
func highWaterMAC(key []byte, seq uint64, rowID int64, rowHash string) []byte {
	m := hmac.New(sha256.New, key)
	m.Write([]byte("tokenhush/audit/high-water|" +
		strconv.FormatUint(seq, 10) + "|" +
		strconv.FormatInt(rowID, 10) + "|" + rowHash))
	return m.Sum(nil)
}

// encode renders the tip as a small, self-describing string (well under the
// macOS 4096 B and Windows 2560 B SecretStore value limits).
func (h highWater) encode(key []byte) string {
	return strings.Join([]string{
		"v1",
		strconv.FormatUint(h.Seq, 10),
		strconv.FormatInt(h.RowID, 10),
		h.RowHash,
		hex.EncodeToString(highWaterMAC(key, h.Seq, h.RowID, h.RowHash)),
	}, "|")
}

// decodeHighWater parses and authenticates a stored tip value.
func decodeHighWater(value string, key []byte) (highWater, error) {
	parts := strings.Split(value, "|")
	if len(parts) != 5 || parts[0] != "v1" {
		return highWater{}, fmt.Errorf("%w: high-water value is malformed", ErrTampered)
	}
	seq, err := strconv.ParseUint(parts[1], 10, 64)
	if err != nil {
		return highWater{}, fmt.Errorf("%w: high-water seq is malformed", ErrTampered)
	}
	rowID, err := strconv.ParseInt(parts[2], 10, 64)
	if err != nil {
		return highWater{}, fmt.Errorf("%w: high-water row id is malformed", ErrTampered)
	}
	wantMAC, err := hex.DecodeString(parts[4])
	if err != nil {
		return highWater{}, fmt.Errorf("%w: high-water MAC is malformed", ErrTampered)
	}
	if !hmac.Equal(wantMAC, highWaterMAC(key, seq, rowID, parts[3])) {
		return highWater{}, fmt.Errorf("%w: high-water MAC mismatch", ErrTampered)
	}
	return highWater{Seq: seq, RowID: rowID, RowHash: parts[3], MAC: parts[4]}, nil
}
