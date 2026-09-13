package rules

// Local cache for verified signed rule packs. The layout under the cache root
// is:
//
//	<root>/active            active serial as text, absent = built-in default
//	<root>/revoked.json      revocation list from the latest accepted manifest
//	<root>/<serial>/manifest.json  raw signed manifest
//	<root>/<serial>/bundle.json     raw signed bundle
//
// Raw verified bytes are stored verbatim so Active re-verifies the exact bytes
// that were signed. The rules schema has no version string, so the monotonic
// serial is the version identifier (and the directory name); see ADR-0020.

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
)

// RevokedList is the persisted revocation list from the latest accepted
// manifest. It lets Active refuse a revoked cached pack while offline.
type RevokedList struct {
	Serials []uint64 `json:"serials,omitempty"`
}

// Revokes reports whether serial is on the list.
func (r RevokedList) Revokes(serial uint64) bool {
	return slices.Contains(r.Serials, serial)
}

// CacheStore persists verified signed packs, the active selection and the last
// accepted revocation list.
type CacheStore interface {
	Save(serial uint64, manifest, bundle []byte) error
	Load(serial uint64) (manifest, bundle []byte, err error)
	Serials() ([]uint64, error)
	Remove(serial uint64) error
	Active() (serial uint64, ok bool, err error)
	SetActive(serial uint64) error
	Revoked() (RevokedList, error)
	SetRevoked(rev RevokedList) error
}

// FileCache is the on-disk CacheStore. Every write is atomic.
type FileCache struct {
	root string
}

// OpenFileCache prepares root as a rule cache and returns it.
func OpenFileCache(root string) (*FileCache, error) {
	if strings.TrimSpace(root) == "" {
		return nil, fmt.Errorf("%w: cache root is required", ErrClientConfig)
	}
	if err := os.MkdirAll(root, 0o700); err != nil {
		return nil, err
	}
	return &FileCache{root: root}, nil
}

// Save writes the raw signed manifest and bundle for serial atomically.
func (c *FileCache) Save(serial uint64, manifest, bundle []byte) error {
	if serial == 0 {
		return fmt.Errorf("%w: serial 0 cannot be cached", ErrPackMalformed)
	}
	dir := c.dir(serial)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	if err := writeFileAtomic(filepath.Join(dir, "manifest.json"), manifest, 0o600); err != nil {
		return err
	}
	return writeFileAtomic(filepath.Join(dir, "bundle.json"), bundle, 0o600)
}

// Load returns the cached raw manifest and bundle for serial.
func (c *FileCache) Load(serial uint64) ([]byte, []byte, error) {
	manifest, err := readCacheFile(filepath.Join(c.dir(serial), "manifest.json"))
	if err != nil {
		return nil, nil, err
	}
	bundle, err := readCacheFile(filepath.Join(c.dir(serial), "bundle.json"))
	if err != nil {
		return nil, nil, err
	}
	return manifest, bundle, nil
}

// Serials lists cached serials in ascending order.
func (c *FileCache) Serials() ([]uint64, error) {
	entries, err := os.ReadDir(c.root)
	if err != nil {
		return nil, err
	}
	var out []uint64
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		n, err := strconv.ParseUint(e.Name(), 10, 64)
		if err != nil || n == 0 {
			continue
		}
		out = append(out, n)
	}
	slices.Sort(out)
	return out, nil
}

// Remove deletes the cached serial. A missing serial is not an error.
func (c *FileCache) Remove(serial uint64) error {
	if serial == 0 {
		return nil
	}
	return os.RemoveAll(c.dir(serial))
}

// Active returns the active serial. ok is false when no remote pack is active,
// i.e. the built-in defaults are in effect.
func (c *FileCache) Active() (uint64, bool, error) {
	raw, err := os.ReadFile(filepath.Join(c.root, "active"))
	if errors.Is(err, fs.ErrNotExist) {
		return 0, false, nil
	}
	if err != nil {
		return 0, false, err
	}
	s := strings.TrimSpace(string(raw))
	if s == "" || s == "0" {
		return 0, false, nil
	}
	n, err := strconv.ParseUint(s, 10, 64)
	if err != nil || n == 0 {
		return 0, false, fmt.Errorf("%w: corrupt active pointer", ErrCacheMiss)
	}
	return n, true, nil
}

// SetActive records serial as active; serial 0 clears the selection so the
// built-in defaults apply.
func (c *FileCache) SetActive(serial uint64) error {
	path := filepath.Join(c.root, "active")
	if serial == 0 {
		if err := os.Remove(path); err != nil && !errors.Is(err, fs.ErrNotExist) {
			return err
		}
		return nil
	}
	return writeFileAtomic(path, []byte(strconv.FormatUint(serial, 10)+"\n"), 0o600)
}

// Revoked returns the persisted revocation list; a missing file means empty.
func (c *FileCache) Revoked() (RevokedList, error) {
	var rev RevokedList
	raw, err := os.ReadFile(filepath.Join(c.root, "revoked.json"))
	if errors.Is(err, fs.ErrNotExist) {
		return rev, nil
	}
	if err != nil {
		return RevokedList{}, err
	}
	if len(raw) == 0 {
		return rev, nil
	}
	if err := json.Unmarshal(raw, &rev); err != nil {
		return RevokedList{}, err
	}
	return rev, nil
}

// SetRevoked persists the revocation list, sorted and deduplicated.
func (c *FileCache) SetRevoked(rev RevokedList) error {
	serials := slices.Clone(rev.Serials)
	slices.Sort(serials)
	serials = slices.Compact(serials)
	raw, err := json.Marshal(RevokedList{Serials: serials})
	if err != nil {
		return err
	}
	return writeFileAtomic(filepath.Join(c.root, "revoked.json"), raw, 0o600)
}

// dir returns the cache directory of one serial.
func (c *FileCache) dir(serial uint64) string {
	return filepath.Join(c.root, strconv.FormatUint(serial, 10))
}

// readCacheFile reads one cache file, mapping absence to ErrCacheMiss.
func readCacheFile(path string) ([]byte, error) {
	raw, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, fmt.Errorf("%w: %s", ErrCacheMiss, filepath.Base(filepath.Dir(path)))
	}
	if err != nil {
		return nil, err
	}
	return raw, nil
}

// writeFileAtomic writes data to path via a temp file in the same directory and
// a rename, so a crash never leaves a torn file.
func writeFileAtomic(path string, data []byte, perm os.FileMode) error {
	dir := filepath.Dir(path)
	if dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return err
		}
	}
	tmp, err := os.CreateTemp(dir, ".tmp-*")
	if err != nil {
		return err
	}
	name := tmp.Name()
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		_ = os.Remove(name)
		return err
	}
	if err := tmp.Chmod(perm); err != nil {
		_ = tmp.Close()
		_ = os.Remove(name)
		return err
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(name)
		return err
	}
	if err := os.Rename(name, path); err != nil {
		_ = os.Remove(name)
		return err
	}
	return nil
}
