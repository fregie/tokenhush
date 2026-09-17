package supply

// highwater_test.go is the W5.3 suite: the monotonic serial guard shared by
// both rule packs and binary updates. Every assertion is inline; nothing here
// touches the network or a fixture file another todo owns.

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"
)

func TestHighWaterMemAdvancesMonotonically(t *testing.T) {
	store := NewMemHighWater()
	if got := store.Current(); got != 0 {
		t.Fatalf("fresh store Current() = %d, want 0", got)
	}
	for _, serial := range []int64{1, 2, 9, 10} {
		if err := store.Advance(serial); err != nil {
			t.Fatalf("Advance(%d) = %v, want nil", serial, err)
		}
		if got := store.Current(); got != serial {
			t.Fatalf("after Advance(%d), Current() = %d", serial, got)
		}
	}
}

func TestHighWaterMemRejectsLowerSerial(t *testing.T) {
	store := NewMemHighWater()
	if err := store.Advance(5); err != nil {
		t.Fatalf("Advance(5) = %v, want nil", err)
	}
	err := store.Advance(1)
	if !errors.Is(err, ErrReplay) {
		t.Fatalf("Advance(1) = %v, want an error wrapping ErrReplay", err)
	}
	t.Logf("QA failure: replay serial 1 after serial 5 -> %v", err)
	var replay *ReplayError
	if !errors.As(err, &replay) {
		t.Fatalf("Advance(1) = %v, want a *ReplayError", err)
	}
	if replay.Current != 5 || replay.Attempted != 1 {
		t.Fatalf("ReplayError = {Current:%d Attempted:%d}, want {5 1}", replay.Current, replay.Attempted)
	}
	if got := store.Current(); got != 5 {
		t.Fatalf("a rejected replay changed Current() to %d, want 5", got)
	}
}

func TestHighWaterEqualSerialIsIdempotent(t *testing.T) {
	store := NewMemHighWater()
	if err := store.Advance(5); err != nil {
		t.Fatalf("Advance(5) = %v, want nil", err)
	}
	if err := store.Advance(5); err != nil {
		t.Fatalf("Advance(5) equal serial = %v, want nil", err)
	}
	if got := store.Current(); got != 5 {
		t.Fatalf("equal serial changed Current() to %d, want 5", got)
	}
}

func TestHighWaterHighestSerialToleratedOnReplay(t *testing.T) {
	// A legitimate replay of the current highest serial is idempotent, not an
	// error: only a strictly older serial is a replay attack.
	store := NewMemHighWater()
	if err := store.Advance(5); err != nil {
		t.Fatalf("Advance(5) = %v, want nil", err)
	}
	for attempt := 0; attempt < 3; attempt++ {
		if err := store.Advance(5); err != nil {
			t.Fatalf("replay %d of the highest serial = %v, want nil", attempt, err)
		}
	}
	if got := store.Current(); got != 5 {
		t.Fatalf("trailing replays changed Current() to %d, want 5", got)
	}
}

func TestHighWaterFilePersistsAtomically(t *testing.T) {
	path := filepath.Join(t.TempDir(), "rules", "highwater.json")
	store, err := NewFileHighWater(path)
	if err != nil {
		t.Fatalf("NewFileHighWater = %v, want nil for a missing file", err)
	}
	if _, err := os.Stat(filepath.Dir(path)); !os.IsNotExist(err) {
		t.Fatalf("parent dir stat = %v, want not-exist before the first write", err)
	}
	if err := store.Advance(7); err != nil {
		t.Fatalf("Advance(7) = %v, want nil", err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat %s = %v", path, err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Fatalf("mode = %o, want 600", perm)
	}
	entries, err := os.ReadDir(filepath.Dir(path))
	if err != nil {
		t.Fatalf("read dir = %v", err)
	}
	if len(entries) != 1 || entries[0].Name() != "highwater.json" {
		t.Fatalf("dir entries = %v, want exactly the high-water file (no temp litter)", entries)
	}
	reloaded, err := NewFileHighWater(path)
	if err != nil {
		t.Fatalf("reload = %v", err)
	}
	if got := reloaded.Current(); got != 7 {
		t.Fatalf("reloaded Current() = %d, want 7", got)
	}
}

func TestHighWaterFileRejectsLowerSerialAndRetainsMark(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "highwater.json")
	store, err := NewFileHighWater(path)
	if err != nil {
		t.Fatalf("NewFileHighWater = %v", err)
	}
	if err := store.Advance(5); err != nil {
		t.Fatalf("Advance(5) = %v", err)
	}
	if err := store.Advance(1); !errors.Is(err, ErrReplay) {
		t.Fatalf("Advance(1) = %v, want an error wrapping ErrReplay", err)
	}
	if got := store.Current(); got != 5 {
		t.Fatalf("Current() = %d after a rejected replay, want 5", got)
	}
	reloaded, err := NewFileHighWater(path)
	if err != nil {
		t.Fatalf("reload = %v", err)
	}
	if got := reloaded.Current(); got != 5 {
		t.Fatalf("reloaded Current() = %d, want the retained 5", got)
	}
}

func TestHighWaterFileFrozenPaths(t *testing.T) {
	dataDir := t.TempDir()
	rules, err := NewRulesHighWater(dataDir)
	if err != nil {
		t.Fatalf("NewRulesHighWater = %v", err)
	}
	update, err := NewUpdateHighWater(dataDir)
	if err != nil {
		t.Fatalf("NewUpdateHighWater = %v", err)
	}
	if err := rules.Advance(4); err != nil {
		t.Fatalf("rules Advance(4) = %v", err)
	}
	if err := update.Advance(11); err != nil {
		t.Fatalf("update Advance(11) = %v", err)
	}
	for rel, want := range map[string]int64{
		"rules/highwater.json":  4,
		"update/highwater.json": 11,
	} {
		path := filepath.Join(dataDir, filepath.FromSlash(rel))
		if _, err := os.Stat(path); err != nil {
			t.Fatalf("frozen path %s missing: %v", rel, err)
		}
		reloaded, err := NewFileHighWater(path)
		if err != nil {
			t.Fatalf("reload %s = %v", rel, err)
		}
		if got := reloaded.Current(); got != want {
			t.Fatalf("%s Current() = %d, want %d", rel, got, want)
		}
	}
}

func TestHighWaterFileDocumentIsStableMetadataOnly(t *testing.T) {
	path := filepath.Join(t.TempDir(), "highwater.json")
	store, err := NewFileHighWater(path)
	if err != nil {
		t.Fatalf("NewFileHighWater = %v", err)
	}
	if err := store.Advance(3); err != nil {
		t.Fatalf("Advance(3) = %v", err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read = %v", err)
	}
	var doc map[string]any
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("unmarshal %q = %v", raw, err)
	}
	if len(doc) != 1 {
		t.Fatalf("document keys = %v, want exactly [serial] (metadata-only)", doc)
	}
	if serial, ok := doc["serial"].(float64); !ok || serial != 3 {
		t.Fatalf("document = %v, want {\"serial\":3}", doc)
	}
}

func TestHighWaterFileCorruptFailsClosed(t *testing.T) {
	cases := map[string]string{
		"empty":         "",
		"truncated":     `{"serial":`,
		"wrong type":    `{"serial":"nope"}`,
		"negative":      `{"serial":-1}`,
		"not an object": `5`,
		"trailing":      `{"serial":1} {"serial":2}`,
	}
	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "highwater.json")
			if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
				t.Fatalf("write fixture = %v", err)
			}
			if _, err := NewFileHighWater(path); !errors.Is(err, ErrHighWaterCorrupt) {
				t.Fatalf("NewFileHighWater = %v, want an error wrapping ErrHighWaterCorrupt", err)
			}
			got, err := os.ReadFile(path)
			if err != nil {
				t.Fatalf("read back = %v", err)
			}
			if string(got) != body {
				t.Fatalf("corrupt file rewritten to %q, want the bytes untouched", got)
			}
		})
	}
}

func TestHighWaterFileUnreadableFailsClosed(t *testing.T) {
	// A directory where the file should be is unreadable, not missing: the
	// store must fail closed instead of starting at serial zero.
	if _, err := NewFileHighWater(t.TempDir()); !errors.Is(err, ErrHighWaterCorrupt) {
		t.Fatalf("NewFileHighWater(dir) = %v, want an error wrapping ErrHighWaterCorrupt", err)
	}
}

func TestHighWaterFileConcurrentAdvance(t *testing.T) {
	path := filepath.Join(t.TempDir(), "highwater.json")
	store, err := NewFileHighWater(path)
	if err != nil {
		t.Fatalf("NewFileHighWater = %v", err)
	}
	var wg sync.WaitGroup
	for serial := int64(1); serial <= 20; serial++ {
		wg.Add(1)
		go func(s int64) {
			defer wg.Done()
			_ = store.Advance(s)
		}(serial)
	}
	wg.Wait()
	if got := store.Current(); got != 20 {
		t.Fatalf("Current() = %d, want 20", got)
	}
	reloaded, err := NewFileHighWater(path)
	if err != nil {
		t.Fatalf("reload = %v", err)
	}
	if got := reloaded.Current(); got != 20 {
		t.Fatalf("reloaded Current() = %d, want 20", got)
	}
}
