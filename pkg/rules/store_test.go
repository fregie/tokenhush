package rules

import (
	"errors"
	"path/filepath"
	"testing"
)

func TestFileCacheRoundTrip(t *testing.T) {
	root := t.TempDir()
	c, err := OpenFileCache(root)
	if err != nil {
		t.Fatalf("OpenFileCache: %v", err)
	}
	if _, _, err := c.Load(7); !errors.Is(err, ErrCacheMiss) {
		t.Fatalf("Load(missing) error = %v, want ErrCacheMiss", err)
	}
	if err := c.Save(7, []byte(`{"m":7}`), []byte(`{"b":7}`)); err != nil {
		t.Fatalf("Save: %v", err)
	}
	if err := c.Save(9, []byte(`{"m":9}`), []byte(`{"b":9}`)); err != nil {
		t.Fatalf("Save: %v", err)
	}
	m, b, err := c.Load(7)
	if err != nil || string(m) != `{"m":7}` || string(b) != `{"b":7}` {
		t.Fatalf("Load(7) = %q,%q,%v", m, b, err)
	}
	serials, err := c.Serials()
	if err != nil {
		t.Fatalf("Serials: %v", err)
	}
	if len(serials) != 2 || serials[0] != 7 || serials[1] != 9 {
		t.Fatalf("Serials = %v, want [7 9]", serials)
	}
	if err := c.Remove(7); err != nil {
		t.Fatalf("Remove: %v", err)
	}
	if _, _, err := c.Load(7); !errors.Is(err, ErrCacheMiss) {
		t.Fatalf("Load after Remove error = %v, want ErrCacheMiss", err)
	}
	if err := c.Remove(7); err != nil {
		t.Fatalf("Remove(missing) error = %v, want nil", err)
	}
}

func TestFileCacheActiveAndRevoked(t *testing.T) {
	c, err := OpenFileCache(t.TempDir())
	if err != nil {
		t.Fatalf("OpenFileCache: %v", err)
	}
	if _, ok, err := c.Active(); err != nil || ok {
		t.Fatalf("Active() = %v,%v, want false,nil", ok, err)
	}
	if err := c.SetActive(7); err != nil {
		t.Fatalf("SetActive: %v", err)
	}
	if active, ok, err := c.Active(); err != nil || !ok || active != 7 {
		t.Fatalf("Active() = %d,%v,%v, want 7,true,nil", active, ok, err)
	}
	if err := c.SetActive(0); err != nil {
		t.Fatalf("SetActive(0): %v", err)
	}
	if _, ok, err := c.Active(); err != nil || ok {
		t.Fatalf("Active() after clear = %v,%v, want false,nil", ok, err)
	}

	if err := c.SetRevoked(RevokedList{Serials: []uint64{9, 3, 3, 7}}); err != nil {
		t.Fatalf("SetRevoked: %v", err)
	}
	rev, err := c.Revoked()
	if err != nil {
		t.Fatalf("Revoked: %v", err)
	}
	if len(rev.Serials) != 3 || rev.Serials[0] != 3 || rev.Serials[2] != 9 {
		t.Fatalf("Revoked.Serials = %v, want sorted unique [3 7 9]", rev.Serials)
	}
	if !rev.Revokes(7) || rev.Revokes(5) {
		t.Fatalf("Revokes wrong: %v", rev.Serials)
	}
}

func TestFileHighWaterPersists(t *testing.T) {
	path := filepath.Join(t.TempDir(), "highwater.json")
	h, err := OpenFileHighWater(path)
	if err != nil {
		t.Fatalf("OpenFileHighWater: %v", err)
	}
	if _, ok, err := h.Highest(KindRules); err != nil || ok {
		t.Fatalf("Highest() = %v,%v, want false,nil", ok, err)
	}
	if err := h.Advance(KindRules, 7); err != nil {
		t.Fatalf("Advance(7): %v", err)
	}
	if err := h.Advance(KindRules, 7); !errors.Is(err, ErrPackReplayed) {
		t.Fatalf("Advance(7) again error = %v, want ErrPackReplayed", err)
	}
	if err := h.Advance(KindRules, 5); !errors.Is(err, ErrPackReplayed) {
		t.Fatalf("Advance(5) error = %v, want ErrPackReplayed", err)
	}

	reopened, err := OpenFileHighWater(path)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	if highest, ok, _ := reopened.Highest(KindRules); !ok || highest != 7 {
		t.Fatalf("reopened high-water = %d,%v, want 7,true", highest, ok)
	}
	if err := reopened.Advance(KindRules, 9); err != nil {
		t.Fatalf("Advance(9): %v", err)
	}
}
