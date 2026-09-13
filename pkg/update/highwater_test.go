package update

import (
	"errors"
	"path/filepath"
	"testing"
)

// TestMemHighWaterMonotonic 断言内存高水位只增不减并拒绝回退。
func TestMemHighWaterMonotonic(t *testing.T) {
	hw := NewMemHighWater()
	if _, ok, _ := hw.Highest(KindManifest); ok {
		t.Fatal("fresh store must report no serial")
	}
	if err := hw.Advance(KindManifest, 10); err != nil {
		t.Fatalf("Advance(10): %v", err)
	}
	if err := hw.Advance(KindManifest, 9); !errors.Is(err, ErrReplayed) {
		t.Fatalf("Advance(9) error = %v, want ErrReplayed", err)
	}
	got, ok, err := hw.Highest(KindManifest)
	if err != nil || !ok || got != 10 {
		t.Fatalf("Highest = (%d, %v, %v), want (10, true, nil)", got, ok, err)
	}
}

// TestFileHighWaterPersistsAcrossReopen 断言高水位跨进程持久化（重开文件后
// 仍拒绝回放），这是防重放跨会话生效的关键。
func TestFileHighWaterPersistsAcrossReopen(t *testing.T) {
	path := filepath.Join(t.TempDir(), "update-highwater.json")

	first, err := OpenFileHighWater(path)
	if err != nil {
		t.Fatalf("OpenFileHighWater: %v", err)
	}
	if err := first.Advance(KindManifest, 42); err != nil {
		t.Fatalf("Advance: %v", err)
	}

	reopened, err := OpenFileHighWater(path)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	got, ok, err := reopened.Highest(KindManifest)
	if err != nil || !ok || got != 42 {
		t.Fatalf("reopened Highest = (%d, %v, %v), want (42, true, nil)", got, ok, err)
	}
	if err := reopened.Advance(KindManifest, 41); !errors.Is(err, ErrReplayed) {
		t.Fatalf("reopen rollback error = %v, want ErrReplayed", err)
	}
}

// TestFileHighWaterKindsAreIndependent 断言不同文档类别各自维护高水位。
func TestFileHighWaterKindsAreIndependent(t *testing.T) {
	path := filepath.Join(t.TempDir(), "update-highwater.json")
	hw, err := OpenFileHighWater(path)
	if err != nil {
		t.Fatalf("OpenFileHighWater: %v", err)
	}
	if err := hw.Advance(KindManifest, 5); err != nil {
		t.Fatalf("Advance manifest: %v", err)
	}
	if err := hw.Advance(KindRevocations, 2); err != nil {
		t.Fatalf("Advance revocations: %v", err)
	}
	if got, _, _ := hw.Highest(KindRevocations); got != 2 {
		t.Fatalf("revocations high-water = %d, want 2", got)
	}
}
