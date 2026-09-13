package update

import (
	"strings"
	"testing"
	"time"
)

// TestStatusExpiredIsVisible 断言清单过期且无法刷新时状态显式标记"更新已过
// 期"并带告警——绝不静默。
func TestStatusExpiredIsVisible(t *testing.T) {
	root := newTestKey("root-1", 90)
	upd := newTestKey("upd-1", 1)
	v := newVerifier(t, root)
	v.CurrentVersion = "0.3.0"
	installKeyList(t, v, root, upd)

	expired := baseManifest()
	expired.Expires = fixedNow.Add(-time.Hour)

	status := v.Status(&expired)
	if !status.Expired {
		t.Fatal("expired metadata must set Status.Expired")
	}
	if len(status.Warnings) == 0 {
		t.Fatal("expired metadata must emit a warning, never stay silent")
	}
	if !strings.Contains(status.Warnings[0], ExpiredMarker) {
		t.Fatalf("warning %q must carry the %q marker", status.Warnings[0], ExpiredMarker)
	}
	if status.LatestVersion != expired.Version {
		t.Fatalf("LatestVersion = %q, want %q", status.LatestVersion, expired.Version)
	}
}

// TestStatusFreshUpToDate 断言新鲜清单且版本相同时无告警、标记已最新。
func TestStatusFreshUpToDate(t *testing.T) {
	v := newVerifier(t, newTestKey("root-1", 90))
	v.CurrentVersion = "0.4.0"
	m := baseManifest()

	status := v.Status(&m)
	if status.Expired {
		t.Fatal("fresh metadata must not be marked expired")
	}
	if !status.UpToDate {
		t.Fatal("current == latest must be up to date")
	}
	if len(status.Warnings) != 0 {
		t.Fatalf("fresh metadata must not warn, got %v", status.Warnings)
	}
}

// TestStatusFreshUpdateAvailable 断言有新版本时 UpToDate 为 false。
func TestStatusFreshUpdateAvailable(t *testing.T) {
	v := newVerifier(t, newTestKey("root-1", 90))
	v.CurrentVersion = "0.3.0"
	m := baseManifest()

	status := v.Status(&m)
	if status.UpToDate {
		t.Fatal("0.3.0 with latest 0.4.0 must report an available update")
	}
}

// TestStatusNoMetadataIsSafe 断言无已见清单时不 panic 且不误报过期。
func TestStatusNoMetadataIsSafe(t *testing.T) {
	v := newVerifier(t, newTestKey("root-1", 90))
	v.CurrentVersion = "0.3.0"
	status := v.Status(nil)
	if status.Expired {
		t.Fatal("absent metadata must not be marked expired")
	}
	if status.CurrentVersion != "0.3.0" {
		t.Fatalf("CurrentVersion = %q, want 0.3.0", status.CurrentVersion)
	}
}

// TestStatusFreshHasNoWarning 断言未过期清单不会误报告警。
func TestStatusFreshHasNoWarning(t *testing.T) {
	v := newVerifier(t, newTestKey("root-1", 90))
	v.CurrentVersion = "0.3.0"
	fresh := baseManifest()
	status := v.Status(&fresh)
	if status.Expired || len(status.Warnings) != 0 {
		t.Fatalf("fresh metadata must not report expiry: %+v", status)
	}
}
