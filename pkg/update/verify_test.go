package update

import (
	"errors"
	"testing"
	"time"
)

// installKeyList is the common setup: one root, one update key in the list.
func installKeyList(t *testing.T, v *Verifier, root, upd testKey) {
	t.Helper()
	applyKeyList(t, v, root, KeyList{
		Serial:    1,
		NotBefore: validFrom(),
		Expires:   validUntil(),
		Keys:      []UpdateKey{upd.updateKey()},
	})
}

// TestVerifyManifestAcceptsValidSignedManifest 是 happy path：验签 + 新鲜度 +
// 高水位全部通过，并返回解码后的清单。
func TestVerifyManifestAcceptsValidSignedManifest(t *testing.T) {
	root := newTestKey("root-1", 90)
	upd := newTestKey("upd-1", 1)
	v := newVerifier(t, root)
	installKeyList(t, v, root, upd)

	got := mustVerifyManifest(t, v, upd.signManifest(t, baseManifest()))
	if got.Version != "0.4.0" || got.Serial != 10 {
		t.Fatalf("decoded manifest = %+v, want version 0.4.0 serial 10", got)
	}
}

// TestVerifyManifestRejectsExpired 断言过期清单被拒（绝不静默接受）。
func TestVerifyManifestRejectsExpired(t *testing.T) {
	root := newTestKey("root-1", 90)
	upd := newTestKey("upd-1", 1)
	v := newVerifier(t, root)
	installKeyList(t, v, root, upd)

	m := baseManifest()
	m.Expires = fixedNow.Add(-time.Minute)
	if _, err := v.VerifyManifest(marshalDoc(t, upd.signManifest(t, m))); !errors.Is(err, ErrExpired) {
		t.Fatalf("error = %v, want ErrExpired", err)
	}
}

// TestVerifyManifestRejectsNotYetValid 断言 not_before 之前拒绝。
func TestVerifyManifestRejectsNotYetValid(t *testing.T) {
	root := newTestKey("root-1", 90)
	upd := newTestKey("upd-1", 1)
	v := newVerifier(t, root)
	installKeyList(t, v, root, upd)

	m := baseManifest()
	m.NotBefore = fixedNow.Add(time.Minute)
	if _, err := v.VerifyManifest(marshalDoc(t, upd.signManifest(t, m))); !errors.Is(err, ErrNotYetValid) {
		t.Fatalf("error = %v, want ErrNotYetValid", err)
	}
}

// TestVerifyManifestRejectsTamperedManifest 断言签名后改字段即验签失败。
func TestVerifyManifestRejectsTamperedManifest(t *testing.T) {
	root := newTestKey("root-1", 90)
	upd := newTestKey("upd-1", 1)
	v := newVerifier(t, root)
	installKeyList(t, v, root, upd)

	tampered := upd.signManifest(t, baseManifest())
	tampered.Version = "0.5.0"
	if _, err := v.VerifyManifest(marshalDoc(t, tampered)); !errors.Is(err, ErrBadSignature) {
		t.Fatalf("error = %v, want ErrBadSignature", err)
	}
}

// TestVerifyManifestRejectsLicenseSignedManifest asserts the update channel
// trusts only key-list-installed update keys: a manifest signed by a key with a
// license-style id is unknown and refused. The two trust chains never converge.
func TestVerifyManifestRejectsLicenseSignedManifest(t *testing.T) {
	root := newTestKey("root-1", 90)
	upd := newTestKey("upd-1", 1)
	license := newTestKey("license-2026a", 42)
	v := newVerifier(t, root)
	installKeyList(t, v, root, upd)

	if _, err := v.VerifyManifest(marshalDoc(t, license.signManifest(t, baseManifest()))); !errors.Is(err, ErrUnknownKey) {
		t.Fatalf("error = %v, want ErrUnknownKey for a license-signed update manifest", err)
	}
}

// TestVerifyManifestRejectsPlainHTTPURL asserts a signed document cannot point
// the artifact download at an unauthenticated origin.
func TestVerifyManifestRejectsPlainHTTPURL(t *testing.T) {
	root := newTestKey("root-1", 90)
	upd := newTestKey("upd-1", 1)
	v := newVerifier(t, root)
	installKeyList(t, v, root, upd)

	m := baseManifest()
	m.URL = "http://dl.tokenhush.com/v0.4.0/tokenhush-linux-amd64"
	if _, err := v.VerifyManifest(marshalDoc(t, upd.signManifest(t, m))); !errors.Is(err, ErrMalformed) {
		t.Fatalf("error = %v, want ErrMalformed for a plain-http artifact URL", err)
	}
}

// TestVerifyManifestRejectsUnknownKey 断言 key_id 不在已接受密钥集时拒绝。
func TestVerifyManifestRejectsUnknownKey(t *testing.T) {
	root := newTestKey("root-1", 90)
	upd := newTestKey("upd-1", 1)
	rogue := newTestKey("upd-rogue", 7)
	v := newVerifier(t, root)
	installKeyList(t, v, root, upd)

	if _, err := v.VerifyManifest(marshalDoc(t, rogue.signManifest(t, baseManifest()))); !errors.Is(err, ErrUnknownKey) {
		t.Fatalf("error = %v, want ErrUnknownKey", err)
	}
}

// TestVerifyManifestRejectsReplayAtOrBelowHighWater 断言 serial ≤ 已见高水位
// 被拒，防重放/回滚。
func TestVerifyManifestRejectsReplayAtOrBelowHighWater(t *testing.T) {
	root := newTestKey("root-1", 90)
	upd := newTestKey("upd-1", 1)
	v := newVerifier(t, root)
	installKeyList(t, v, root, upd)
	mustVerifyManifest(t, v, upd.signManifest(t, baseManifest())) // serial 10

	for _, serial := range []uint64{10, 9, 1} {
		m := baseManifest()
		m.Serial = serial
		m.Version = "0.5.0"
		if _, err := v.VerifyManifest(marshalDoc(t, upd.signManifest(t, m))); !errors.Is(err, ErrReplayed) {
			t.Fatalf("serial %d error = %v, want ErrReplayed", serial, err)
		}
	}
}

// TestRejectedManifestDoesNotAdvanceHighWater 断言被拒清单不会推进高水位，
// 否则一次伪造尝试即可冻结后续合法清单。
func TestRejectedManifestDoesNotAdvanceHighWater(t *testing.T) {
	root := newTestKey("root-1", 90)
	upd := newTestKey("upd-1", 1)
	v := newVerifier(t, root)
	installKeyList(t, v, root, upd)
	mustVerifyManifest(t, v, upd.signManifest(t, baseManifest())) // serial 10

	m := baseManifest()
	m.Serial = 9
	if _, err := v.VerifyManifest(marshalDoc(t, upd.signManifest(t, m))); !errors.Is(err, ErrReplayed) {
		t.Fatalf("error = %v, want ErrReplayed", err)
	}
	highest, ok, err := v.HighWater.Highest(KindManifest)
	if err != nil || !ok || highest != 10 {
		t.Fatalf("high-water = (%d, %v, %v), want (10, true, nil)", highest, ok, err)
	}
}

// TestVerifyManifestRejectsDowngrade 断言低于当前版本的清单在默认情况下被拒。
func TestVerifyManifestRejectsDowngrade(t *testing.T) {
	root := newTestKey("root-1", 90)
	upd := newTestKey("upd-1", 1)
	v := newVerifier(t, root)
	v.CurrentVersion = "1.0.0"
	installKeyList(t, v, root, upd)

	if _, err := v.VerifyManifest(marshalDoc(t, upd.signManifest(t, baseManifest()))); !errors.Is(err, ErrDowngrade) {
		t.Fatalf("error = %v, want ErrDowngrade", err)
	}
	if _, ok, _ := v.HighWater.Highest(KindManifest); ok {
		t.Fatal("rejected downgrade must not advance the high-water mark")
	}
}

// TestAllowDowngradeOverrideAudits 断言开发态降级放行时必须留下审计事件。
func TestAllowDowngradeOverrideAudits(t *testing.T) {
	root := newTestKey("root-1", 90)
	upd := newTestKey("upd-1", 1)
	v := newVerifier(t, root)
	v.CurrentVersion = "1.0.0"
	v.AllowDowngrade = true
	var events []DowngradeEvent
	v.Audit = func(e DowngradeEvent) { events = append(events, e) }
	installKeyList(t, v, root, upd)

	mustVerifyManifest(t, v, upd.signManifest(t, baseManifest()))
	if len(events) != 1 {
		t.Fatalf("audit events = %d, want 1", len(events))
	}
	if events[0].From != "1.0.0" || events[0].To != "0.4.0" {
		t.Fatalf("audit event = %+v, want From 1.0.0 To 0.4.0", events[0])
	}
}

// TestAllowDowngradeEnabledReadsEnv 断言降级开关只认显式环境变量真值。
func TestAllowDowngradeEnabledReadsEnv(t *testing.T) {
	for _, tc := range []struct {
		val  string
		want bool
	}{
		{"", false}, {"0", false}, {"1", true}, {"true", true}, {"YES", true}, {"on", true}, {"no", false},
	} {
		getenv := func(string) string { return tc.val }
		if got := AllowDowngradeEnabled(getenv); got != tc.want {
			t.Errorf("AllowDowngradeEnabled(%q) = %v, want %v", tc.val, got, tc.want)
		}
	}
}

// TestVerifyManifestRejectsOversizedDocument 断言超限文档在 JSON 解析前被拒，
// 避免内存耗尽。
func TestVerifyManifestRejectsOversizedDocument(t *testing.T) {
	v := newVerifier(t, newTestKey("root-1", 90))
	raw := make([]byte, MaxDocumentSize+1)
	if _, err := v.VerifyManifest(raw); !errors.Is(err, ErrTooLarge) {
		t.Fatalf("error = %v, want ErrTooLarge", err)
	}
}
