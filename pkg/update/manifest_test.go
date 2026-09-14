package update

import (
	"errors"
	"strings"
	"testing"
	"time"
)

// TestManifestSigningInputIgnoresRevokedOrder 断言签名输入对撤销列表排序，
// 使签发与校验双方无需 JSON 规范化即可一致。
func TestManifestSigningInputIgnoresRevokedOrder(t *testing.T) {
	a := baseManifest()
	a.RevokedSerials = []uint64{3, 1, 2}
	a.RevokedVersions = []string{"0.2.0", "0.1.0"}
	b := baseManifest()
	b.RevokedSerials = []uint64{1, 2, 3}
	b.RevokedVersions = []string{"0.1.0", "0.2.0"}
	if string(ManifestSigningInput(a)) != string(ManifestSigningInput(b)) {
		t.Fatalf("signing input must be order-independent:\n%q\n%q",
			ManifestSigningInput(a), ManifestSigningInput(b))
	}
}

// TestManifestFreshness 覆盖有效窗口三态。
func TestManifestFreshness(t *testing.T) {
	m := baseManifest()
	if got := m.Freshness(fixedNow); got != Fresh {
		t.Errorf("within window Freshness = %v, want Fresh", got)
	}
	if got := m.Freshness(m.Expires.Add(time.Second)); got != Expired {
		t.Errorf("past expires Freshness = %v, want Expired", got)
	}
	if got := m.Freshness(m.NotBefore.Add(-time.Second)); got != NotYetValid {
		t.Errorf("before not_before Freshness = %v, want NotYetValid", got)
	}
}

// TestManifestFieldValidation 断言字段校验在验签前拒绝畸形/危险输入。每个
// manifest 都由合法密钥签名，因此拒绝只能来自字段规则本身。
func TestManifestFieldValidation(t *testing.T) {
	key := newTestKey("upd-1", 1)
	base := func() Manifest { return baseManifest() }
	tests := []struct {
		name string
		bad  func(m *Manifest)
	}{
		{"missing version", func(m *Manifest) { m.Version = "" }},
		{"non-numeric version", func(m *Manifest) { m.Version = "banana" }},
		{"missing os", func(m *Manifest) { m.OS = "" }},
		{"missing arch", func(m *Manifest) { m.Arch = "" }},
		{"missing url", func(m *Manifest) { m.URL = "" }},
		{"non-https url", func(m *Manifest) { m.URL = "http://dl.tokenhush.com/x" }},
		{"bad sha256 length", func(m *Manifest) { m.SHA256 = "abcd" }},
		{"non-hex sha256", func(m *Manifest) { m.SHA256 = strings.Repeat("zz", 32) }},
		{"missing channel", func(m *Manifest) { m.Channel = "" }},
		{"missing not_before", func(m *Manifest) { m.NotBefore = time.Time{} }},
		{"missing expires", func(m *Manifest) { m.Expires = time.Time{} }},
		{"expires before not_before", func(m *Manifest) { m.Expires = m.NotBefore.Add(-time.Minute) }},
		{"self-revoked serial", func(m *Manifest) { m.RevokedSerials = []uint64{m.Serial} }},
		{"self-revoked version", func(m *Manifest) { m.RevokedVersions = []string{m.Version} }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := base()
			tt.bad(&m)
			signed := key.signManifest(t, m)
			v := newVerifier(t, newTestKey("root-1", 90))
			applyKeyList(t, v, newTestKey("root-1", 90), KeyList{Serial: 1, NotBefore: validFrom(), Expires: validUntil(), Keys: []UpdateKey{key.updateKey()}})
			if _, err := v.VerifyManifest(marshalDoc(t, signed)); !errors.Is(err, ErrMalformed) {
				t.Fatalf("VerifyManifest error = %v, want ErrMalformed", err)
			}
		})
	}
}

// TestRevocationListIsRevoked 断言独立撤销文档按版本与 serial 命中。
func TestRevocationListIsRevoked(t *testing.T) {
	r := RevocationList{
		Channel:         "stable",
		Serial:          5,
		RevokedSerials:  []uint64{4},
		RevokedVersions: []string{"0.3.9"},
	}
	if !r.IsRevoked("0.3.9", 99) {
		t.Error("revoked version must be reported")
	}
	if !r.IsRevoked("9.9.9", 4) {
		t.Error("revoked serial must be reported")
	}
	if r.IsRevoked("0.4.0", 10) {
		t.Error("unlisted version/serial must not be reported")
	}
}

// TestRevocationSigningInputIgnoresOrder 断言撤销文档签名输入同样排序。
func TestRevocationSigningInputIgnoresOrder(t *testing.T) {
	a := RevocationList{Channel: "stable", Serial: 5, RevokedSerials: []uint64{2, 1}, RevokedVersions: []string{"b", "a"}}
	b := RevocationList{Channel: "stable", Serial: 5, RevokedSerials: []uint64{1, 2}, RevokedVersions: []string{"a", "b"}}
	if string(RevocationSigningInput(a)) != string(RevocationSigningInput(b)) {
		t.Fatal("revocation signing input must be order-independent")
	}
}

// TestCompareVersions 断言降级比较是纯数值语义（major.minor.patch）。
func TestCompareVersions(t *testing.T) {
	tests := []struct {
		a, b string
		want int
	}{
		{"0.4.0", "0.3.0", 1},
		{"0.3.0", "0.4.0", -1},
		{"0.3.0", "0.3.0", 0},
		{"1.0.0", "0.9.9", 1},
		{"0.3.10", "0.3.9", 1},
		{"0.4.0-rc1", "0.4.0", 0},
		{"0.0.0-dev", "0.0.0", 0},
		{"0.4.0+build.7", "0.4.0", 0},
		{"0.4.0-rc1", "0.3.0", 1},
	}
	for _, tt := range tests {
		got, err := CompareVersions(tt.a, tt.b)
		if err != nil {
			t.Fatalf("CompareVersions(%q,%q): %v", tt.a, tt.b, err)
		}
		if got != tt.want {
			t.Errorf("CompareVersions(%q,%q) = %d, want %d", tt.a, tt.b, got, tt.want)
		}
	}
	if _, err := CompareVersions("banana", "0.3.0"); !errors.Is(err, ErrMalformed) {
		t.Fatalf("non-numeric version error = %v, want ErrMalformed", err)
	}
}
