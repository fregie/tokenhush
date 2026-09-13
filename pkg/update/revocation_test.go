package update

import (
	"errors"
	"testing"
	"time"
)

// TestVerifyRevocationsIsIndependentSignedDocument 断言撤销清单是独立、可自
// 验证的签名文档：验签 + 新鲜度通过后可独立取得，不依赖任何 manifest。
func TestVerifyRevocationsIsIndependentSignedDocument(t *testing.T) {
	root := newTestKey("root-1", 90)
	upd := newTestKey("upd-1", 1)
	v := newVerifier(t, root)
	installKeyList(t, v, root, upd)

	rev := upd.signRevocations(t, RevocationList{
		Channel:         "stable",
		Serial:          5,
		NotBefore:       validFrom(),
		Expires:         validUntil(),
		RevokedSerials:  []uint64{10},
		RevokedVersions: []string{"0.4.0"},
	})
	got, err := v.VerifyRevocations(marshalDoc(t, rev))
	if err != nil {
		t.Fatalf("VerifyRevocations: %v", err)
	}
	if !got.IsRevoked("0.4.0", 0) {
		t.Fatal("verified revocation list must report the revoked version")
	}
}

// TestVerifyRevocationsRejectsExpired 断言过期撤销文档被拒（撤销信息也有保质期）。
func TestVerifyRevocationsRejectsExpired(t *testing.T) {
	root := newTestKey("root-1", 90)
	upd := newTestKey("upd-1", 1)
	v := newVerifier(t, root)
	installKeyList(t, v, root, upd)

	rev := upd.signRevocations(t, RevocationList{
		Channel:   "stable",
		Serial:    5,
		NotBefore: validFrom(),
		Expires:   fixedNow.Add(-time.Minute),
	})
	if _, err := v.VerifyRevocations(marshalDoc(t, rev)); !errors.Is(err, ErrExpired) {
		t.Fatalf("error = %v, want ErrExpired", err)
	}
}

// TestVerifyRevocationsRejectsReplay 断言撤销文档 serial 亦受高水位保护，
// 防止用旧撤销列表"遗忘"某次撤销。
func TestVerifyRevocationsRejectsReplay(t *testing.T) {
	root := newTestKey("root-1", 90)
	upd := newTestKey("upd-1", 1)
	v := newVerifier(t, root)
	installKeyList(t, v, root, upd)

	fresh := RevocationList{Channel: "stable", Serial: 5, NotBefore: validFrom(), Expires: validUntil(), RevokedVersions: []string{"0.4.0"}}
	if _, err := v.VerifyRevocations(marshalDoc(t, upd.signRevocations(t, fresh))); err != nil {
		t.Fatalf("fresh revocations: %v", err)
	}

	stale := fresh
	stale.Serial = 4
	if _, err := v.VerifyRevocations(marshalDoc(t, upd.signRevocations(t, stale))); !errors.Is(err, ErrReplayed) {
		t.Fatalf("error = %v, want ErrReplayed", err)
	}
}

// TestVerifyRevocationsRejectsBadSignature 断言篡改的撤销文档验签失败。
func TestVerifyRevocationsRejectsBadSignature(t *testing.T) {
	root := newTestKey("root-1", 90)
	upd := newTestKey("upd-1", 1)
	v := newVerifier(t, root)
	installKeyList(t, v, root, upd)

	rev := upd.signRevocations(t, RevocationList{Channel: "stable", Serial: 5, NotBefore: validFrom(), Expires: validUntil()})
	rev.RevokedVersions = []string{"0.5.0"}
	if _, err := v.VerifyRevocations(marshalDoc(t, rev)); !errors.Is(err, ErrBadSignature) {
		t.Fatalf("error = %v, want ErrBadSignature", err)
	}
}
