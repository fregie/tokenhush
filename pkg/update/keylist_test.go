package update

import (
	"errors"
	"testing"
	"time"
)

// TestKeyRotationOverlapVerifiesWithBothKeys 断言轮换重叠期内新旧 key_id 均可验。
func TestKeyRotationOverlapVerifiesWithBothKeys(t *testing.T) {
	root := newTestKey("root-1", 90)
	oldKey := newTestKey("upd-old", 1)
	newKey := newTestKey("upd-new", 2)
	v := newVerifier(t, root)
	applyKeyList(t, v, root, KeyList{
		Serial:    1,
		NotBefore: validFrom(),
		Expires:   validUntil(),
		Keys:      []UpdateKey{oldKey.updateKey(), newKey.updateKey()},
	})

	mustVerifyManifest(t, v, oldKey.signManifest(t, baseManifest()))
	second := baseManifest()
	second.Serial = 11
	mustVerifyManifest(t, v, newKey.signManifest(t, second))
}

// TestKeyListRejectsUntrustedRootSignature 断言非内嵌根签名的 key-list 被拒，
// 防止攻击者用自签密钥集替换信任根。
func TestKeyListRejectsUntrustedRootSignature(t *testing.T) {
	trusted := newTestKey("root-1", 90)
	attacker := newTestKey("root-evil", 91)
	upd := newTestKey("upd-1", 1)
	v := newVerifier(t, trusted)

	kl := attacker.signKeyList(t, KeyList{
		Serial:    1,
		NotBefore: validFrom(),
		Expires:   validUntil(),
		Keys:      []UpdateKey{upd.updateKey()},
	})
	if err := v.ApplyKeyList(marshalDoc(t, kl)); !errors.Is(err, ErrUnknownKey) && !errors.Is(err, ErrBadSignature) {
		t.Fatalf("error = %v, want key rejection", err)
	}
}

// TestLeakRecoveryRejectsManifestsFromRemovedKey 断言泄露恢复后，旧（已移除）
// 更新密钥签名的 manifest 被拒，而新密钥可用。
func TestLeakRecoveryRejectsManifestsFromRemovedKey(t *testing.T) {
	root := newTestKey("root-1", 90)
	leaked := newTestKey("upd-leaked", 1)
	fresh := newTestKey("upd-fresh", 2)
	v := newVerifier(t, root)
	applyKeyList(t, v, root, KeyList{
		Serial:    1,
		NotBefore: validFrom(),
		Expires:   validUntil(),
		Keys:      []UpdateKey{leaked.updateKey(), fresh.updateKey()},
	})

	// Recovery: the root publishes a new key list that drops the leaked key.
	applyKeyList(t, v, root, KeyList{
		Serial:    2,
		NotBefore: validFrom(),
		Expires:   validUntil(),
		Keys:      []UpdateKey{fresh.updateKey()},
	})

	if _, err := v.VerifyManifest(marshalDoc(t, leaked.signManifest(t, baseManifest()))); !errors.Is(err, ErrUnknownKey) {
		t.Fatalf("leaked-key manifest error = %v, want ErrUnknownKey", err)
	}
	second := baseManifest()
	second.Serial = 11
	mustVerifyManifest(t, v, fresh.signManifest(t, second))
}

// TestKeyListRollbackRejected 断言旧 key-list 不能被重放以复活已撤销的密钥
// （否则泄露恢复可被回滚）。
func TestKeyListRollbackRejected(t *testing.T) {
	root := newTestKey("root-1", 90)
	leaked := newTestKey("upd-leaked", 1)
	fresh := newTestKey("upd-fresh", 2)
	v := newVerifier(t, root)

	withLeaked := KeyList{
		Serial:    1,
		NotBefore: validFrom(),
		Expires:   validUntil(),
		Keys:      []UpdateKey{leaked.updateKey(), fresh.updateKey()},
	}
	applyKeyList(t, v, root, withLeaked)
	applyKeyList(t, v, root, KeyList{
		Serial:    2,
		NotBefore: validFrom(),
		Expires:   validUntil(),
		Keys:      []UpdateKey{fresh.updateKey()},
	})

	if err := v.ApplyKeyList(marshalDoc(t, root.signKeyList(t, withLeaked))); !errors.Is(err, ErrReplayed) {
		t.Fatalf("replayed key list error = %v, want ErrReplayed", err)
	}
}

// TestKeyListRejectsExpiredUpdateKey 断言超出密钥自身有效窗口的更新密钥不再
// 被接受（重叠期结束后旧密钥自然失效）。
func TestKeyListRejectsExpiredUpdateKey(t *testing.T) {
	root := newTestKey("root-1", 90)
	expired := newTestKey("upd-old", 1)
	v := newVerifier(t, root)
	entry := expired.updateKey()
	entry.Expires = fixedNow.Add(-time.Minute)
	applyKeyList(t, v, root, KeyList{
		Serial:    1,
		NotBefore: validFrom(),
		Expires:   validUntil(),
		Keys:      []UpdateKey{entry},
	})

	if _, err := v.VerifyManifest(marshalDoc(t, expired.signManifest(t, baseManifest()))); !errors.Is(err, ErrKeyNotValid) {
		t.Fatalf("error = %v, want ErrKeyNotValid", err)
	}
}

// TestRootRotationAcceptsNewlyEmbeddedRoot 断言内嵌根集合可容纳多把根密钥，
// 使根密钥轮换期间新旧根签发的 key-list 都可验。
func TestRootRotationAcceptsNewlyEmbeddedRoot(t *testing.T) {
	oldRoot := newTestKey("root-old", 90)
	newRoot := newTestKey("root-new", 91)
	upd := newTestKey("upd-1", 1)
	v := newVerifier(t, oldRoot, newRoot)

	newList := KeyList{
		Serial:    9,
		NotBefore: validFrom(),
		Expires:   validUntil(),
		Keys:      []UpdateKey{upd.updateKey()},
	}
	if err := v.ApplyKeyList(marshalDoc(t, newRoot.signKeyList(t, newList))); err != nil {
		t.Fatalf("new-root key list rejected: %v", err)
	}
	mustVerifyManifest(t, v, upd.signManifest(t, baseManifest()))
}
