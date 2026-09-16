package platform

import (
	"crypto/hkdf"
	"crypto/sha256"
	"encoding/hex"
	"path/filepath"
	"testing"
)

// TestSecretStoreDerivationFrozen pins the byte-level derivation existing
// ciphertext depends on: the canonical service/key serialization, the SHA-256
// file-name digest, the file naming layout, and the HKDF-SHA256 entry-key
// vector (hash, nil salt, info = credentialAAD, 32-byte output). Any change to
// these inputs makes previously written secrets undecryptable, so this test
// must be updated only with an explicit data migration.
func TestSecretStoreDerivationFrozen(t *testing.T) {
	t.Parallel()

	const (
		frozenAAD    = "tokenhush/audit\x00hmac-key"
		frozenDigest = "52728b5843701f0013fd3153eb3497c7d0a11974d0c06582569a1b2333aa622c"
		frozenKey    = "557d2338c7ca32a866e52602c2a55c9ccdcac27205b2683d657130ef798ac195"
		frozenDir    = "/frozen/secrets"
	)

	t.Run("credential_aad_serialization", func(t *testing.T) {
		if got := credentialAAD("tokenhush/audit", "hmac-key"); got != frozenAAD {
			t.Fatalf("credentialAAD() = %q, want frozen %q", got, frozenAAD)
		}
	})

	t.Run("file_name_digest_and_layout", func(t *testing.T) {
		sum := sha256.Sum256([]byte(frozenAAD))
		if got := hex.EncodeToString(sum[:]); got != frozenDigest {
			t.Fatalf("sha256(credentialAAD) = %s, want frozen %s", got, frozenDigest)
		}
		if secretsDirName != "secrets" || secretFileExt != ".secret" {
			t.Fatalf("file layout changed: dir=%q ext=%q", secretsDirName, secretFileExt)
		}
		store := &fileStore{dir: frozenDir}
		want := filepath.Join(frozenDir, frozenDigest+secretFileExt)
		if got := store.pathFor("tokenhush/audit", "hmac-key"); got != want {
			t.Fatalf("pathFor() = %q, want frozen %q", got, want)
		}
	})

	t.Run("hkdf_entry_key_vector", func(t *testing.T) {
		key, err := hkdf.Key(sha256.New, []byte("frozen-machine-secret"), nil, frozenAAD, aes256KeyLen)
		if err != nil {
			t.Fatalf("hkdf.Key() error = %v", err)
		}
		if got := hex.EncodeToString(key); got != frozenKey {
			t.Fatalf("hkdf.Key() = %s, want frozen %s", got, frozenKey)
		}
		if aes256KeyLen != 32 {
			t.Fatalf("aes256KeyLen = %d, want the frozen 32 bytes", aes256KeyLen)
		}
	})
}
