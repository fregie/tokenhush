package platform

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

const (
	// secretsDirName is the directory below the platform data dir that holds
	// file-backend entries. DataDir already guarantees it is never CWD or the
	// (possibly read-only) install prefix.
	secretsDirName = "secrets"

	// secretFileExt marks one file-store entry. File names are SHA-256 hashes
	// of the service/key coordinates, so caller-controlled names can never
	// traverse paths and entry names leak no metadata.
	secretFileExt = ".secret"

	// machineIDPath is read when present to bind the derived key to the Linux
	// machine identity; the portable fallback is hostname plus user home.
	machineIDPath = "/etc/machine-id"

	// aes256KeyLen is the AES-256 entry key size in bytes.
	aes256KeyLen = 32
)

// errNoMachineSecret reports that no machine-bound input could be collected. It
// makes the encrypted layer report itself unavailable so the selector can fall
// through to the (honest, warned) plaintext layer instead of inventing a weak
// fixed key.
var errNoMachineSecret = errors.New("platform: no machine-bound secret source available")

// fileStore implements both file layers: AES-256-GCM when machineSecret is set,
// raw 0600 bytes when it is nil (the warned plaintext fallback).
type fileStore struct {
	dir           string
	machineSecret []byte
}

// newPlaintextFileStore opens the last-resort plaintext layer.
func newPlaintextFileStore(dataDir string) (storeBackend, error) {
	return newFileStore(dataDir, nil)
}

// newEncryptedFileStore opens the AES-GCM layer keyed from machineSecret.
func newEncryptedFileStore(dataDir string, machineSecret []byte) (storeBackend, error) {
	if len(machineSecret) == 0 {
		return nil, errNoMachineSecret
	}
	return newFileStore(dataDir, machineSecret)
}

func newFileStore(dataDir string, machineSecret []byte) (storeBackend, error) {
	if strings.TrimSpace(dataDir) == "" {
		return nil, errors.New("platform: data dir is empty")
	}
	dir := filepath.Join(dataDir, secretsDirName)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("platform: create secrets dir: %w", err)
	}
	store := &fileStore{dir: dir, machineSecret: machineSecret}
	if err := store.selfTest(probeService, probeKey); err != nil {
		return nil, err
	}
	return store, nil
}

// selfTest proves this layer can round-trip before the selector commits to it,
// then removes the scratch entry so no probe state is left behind.
func (s *fileStore) selfTest(service, key string) error {
	probe := make([]byte, 16)
	if _, err := rand.Read(probe); err != nil {
		return fmt.Errorf("platform: secret store self-test: %w", err)
	}
	value := hex.EncodeToString(probe)

	if err := s.set(service, key, value); err != nil {
		return fmt.Errorf("platform: secret store self-test: %w", err)
	}
	got, err := s.get(service, key)
	if err != nil || got != value {
		_ = s.delete(service, key)
		return errors.New("platform: secret store self-test round trip failed")
	}
	if err := s.delete(service, key); err != nil {
		return fmt.Errorf("platform: secret store self-test cleanup: %w", err)
	}
	return nil
}

func (s *fileStore) get(service, key string) (string, error) {
	if err := validateCredential(service, key); err != nil {
		return "", err
	}
	data, err := os.ReadFile(s.pathFor(service, key))
	if errors.Is(err, fs.ErrNotExist) {
		return "", ErrNotFound
	}
	if err != nil {
		return "", fmt.Errorf("platform: read secret entry: %w", err)
	}
	return s.decode(service, key, data)
}

func (s *fileStore) set(service, key, value string) error {
	if err := validateCredential(service, key); err != nil {
		return err
	}
	payload, err := s.encode(service, key, value)
	if err != nil {
		return err
	}
	return writeFileAtomic(s.pathFor(service, key), payload)
}

func (s *fileStore) delete(service, key string) error {
	if err := validateCredential(service, key); err != nil {
		return err
	}
	if err := os.Remove(s.pathFor(service, key)); err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return ErrNotFound
		}
		return fmt.Errorf("platform: delete secret entry: %w", err)
	}
	return nil
}

// encode seals value on the encrypted layer. credentialAAD is passed as
// additional authenticated data so an entry cannot be swapped with another
// service/key file.
func (s *fileStore) encode(service, key, value string) ([]byte, error) {
	if s.machineSecret == nil {
		return []byte(value), nil
	}
	aead, err := s.newAEAD(service, key)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("platform: secret nonce: %w", err)
	}
	return aead.Seal(nonce, nonce, []byte(value), []byte(credentialAAD(service, key))), nil
}

func (s *fileStore) decode(service, key string, data []byte) (string, error) {
	if s.machineSecret == nil {
		return string(data), nil
	}
	aead, err := s.newAEAD(service, key)
	if err != nil {
		return "", err
	}
	if len(data) < aead.NonceSize() {
		return "", fmt.Errorf("%w: entry too short", ErrSecretCorrupt)
	}
	plain, err := aead.Open(nil, data[:aead.NonceSize()], data[aead.NonceSize():], []byte(credentialAAD(service, key)))
	if err != nil {
		return "", fmt.Errorf("%w: %v", ErrSecretCorrupt, err)
	}
	return string(plain), nil
}

// newAEAD derives a per-entry key with HKDF-SHA256 from the machine-bound
// secret, using the entry coordinates as the info string.
func (s *fileStore) newAEAD(service, key string) (cipher.AEAD, error) {
	entryKey, err := hkdf.Key(sha256.New, s.machineSecret, nil, credentialAAD(service, key), aes256KeyLen)
	if err != nil {
		return nil, fmt.Errorf("platform: derive secret key: %w", err)
	}
	block, err := aes.NewCipher(entryKey)
	if err != nil {
		return nil, fmt.Errorf("platform: secret cipher: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("platform: secret AEAD: %w", err)
	}
	return aead, nil
}

// pathFor maps a credential to its hashed file name.
func (s *fileStore) pathFor(service, key string) string {
	sum := sha256.Sum256([]byte(credentialAAD(service, key)))
	return filepath.Join(s.dir, hex.EncodeToString(sum[:])+secretFileExt)
}

// credentialAAD is the canonical service/key serialization used for file
// naming, HKDF info and AEAD associated data.
func credentialAAD(service, key string) string { return service + "\x00" + key }

// writeFileAtomic writes data through a same-directory temp file (0600) and an
// atomic rename, so readers never observe a half-written entry.
func writeFileAtomic(path string, data []byte) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), ".tmp-secret-*")
	if err != nil {
		return fmt.Errorf("platform: create temp secret: %w", err)
	}
	tmpName := tmp.Name()

	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		_ = os.Remove(tmpName)
		return fmt.Errorf("platform: write temp secret: %w", err)
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(tmpName)
		return fmt.Errorf("platform: close temp secret: %w", err)
	}
	if err := os.Rename(tmpName, path); err != nil {
		_ = os.Remove(tmpName)
		return fmt.Errorf("platform: install secret entry: %w", err)
	}
	return nil
}

// defaultMachineSecret collects the best machine-bound inputs the portable
// runtime exposes: hostname, user home and, when readable, /etc/machine-id. The
// joined result is hashed into fixed-length HKDF input keying material.
//
// Honest boundary: this default is best-effort binding, not a TPM or Secure
// Enclave. It stops entries from being copied to another (user, machine) pair,
// but a local attacker who can read these public inputs gains nothing from the
// encryption — it is defense in depth above plaintext, not a trust boundary.
// Callers needing stronger binding inject their own source via
// secretStoreConfig.machineSecret.
func defaultMachineSecret() ([]byte, error) {
	parts := make([]string, 0, 3)
	if host, err := os.Hostname(); err == nil && host != "" {
		parts = append(parts, "host="+host)
	}
	if home, err := os.UserHomeDir(); err == nil && home != "" {
		parts = append(parts, "home="+home)
	}
	if machineID, err := os.ReadFile(machineIDPath); err == nil {
		if trimmed := strings.TrimSpace(string(machineID)); trimmed != "" {
			parts = append(parts, "machine-id="+trimmed)
		}
	}
	if len(parts) == 0 {
		return nil, errNoMachineSecret
	}
	sum := sha256.Sum256([]byte(strings.Join(parts, "\x00")))
	return sum[:], nil
}
