//go:build linux

package platform

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

const (
	// systemdCredsBinary encrypts credentials with the TPM or the host key.
	// It is invoked as a subprocess; the secret itself only ever travels on
	// stdin/stdout, never in argv.
	systemdCredsBinary = "systemd-creds"

	// systemdCredsFileExt marks one systemd-creds entry.
	systemdCredsFileExt = ".cred"
)

// systemdCredsStore is the Linux-only second layer of the fallback chain.
type systemdCredsStore struct {
	dir string
}

// newSystemdCredsStore reports whether systemd-creds is usable: the binary must
// be on PATH, the data dir must accept entries, and a real encrypt/decrypt
// round trip must succeed (a TPM-less or key-less host fails here and the
// selector falls through to the encrypted file layer).
func newSystemdCredsStore(dataDir string) (storeBackend, bool) {
	if _, err := exec.LookPath(systemdCredsBinary); err != nil {
		return nil, false
	}
	if strings.TrimSpace(dataDir) == "" {
		return nil, false
	}
	dir := filepath.Join(dataDir, secretsDirName)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, false
	}
	store := &systemdCredsStore{dir: dir}
	if err := store.selfTest(); err != nil {
		return nil, false
	}
	return store, true
}

// selfTest proves a real encrypt/decrypt round trip works, then removes the
// scratch entry.
func (s *systemdCredsStore) selfTest() error {
	probe := make([]byte, 16)
	if _, err := rand.Read(probe); err != nil {
		return err
	}
	value := hex.EncodeToString(probe)

	if err := s.set(probeService, probeKey, value); err != nil {
		return err
	}
	got, err := s.get(probeService, probeKey)
	if err != nil || got != value {
		_ = s.delete(probeService, probeKey)
		return errors.New("platform: systemd-creds self-test round trip failed")
	}
	return s.delete(probeService, probeKey)
}

func (s *systemdCredsStore) get(service, key string) (string, error) {
	if err := validateCredential(service, key); err != nil {
		return "", err
	}
	path := s.pathFor(service, key)
	if _, err := os.Stat(path); errors.Is(err, fs.ErrNotExist) {
		return "", ErrNotFound
	}
	out, err := runSystemdCreds(systemdCredsDecryptArgv(credentialName(service, key), path), nil)
	if err != nil {
		return "", err
	}
	return string(out), nil
}

func (s *systemdCredsStore) set(service, key, value string) error {
	if err := validateCredential(service, key); err != nil {
		return err
	}
	ciphertext, err := runSystemdCreds(systemdCredsEncryptArgv(credentialName(service, key)), []byte(value))
	if err != nil {
		return err
	}
	if len(ciphertext) == 0 {
		return errors.New("platform: systemd-creds returned empty ciphertext")
	}
	return writeFileAtomic(s.pathFor(service, key), ciphertext)
}

func (s *systemdCredsStore) delete(service, key string) error {
	if err := validateCredential(service, key); err != nil {
		return err
	}
	if err := os.Remove(s.pathFor(service, key)); err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return ErrNotFound
		}
		return fmt.Errorf("platform: delete systemd credential: %w", err)
	}
	return nil
}

// pathFor maps a credential to its hashed file name.
func (s *systemdCredsStore) pathFor(service, key string) string {
	sum := sha256.Sum256([]byte(credentialAAD(service, key)))
	return filepath.Join(s.dir, hex.EncodeToString(sum[:])+systemdCredsFileExt)
}

// credentialName derives a stable, valid systemd credential name (alphanumerics
// plus '_') from the service/key pair. It is metadata, never secret.
func credentialName(service, key string) string {
	sum := sha256.Sum256([]byte(credentialAAD(service, key)))
	return "tokenhush_" + hex.EncodeToString(sum[:16])
}

// systemdCredsEncryptArgv returns the encrypt invocation: PLAINTEXT "-" is the
// stdin payload and CIPHERTEXT "-" is captured from stdout, so the secret never
// enters argv.
func systemdCredsEncryptArgv(name string) []string {
	return []string{systemdCredsBinary, "encrypt", "--name=" + name, "-", "-"}
}

// systemdCredsDecryptArgv returns the decrypt invocation: ciphertext from the
// entry file, plaintext to stdout. Names and file paths are metadata only.
func systemdCredsDecryptArgv(name, path string) []string {
	return []string{systemdCredsBinary, "decrypt", "--name=" + name, path, "-"}
}

// runSystemdCreds executes one systemd-creds invocation. Errors deliberately do
// not embed stderr: diagnostics are not guaranteed secret-free and error
// messages must never leak values.
func runSystemdCreds(argv []string, stdin []byte) ([]byte, error) {
	cmd := exec.Command(argv[0], argv[1:]...)
	cmd.Stdin = bytes.NewReader(stdin)
	var stdout bytes.Buffer
	cmd.Stdout = &stdout
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("platform: systemd-creds %s: %w", argv[1], err)
	}
	return stdout.Bytes(), nil
}
