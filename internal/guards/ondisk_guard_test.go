// On-disk guard: no request or response plaintext may land on disk. The
// scanner is exercised with a runtime-generated secret so the guard can never
// match its own source; the sink-level half lands in W1.2 and the end-to-end
// run-level half in W6.6.
package guards

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"testing"
)

// looksBinary reports whether data appears to be binary, sniffing the leading
// bytes for a NUL. Binary files cannot carry the ASCII secret and are skipped.
func looksBinary(data []byte) bool {
	const sniff = 8192
	if len(data) > sniff {
		data = data[:sniff]
	}
	return bytes.IndexByte(data, 0) >= 0
}

// scanForPlaintext walks root and returns the sorted repo-relative slash paths
// of every regular file whose bytes contain secret. Directories named .git and
// .omo are skipped, as are unreadable and binary files.
func scanForPlaintext(root, secret string) ([]string, error) {
	var hits []string
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			if d != nil && d.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		if d.IsDir() {
			switch d.Name() {
			case ".git", ".omo":
				return filepath.SkipDir
			}
			return nil
		}
		if !d.Type().IsRegular() {
			return nil
		}
		data, err := os.ReadFile(path)
		if err != nil || looksBinary(data) {
			return nil
		}
		if !bytes.Contains(data, []byte(secret)) {
			return nil
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			rel = path
		}
		hits = append(hits, filepath.ToSlash(rel))
		return nil
	})
	if err != nil {
		return nil, err
	}
	sort.Strings(hits)
	return hits, nil
}

// randomSecret returns a 64-character hex secret generated at test runtime, so
// a guard can never match bytes baked into its own source.
func randomSecret(t *testing.T) string {
	t.Helper()
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		t.Fatalf("crypto/rand: %v", err)
	}
	return hex.EncodeToString(buf)
}

func TestOndiskGuardScannerDetectsPlantedSecret(t *testing.T) {
	secret := randomSecret(t)
	dir := t.TempDir()

	writeFile := func(rel, content string) {
		t.Helper()
		path := filepath.Join(dir, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatalf("mkdir for %s: %v", rel, err)
		}
		if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
			t.Fatalf("write %s: %v", rel, err)
		}
	}

	writeFile("leak.txt", "planted plaintext: "+secret+"\n")
	writeFile("clean.txt", "nothing sensitive lives here\n")

	hits, err := scanForPlaintext(dir, secret)
	if err != nil {
		t.Fatalf("scanForPlaintext(%s): %v", dir, err)
	}
	if len(hits) != 1 || hits[0] != "leak.txt" {
		t.Fatalf("scanForPlaintext(%s) = %v, want exactly [leak.txt]", dir, hits)
	}

	t.Run("ignored dirs and nested files", func(t *testing.T) {
		skipDir := t.TempDir()
		for _, rel := range []string{".git/hidden.txt", ".omo/state.txt", "nested/deep/leak.txt"} {
			path := filepath.Join(skipDir, filepath.FromSlash(rel))
			if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
				t.Fatalf("mkdir for %s: %v", rel, err)
			}
			if err := os.WriteFile(path, []byte(secret), 0o600); err != nil {
				t.Fatalf("write %s: %v", rel, err)
			}
		}
		got, err := scanForPlaintext(skipDir, secret)
		if err != nil {
			t.Fatalf("scanForPlaintext(%s): %v", skipDir, err)
		}
		if len(got) != 1 || got[0] != "nested/deep/leak.txt" {
			t.Fatalf("scanForPlaintext(%s) = %v, want exactly [nested/deep/leak.txt]", skipDir, got)
		}
	})

	repoHits, err := scanForPlaintext(repoRoot(t), secret)
	if err != nil {
		t.Fatalf("scanForPlaintext(%s): %v", repoRoot(t), err)
	}
	if len(repoHits) != 0 {
		t.Errorf("runtime-generated secret leaked into the repository tree: %v", repoHits)
	}
}

func TestOndiskGuardRunLevel(t *testing.T) {
	skipGuard(t, "ondisk", "run-level half completes in W6.6 (sink-level half in W1.2)")
}
