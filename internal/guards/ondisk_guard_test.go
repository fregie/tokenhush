// On-disk guard: no request or response plaintext may land on disk. The
// scanner is exercised with a runtime-generated secret so the guard can never
// match its own source; the sink-level half lives in
// pkg/audit/invariants_test.go and the run-level half below drives the real
// binary end to end and scans everything the run could have written.
package guards

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"io/fs"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"sync"
	"syscall"
	"testing"
	"time"
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

// invariant2Secret returns a runtime-generated secret the email detector
// flags, so the pipeline really substitutes it and the scan hunts bytes that
// moved through the redaction path.
func invariant2Secret(t *testing.T) string {
	t.Helper()
	buf := make([]byte, 8)
	if _, err := rand.Read(buf); err != nil {
		t.Fatalf("crypto/rand: %v", err)
	}
	return "guard-" + hex.EncodeToString(buf) + "@example.com"
}

// assertNoSecret fails the test when the plaintext secret appears in any
// readable file below root, naming each offending path.
func assertNoSecret(t *testing.T, root, secret, what string) {
	t.Helper()
	hits, err := scanForPlaintext(root, secret)
	if err != nil {
		t.Fatalf("scan %s: %v", what, err)
	}
	if len(hits) != 0 {
		t.Errorf("plaintext secret found in %s: %v", what, hits)
	}
}

// waitForGuardGateway polls the gateway's local route until it answers.
func waitForGuardGateway(t *testing.T, base string) {
	t.Helper()
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		response, err := http.Get(base + "/v1/models")
		if err == nil {
			_ = response.Body.Close()
			if response.StatusCode == http.StatusOK {
				return
			}
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("the gateway at %s never became ready", base)
}

// freeLoopbackPort reserves an ephemeral loopback port and returns it. The
// reservation is released before the gateway binds, so a lost race fails the
// test loudly at the first request.
func freeLoopbackPort(t *testing.T) int {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserve a loopback port: %v", err)
	}
	defer func() { _ = listener.Close() }()
	_, text, err := net.SplitHostPort(listener.Addr().String())
	if err != nil {
		t.Fatalf("split the reserved address: %v", err)
	}
	port, err := strconv.Atoi(text)
	if err != nil {
		t.Fatalf("parse the reserved port: %v", err)
	}
	return port
}

// TestInvariant2NoPlaintextOnDisk is the run-level half of invariant 2: it
// starts the real binary against a loopback echo upstream, drives one request
// carrying a runtime-generated secret through the live gateway, and scans both
// the directory the run wrote and the repository tree for that secret in
// plaintext. The planted file proves the run-level scan has teeth.
func TestInvariant2NoPlaintextOnDisk(t *testing.T) {
	secret := invariant2Secret(t)
	repo := repoRoot(t)

	var (
		upstreamMu  sync.Mutex
		upstreamGot []byte
	)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Errorf("read the upstream body: %v", err)
			return
		}
		upstreamMu.Lock()
		upstreamGot = bytes.Clone(body)
		upstreamMu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(body)
	}))
	defer upstream.Close()

	tmp := t.TempDir()
	// The binary and the home are siblings: pkg/platform rejects a
	// TOKENHUSH_HOME at or inside the executable's directory.
	exe := filepath.Join(tmp, "bin", "tokenhush")
	if err := os.MkdirAll(filepath.Dir(exe), 0o700); err != nil {
		t.Fatalf("create the binary directory: %v", err)
	}
	buildCtx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	build := exec.CommandContext(buildCtx, "go", "build", "-o", exe, "./cmd/tokenhush")
	build.Dir = repo
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("go build ./cmd/tokenhush: %v\n%s", err, out)
	}

	home := filepath.Join(tmp, "home")
	configDir := filepath.Join(home, "config")
	dataDir := filepath.Join(home, "data")
	if err := os.MkdirAll(configDir, 0o700); err != nil {
		t.Fatalf("create the config directory: %v", err)
	}
	port := freeLoopbackPort(t)
	config := fmt.Sprintf("listen:\n  host: 127.0.0.1\n  port: %d\nupstreams:\n  - match: /v1/chat/completions\n    target: %s\n", port, upstream.URL)
	if err := os.WriteFile(filepath.Join(configDir, "tokenhush.yaml"), []byte(config), 0o600); err != nil {
		t.Fatalf("write tokenhush.yaml: %v", err)
	}

	run := exec.Command(exe, "run")
	run.Dir = repo
	run.Env = append(os.Environ(), "TOKENHUSH_HOME="+home)
	run.Stdout, run.Stderr = io.Discard, io.Discard
	if err := run.Start(); err != nil {
		t.Fatalf("start the gateway: %v", err)
	}
	waited := make(chan error, 1)
	go func() { waited <- run.Wait() }()
	stopped := false
	defer func() {
		if !stopped {
			_ = run.Process.Kill()
			<-waited
		}
	}()

	base := fmt.Sprintf("http://127.0.0.1:%d", port)
	waitForGuardGateway(t, base)

	body := []byte(fmt.Sprintf(`{"messages":[{"role":"user","content":"write to %s"}]}`, secret))
	request, err := http.NewRequest(http.MethodPost, base+"/v1/chat/completions", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	request.Header.Set("Content-Type", "application/json")
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		t.Fatalf("POST the secret: %v", err)
	}
	got, err := io.ReadAll(response.Body)
	_ = response.Body.Close()
	if err != nil {
		t.Fatalf("read the response: %v", err)
	}
	if response.StatusCode != http.StatusOK {
		t.Fatalf("POST = %d, want 200 (body %s)", response.StatusCode, got)
	}
	if !bytes.Contains(got, []byte(secret)) {
		t.Fatalf("the round trip did not restore the secret, so the scan would be vacuous: %s", got)
	}
	upstreamMu.Lock()
	sent := bytes.Clone(upstreamGot)
	upstreamMu.Unlock()
	if bytes.Contains(sent, []byte(secret)) {
		t.Fatalf("the secret reached the upstream: %s", sent)
	}
	if !bytes.Contains(sent, []byte("__PII_")) {
		t.Fatalf("no placeholder reached the upstream: %s", sent)
	}

	assertNoSecret(t, home, secret, "the data directory")
	assertNoSecret(t, repo, secret, "the repository tree")

	planted := filepath.Join(dataDir, "planted-plaintext.txt")
	if err := os.WriteFile(planted, []byte(secret), 0o600); err != nil {
		t.Fatalf("plant the scratch plaintext: %v", err)
	}
	hits, err := scanForPlaintext(home, secret)
	if err != nil {
		t.Fatalf("scanForPlaintext planted: %v", err)
	}
	if len(hits) != 1 || hits[0] != "data/planted-plaintext.txt" {
		t.Fatalf("the planted plaintext was not caught: %v", hits)
	}
	if err := os.Remove(planted); err != nil {
		t.Fatalf("remove the planted plaintext: %v", err)
	}

	if err := run.Process.Signal(syscall.SIGTERM); err != nil {
		t.Fatalf("signal the gateway: %v", err)
	}
	select {
	case err := <-waited:
		stopped = true
		if err != nil {
			t.Fatalf("the gateway exited with %v, want a clean SIGTERM shutdown", err)
		}
	case <-time.After(10 * time.Second):
		_ = run.Process.Kill()
		t.Fatal("the gateway did not exit within 10s of SIGTERM")
	}
	assertNoSecret(t, home, secret, "the data directory after shutdown")
}
