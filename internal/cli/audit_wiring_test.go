package cli

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/fregie/tokenhush/pkg/audit"
	"github.com/fregie/tokenhush/pkg/config"
	"github.com/fregie/tokenhush/pkg/platform"
	"github.com/fregie/tokenhush/pkg/proxy"
	_ "modernc.org/sqlite"
)

// stubSecrets is a hermetic platform.SecretStore for the audit-wiring tests. It
// keeps the two audit keys and the high-water tip in memory so a test can seed,
// tamper and re-open a store with byte-identical keys.
type stubSecrets struct {
	mu sync.Mutex
	m  map[string]string
}

func newStubSecrets() *stubSecrets { return &stubSecrets{m: map[string]string{}} }

func stubSecretKey(service, key string) string { return service + "\x00" + key }

func (s *stubSecrets) Get(service, key string) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	v, ok := s.m[stubSecretKey(service, key)]
	if !ok {
		return "", platform.ErrNotFound
	}
	return v, nil
}

func (s *stubSecrets) Set(service, key, value string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.m[stubSecretKey(service, key)] = value
	return nil
}

func (s *stubSecrets) Delete(service, key string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.m[stubSecretKey(service, key)]; !ok {
		return platform.ErrNotFound
	}
	delete(s.m, stubSecretKey(service, key))
	return nil
}

func (s *stubSecrets) Backend() string { return "stub" }

// findAuditRecord returns the first record matching provider and path.
func findAuditRecord(records []audit.Record, provider, path string) *audit.Record {
	for i := range records {
		if records[i].Provider == provider && records[i].Path == path {
			return &records[i]
		}
	}
	return nil
}

// openTestAudit opens the real pkg/audit store at the daemon's default path
// using the shared stub secrets, so the daemon's own OpenStore call derives the
// exact same keys.
func openTestAudit(t *testing.T, dataDir string, secrets platform.SecretStore) *audit.Store {
	t.Helper()
	store, err := audit.OpenStore(audit.StoreConfig{
		Path:    filepath.Join(dataDir, auditDBFileName),
		Secrets: secrets,
	})
	if err != nil {
		t.Fatalf("open test audit store: %v", err)
	}
	return store
}

// tamperAuditRow runs one SQL statement against the audit database as an
// outside writer, the way an attacker with file access would.
func tamperAuditRow(t *testing.T, dataDir, stmt string) {
	t.Helper()
	dsn := filepath.Join(dataDir, auditDBFileName) + "?_pragma=busy_timeout(5000)"
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		t.Fatalf("open tamper db: %v", err)
	}
	defer func() { _ = db.Close() }()
	if _, err := db.Exec(stmt); err != nil {
		t.Fatalf("tamper statement %q: %v", stmt, err)
	}
}

// TestRunServerStartupVerifyTampered proves the strongest fail-safe: a store
// whose row chain was tampered before startup is refused with a typed
// ErrTampered, a loud alert, and no session files.
func TestRunServerStartupVerifyTampered(t *testing.T) {
	secrets := newStubSecrets()
	dataDir := t.TempDir()

	seed := openTestAudit(t, dataDir, secrets)
	if err := seed.Record(audit.Record{
		TS:       time.Now().UnixMilli(),
		Provider: "anthropic",
		Path:     "/v1/messages",
		Method:   http.MethodPost,
		Status:   http.StatusOK,
	}); err != nil {
		t.Fatalf("seed record: %v", err)
	}
	if err := seed.Close(); err != nil {
		t.Fatalf("close seed store: %v", err)
	}
	tamperAuditRow(t, dataDir, `UPDATE requests SET path = '/tampered' WHERE id = 1`)

	cfg := config.Default()
	cfg.Listen.Host = "127.0.0.1"
	cfg.Listen.Port = 0

	var stderr bytes.Buffer
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	err := RunServer(ctx, &cfg, RunDeps{DataDir: dataDir, Secrets: secrets, Stderr: &stderr})
	if !errors.Is(err, audit.ErrTampered) {
		t.Fatalf("RunServer error = %v, want errors.Is(_, audit.ErrTampered)", err)
	}
	if !strings.Contains(stderr.String(), auditTamperAlert) {
		t.Errorf("stderr = %q, want the tamper alert %q", stderr.String(), auditTamperAlert)
	}
	if _, statErr := os.Stat(filepath.Join(dataDir, proxy.ControlTokenFileName)); !errors.Is(statErr, os.ErrNotExist) {
		t.Errorf("a tampered store still wrote a control token (stat err=%v)", statErr)
	}
}

// TestRunServerAuditReadVerifyTampered proves GET /audit re-verifies the chain:
// tampering a committed row while the daemon runs turns the next audit read
// into a 500 plus a loud alert, never a silently served forged row.
func TestRunServerAuditReadVerifyTampered(t *testing.T) {
	upstream := &echoUpstream{}
	upstreamSrv := httptest.NewServer(upstream)
	defer upstreamSrv.Close()

	cfg := config.Default()
	cfg.Listen.Host = "127.0.0.1"
	cfg.Listen.Port = 0
	cfg.Upstreams = config.Upstreams{"/v1/messages": upstreamSrv.URL}

	secrets := newStubSecrets()
	dataDir := t.TempDir()
	var stderr bytes.Buffer
	base, token, stop := startTestDaemon(t, &cfg, RunDeps{DataDir: dataDir, Secrets: secrets, Stderr: &stderr})
	defer func() { _ = stop() }()

	intact := doGet(t, base+"/audit", token, "")
	if intact.StatusCode != http.StatusOK {
		t.Fatalf("intact GET /audit = %d, want 200", intact.StatusCode)
	}

	tamperAuditRow(t, dataDir, `UPDATE requests SET method = 'TAMPERED' WHERE id = 1`)

	forged := doGet(t, base+"/audit", token, "")
	if forged.StatusCode != http.StatusInternalServerError {
		t.Fatalf("tampered GET /audit = %d, want 500", forged.StatusCode)
	}
	if !strings.Contains(stderr.String(), auditTamperAlert) {
		t.Errorf("stderr = %q, want the tamper alert %q", stderr.String(), auditTamperAlert)
	}
}

// TestRunServerAuditStoreUnavailableFailsSafe proves an unavailable store does
// not degrade to a silent no-op: startup fails with an error and a loud alert.
func TestRunServerAuditStoreUnavailableFailsSafe(t *testing.T) {
	root := t.TempDir()
	dataDir := filepath.Join(root, "not-a-directory")
	if err := os.WriteFile(dataDir, []byte("x"), 0o600); err != nil {
		t.Fatalf("write blocking file: %v", err)
	}

	cfg := config.Default()
	cfg.Listen.Host = "127.0.0.1"
	cfg.Listen.Port = 0

	var stderr bytes.Buffer
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	err := RunServer(ctx, &cfg, RunDeps{DataDir: dataDir, Secrets: newStubSecrets(), Stderr: &stderr})
	if err == nil {
		t.Fatal("RunServer succeeded with an unavailable audit store; want a fail-safe error")
	}
	if !strings.Contains(stderr.String(), auditUnavailableAlert) {
		t.Errorf("stderr = %q, want the unavailable alert %q", stderr.String(), auditUnavailableAlert)
	}
}

// TestRunServerSinkOverride keeps the explicit AuditSink seam working: an
// injected sink receives the lifecycle and per-request metadata rows and the
// daemon does not open the platform store.
func TestRunServerSinkOverride(t *testing.T) {
	upstream := &echoUpstream{}
	upstreamSrv := httptest.NewServer(upstream)
	defer upstreamSrv.Close()

	cfg := config.Default()
	cfg.Listen.Host = "127.0.0.1"
	cfg.Listen.Port = 0
	cfg.Upstreams = config.Upstreams{"/v1/messages": upstreamSrv.URL}

	sink := &recordingSink{}
	base, _, stop := startTestDaemon(t, &cfg, RunDeps{DataDir: t.TempDir(), Sink: sink})
	defer func() { _ = stop() }()

	body := `{"model":"test","messages":[{"role":"user","content":"hello"}]}`
	if got := postBody(t, base+"/v1/messages", "application/json", body, nil); got.StatusCode != http.StatusOK {
		t.Fatalf("data-plane status = %d, want 200", got.StatusCode)
	}
	paths := sink.paths()
	if !containsString(paths, "start") {
		t.Errorf("injected sink missing startup row; paths = %v", paths)
	}
	if !containsString(paths, "/v1/messages") {
		t.Errorf("injected sink missing per-request row; paths = %v", paths)
	}
}
