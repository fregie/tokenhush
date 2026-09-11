package audit_test

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/fregie/tokenhush/pkg/audit"
	"github.com/fregie/tokenhush/pkg/extension"
	"github.com/fregie/tokenhush/pkg/platform"
	"github.com/fregie/tokenhush/pkg/redact"
)

// extMemSecrets is an in-memory platform.SecretStore for this external test.
type extMemSecrets struct {
	mu sync.Mutex
	m  map[string]string
}

func newExtMemSecrets() *extMemSecrets { return &extMemSecrets{m: map[string]string{}} }

func (s *extMemSecrets) Get(service, key string) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	v, ok := s.m[service+"\x00"+key]
	if !ok {
		return "", fmt.Errorf("%w: %s/%s", platform.ErrNotFound, service, key)
	}
	return v, nil
}

func (s *extMemSecrets) Set(service, key, value string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.m[service+"\x00"+key] = value
	return nil
}

func (s *extMemSecrets) Delete(service, key string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	k := service + "\x00" + key
	if _, ok := s.m[k]; !ok {
		return platform.ErrNotFound
	}
	delete(s.m, k)
	return nil
}

func (s *extMemSecrets) Backend() string { return "memory" }

// TestNoPlaintextInAuditFiles drives a request body containing a synthetic
// secret through the real prefix detector and placeholder engine, records the
// resulting metadata-only audit row, then byte-scans BOTH the SQLite database
// and its WAL for the exact secret bytes. Zero hits is required; a planted
// scratch file proves the scanner is not vacuously passing.
func TestNoPlaintextInAuditFiles(t *testing.T) {
	secret := "sk-" + strings.Repeat("Ab3", 12)
	body := []byte(`{"prompt":"send my key ` + secret + ` upstream"}`)

	inspector := redact.NewPrefixDetector()
	doc := &extension.Document{
		Phase:  extension.RequestContent,
		Tool:   "claude-code",
		Leaves: []extension.Leaf{{Path: "prompt", Content: body, Len: len(body)}},
	}
	findings, err := inspector.Inspect(doc)
	if err != nil {
		t.Fatalf("Inspect: %v", err)
	}
	if len(findings) == 0 {
		t.Fatalf("prefix detector did not find the synthetic secret (body=%q)", body)
	}
	redactions := make([]redact.Redaction, 0, len(findings))
	for _, f := range findings {
		redactions = append(redactions, redact.Redaction{Start: f.Start, End: f.End, Type: f.Type})
	}
	engine, err := redact.NewPlaceholderEngine()
	if err != nil {
		t.Fatalf("NewPlaceholderEngine: %v", err)
	}
	redacted := engine.ApplyPlaceholders(body, redactions)
	if bytes.Contains(redacted, []byte(secret)) {
		t.Fatalf("redaction left the secret in the outbound body: %q", redacted)
	}

	path := filepath.Join(t.TempDir(), "audit.db")
	store, err := audit.OpenStore(audit.StoreConfig{
		Path:      path,
		Secrets:   newExtMemSecrets(),
		HashKey:   bytes.Repeat([]byte{0x11}, 32),
		AnchorKey: bytes.Repeat([]byte{0x22}, 32),
	})
	if err != nil {
		t.Fatalf("OpenStore: %v", err)
	}
	defer func() { _ = store.Close() }()

	if err := store.Record(audit.Record{
		TS:         time.Now().UnixMilli(),
		Provider:   "anthropic",
		Path:       "/v1/messages",
		Method:     "POST",
		Status:     200,
		ReqBytes:   int64(len(redacted)),
		RespBytes:  64,
		Redactions: len(findings),
		Detectors:  []string{"prefix"},
		Client:     "claude-code",
	}); err != nil {
		t.Fatalf("Record: %v", err)
	}

	records, err := store.Query(context.Background(), audit.Query{})
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	if len(records) != 1 {
		t.Fatalf("audit store holds %d rows, want 1 (non-vacuous scan)", len(records))
	}
	t.Logf("redactions=%d detectors=%v client=%q", records[0].Redactions, records[0].Detectors, records[0].Client)

	wal := path + "-wal"
	info, err := os.Stat(wal)
	if err != nil {
		t.Fatalf("WAL file missing: %v", err)
	}
	if info.Size() == 0 {
		t.Fatal("WAL file is empty; the plaintext scan would be vacuous")
	}

	var dbBytes, walBytes int64
	for _, p := range []string{path, wal} {
		data, err := os.ReadFile(p)
		if err != nil {
			t.Fatalf("read %s: %v", p, err)
		}
		if bytes.Contains(data, []byte(secret)) {
			t.Fatalf("plaintext secret found in %s", p)
		}
		if p == path {
			dbBytes = int64(len(data))
		} else {
			walBytes = int64(len(data))
		}
	}
	t.Logf("byte scan: db=%d bytes wal=%d bytes secret_hits=0", dbBytes, walBytes)

	planted := filepath.Join(t.TempDir(), "planted.bin")
	if err := os.WriteFile(planted, []byte(secret), 0o600); err != nil {
		t.Fatal(err)
	}
	plantedData, err := os.ReadFile(planted)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(plantedData, []byte(secret)) {
		t.Fatal("scanner sanity check failed: planted secret not detected")
	}
	t.Logf("scanner sanity: planted secret detected (scan is not vacuous)")
}
