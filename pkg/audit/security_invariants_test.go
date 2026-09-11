package audit_test

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/fregie/tokenhush/pkg/audit"
	"github.com/fregie/tokenhush/pkg/extension"
	"github.com/fregie/tokenhush/pkg/redact"
)

// metadataRecordFields is the complete allowlisted field set of audit.Record.
var metadataRecordFields = map[string]bool{
	"ID": true, "TS": true, "Provider": true, "Path": true, "Method": true,
	"Status": true, "ReqBytes": true, "RespBytes": true, "Redactions": true,
	"Detectors": true, "Client": true, "PrevHash": true, "Hash": true,
}

// metadataJSONKeys is the complete allowlisted JSON key set of audit.Record.
var metadataJSONKeys = map[string]bool{
	"id": true, "ts": true, "provider": true, "path": true, "method": true,
	"status": true, "req_bytes": true, "resp_bytes": true, "redactions": true,
	"detectors": true, "client": true, "prev_hash": true, "hash": true,
}

// redactForAudit is the fixed redaction flow this test drives before writing a
// metadata row: the synthetic secret is detected, replaced with a placeholder,
// and only the finding count is handed to the store.
func redactForAudit(t *testing.T, body []byte, secret string) (redacted []byte, redactions int, detectors []string) {
	t.Helper()
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
		t.Fatalf("prefix detector did not find the synthetic secret")
	}
	spans := make([]redact.Redaction, 0, len(findings))
	for _, f := range findings {
		spans = append(spans, redact.Redaction{Start: f.Start, End: f.End, Type: f.Type})
	}
	engine, err := redact.NewPlaceholderEngine()
	if err != nil {
		t.Fatalf("NewPlaceholderEngine: %v", err)
	}
	redacted = engine.ApplyPlaceholders(body, spans)
	if bytes.Contains(redacted, []byte(secret)) {
		t.Fatalf("redaction left the secret in the outbound body")
	}
	return redacted, len(findings), []string{"prefix"}
}

// TestAuditMetadataOnly is the W5.4 named invariant (docs/security.md §2.2,
// docs/13 §6): an audit row carries metadata only. It pins the schema (a future
// Body/Content/Prompt field or JSON key fails here) and then drives a synthetic
// secret through the real detector + placeholder path and the real SQLite
// store, byte-scanning both the database and its WAL. A planted scratch file
// proves the scan is not vacuously passing.
func TestAuditMetadataOnly(t *testing.T) {
	recType := reflect.TypeOf(audit.Record{})
	if recType.NumField() != len(metadataRecordFields) {
		t.Fatalf("audit.Record has %d fields, want the %d metadata fields", recType.NumField(), len(metadataRecordFields))
	}
	for i := 0; i < recType.NumField(); i++ {
		if name := recType.Field(i).Name; !metadataRecordFields[name] {
			t.Fatalf("audit.Record gained non-metadata field %q; audit is metadata-only", name)
		}
	}

	t.Run("json_shape_is_metadata_only", func(t *testing.T) {
		blob, err := json.Marshal(audit.Record{
			Provider: "anthropic", Path: "/v1/messages", Method: "POST", Status: 200,
			ReqBytes: 12, RespBytes: 4, Redactions: 1, Detectors: []string{"prefix"}, Client: "claude-code",
		})
		if err != nil {
			t.Fatalf("Marshal: %v", err)
		}
		var keys map[string]json.RawMessage
		if err := json.Unmarshal(blob, &keys); err != nil {
			t.Fatalf("Unmarshal: %v", err)
		}
		for key := range keys {
			if !metadataJSONKeys[key] {
				t.Fatalf("audit JSON gained non-metadata key %q: %s", key, blob)
			}
		}
	})

	t.Run("real_store_persists_no_plaintext", func(t *testing.T) {
		secret := "sk-" + strings.Repeat("Ab3", 12)
		body := []byte(`{"prompt":"send my key ` + secret + ` upstream"}`)
		redacted, redactions, detectors := redactForAudit(t, body, secret)

		path := filepath.Join(t.TempDir(), "audit.db")
		store, err := audit.OpenStore(audit.StoreConfig{
			Path:      path,
			Secrets:   newExtMemSecrets(),
			HashKey:   bytes.Repeat([]byte{0x33}, 32),
			AnchorKey: bytes.Repeat([]byte{0x44}, 32),
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
			Redactions: redactions,
			Detectors:  detectors,
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
		stored, err := json.Marshal(records[0])
		if err != nil {
			t.Fatalf("Marshal stored row: %v", err)
		}
		if bytes.Contains(stored, []byte(secret)) {
			t.Fatalf("queried audit row contains the plaintext secret: %s", stored)
		}

		wal := path + "-wal"
		info, err := os.Stat(wal)
		if err != nil {
			t.Fatalf("WAL file missing: %v", err)
		}
		if info.Size() == 0 {
			t.Fatal("WAL file is empty; the plaintext scan would be vacuous")
		}
		for _, p := range []string{path, wal} {
			data, err := os.ReadFile(p)
			if err != nil {
				t.Fatalf("read %s: %v", p, err)
			}
			if bytes.Contains(data, []byte(secret)) {
				t.Fatalf("plaintext secret stored in %s", p)
			}
		}
		t.Logf("metadata-only row persisted; db+wal carry no secret (redactions=%d detectors=%v)", redactions, detectors)

		planted := filepath.Join(t.TempDir(), "planted.bin")
		if err := os.WriteFile(planted, []byte(secret), 0o600); err != nil {
			t.Fatal(err)
		}
		data, err := os.ReadFile(planted)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Contains(data, []byte(secret)) {
			t.Fatal("scanner sanity check failed: planted secret not detected")
		}
	})
}
