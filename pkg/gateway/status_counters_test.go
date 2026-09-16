package gateway

// W6.5 gateway-layer regressions: GET /status exposes the per-session
// self-protection counters, and a control-plane allowlist mutation both
// increments AllowlistMutations and writes exactly one metadata-only audit row.
// The W5.3 handler harness (w53Server) and its recording sink are reused; no
// new production path is introduced.

import (
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/fregie/tokenhush/pkg/allowlist"
)

// w65StatusView is the /status subset the W6.5 assertions read.
type w65StatusView struct {
	Allowlist                   int    `json:"allowlist"`
	AllowlistMutations          uint64 `json:"allowlist_mutations"`
	SelfProtectionInterceptions uint64 `json:"self_protection_interceptions"`
	StreamGuardRefusals         uint64 `json:"stream_guard_refusals"`
	StreamGuardFailClosed       uint64 `json:"stream_guard_fail_closed"`
	EgressBlocks                uint64 `json:"egress_blocks"`
}

// TestStatusAllowlistMutationCounterAndRow locks the W6.5 mutation side:
// each successful control-plane mutation increments AllowlistMutations on
// /status and writes one metadata-only row (action, source, resulting count —
// never the entry value).
func TestStatusAllowlistMutationCounterAndRow(t *testing.T) {
	store, err := allowlist.Open(t.TempDir(), []string{w53Seed}, io.Discard)
	if err != nil {
		t.Fatalf("allowlist.Open: %v", err)
	}
	sink := &w53Sink{}
	_, upstreamURL := w13UpstreamServer(t)
	srv := w53Server(t, store, sink, upstreamURL)

	readStatus := func() w65StatusView {
		t.Helper()
		code, _, body := w53Request(t, srv, http.MethodGet, controlStatusPath, w53ControlToken, nil, nil)
		if code != http.StatusOK {
			t.Fatalf("GET /status = %d, want 200 (body %q)", code, body)
		}
		var got w65StatusView
		if err := json.Unmarshal(body, &got); err != nil {
			t.Fatalf("/status is not JSON (%v): %q", err, body)
		}
		return got
	}

	if got := readStatus(); got.AllowlistMutations != 0 {
		t.Fatalf("initial allowlist_mutations = %d, want 0", got.AllowlistMutations)
	}
	if got := readStatus(); got.SelfProtectionInterceptions != 0 || got.StreamGuardRefusals != 0 ||
		got.StreamGuardFailClosed != 0 || got.EgressBlocks != 0 {
		t.Fatalf("a run with no traffic reports nonzero C8 counters: %+v", got)
	}

	code, _, _ := w53Request(t, srv, http.MethodPost, controlAllowlistPath, w53ControlToken,
		[]byte(`{"entry":"w65.runtime.entry"}`), nil)
	if code != http.StatusOK {
		t.Fatalf("POST /allowlist = %d, want 200", code)
	}

	got := readStatus()
	if got.AllowlistMutations != 1 {
		t.Fatalf("allowlist_mutations after one POST = %d, want 1", got.AllowlistMutations)
	}
	if got.Allowlist != 2 {
		t.Fatalf("allowlist entries = %d, want 2 (seed + runtime)", got.Allowlist)
	}

	rows := sink.records()
	if len(rows) != 1 {
		t.Fatalf("audit rows = %d (%+v), want exactly 1", len(rows), rows)
	}
	row := rows[0]
	if row.Provider != controlAuditProvider || row.Method != "add" ||
		row.Path != controlAllowlistPath || row.Client != "allowlist-source-cli" {
		t.Fatalf("mutation row shape = %+v, want provider=%s method=add path=%s client=allowlist-source-cli",
			row, controlAuditProvider, controlAllowlistPath)
	}
	if len(row.Detectors) != 1 || row.Detectors[0] != "entries:2" {
		t.Fatalf("mutation row detectors = %v, want [entries:2]", row.Detectors)
	}
	if row.TS <= 0 {
		t.Fatalf("mutation row ts = %d, want a positive unix-millisecond timestamp", row.TS)
	}
	t.Logf("W65_MUTATION_ROW provider=%s path=%s method=%s client=%s detectors=%v ts=%d",
		row.Provider, row.Path, row.Method, row.Client, row.Detectors, row.TS)

	for _, field := range append([]string{row.Provider, row.Path, row.Method, row.Client}, row.Detectors...) {
		if strings.Contains(field, "w65.runtime.entry") {
			t.Fatalf("mutation row leaked the entry value: %+v", row)
		}
	}

	// Each successful mutation writes its own row and moves the counter.
	code, _, _ = w53Request(t, srv, http.MethodDelete, controlAllowlistPath, w53ControlToken,
		[]byte(`{"entry":"w65.runtime.entry"}`), nil)
	if code != http.StatusOK {
		t.Fatalf("DELETE /allowlist = %d, want 200", code)
	}
	if got := readStatus(); got.AllowlistMutations != 2 {
		t.Fatalf("allowlist_mutations after add+remove = %d, want 2", got.AllowlistMutations)
	}
	if rows := sink.records(); len(rows) != 2 {
		t.Fatalf("audit rows after add+remove = %d, want 2", len(rows))
	}
}
