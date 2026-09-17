package proxy

// W6.5 regressions: every C8 refusal (the buffered W6.3 path, the streaming
// W6.4 path, including the cap-exhaustion fail-closed refusal) increments the
// pipeline counter the status endpoint exposes and writes exactly one
// metadata-only audit row through the audit.AuditSink seam. No row, field or
// counter may carry the refused content, a matched candidate or a body byte.
// See guardaudit.go.

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"testing"

	"github.com/fregie/tokenhush/pkg/audit"
)

// w65Sink is a recording audit.AuditSink, the seam core passes as
// audit.NoopSink{} in production.
type w65Sink struct {
	mu   sync.Mutex
	rows []audit.Record
}

func (s *w65Sink) Record(rec audit.Record) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.rows = append(s.rows, rec)
	return nil
}

func (s *w65Sink) records() []audit.Record {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]audit.Record(nil), s.rows...)
}

// w65Pipeline builds the W6.3 harness pipeline (full C8 mode set, empty
// registry) with a recording sink installed through PipelineConfig.
func w65Pipeline(t *testing.T, sink audit.AuditSink) *Pipeline {
	t.Helper()
	return w45Pipeline(t, PipelineConfig{
		Registry:              w45Registry(t),
		Engine:                w45Engine(t),
		Tool:                  "w6.5",
		Sink:                  sink,
		SelfProtectionEnabled: true,
		SelfProtectionModes:   []string{MutationChannelCLI, MutationChannelControlPort, MutationChannelFileWrite},
	})
}

// w65RowContains reports whether a row — any of its string fields or its JSON
// serialization, i.e. exactly what a real store persists — carries needle.
func w65RowContains(row audit.Record, needle string) bool {
	for _, field := range append([]string{row.Provider, row.Path, row.Method, row.Client}, row.Detectors...) {
		if strings.Contains(field, needle) {
			return true
		}
	}
	raw, err := json.Marshal(row)
	return err == nil && bytes.Contains(raw, []byte(needle))
}

// w65AssertRow asserts the frozen metadata-only row shape for one refusal.
func w65AssertRow(t *testing.T, row audit.Record, surface, channel, reason string, refusals uint64) {
	t.Helper()
	if row.TS <= 0 {
		t.Errorf("row ts = %d, want a positive unix-millisecond timestamp", row.TS)
	}
	if row.Provider != auditProviderSelfProtection {
		t.Errorf("row provider = %q, want %q", row.Provider, auditProviderSelfProtection)
	}
	if row.Method != RedactionActionMutationChannelBlocked {
		t.Errorf("row method = %q, want %q", row.Method, RedactionActionMutationChannelBlocked)
	}
	if row.Path != surface {
		t.Errorf("row path/surface = %q, want %q", row.Path, surface)
	}
	if row.Client != auditSourceModel {
		t.Errorf("row client/source = %q, want %q", row.Client, auditSourceModel)
	}
	wantDetectors := []string{
		"channel:" + channel,
		"result:" + auditResultRefused,
		"reason:" + reason,
	}
	if len(row.Detectors) != len(wantDetectors) {
		t.Fatalf("row detectors = %v, want %v", row.Detectors, wantDetectors)
	}
	for i := range wantDetectors {
		if row.Detectors[i] != wantDetectors[i] {
			t.Fatalf("row detectors = %v, want %v", row.Detectors, wantDetectors)
		}
	}
	t.Logf("W65_ROW surface=%s client=%s detectors=%v", row.Path, row.Client, row.Detectors)
}

// TestMutationChannelGuardAudit is the W6.5 audit-row acceptance test: one row
// per refusal, the buffered and streamed refusals are distinguishable, and the
// streaming counter never leaks into the buffered counter.
func TestMutationChannelGuardAudit(t *testing.T) {
	t.Run("buffered_interception_counts_and_records_one_row", func(t *testing.T) {
		sink := &w65Sink{}
		pipe := w65Pipeline(t, sink)
		arguments := `{"cmd":"tokenhush allowlist add evil.example","note":"ok"}`
		body := w63Body(t, arguments)

		out, err := pipe.transformResponse(body, pipe.tool)
		if err != nil {
			t.Fatalf("transformResponse = %v, want nil", err)
		}
		w63WantArgs(t, out, w63Refusal(MutationChannelCLI))

		if got := pipe.SelfProtectionInterceptions(); got != 1 {
			t.Fatalf("SelfProtectionInterceptions = %d, want 1", got)
		}
		if got := pipe.StreamGuardRefusals(); got != 0 {
			t.Fatalf("StreamGuardRefusals = %d, want 0 for the buffered path", got)
		}
		rows := sink.records()
		if len(rows) != 1 {
			t.Fatalf("audit rows = %d (%+v), want exactly 1", len(rows), rows)
		}
		w65AssertRow(t, rows[0], auditSurfaceBuffered, MutationChannelCLI, sseGuardReasonMatch, 1)
	})

	t.Run("streamed_match_counts_and_records_one_row", func(t *testing.T) {
		sink := &w65Sink{}
		pipe := w65Pipeline(t, sink)
		w, _ := w14SSEWriter(t, pipe)

		fragments := []string{"token", "hush allow", "list add evil.example MARK-W65"}
		input := append(w64ArgumentsStream(t, fragments), w64FinishEvent...)
		input = append(input, w64DoneEvent...)
		if _, err := w.backfill.Write(input); err != nil {
			t.Fatalf("Write: %v", err)
		}
		if err := w.backfill.Flush(); err != nil {
			t.Fatalf("Flush: %v", err)
		}

		if got := pipe.StreamGuardRefusals(); got != 1 {
			t.Fatalf("StreamGuardRefusals = %d, want 1", got)
		}
		if got := pipe.StreamGuardFailClosed(); got != 0 {
			t.Fatalf("StreamGuardFailClosed = %d, want 0 for a match", got)
		}
		if got := pipe.SelfProtectionInterceptions(); got != 0 {
			t.Fatalf("SelfProtectionInterceptions = %d, want 0 for the streaming path", got)
		}
		rows := sink.records()
		if len(rows) != 1 {
			t.Fatalf("audit rows = %d (%+v), want exactly 1", len(rows), rows)
		}
		w65AssertRow(t, rows[0], auditSurfaceStream, MutationChannelCLI, sseGuardReasonMatch, 1)
	})

	t.Run("cap_exhaustion_records_a_fail_closed_row", func(t *testing.T) {
		sink := &w65Sink{}
		pipe := w65Pipeline(t, sink)
		w, rec := w14SSEWriter(t, pipe)

		fragments := w64BigLegalArguments()
		input := append(w64ArgumentsStream(t, fragments), w64FinishEvent...)
		input = append(input, w64DoneEvent...)
		if _, err := w.backfill.Write(input); err != nil {
			t.Fatalf("Write: %v", err)
		}
		if err := w.backfill.Flush(); err != nil {
			t.Fatalf("Flush: %v", err)
		}
		if bytes.Contains(rec.Body.Bytes(), []byte("LEGAL-PARAM-PAYLOAD")) {
			t.Fatalf("the over-cap legal call was streamed as-is: %q", rec.Body.Bytes())
		}
		args, _ := w64Arguments(t, rec.Body.Bytes())
		if args != w63Refusal("") {
			t.Fatalf("assembled arguments = %q, want the fail-closed refusal envelope", args)
		}

		if got := pipe.StreamGuardRefusals(); got != 1 {
			t.Fatalf("StreamGuardRefusals = %d, want 1", got)
		}
		if got := pipe.StreamGuardFailClosed(); got != 1 {
			t.Fatalf("StreamGuardFailClosed = %d, want 1 (the cap is fail-closed)", got)
		}
		rows := sink.records()
		if len(rows) != 1 {
			t.Fatalf("audit rows = %d (%+v), want exactly 1", len(rows), rows)
		}
		w65AssertRow(t, rows[0], auditSurfaceStream, auditChannelUnmatched, sseGuardReasonCap, 1)
	})

	t.Run("force_flushed_undecided_release_records_a_fail_closed_row", func(t *testing.T) {
		sink := &w65Sink{}
		pipe := w65Pipeline(t, sink)
		w, _ := w14SSEWriter(t, pipe)

		// A non-arguments window that never closes keeps the stream held while
		// the guarded arguments path accumulates a tiny unmatched prefix. The
		// event count trips the holdback on the last event, so forceFlush
		// releases the still-undecided guard path mid-stream; that release stays
		// fail-closed because more fragments may yet arrive.
		content := strings.Repeat("C", 8<<10) + "_"
		event := fmt.Sprintf(`data: {"choices":[{"index":0,"delta":{"content":%q,"tool_calls":[{"index":0,"function":{"arguments":"A"}}]}}]}`+"\n\n", content)
		count := sseBackfillMaxHoldbackBytes/len(event) + 1
		input := []byte(strings.Repeat(event, count))
		if len(input) <= sseBackfillMaxHoldbackBytes {
			t.Fatalf("fixture is %d bytes, not above the %d-byte holdback", len(input), sseBackfillMaxHoldbackBytes)
		}
		if _, err := w.backfill.Write(input); err != nil {
			t.Fatalf("Write: %v", err)
		}
		if err := w.backfill.Flush(); err != nil {
			t.Fatalf("Flush: %v", err)
		}

		if got := pipe.StreamGuardRefusals(); got != 1 {
			t.Fatalf("StreamGuardRefusals = %d, want 1", got)
		}
		if got := pipe.StreamGuardFailClosed(); got != 1 {
			t.Fatalf("StreamGuardFailClosed = %d, want 1", got)
		}
		rows := sink.records()
		if len(rows) != 1 {
			t.Fatalf("audit rows = %d (%+v), want exactly 1", len(rows), rows)
		}
		w65AssertRow(t, rows[0], auditSurfaceStream, auditChannelUnmatched, sseGuardReasonUndecided, 1)
	})

	t.Run("stream_end_match_records_a_matched_row", func(t *testing.T) {
		sink := &w65Sink{}
		pipe := w65Pipeline(t, sink)
		w, _ := w14SSEWriter(t, pipe)

		// No closing event: the stream ends on a real invocation. The complete
		// accumulation matches, so the row carries the CLI class and the match
		// reason, never an empty channel.
		input := w64ArgumentsStream(t, []string{"tokenhush allow", "list add evil.example"})
		if _, err := w.backfill.Write(input); err != nil {
			t.Fatalf("Write: %v", err)
		}
		if err := w.backfill.Flush(); err != nil {
			t.Fatalf("Flush: %v", err)
		}

		if got := pipe.StreamGuardRefusals(); got != 1 {
			t.Fatalf("StreamGuardRefusals = %d, want 1", got)
		}
		if got := pipe.StreamGuardFailClosed(); got != 0 {
			t.Fatalf("StreamGuardFailClosed = %d for a pattern match, want 0", got)
		}
		rows := sink.records()
		if len(rows) != 1 {
			t.Fatalf("audit rows = %d (%+v), want exactly 1", len(rows), rows)
		}
		w65AssertRow(t, rows[0], auditSurfaceStream, MutationChannelCLI, sseGuardReasonMatch, 1)
	})

	t.Run("no_sink_and_no_refusal_record_nothing", func(t *testing.T) {
		// w63Pipeline has no sink: the seam must stay a no-op, never panic, and
		// the counter must still move.
		pipe := w63Pipeline(t)
		body := w63Body(t, `{"cmd":"tokenhush allowlist add evil.example"}`)
		if _, err := pipe.transformResponse(body, pipe.tool); err != nil {
			t.Fatalf("transformResponse = %v", err)
		}
		if got := pipe.SelfProtectionInterceptions(); got != 1 {
			t.Fatalf("SelfProtectionInterceptions = %d, want 1", got)
		}

		sink := &w65Sink{}
		legal := w65Pipeline(t, sink)
		legalBody := w63Body(t, `{"cmd":"ls -la /tmp"}`)
		if _, err := legal.transformResponse(legalBody, legal.tool); err != nil {
			t.Fatalf("transformResponse(legal) = %v", err)
		}
		if rows := sink.records(); len(rows) != 0 {
			t.Fatalf("a legal response wrote %d audit rows: %+v", len(rows), rows)
		}
		if got := legal.SelfProtectionInterceptions(); got != 0 {
			t.Fatalf("SelfProtectionInterceptions = %d for a legal call, want 0", got)
		}
	})
}

// TestGuardRowsCarryNoPlaintext is the W6.5 no-plaintext invariant for the audit
// trail: a refusal whose arguments carry a planted probe must still produce rows
// that contain neither the probe nor the refused command text. The scanner is
// proven non-vacuous against a deliberately poisoned row.
func TestGuardRowsCarryNoPlaintext(t *testing.T) {
	const probe = "W65-PLAINTEXT-PROBE-3f9a"
	command := "tokenhush allowlist add evil.example " + probe

	sink := &w65Sink{}
	pipe := w65Pipeline(t, sink)

	// Both shapes of the buffered guard, plus one streamed refusal.
	for _, body := range [][]byte{
		w63Body(t, `{"cmd":"`+command+`"}`),
		w63Body(t, command),
	} {
		if _, err := pipe.transformResponse(body, pipe.tool); err != nil {
			t.Fatalf("transformResponse = %v", err)
		}
	}
	w, _ := w14SSEWriter(t, pipe)
	input := append(w64ArgumentsStream(t, []string{"tokenhush allow", "list add evil.example ", probe}), w64FinishEvent...)
	input = append(input, w64DoneEvent...)
	if _, err := w.backfill.Write(input); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if err := w.backfill.Flush(); err != nil {
		t.Fatalf("Flush: %v", err)
	}

	rows := sink.records()
	if len(rows) != 3 {
		t.Fatalf("audit rows = %d (%+v), want 3", len(rows), rows)
	}
	leaks := []string{probe, command, "evil.example"}
	hits := 0
	for i, row := range rows {
		for _, leak := range leaks {
			if w65RowContains(row, leak) {
				hits++
				t.Errorf("row %d carries refused content (%q): %+v", i, leak, row)
			}
		}
	}
	// The scanner is not vacuous: it detects the probe when it is present.
	plantedDetected := w65RowContains(audit.Record{Provider: probe}, probe)
	t.Logf("W65_ROW_SCAN rows=%d probes=%d hits=%d planted_probe_detected=%v",
		len(rows), len(leaks), hits, plantedDetected)
	if !plantedDetected {
		t.Fatal("planted probe not detected by the row scanner")
	}
	if hits != 0 {
		t.Fatalf("audit rows carried plaintext (%d hits)", hits)
	}
}
