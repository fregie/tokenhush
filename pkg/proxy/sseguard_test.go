package proxy

// W6.4 regressions: the SSE response path gets the C8 mutation-channel guard.
// A tool call's `arguments` path accumulates its streamed fragments under a
// bounded cap (SSEGuardCap) and the tool call is refused — the whole arguments
// value is replaced by the W6.3 refusal notice — as soon as a W6.2 pattern
// matches after accumulation, when the accumulation reaches the cap without a
// decision, or when a not-yet-decided path is released by forceFlush/stream
// end. Every other streaming path stays unbounded and byte-identical.
// See sseguard.go, ssebackfill.go and responseguard.go.

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/fregie/tokenhush/pkg/protocol"
)

// w64ArgumentsEvent renders one OpenAI-shaped streamed tool-call delta carrying
// one decoded arguments fragment; an OpenAI client concatenates those fragments
// across events to recover the tool call's arguments value.
func w64ArgumentsEvent(t *testing.T, fragment string) []byte {
	t.Helper()
	quoted, err := json.Marshal(fragment)
	if err != nil {
		t.Fatalf("marshal arguments fragment: %v", err)
	}
	return []byte(`data: {"choices":[{"index":0,"delta":{"tool_calls":[{"index":0,"function":{"arguments":` +
		string(quoted) + `}}]}}]}` + "\n\n")
}

// w64FinishEvent ends a tool-call stream without an arguments leaf, so the guard
// observes the arguments path stop receiving fragments (a path change).
var w64FinishEvent = []byte(`data: {"choices":[{"index":0,"delta":{},"finish_reason":"tool_calls"}]}` + "\n\n")

// w64DoneEvent is the OpenAI stream terminator.
var w64DoneEvent = []byte("data: [DONE]\n\n")

// w64ArgumentsStream frames every fragment as its own event.
func w64ArgumentsStream(t *testing.T, fragments []string) []byte {
	t.Helper()
	var out bytes.Buffer
	for _, f := range fragments {
		out.Write(w64ArgumentsEvent(t, f))
	}
	return out.Bytes()
}

// w64Arguments replays a client's SSE decoding over out and concatenates every
// `arguments` delta — exactly what an OpenAI client does to assemble the tool
// call — and reports how many events carried an arguments leaf.
func w64Arguments(t *testing.T, out []byte) (string, int) {
	t.Helper()
	dec := protocol.NewSSEDecoder()
	events := append(dec.Feed(out), dec.Close()...)
	var args strings.Builder
	count := 0
	for _, ev := range events {
		if !ev.DataSingle {
			continue
		}
		payload := ev.Raw[ev.DataOffset : ev.DataOffset+ev.DataLen]
		leaves, err := protocol.Walk(payload)
		if err != nil {
			continue
		}
		for _, leaf := range leaves {
			if leaf.Encoded || !isMutationChannelArgumentsPath(leaf.Path) {
				continue
			}
			args.WriteString(leaf.Content)
			count++
		}
	}
	return args.String(), count
}

// w64Refusal records one guard refusal observed on a directly-constructed
// backfiller: the matched channel class ("" when no pattern matched) and the
// documented refusal reason.
type w64Refusal struct {
	class  string
	reason string
}

// w64GuardBackfiller builds a backfiller with the real W6.2 detector installed
// and returns it together with the refusal recorder, so a test can assert the
// refusal reason the pipeline counter collapses.
func w64GuardBackfiller(t *testing.T, dst *bytes.Buffer) (*sseBackfiller, *[]w64Refusal) {
	t.Helper()
	detect := w63Pipeline(t).DetectMutationChannel
	refusals := &[]w64Refusal{}
	b := newSSEBackfiller(dst, 128, t4Replace)
	b.setToolCallGuard(detect, func(class, reason string) {
		*refusals = append(*refusals, w64Refusal{class: class, reason: reason})
	})
	return b, refusals
}

// w64BigLegalArguments returns the argument fragments of one legal (never
// matching) tool call whose assembled arguments exceed SSEGuardCap by a margin,
// while the held raw events stay below sseBackfillMaxHoldbackBytes — so the
// guard's own cap, not the backfiller's holdback, is what trips.
func w64BigLegalArguments() []string {
	const marker = "LEGAL-PARAM-PAYLOAD"
	payload := SSEGuardCap + SSEGuardCap/4
	doc := `{"path":"/tmp/big.bin","content":"` + marker +
		strings.Repeat("A", payload-len(marker)) + `"}`
	const chunk = 4 << 10
	var fragments []string
	for len(doc) > 0 {
		n := min(chunk, len(doc))
		fragments = append(fragments, doc[:n])
		doc = doc[n:]
	}
	return fragments
}

// TestSSEToolCallGuard is the W6.4 acceptance test.
func TestSSEToolCallGuard(t *testing.T) {
	notice := mutationChannelRefusalNotice

	t.Run("cap_is_frozen_at_or_below_the_holdback", func(t *testing.T) {
		// The cap must be explicitly defined, positive, and never above the
		// holdback: past sseBackfillMaxHoldbackBytes the backfiller
		// force-flushes and a larger cap could never be reached.
		if SSEGuardCap <= 0 {
			t.Fatalf("SSEGuardCap = %d, want a positive bound", SSEGuardCap)
		}
		if SSEGuardCap != 64<<10 {
			t.Fatalf("SSEGuardCap = %d, want the frozen 64 KiB", SSEGuardCap)
		}
		if SSEGuardCap > sseBackfillMaxHoldbackBytes {
			t.Fatalf("SSEGuardCap = %d exceeds sseBackfillMaxHoldbackBytes = %d",
				SSEGuardCap, sseBackfillMaxHoldbackBytes)
		}
		t.Logf("SSEGuardCap=%d sseBackfillMaxHoldbackBytes=%d", SSEGuardCap, sseBackfillMaxHoldbackBytes)
	})

	t.Run("legal_call_under_cap_passes_byte_identical", func(t *testing.T) {
		pipe := w63Pipeline(t)
		reporter, events := w14Reporter()
		pipe.SetRedactionReporter(reporter)
		w, rec := w14SSEWriter(t, pipe)

		fragments := []string{`{"path":"/tmp/`, `report.txt","content":`, `"hello world`, `"}`}
		input := append(w64ArgumentsStream(t, fragments), w64FinishEvent...)
		input = append(input, w64DoneEvent...)

		if _, err := w.backfill.Write(input); err != nil {
			t.Fatalf("Write: %v", err)
		}
		if err := w.backfill.Flush(); err != nil {
			t.Fatalf("Flush: %v", err)
		}
		out := rec.Body.Bytes()
		if !bytes.Equal(out, input) {
			t.Fatalf("a legal streamed tool call was rewritten:\n got %q\nwant %q", out, input)
		}
		if got := pipe.StreamGuardRefusals(); got != 0 {
			t.Fatalf("StreamGuardRefusals = %d for a legal call, want 0", got)
		}
		if got := pipe.StreamGuardFailClosed(); got != 0 {
			t.Fatalf("StreamGuardFailClosed = %d for a legal call, want 0", got)
		}
		if len(*events) != 0 {
			t.Fatalf("reporter events = %d (%+v), want 0", len(*events), *events)
		}
		args, n := w64Arguments(t, out)
		want := `{"path":"/tmp/report.txt","content":"hello world"}`
		if args != want || n != len(fragments) {
			t.Fatalf("assembled arguments = %q (%d events), want %q (%d)", args, n, want, len(fragments))
		}
	})

	t.Run("command_split_across_events_is_matched_after_accumulation", func(t *testing.T) {
		pipe := w63Pipeline(t)
		reporter, events := w14Reporter()
		pipe.SetRedactionReporter(reporter)
		w, rec := w14SSEWriter(t, pipe)

		// No single fragment, and no single event, carries the command; only the
		// accumulation of all three does.
		fragments := []string{"token", "hush allow", "list add evil.example MARK-HIT"}
		input := append(w64ArgumentsStream(t, fragments), w64FinishEvent...)
		input = append(input, w64DoneEvent...)

		if _, err := w.backfill.Write(input); err != nil {
			t.Fatalf("Write: %v", err)
		}
		if err := w.backfill.Flush(); err != nil {
			t.Fatalf("Flush: %v", err)
		}
		out := rec.Body.Bytes()
		t.Logf("W64_SPLIT_IN=%q", input)
		t.Logf("W64_SPLIT_OUT=%q", out)
		if bytes.Contains(out, []byte("MARK-HIT")) || bytes.Contains(out, []byte("evil.example")) {
			t.Fatalf("a fragment of the split command survived: %q", out)
		}
		args, n := w64Arguments(t, out)
		if args != notice || n != len(fragments) {
			t.Fatalf("assembled arguments = %q (%d events), want the notice (%d events)", args, n, len(fragments))
		}
		if got := pipe.StreamGuardRefusals(); got != 1 {
			t.Fatalf("StreamGuardRefusals = %d, want 1", got)
		}
		if got := pipe.StreamGuardFailClosed(); got != 0 {
			t.Fatalf("StreamGuardFailClosed = %d for a pattern match, want 0", got)
		}
		if len(*events) != 1 {
			t.Fatalf("reporter events = %d (%+v), want exactly 1", len(*events), *events)
		}
		if gotEvent := (*events)[0]; gotEvent.Action != RedactionActionMutationChannelBlocked ||
			gotEvent.Type != MutationChannelCLI || gotEvent.Direction != RedactionDirectionResponse {
			t.Fatalf("event = %+v, want the mutation-channel block event for %s", gotEvent, MutationChannelCLI)
		}
		// Framing is preserved: every input event still produced one record.
		if got, want := strings.Count(string(out), "\n\n"), len(fragments)+2; got != want {
			t.Fatalf("event count = %d, want %d: %q", got, want, out)
		}
	})

	t.Run("fragments_after_the_hit_are_dropped", func(t *testing.T) {
		pipe := w63Pipeline(t)
		w, rec := w14SSEWriter(t, pipe)

		fragments := []string{
			"token", "hush allow", "list add MARK-HIT",
			" && MARK-AFTER-1", " && MARK-AFTER-2",
		}
		input := append(w64ArgumentsStream(t, fragments), w64FinishEvent...)
		input = append(input, w64DoneEvent...)

		if _, err := w.backfill.Write(input); err != nil {
			t.Fatalf("Write: %v", err)
		}
		if err := w.backfill.Flush(); err != nil {
			t.Fatalf("Flush: %v", err)
		}
		out := rec.Body.Bytes()
		t.Logf("W64_POSTHIT_OUT=%q", out)
		for _, marker := range []string{"MARK-HIT", "MARK-AFTER-1", "MARK-AFTER-2"} {
			if bytes.Contains(out, []byte(marker)) {
				t.Fatalf("post-hit fragment %q reached the client: %q", marker, out)
			}
		}
		args, n := w64Arguments(t, out)
		if args != notice || n != len(fragments) {
			t.Fatalf("assembled arguments = %q (%d events), want the notice (%d events)", args, n, len(fragments))
		}
		if got := strings.Count(string(out), notice); got != 1 {
			t.Fatalf("refusal notice appears %d times, want exactly 1", got)
		}
		if got := pipe.StreamGuardRefusals(); got != 1 {
			t.Fatalf("StreamGuardRefusals = %d, want 1 (post-hit fragments must not re-refuse)", got)
		}
	})

	t.Run("over_cap_legal_call_is_refused_and_counted", func(t *testing.T) {
		pipe := w63Pipeline(t)
		reporter, events := w14Reporter()
		pipe.SetRedactionReporter(reporter)
		w, rec := w14SSEWriter(t, pipe)

		fragments := w64BigLegalArguments()
		total := 0
		for _, f := range fragments {
			total += len(f)
		}
		if total <= SSEGuardCap {
			t.Fatalf("fixture arguments are %d bytes, not above the %d-byte cap", total, SSEGuardCap)
		}
		input := append(w64ArgumentsStream(t, fragments), w64FinishEvent...)
		input = append(input, w64DoneEvent...)

		if _, err := w.backfill.Write(input); err != nil {
			t.Fatalf("Write: %v", err)
		}
		if err := w.backfill.Flush(); err != nil {
			t.Fatalf("Flush: %v", err)
		}
		out := rec.Body.Bytes()
		if bytes.Contains(out, []byte("LEGAL-PARAM-PAYLOAD")) {
			t.Fatalf("the over-cap legal call was streamed as-is instead of refused: %q", out)
		}
		args, _ := w64Arguments(t, out)
		if args != notice {
			t.Fatalf("assembled arguments = %q, want the refusal notice", args)
		}
		if got := pipe.StreamGuardRefusals(); got != 1 {
			t.Fatalf("StreamGuardRefusals = %d, want 1", got)
		}
		if got := pipe.StreamGuardFailClosed(); got != 1 {
			t.Fatalf("StreamGuardFailClosed = %d, want 1 (the cap is fail-closed)", got)
		}
		if len(*events) != 1 || (*events)[0].Action != RedactionActionMutationChannelBlocked {
			t.Fatalf("reporter events = %+v, want exactly one mutation-channel block", *events)
		}
	})

	t.Run("cap_exhaustion_is_attributed_to_the_cap_not_a_match", func(t *testing.T) {
		var dst bytes.Buffer
		b, refusals := w64GuardBackfiller(t, &dst)
		fragments := w64BigLegalArguments()
		input := append(w64ArgumentsStream(t, fragments), w64FinishEvent...)

		if _, err := b.Write(input); err != nil {
			t.Fatalf("Write: %v", err)
		}
		if err := b.Flush(); err != nil {
			t.Fatalf("Flush: %v", err)
		}
		if len(*refusals) != 1 {
			t.Fatalf("refusals = %d (%+v), want exactly 1", len(*refusals), *refusals)
		}
		if got := (*refusals)[0]; got.reason != sseGuardReasonCap || got.class != "" {
			t.Fatalf("refusal = %+v, want reason %q with no matched class", got, sseGuardReasonCap)
		}
		args, _ := w64Arguments(t, dst.Bytes())
		if args != mutationChannelRefusalNotice {
			t.Fatalf("assembled arguments = %q, want the refusal notice", args)
		}
		if bytes.Contains(dst.Bytes(), []byte("LEGAL-PARAM-PAYLOAD")) {
			t.Fatalf("the over-cap legal payload survived: %q", dst.Bytes())
		}
	})

	t.Run("non_arguments_path_is_unbounded_and_untouched", func(t *testing.T) {
		pipe := w63Pipeline(t)
		w, rec := w14SSEWriter(t, pipe)

		var in bytes.Buffer
		// A small, legal tool call so the guard is armed and active.
		in.Write(w64ArgumentsEvent(t, `{"path":"/tmp/x"}`))
		// A non-arguments path far above SSEGuardCap must stream unbounded.
		const chunk = 8 << 10
		for written := 0; written < SSEGuardCap*2; written += chunk {
			fmt.Fprintf(&in, `data: {"choices":[{"index":0,"delta":{"content":%q}}]}`+"\n\n",
				strings.Repeat("B", chunk))
		}
		in.Write(w64FinishEvent)
		in.Write(w64DoneEvent)
		input := in.Bytes()

		if _, err := w.backfill.Write(input); err != nil {
			t.Fatalf("Write: %v", err)
		}
		if err := w.backfill.Flush(); err != nil {
			t.Fatalf("Flush: %v", err)
		}
		if got := rec.Body.Bytes(); !bytes.Equal(got, input) {
			t.Fatalf("an oversized non-arguments path was rewritten (len got %d, want %d)", len(got), len(input))
		}
		if got := pipe.StreamGuardRefusals(); got != 0 {
			t.Fatalf("StreamGuardRefusals = %d for a non-arguments path, want 0", got)
		}
	})

	t.Run("path_released_at_stream_end_without_a_decision_is_refused", func(t *testing.T) {
		var dst bytes.Buffer
		b, refusals := w64GuardBackfiller(t, &dst)
		// Two legal fragments, no closing event: the stream ends while the
		// guard is undecided, so the tool call is refused (fail-closed).
		input := w64ArgumentsStream(t, []string{`{"path":"/tmp/`, `report.txt"}`})

		if _, err := b.Write(input); err != nil {
			t.Fatalf("Write: %v", err)
		}
		if err := b.Flush(); err != nil {
			t.Fatalf("Flush: %v", err)
		}
		if len(*refusals) != 1 {
			t.Fatalf("refusals = %d (%+v), want exactly 1", len(*refusals), *refusals)
		}
		if got := (*refusals)[0]; got.reason != sseGuardReasonUndecided || got.class != "" {
			t.Fatalf("refusal = %+v, want reason %q", got, sseGuardReasonUndecided)
		}
		args, _ := w64Arguments(t, dst.Bytes())
		if args != mutationChannelRefusalNotice {
			t.Fatalf("assembled arguments = %q, want the refusal notice", args)
		}
	})

	t.Run("force_flush_releases_an_undecided_guard_path_as_a_refusal", func(t *testing.T) {
		var dst bytes.Buffer
		b, refusals := w64GuardBackfiller(t, &dst)

		// Each event advances a non-arguments window that never closes (its
		// trailing '_' may still start a placeholder) while the guarded
		// arguments path accumulates a tiny unmatched prefix. The event count is
		// chosen so the held bytes first pass sseBackfillMaxHoldbackBytes on the
		// LAST event: forceFlush then releases the undecided guard path, which
		// must be refused, never drained as original bytes.
		content := strings.Repeat("C", 8<<10) + "_"
		event := fmt.Sprintf(`data: {"choices":[{"index":0,"delta":{"content":%q,"tool_calls":[{"index":0,"function":{"arguments":"A"}}]}}]}`+"\n\n", content)
		count := sseBackfillMaxHoldbackBytes/len(event) + 1
		if (count-1)*len(event) > sseBackfillMaxHoldbackBytes {
			t.Fatalf("fixture would trip the holdback before the last event")
		}
		input := []byte(strings.Repeat(event, count))
		if len(input) <= sseBackfillMaxHoldbackBytes {
			t.Fatalf("fixture is %d bytes, not above the %d-byte holdback", len(input), sseBackfillMaxHoldbackBytes)
		}

		if _, err := b.Write(input); err != nil {
			t.Fatalf("Write: %v", err)
		}
		// The holdback must have tripped during Write so held events were
		// emitted mid-stream (that is what proves forceFlush ran).
		if dst.Len() == 0 {
			t.Fatalf("holdback did not force-flush anything during Write")
		}
		if _, err := b.Write(w64FinishEvent); err != nil {
			t.Fatalf("Write(finish): %v", err)
		}
		if err := b.Flush(); err != nil {
			t.Fatalf("Flush: %v", err)
		}
		if len(*refusals) != 1 {
			t.Fatalf("refusals = %d (%+v), want exactly 1", len(*refusals), *refusals)
		}
		if got := (*refusals)[0]; got.reason != sseGuardReasonUndecided || got.class != "" {
			t.Fatalf("refusal = %+v, want reason %q", got, sseGuardReasonUndecided)
		}
		args, _ := w64Arguments(t, dst.Bytes())
		if args != mutationChannelRefusalNotice {
			t.Fatalf("assembled arguments = %q, want the refusal notice", args)
		}
	})
}
