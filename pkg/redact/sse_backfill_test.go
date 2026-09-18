package redact

import (
	"bytes"
	"strings"
	"testing"

	"github.com/fregie/tokenhush/pkg/protocol"
)

// sseRecord renders one SSE record carrying a single data line.
func sseRecord(event, data string) string {
	return "event: " + event + "\ndata: " + data + "\n\n"
}

// mintRestorable mints a placeholder for secret and records its reverse
// mapping on a fresh session backfiller.
func mintRestorable(t *testing.T, secret []byte, kind string) (*Backfiller, string) {
	t.Helper()
	back := NewBackfiller()
	p, err := back.Mint(NewForwardWriter(newEngine()), secret, kind)
	if err != nil {
		t.Fatalf("Mint(%q, %q): %v", secret, kind, err)
	}
	return back, p
}

// decodeStream decodes every record of stream, including the Close flush.
func decodeStream(t *testing.T, stream []byte) []protocol.Event {
	t.Helper()
	dec := protocol.NewDecoder()
	events, err := dec.Feed(stream)
	if err != nil {
		t.Fatalf("Feed: %v", err)
	}
	tail, err := dec.Close()
	if err != nil {
		t.Fatalf("Close: %v", err)
	}
	return append(events, tail...)
}

// TestSSEBackfillRestoresSplitAcrossThreeDeltas: one placeholder split across
// three data payloads is restored exactly once, in the last payload, while the
// event framing survives untouched.
func TestSSEBackfillRestoresSplitAcrossThreeDeltas(t *testing.T) {
	secret := []byte("alice@example.com")
	back, p := mintRestorable(t, secret, "email")
	if len(p) <= 20 {
		t.Fatalf("placeholder %q is too short to split across three deltas", p)
	}

	in := sseRecord("delta", p[:8]) + sseRecord("delta", p[8:20]) + sseRecord("delta", p[20:]+" tail")
	out := NewSSEBackfiller(back, nil).process([]byte(in))

	if got := bytes.Count(out, secret); got != 1 {
		t.Fatalf("secret appears %d times, want exactly 1 in %q", got, out)
	}
	if bytes.Contains(out, []byte(placeholderLiteralPrefix)) {
		t.Fatalf("placeholder prefix survived in %q", out)
	}
	if got := strings.Count(string(out), "event: delta\n"); got != 3 {
		t.Fatalf("event: delta lines = %d, want 3 in %q", got, out)
	}

	events := decodeStream(t, out)
	if len(events) != 3 {
		t.Fatalf("event count = %d, want 3", len(events))
	}
	for i, ev := range events {
		if ev.Event != "delta" {
			t.Fatalf("event %d name = %q, want delta", i, ev.Event)
		}
	}
	for i := 0; i < 2; i++ {
		if got := string(events[i].Data); got != "" {
			t.Fatalf("event %d data = %q, want empty (bytes still held)", i, got)
		}
	}
	if got := string(events[2].Data); got != string(secret)+" tail" {
		t.Fatalf("event 2 data = %q, want %q", got, string(secret)+" tail")
	}

	// The framing is byte-preserved: only the data values changed.
	want := sseRecord("delta", "") + sseRecord("delta", "") + sseRecord("delta", string(secret)+" tail")
	if string(out) != want {
		t.Fatalf("process:\n got %q\nwant %q", out, want)
	}
}

// TestSSEBackfillNoMatchIsByteIdentical: a multi-event stream with nothing to
// restore round-trips byte-for-byte.
func TestSSEBackfillNoMatchIsByteIdentical(t *testing.T) {
	back, _ := mintRestorable(t, []byte("alice@example.com"), "email")

	in := sseRecord("delta", "plain text, nothing to restore") +
		sseRecord("message", "more plain text") +
		"id: 7\nretry: 250\ndata: third record\n\n"
	out := NewSSEBackfiller(back, nil).process([]byte(in))
	if !bytes.Equal(out, []byte(in)) {
		t.Fatalf("process changed a no-match stream:\n got %q\nwant %q", out, in)
	}
}

// TestSSEBackfillPreservesNonDeltaFields: id, retry and comment lines are not
// touched; only the data payload is rewritten.
func TestSSEBackfillPreservesNonDeltaFields(t *testing.T) {
	secret := "alice@example.com"
	back, p := mintRestorable(t, []byte(secret), "email")

	in := "id: 42\nretry: 1000\n: keepalive\nevent: delta\ndata: " + p + "\n\n"
	out := NewSSEBackfiller(back, nil).process([]byte(in))
	want := "id: 42\nretry: 1000\n: keepalive\nevent: delta\ndata: " + secret + "\n\n"
	if string(out) != want {
		t.Fatalf("process:\n got %q\nwant %q", out, want)
	}
	for _, kept := range []string{"id: 42\n", "retry: 1000\n", ": keepalive\n"} {
		if !strings.Contains(string(out), kept) {
			t.Fatalf("process dropped %q from %q", kept, out)
		}
	}
}

// TestSSEBackfillDoneAndPingPassThrough: sentinel and ping records are
// byte-identical passthrough.
func TestSSEBackfillDoneAndPingPassThrough(t *testing.T) {
	back, _ := mintRestorable(t, []byte("alice@example.com"), "email")

	for _, in := range []string{
		"data: [DONE]\n\n",
		"event: ping\ndata: alive\n\n",
		"data: [DONE]\n\nevent: ping\ndata: alive\n\n",
	} {
		out := NewSSEBackfiller(back, nil).process([]byte(in))
		if !bytes.Equal(out, []byte(in)) {
			t.Fatalf("process(%q) = %q, want byte-identical passthrough", in, out)
		}
	}
}

// TestSSEBackfillOutputLengthAccountsForReplacement: the output is shorter by
// exactly the placeholder length minus the secret length.
func TestSSEBackfillOutputLengthAccountsForReplacement(t *testing.T) {
	secret := []byte("alice@example.com")
	back, p := mintRestorable(t, secret, "email")

	in := sseRecord("delta", "before "+p+" after")
	out := NewSSEBackfiller(back, nil).process([]byte(in))
	if got, want := len(out), len(in)-len(p)+len(secret); got != want {
		t.Fatalf("len(out) = %d, want %d (input %d - placeholder %d + secret %d)",
			got, want, len(in), len(p), len(secret))
	}
	want := sseRecord("delta", "before "+string(secret)+" after")
	if string(out) != want {
		t.Fatalf("process:\n got %q\nwant %q", out, want)
	}
}

// TestSSEBackfillForeignPlaceholderUnchanged: a syntactically valid but unmapped
// placeholder is forwarded verbatim and never fabricated into a secret.
func TestSSEBackfillForeignPlaceholderUnchanged(t *testing.T) {
	back, _ := mintRestorable(t, []byte("alice@example.com"), "email")
	const foreign = "__PII_email_deadbeefcafe__"

	in := sseRecord("delta", "unknown "+foreign+" stays")
	out := NewSSEBackfiller(back, nil).process([]byte(in))
	if !bytes.Equal(out, []byte(in)) {
		t.Fatalf("process changed a foreign placeholder:\n got %q\nwant %q", out, in)
	}
	if !bytes.Contains(out, []byte(foreign)) {
		t.Fatalf("foreign placeholder %q vanished from %q", foreign, out)
	}
}

// TestSSEBackfillTailPrefixFlushedLiterally: data ending in a token prefix that
// never completes is flushed back into the same span, leaving the stream
// byte-identical.
func TestSSEBackfillTailPrefixFlushedLiterally(t *testing.T) {
	back, _ := mintRestorable(t, []byte("alice@example.com"), "email")

	in := sseRecord("delta", "hello __PII_")
	out := NewSSEBackfiller(back, nil).process([]byte(in))
	if !bytes.Equal(out, []byte(in)) {
		t.Fatalf("process:\n got %q\nwant the literal tail flushed back: %q", out, in)
	}
}
