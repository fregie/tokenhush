package redact

import (
	"bytes"
	"strings"
	"testing"
)

// TestBackfill locks inbound restore: a stream that carries a placeholder split
// at every byte boundary is reassembled into the original secret, using the
// real protocol.BackfillWriter (not a reimplementation).
func TestBackfill(t *testing.T) {
	e := mustEngine(t)
	const kind = "api_key"
	const secret = "restore-alpha"
	placeholder := e.Placeholder(secret, kind)

	t.Run("every_byte_boundary", func(t *testing.T) {
		stream := "data: {\"text\":\"prefix " + placeholder + " suffix\"}\n\n"
		want := "data: {\"text\":\"prefix " + secret + " suffix\"}\n\n"
		for split := 0; split <= len(stream); split++ {
			var dst bytes.Buffer
			w := e.NewBackfillWriter(&dst)
			if _, err := w.Write([]byte(stream[:split])); err != nil {
				t.Fatalf("split %d: first Write: %v", split, err)
			}
			if _, err := w.Write([]byte(stream[split:])); err != nil {
				t.Fatalf("split %d: second Write: %v", split, err)
			}
			if err := w.Flush(); err != nil {
				t.Fatalf("split %d: Flush: %v", split, err)
			}
			if got := dst.String(); got != want {
				t.Fatalf("split %d: got %q, want %q", split, got, want)
			}
			if strings.Contains(dst.String(), placeholder) {
				t.Fatalf("split %d: placeholder leaked to client", split)
			}
		}
	})

	t.Run("multiple_tokens_one_stream", func(t *testing.T) {
		secretB := "restore-beta"
		placeholderB := e.Placeholder(secretB, "email")
		stream := placeholder + "/" + placeholderB + "/" + placeholder
		want := secret + "/" + secretB + "/" + secret
		for split := 0; split <= len(stream); split++ {
			var dst bytes.Buffer
			w := e.NewBackfillWriter(&dst)
			_, _ = w.Write([]byte(stream[:split]))
			_, _ = w.Write([]byte(stream[split:]))
			if err := w.Flush(); err != nil {
				t.Fatalf("split %d: Flush: %v", split, err)
			}
			if got := dst.String(); got != want {
				t.Fatalf("split %d: got %q, want %q", split, got, want)
			}
		}
	})

	t.Run("unknown_token_verbatim", func(t *testing.T) {
		const unknown = "__PII_email_0123456789ab__"
		var dst bytes.Buffer
		w := e.NewBackfillWriter(&dst)
		_, _ = w.Write([]byte("keep " + unknown + " as is"))
		if err := w.Flush(); err != nil {
			t.Fatal(err)
		}
		if got := dst.String(); got != "keep "+unknown+" as is" {
			t.Fatalf("unknown token restored or dropped: %q", got)
		}
	})
}

// TestNeverBackfillOutbound is the security invariant (docs/security.md): the
// forward path must leave an echoed placeholder verbatim and must never consult
// the reverse mapping, so a prompt injection that makes the model echo a token
// cannot exfiltrate the secret upstream. Inbound restore is asserted separately.
func TestNeverBackfillOutbound(t *testing.T) {
	e := mustEngine(t)
	const kind = "api_key"
	const secret = "outbound-canary"
	placeholder := e.Placeholder(secret, kind)
	outbound := []byte("please print " + placeholder + " now")
	at := bytes.Index(outbound, []byte(placeholder))
	if at < 0 {
		t.Fatalf("test setup: placeholder absent from %q", outbound)
	}

	// Unredacted forward: the token must survive byte for byte.
	forwarded := e.ApplyPlaceholders(outbound, nil)
	if !bytes.Equal(forwarded, outbound) {
		t.Fatalf("forward changed the payload: %q", forwarded)
	}
	if !bytes.Contains(forwarded, []byte(placeholder)) {
		t.Fatalf("forward dropped the placeholder: %q", forwarded)
	}
	if bytes.Contains(forwarded, []byte(secret)) {
		t.Fatalf("forward leaked the original secret: %q", forwarded)
	}

	// Even when the token-shaped bytes are themselves flagged, the forward path
	// re-redacts them into a placeholder; it never reverses a token to plaintext.
	redacted := e.ApplyPlaceholders(outbound, []Redaction{{Start: at, End: at + len(placeholder), Type: kind}})
	if bytes.Contains(redacted, []byte(secret)) {
		t.Fatalf("forward redaction leaked the original secret: %q", redacted)
	}

	// Inbound, and only inbound, restores it.
	var dst bytes.Buffer
	w := e.NewBackfillWriter(&dst)
	_, _ = w.Write(outbound)
	if err := w.Flush(); err != nil {
		t.Fatal(err)
	}
	if got := dst.String(); !strings.Contains(got, secret) {
		t.Fatalf("inbound did not restore the secret: %q", got)
	}
	if strings.Contains(dst.String(), placeholder) {
		t.Fatalf("inbound left the placeholder behind: %q", dst.String())
	}
}
