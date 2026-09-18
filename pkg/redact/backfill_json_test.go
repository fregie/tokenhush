package redact

import (
	"bytes"
	"encoding/json"
	"testing"
)

// pemSecret is the headline restore shape: a multi-line PEM whose JSON string
// spelling needs `\n` escapes, not raw newlines.
var pemSecret = []byte("-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkq\nhkiG9w0BAQEFAASC\n-----END PRIVATE KEY-----\n")

// decodeJSONObject fails the test unless body is valid JSON and returns its
// decoded object. Every buffered JSON assertion goes through this, so a
// malformed splice fails as invalid JSON before any value comparison.
func decodeJSONObject(t *testing.T, body []byte) map[string]any {
	t.Helper()
	if !json.Valid(body) {
		t.Fatalf("backfilled body is not valid JSON: %q", body)
	}
	var got map[string]any
	if err := json.Unmarshal(body, &got); err != nil {
		t.Fatalf("json.Unmarshal(%q): %v", body, err)
	}
	return got
}

// quotedValue renders secret as the JSON string literal of a value slot.
func quotedValue(t *testing.T, secret []byte) string {
	t.Helper()
	quoted, err := json.Marshal(string(secret))
	if err != nil {
		t.Fatalf("json.Marshal(secret): %v", err)
	}
	return string(quoted)
}

func TestBackfillJSONBodyEscapesPEMSecret(t *testing.T) {
	back, p := mintRestorable(t, pemSecret, "private_key")
	body := []byte(`{"content":"` + p + `"}`)

	out := back.Backfill(body)
	if got := decodeJSONObject(t, out)["content"]; got != string(pemSecret) {
		t.Fatalf("decoded content = %q, want the original PEM %q", got, pemSecret)
	}
	if bytes.Contains(out, []byte(placeholderPrefix)) {
		t.Fatalf("placeholder survived Backfill: %q", out)
	}
}

func TestBackfillJSONBodyEscapesQuoteBackslashSecret(t *testing.T) {
	secret := []byte("pass\\word\" with quote\nand newline")
	back, p := mintRestorable(t, secret, "api_key")
	body := []byte(`{"k":"` + p + `"}`)

	out := back.Backfill(body)
	if got := decodeJSONObject(t, out)["k"]; got != string(secret) {
		t.Fatalf("decoded k = %q, want %q", got, secret)
	}
	if bytes.Contains(out, []byte(placeholderPrefix)) {
		t.Fatalf("placeholder survived Backfill: %q", out)
	}
}

func TestBackfillJSONInJSONDepthTwoStaysParseable(t *testing.T) {
	secret := []byte("line1\n\"quoted\"\\end")
	back, p := mintRestorable(t, secret, "api_key")

	inner, err := json.Marshal(map[string]string{"inner": p})
	if err != nil {
		t.Fatalf("marshal inner: %v", err)
	}
	body, err := json.Marshal(map[string]string{"outer": string(inner)})
	if err != nil {
		t.Fatalf("marshal outer: %v", err)
	}

	out := back.Backfill(body)
	outerValue, ok := decodeJSONObject(t, out)["outer"].(string)
	if !ok {
		t.Fatalf("outer value is not a string in %q", out)
	}
	if !json.Valid([]byte(outerValue)) {
		t.Fatalf("inner decoded JSON is invalid: %q", outerValue)
	}
	var leaf map[string]string
	if err := json.Unmarshal([]byte(outerValue), &leaf); err != nil {
		t.Fatalf("unmarshal inner: %v", err)
	}
	if leaf["inner"] != string(secret) {
		t.Fatalf("inner value = %q, want %q", leaf["inner"], secret)
	}
	if bytes.Contains(out, []byte(placeholderPrefix)) {
		t.Fatalf("placeholder survived a depth-2 body: %q", out)
	}
}

func TestBackfillJSONObjectKeyGetsOneEscapeLevel(t *testing.T) {
	secret := []byte("key\\with\"meta\nline")
	back, p := mintRestorable(t, secret, "api_key")
	body := []byte(`{"` + p + `":"v"}`)

	out := back.Backfill(body)
	if !json.Valid(out) {
		t.Fatalf("key restore produced invalid JSON: %q", out)
	}
	var got map[string]string
	if err := json.Unmarshal(out, &got); err != nil {
		t.Fatalf("json.Unmarshal(%q): %v", out, err)
	}
	if got[string(secret)] != "v" {
		t.Fatalf("decoded key set = %v, want the restored secret as key", got)
	}
	if bytes.Contains(out, []byte(placeholderPrefix)) {
		t.Fatalf("placeholder survived in a key: %q", out)
	}
}

func TestBackfillPlainTextStillSplicesRawSecret(t *testing.T) {
	back, p := mintRestorable(t, pemSecret, "private_key")
	body := []byte("echo " + p + " tail")

	out := back.Backfill(body)
	want := bytes.ReplaceAll(body, []byte(p), pemSecret)
	if !bytes.Equal(out, want) {
		t.Fatalf("plain-text Backfill = %q, want the raw splice %q", out, want)
	}
}

func TestBackfillJSONExcludedSecretUntouched(t *testing.T) {
	back, p := mintRestorable(t, pemSecret, "private_key")
	back.ExcludeFromBackfill(pemSecret)
	body := []byte(`{"k":"` + p + `"}`)

	out := back.Backfill(body)
	if !bytes.Equal(out, body) {
		t.Fatalf("excluded secret was consumed: %q, want %q", out, body)
	}
	if !bytes.Contains(out, []byte(p)) {
		t.Fatalf("excluded placeholder vanished: %q", out)
	}
}

func TestBackfillJSONForeignPlaceholderUntouched(t *testing.T) {
	back, _ := mintRestorable(t, []byte("alice@example.com"), "email")
	const foreign = "__PII_email_deadbeefcafe__"
	body := []byte(`{"k":"` + foreign + `","v":"keep"}`)

	out := back.Backfill(body)
	if !bytes.Equal(out, body) {
		t.Fatalf("foreign placeholder body changed: %q, want %q", out, body)
	}
}

func TestBackfillJSONIdempotent(t *testing.T) {
	back, p := mintRestorable(t, pemSecret, "private_key")
	body := []byte(`{"content":"` + p + `","nested":"` + p + `"}`)

	once := back.Backfill(body)
	twice := back.Backfill(once)
	if !bytes.Equal(twice, once) {
		t.Fatalf("second Backfill changed the body:\n once %q\ntwice %q", once, twice)
	}
	got := decodeJSONObject(t, once)["content"]
	if got != string(pemSecret) {
		t.Fatalf("decoded content = %q, want %q", got, pemSecret)
	}
}
