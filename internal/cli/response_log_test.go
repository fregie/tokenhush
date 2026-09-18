package cli

import (
	"strings"
	"testing"

	"github.com/fregie/tokenhush/pkg/redact"
)

// mintedBackfiller returns a session backfiller and the placeholder it minted
// for one email secret.
func mintedBackfiller(t *testing.T) (*redact.Backfiller, string) {
	t.Helper()
	b := redact.NewBackfiller()
	placeholder, err := b.Mint(redact.NewForwardWriter(nil), []byte("__PII_email_3751b87e112f__"), "email")
	if err != nil {
		t.Fatalf("Mint: %v", err)
	}
	return b, placeholder
}

// TestResponseLogReportsRestores pins that the response path logs one
// metadata-only line naming the restored count and nothing else.
func TestResponseLogReportsRestores(t *testing.T) {
	b, placeholder := mintedBackfiller(t)
	var out strings.Builder

	got := newResponseLog(b, &out, true).Backfill([]byte("hi " + placeholder + " and " + placeholder))
	if strings.Contains(string(got), placeholder) {
		t.Fatalf("placeholders survived: %s", got)
	}
	if want := "tokenhush: restored response placeholders=2\n"; out.String() != want {
		t.Fatalf("log = %q, want %q", out.String(), want)
	}
}

// TestResponseLogIsSilencedByTheFlagAndForeignTokens pins that the switch and an
// unknown token both keep the response path quiet.
func TestResponseLogIsSilencedByTheFlagAndForeignTokens(t *testing.T) {
	b, placeholder := mintedBackfiller(t)

	var silenced strings.Builder
	newResponseLog(b, &silenced, false).Backfill([]byte(placeholder))
	if silenced.Len() != 0 {
		t.Fatalf("disabled response log wrote %q", silenced.String())
	}

	var foreign strings.Builder
	newResponseLog(redact.NewBackfiller(), &foreign, true).Backfill([]byte("__PII_email_deadbeefcafe__"))
	if foreign.Len() != 0 {
		t.Fatalf("foreign token wrote %q", foreign.String())
	}
}
