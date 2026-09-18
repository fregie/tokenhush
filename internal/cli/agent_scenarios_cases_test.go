// agent_scenarios_cases_test.go holds the fixture bodies the scenario matrix
// drives. Dynamic payloads (the PEM, the JSON-in-JSON wrapper, the 1.5 MB leaf,
// the 40 KB data URL, the tool-call bodies) are built at run time; no large blob
// is checked in.
package cli

import (
	"encoding/json"
	"strings"
	"testing"
)

// agentGoFixture is a Go test file whose single email fixture must be redacted.
const agentGoFixture = `package contacts

import "testing"

func TestLookup(t *testing.T) {
	contact, err := Lookup("user@example.com")
	if err != nil {
		t.Fatalf("lookup: %v", err)
	}
	if contact == nil {
		t.Fatal("nil contact")
	}
}
`

// agentKeysInComments carries three provider keys inside comments.
const agentKeysInComments = `package main

// TODO(secrets): rotate AKIAIOSFODNN7EXAMPLE and the legacy
// ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789 before the release.
// The old client used sk-AbCdEfGhIjKlMnOpQrStUvWx.
`

// agentLuhnValidCard is a Luhn-valid test card that must be redacted, unlike
// the Luhn-invalid and all-same-digit fixtures.
const agentLuhnValidCard = "4242424242424242"

// agentPEM is a multi-line PEM private key: json.Marshal escapes its newlines,
// so the decoded span is not a raw substring and the substitution must map the
// span back to the raw bytes.
var agentPEM = strings.Join([]string{
	"-----BEGIN PRIVATE KEY-----",
	"MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC7VJTUt9Us8cKj",
	"MzEfYyjiWA4R4/M2bS1GB4t7NXp98C3SC6dVMvDuictGeurT8jNbvJZHtCSuYEvu",
	"NMoSfRZaYDapmCaQsGc6l9C1Cbh5zFvWqK4eS1R5KqZ1F9C0S3o2Rk=",
	"-----END PRIVATE KEY-----",
}, "\n")

// agentJWT is a structurally valid JWT fixture: its header decodes to JSON with
// an "alg" member, which is what the detector verifies.
const agentJWT = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIn0.c2lnbmF0dXJlLXRlc3Q"

// agentQuotedSecretContent renders the keyword-rule secret, which carries a
// double quote and a backslash, inside a sentence.
func agentQuotedSecretContent(quoted string) string {
	return "the literal " + quoted + " end"
}

// agentJSONInJSONBody wraps a properly encoded inner JSON document inside the
// JSON string of an outer request, so the secret sits behind two layers of
// string escaping.
func agentJSONInJSONBody(t *testing.T, quoted string) []byte {
	t.Helper()
	inner, err := json.Marshal(map[string]string{"note": agentQuotedSecretContent(quoted)})
	if err != nil {
		t.Fatalf("marshal the inner JSON: %v", err)
	}
	return redactJSONBody(t, string(inner))
}

// agentLargeLeaf returns a single string leaf that exceeds the old fixed 1 MiB
// detector cap with the secret at the very end.
func agentLargeLeaf(t *testing.T, secret string) string {
	t.Helper()
	content := strings.Repeat("A", 1536*1024) + " " + secret
	if len(content) <= 1<<20 {
		t.Fatalf("the large leaf (%d bytes) must exceed the old 1 MiB cap", len(content))
	}
	return content
}

// agentMultiSecretContent carries five distinct secrets of four categories in
// one ordinary configuration body.
const agentMultiSecretContent = "config: user@example.com AKIAIOSFODNN7EXAMPLE " +
	"card=4242424242424242 token=ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789 " +
	"key=sk-AbCdEfGhIjKlMnOpQrStUvWx"

// agentHexIdentifiers carries every legitimate hex shape that must not be
// mistaken for a credential: a 40-hex git SHA, a 16-hex short id, a 64-hex blob
// and a UUID.
const agentHexIdentifiers = "revision 0123456789abcdef0123456789abcdef01234567 " +
	"short 0123456789abcdef " +
	"blob 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef " +
	"uuid 550e8400-e29b-41d4-a716-446655440000"

// agentInvalidCards carries a Luhn-invalid 16-digit run and a Luhn-valid
// all-same-digit run, both of which the card detector must reject.
const agentInvalidCards = "rejected 4111111111111112 and repeated 0000000000000000"

// agentBareAt carries a localhost address and prose with a bare at sign.
const agentBareAt = "contact user@localhost or ping me @ home later"

// agentEmbeddedAKIA carries an AKIA-shaped run inside a longer word, which the
// token-boundary check must reject.
const agentEmbeddedAKIA = "embedded zAKIAIOSFODNN7EXAMPLEz inside a longer word"

// agentShortPrefixTokens carries a too-short sk- prefix and a short base64
// string.
const agentShortPrefixTokens = "too short sk-abc and a short base64 aGVsbG8="

// agentCertificate is a certificate block: its header shares the PEM shape but
// is not a private key, so it must never be redacted.
var agentCertificate = strings.Join([]string{
	"-----BEGIN CERTIFICATE-----",
	"MIIBszCCAVmgAwIBAgIUdummyCertificateBody000000000000000000000",
	"-----END CERTIFICATE-----",
}, "\n")

// agentURL is an ordinary API endpoint that must not be mistaken for anything.
const agentURL = "POST https://vibe.tran.so/v1/chat/completions with the session token"

// agentBase64PNG is the base64 of a 1x1 PNG; agentDataURL repeats it until the
// payload is ~40 KB, so no large blob is checked in.
const agentBase64PNG = "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mP8z8BQDwAEhQGAhKmMIQAAAABJRU5ErkJggg=="

// agentDataURL returns a data URL whose base64 body is ~40 KB.
func agentDataURL(t *testing.T) string {
	t.Helper()
	blob := strings.Repeat(agentBase64PNG, 360)
	if len(blob) < 32*1024 {
		t.Fatalf("the data URL payload (%d bytes) must be about 40 KB", len(blob))
	}
	return "data:image/png;base64," + blob
}

// agentVersionHost is ordinary version and host text with short digit runs.
const agentVersionHost = "go1.25.4 at 127.0.0.1:8790, version 1.2.3"

// agentToolCallBody is an OpenAI-style tool-calling request whose
// tool_calls[].function.arguments member is a JSON string carrying the secret.
func agentToolCallBody(t *testing.T, secret string) []byte {
	t.Helper()
	arguments, err := json.Marshal(map[string]string{"cmd": "echo " + secret})
	if err != nil {
		t.Fatalf("marshal the tool arguments: %v", err)
	}
	body, err := json.Marshal(map[string]any{
		"model": "gpt-4o",
		"messages": []map[string]any{{
			"role": "assistant",
			"tool_calls": []map[string]any{{
				"id":   "call_scenario_1",
				"type": "function",
				"function": map[string]any{
					"name":      "run_shell",
					"arguments": string(arguments),
				},
			}},
		}},
		"tools": []map[string]any{{
			"type": "function",
			"function": map[string]any{
				"name":       "run_shell",
				"parameters": map[string]any{"type": "object"},
			},
		}},
	})
	if err != nil {
		t.Fatalf("marshal the tool-call body: %v", err)
	}
	return body
}

// agentToolResultBody is an Anthropic-style tool_result content block carrying
// the secret in its nested text block.
func agentToolResultBody(t *testing.T, secret string) []byte {
	t.Helper()
	body, err := json.Marshal(map[string]any{
		"model":      "claude-sonnet-4-20250514",
		"max_tokens": 1024,
		"messages": []map[string]any{{
			"role": "user",
			"content": []map[string]any{{
				"type":        "tool_result",
				"tool_use_id": "toolu_scenario_1",
				"content": []map[string]any{{
					"type": "text",
					"text": "the command returned " + secret,
				}},
			}},
		}},
	})
	if err != nil {
		t.Fatalf("marshal the tool-result body: %v", err)
	}
	return body
}

// agentDiff is a unified diff whose added line carries a provider key.
const agentDiff = `--- a/.env
+++ b/.env
@@ -1,4 +1,5 @@
 DATABASE_URL=postgres://localhost/app
+OPENAI_API_KEY=sk-AbCdEfGhIjKlMnOpQrStUvWx
 PORT=8080
 SHELL=/bin/zsh
`

// agentShellCommand is a shell command string with an exported key.
const agentShellCommand = `export OPENAI_API_KEY=sk-AbCdEfGhIjKlMnOpQrStUvWx && tokenhush run --config ./tokenhush.yaml`

// agentEnvDump is an environment dump with one credential line.
const agentEnvDump = `PATH=/usr/local/bin
HOME=/home/dev
MY_TOKEN=ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789
SHELL=/bin/zsh
`

// agentMarkdown is documentation with an example credential and a shared
// account address.
const agentMarkdown = "# Local development\n\n" +
	"Set the key before running the agent:\n\n" +
	"```sh\n" +
	"export OPENAI_API_KEY=sk-AbCdEfGhIjKlMnOpQrStUvWx\n" +
	"```\n\n" +
	"Or use the shared account dev@example.com.\n"

// agentUnicodeMarker is the CJK run whose bytes must survive the round trip.
const agentUnicodeMarker = "こんにちは、世界。"

// agentUnicodeContent is CJK prose carrying one provider key.
const agentUnicodeContent = agentUnicodeMarker + "今晚 vibe coding 用 sk-AbCdEfGhIjKlMnOpQrStUvWx で進めます。"
