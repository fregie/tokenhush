package filter

import (
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"
)

// localDocument is the exact schema example from the plan: no envelope, so it
// is an operator document, and one rule carrying every wire field.
const localDocument = `{
  "allowlist": ["literal"],
  "blocklist": ["literal"],
  "rules": [
    {
      "id": "proj-token",
      "type": "regex",
      "category": "api_key",
      "scope": "request",
      "action": "redact",
      "priority": 100,
      "pattern": "PROJ-[0-9]{4,}",
      "keywords": ["secret"],
      "case_sensitive": true,
      "confidence": 0.85,
      "allowlist": ["not-a-secret"],
      "min_digits": 13,
      "max_digits": 19,
      "alphabet": "base64",
      "min_length": 28,
      "min_entropy": 4.0,
      "pure_hex_excluded": true,
      "pem_headers": ["PRIVATE KEY"],
      "command": "",
      "subcommand": "",
      "verbs": [],
      "targets": []
    }
  ]
}`

// bundleDocument is the same content under a signed remote pack envelope.
const bundleDocument = `{
  "channel": "stable",
  "schema_version": 1,
  "min_binary_version": "0.3.0",
  "serial": 4,
  "key_id": "rules-2026-09",
  "not_before": "2026-09-14T00:00:00Z",
  "expires": "2027-09-14T00:00:00Z",
  "detectors": {"prefix": true, "email": true},
  "disabled_categories": [],
  "allowlist": ["literal"],
  "blocklist": ["literal"],
  "rules": [
    {"id": "proj-token", "type": "keyword", "category": "api_key", "action": "warn", "keywords": ["secret"]}
  ]
}`

func TestDecodeLocalDocument(t *testing.T) {
	doc, err := DecodeDocument([]byte(localDocument))
	if err != nil {
		t.Fatalf("DecodeDocument(local): %v", err)
	}
	if doc.RemotePack {
		t.Error("a document without serial + key_id must not be a remote pack")
	}
	if len(doc.Allowlist) != 1 || doc.Allowlist[0] != "literal" {
		t.Errorf("Allowlist = %v, want [literal]", doc.Allowlist)
	}
	if len(doc.Blocklist) != 1 || doc.Blocklist[0] != "literal" {
		t.Errorf("Blocklist = %v, want [literal]", doc.Blocklist)
	}
	if len(doc.Rules) != 1 {
		t.Fatalf("decoded %d rules, want 1", len(doc.Rules))
	}
	rule := doc.Rules[0]
	if rule.ID != "proj-token" || rule.Type != TypeRegex || rule.Category != CategoryAPIKey {
		t.Errorf("identity fields = (%q, %q, %q)", rule.ID, rule.Type, rule.Category)
	}
	if rule.Scope != ScopeRequest || rule.Action != ActionRedact {
		t.Errorf("phase fields = (%q, %q)", rule.Scope, rule.Action)
	}
	if rule.Priority != 100 || rule.Confidence != 0.85 {
		t.Errorf("priority/confidence = (%d, %v), want (100, 0.85)", rule.Priority, rule.Confidence)
	}
	if rule.Pattern != `PROJ-[0-9]{4,}` || !rule.CaseSensitive {
		t.Errorf("pattern/case = (%q, %v)", rule.Pattern, rule.CaseSensitive)
	}
	if len(rule.Keywords) != 1 || rule.Keywords[0] != "secret" {
		t.Errorf("Keywords = %v, want [secret]", rule.Keywords)
	}
	if len(rule.Allowlist) != 1 || rule.Allowlist[0] != "not-a-secret" {
		t.Errorf("rule Allowlist = %v, want [not-a-secret]", rule.Allowlist)
	}
	if rule.MinDigits != 13 || rule.MaxDigits != 19 || rule.MinLength != 28 {
		t.Errorf("numeric bounds = (%d, %d, %d)", rule.MinDigits, rule.MaxDigits, rule.MinLength)
	}
	if rule.Alphabet != "base64" || rule.MinEntropy != 4.0 || !rule.PureHexExcluded {
		t.Errorf("entropy fields = (%q, %v, %v)", rule.Alphabet, rule.MinEntropy, rule.PureHexExcluded)
	}
	if len(rule.PEMHeaders) != 1 || rule.PEMHeaders[0] != "PRIVATE KEY" {
		t.Errorf("PEMHeaders = %v, want [PRIVATE KEY]", rule.PEMHeaders)
	}
	if rule.ExcludedFromEvaluation {
		t.Error("a regex rule must not be marked parse-only")
	}
}

func TestDecodeBundleDocument(t *testing.T) {
	doc, err := DecodeDocument([]byte(bundleDocument))
	if err != nil {
		t.Fatalf("DecodeDocument(bundle): %v", err)
	}
	if !doc.RemotePack {
		t.Error("serial + key_id must mark the document as a remote pack")
	}
	if doc.Channel != "stable" || doc.SchemaVersion != 1 || doc.MinBinaryVersion != "0.3.0" {
		t.Errorf("envelope = (%q, %d, %q)", doc.Channel, doc.SchemaVersion, doc.MinBinaryVersion)
	}
	if doc.Serial != 4 || doc.KeyID != "rules-2026-09" {
		t.Errorf("serial/key = (%d, %q), want (4, rules-2026-09)", doc.Serial, doc.KeyID)
	}
	if want := time.Date(2026, 9, 14, 0, 0, 0, 0, time.UTC); !doc.NotBefore.Equal(want) {
		t.Errorf("NotBefore = %v, want %v", doc.NotBefore, want)
	}
	if want := time.Date(2027, 9, 14, 0, 0, 0, 0, time.UTC); !doc.Expires.Equal(want) {
		t.Errorf("Expires = %v, want %v", doc.Expires, want)
	}
	if !doc.Detectors["prefix"] || !doc.Detectors["email"] || len(doc.Detectors) != 2 {
		t.Errorf("Detectors = %v, want prefix+email on", doc.Detectors)
	}
	if doc.DisabledCategories == nil || len(doc.DisabledCategories) != 0 {
		t.Errorf("DisabledCategories = %v, want an empty list", doc.DisabledCategories)
	}
	if len(doc.Rules) != 1 || doc.Rules[0].ID != "proj-token" {
		t.Fatalf("Rules = %v, want one proj-token rule", doc.Rules)
	}
	if doc.Rules[0].Category != CategoryAPIKey || doc.Rules[0].Action != ActionWarn {
		t.Errorf("rule fields = (%q, %q)", doc.Rules[0].Category, doc.Rules[0].Action)
	}
}

func TestDecodeRuleDefaultsArePresenceOnly(t *testing.T) {
	doc, err := DecodeDocument([]byte(`{"rules":[{"id":"bare","type":"keyword","keywords":["x"],"action":"warn"}]}`))
	if err != nil {
		t.Fatalf("DecodeDocument(defaults): %v", err)
	}
	rule := doc.Rules[0]
	if rule.Category != CategoryCustom {
		t.Errorf("default Category = %q, want %q", rule.Category, CategoryCustom)
	}
	if rule.Scope != ScopeRequest {
		t.Errorf("default Scope = %q, want %q", rule.Scope, ScopeRequest)
	}
	if rule.Priority != DefaultPriority {
		t.Errorf("default Priority = %d, want %d", rule.Priority, DefaultPriority)
	}
	if rule.Confidence != DefaultConfidence {
		t.Errorf("default Confidence = %v, want %v", rule.Confidence, DefaultConfidence)
	}

	explicit := `{"rules":[{"id":"bare","type":"keyword","keywords":["x"],"action":"warn","priority":7,"confidence":1}]}`
	doc, err = DecodeDocument([]byte(explicit))
	if err != nil {
		t.Fatalf("DecodeDocument(explicit): %v", err)
	}
	if doc.Rules[0].Priority != 7 || doc.Rules[0].Confidence != 1 {
		t.Errorf("explicit priority/confidence = (%d, %v), want (7, 1)", doc.Rules[0].Priority, doc.Rules[0].Confidence)
	}
}

func TestDecodeRejectsUnknownFieldByName(t *testing.T) {
	_, err := DecodeDocument([]byte(`{"unknown_field": 1}`))
	if !errors.Is(err, ErrUnknownField) {
		t.Fatalf("DecodeDocument(unknown_field) error = %v, want ErrUnknownField", err)
	}
	if !strings.Contains(err.Error(), "unknown_field") {
		t.Errorf("error %q must name the unknown field", err)
	}

	_, err = DecodeDocument([]byte(`{"rules":[{"id":"a","type":"regex","pattern":"x+","action":"warn","bogus":1}]}`))
	if !errors.Is(err, ErrUnknownField) {
		t.Fatalf("DecodeDocument(nested bogus) error = %v, want ErrUnknownField", err)
	}
	if !strings.Contains(err.Error(), "rules[0].bogus") {
		t.Errorf("error %q must name rules[0].bogus", err)
	}
}

func TestDecodeRejectsInvalidShape(t *testing.T) {
	for _, raw := range []string{`null`, `[]`, `"x"`, `{"rules":"not-a-list"}`} {
		_, err := DecodeDocument([]byte(raw))
		if !errors.Is(err, ErrInvalidValue) {
			t.Errorf("DecodeDocument(%s) error = %v, want ErrInvalidValue", raw, err)
		}
	}
}

func TestDecodeRequiresSerialAndKeyIDTogether(t *testing.T) {
	for _, raw := range []string{`{"serial":1}`, `{"key_id":"rules-2026-09"}`} {
		_, err := DecodeDocument([]byte(raw))
		if !errors.Is(err, ErrInvalidValue) {
			t.Errorf("DecodeDocument(%s) error = %v, want ErrInvalidValue", raw, err)
		}
	}
}

func TestDecodeRejectsUnknownRuleType(t *testing.T) {
	_, err := DecodeDocument([]byte(`{"rules":[{"id":"r","type":"frobnicate","action":"warn"}]}`))
	if !errors.Is(err, ErrInvalidValue) {
		t.Fatalf("error = %v, want ErrInvalidValue", err)
	}
	if !strings.Contains(err.Error(), "frobnicate") || !strings.Contains(err.Error(), "rules[0].type") {
		t.Errorf("error %q must name rules[0].type and frobnicate", err)
	}
}

func TestDecodeRejectsEmptyMatchingRegex(t *testing.T) {
	for _, pattern := range []string{"", "a*", "(?s).*"} {
		doc := fmt.Sprintf(`{"rules":[{"id":"rx","type":"regex","action":"warn","pattern":%q}]}`, pattern)
		_, err := DecodeDocument([]byte(doc))
		if !errors.Is(err, ErrInvalidValue) {
			t.Errorf("pattern %q: error = %v, want ErrInvalidValue", pattern, err)
		}
		if err != nil && !strings.Contains(err.Error(), "rules[0].pattern") {
			t.Errorf("pattern %q: error %q must name rules[0].pattern", pattern, err)
		}
	}

	_, err := DecodeDocument([]byte(`{"rules":[{"id":"rx","type":"regex","action":"warn","pattern":"("}]}`))
	if !errors.Is(err, ErrInvalidValue) {
		t.Errorf("invalid regex error = %v, want ErrInvalidValue", err)
	}
}

func TestDecodeRejectsInvalidEnums(t *testing.T) {
	cases := []struct {
		name string
		doc  string
		want string
	}{
		{"category", `{"rules":[{"id":"r","type":"keyword","keywords":["x"],"action":"warn","category":"mystery"}]}`, "rules[0].category"},
		{"scope", `{"rules":[{"id":"r","type":"keyword","keywords":["x"],"action":"warn","scope":"sideways"}]}`, "rules[0].scope"},
		{"action", `{"rules":[{"id":"r","type":"keyword","keywords":["x"],"action":"explode"}]}`, "rules[0].action"},
		{"confidence zero", `{"rules":[{"id":"r","type":"keyword","keywords":["x"],"action":"warn","confidence":0}]}`, "rules[0].confidence"},
		{"confidence high", `{"rules":[{"id":"r","type":"keyword","keywords":["x"],"action":"warn","confidence":1.5}]}`, "rules[0].confidence"},
		{"action missing", `{"rules":[{"id":"r","type":"keyword","keywords":["x"]}]}`, "rules[0].action"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := DecodeDocument([]byte(tc.doc))
			if !errors.Is(err, ErrInvalidValue) {
				t.Fatalf("error = %v, want ErrInvalidValue", err)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error %q must name %s", err, tc.want)
			}
		})
	}
}

func TestDecodeRejectsBadRuleIDs(t *testing.T) {
	for _, id := range []string{"Proj", "1proj", "", strings.Repeat("a", 65)} {
		doc := fmt.Sprintf(`{"rules":[{"id":%q,"type":"keyword","keywords":["x"],"action":"warn"}]}`, id)
		_, err := DecodeDocument([]byte(doc))
		if !errors.Is(err, ErrInvalidValue) {
			t.Errorf("id %q: error = %v, want ErrInvalidValue", id, err)
		}
		if err != nil && !strings.Contains(err.Error(), "rules[0].id") {
			t.Errorf("id %q: error %q must name rules[0].id", id, err)
		}
	}

	duplicate := `{"rules":[
		{"id":"same","type":"keyword","keywords":["x"],"action":"warn"},
		{"id":"same","type":"keyword","keywords":["y"],"action":"warn"}
	]}`
	_, err := DecodeDocument([]byte(duplicate))
	if !errors.Is(err, ErrInvalidValue) {
		t.Fatalf("duplicate id error = %v, want ErrInvalidValue", err)
	}
	if !strings.Contains(err.Error(), "rules[1].id") {
		t.Errorf("duplicate id error %q must name rules[1].id", err)
	}
}

func TestDecodeCommandRuleIsParseOnly(t *testing.T) {
	doc, err := DecodeDocument([]byte(`{"rules":[{
		"id":"risky-cmd","type":"command","category":"custom","scope":"both","action":"block",
		"command":"aws","subcommand":"s3","verbs":["rm","delete"],"targets":["/prod/"]
	}]}`))
	if err != nil {
		t.Fatalf("a command rule must decode successfully: %v", err)
	}
	if len(doc.Rules) != 1 {
		t.Fatalf("decoded %d rules, want 1 (a command rule is never dropped)", len(doc.Rules))
	}
	rule := doc.Rules[0]
	if rule.Command != "aws" || rule.Subcommand != "s3" {
		t.Errorf("command/subcommand = (%q, %q), want (aws, s3)", rule.Command, rule.Subcommand)
	}
	if len(rule.Verbs) != 2 || rule.Verbs[0] != "rm" || rule.Verbs[1] != "delete" {
		t.Errorf("Verbs = %v, want [rm delete]", rule.Verbs)
	}
	if len(rule.Targets) != 1 || rule.Targets[0] != "/prod/" {
		t.Errorf("Targets = %v, want [/prod/]", rule.Targets)
	}
	if !rule.ExcludedFromEvaluation {
		t.Error("a command rule must be marked excluded from evaluation")
	}
}

// literalList renders n distinct JSON string literals.
func literalList(n int) string {
	items := make([]string, n)
	for i := range items {
		items[i] = fmt.Sprintf("%q", fmt.Sprintf("k%d", i))
	}
	return "[" + strings.Join(items, ",") + "]"
}

// ruleList renders n valid regex rules with unique ids.
func ruleList(n int) string {
	items := make([]string, n)
	for i := range items {
		items[i] = fmt.Sprintf(`{"id":"r%d","type":"regex","pattern":"x%d+","action":"warn"}`, i, i)
	}
	return "[" + strings.Join(items, ",") + "]"
}

func TestDecodeBounds(t *testing.T) {
	cases := []struct {
		name string
		doc  string
		want string
	}{
		{"257th rule", fmt.Sprintf(`{"rules":%s}`, ruleList(MaxRules+1)), "rules"},
		{"65th keyword", fmt.Sprintf(`{"rules":[{"id":"kw","type":"keyword","action":"warn","keywords":%s}]}`, literalList(MaxKeywordsPerRule+1)), "rules[0].keywords"},
		{"257th global entry", fmt.Sprintf(`{"allowlist":%s}`, literalList(MaxListEntries+1)), "allowlist"},
		{"65th rule allowlist entry", fmt.Sprintf(`{"rules":[{"id":"kw","type":"keyword","action":"warn","keywords":["x"],"allowlist":%s}]}`, literalList(MaxRuleAllowlist+1)), "rules[0].allowlist"},
		{"257-byte literal", fmt.Sprintf(`{"allowlist":[%q]}`, strings.Repeat("a", MaxLiteralBytes+1)), "allowlist[0]"},
		{"1025-byte pattern", fmt.Sprintf(`{"rules":[{"id":"rx","type":"regex","action":"warn","pattern":%q}]}`, strings.Repeat("a", MaxPatternBytes+1)), "rules[0].pattern"},
		{"17th verb", fmt.Sprintf(`{"rules":[{"id":"cmd","type":"command","command":"rm","verbs":%s}]}`, literalList(MaxCommandVerbsPerRule+1)), "rules[0].verbs"},
		{"17th target", fmt.Sprintf(`{"rules":[{"id":"cmd","type":"command","command":"rm","targets":%s}]}`, literalList(MaxCommandTargetsPerRule+1)), "rules[0].targets"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := DecodeDocument([]byte(tc.doc))
			if !errors.Is(err, ErrBoundExceeded) {
				t.Fatalf("error = %v, want ErrBoundExceeded", err)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error %q must name %s", err, tc.want)
			}
		})
	}
}

func TestDecodeBoundsAtTheLimit(t *testing.T) {
	cases := []struct {
		name string
		doc  string
	}{
		{"256 rules", fmt.Sprintf(`{"rules":%s}`, ruleList(MaxRules))},
		{"64 keywords", fmt.Sprintf(`{"rules":[{"id":"kw","type":"keyword","action":"warn","keywords":%s}]}`, literalList(MaxKeywordsPerRule))},
		{"256 global entries", fmt.Sprintf(`{"allowlist":%s}`, literalList(MaxListEntries))},
		{"64 rule allowlist entries", fmt.Sprintf(`{"rules":[{"id":"kw","type":"keyword","action":"warn","keywords":["x"],"allowlist":%s}]}`, literalList(MaxRuleAllowlist))},
		{"256-byte literal", fmt.Sprintf(`{"allowlist":[%q]}`, strings.Repeat("a", MaxLiteralBytes))},
		{"1024-byte pattern", fmt.Sprintf(`{"rules":[{"id":"rx","type":"regex","action":"warn","pattern":%q}]}`, strings.Repeat("a", MaxPatternBytes))},
		{"16 verbs", fmt.Sprintf(`{"rules":[{"id":"cmd","type":"command","command":"rm","verbs":%s}]}`, literalList(MaxCommandVerbsPerRule))},
		{"16 targets", fmt.Sprintf(`{"rules":[{"id":"cmd","type":"command","command":"rm","targets":%s}]}`, literalList(MaxCommandTargetsPerRule))},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := DecodeDocument([]byte(tc.doc)); err != nil {
				t.Fatalf("at-the-limit document must decode: %v", err)
			}
		})
	}
}

func TestMaxMatchesIsFrozen(t *testing.T) {
	if MaxMatches != 4096 {
		t.Errorf("MaxMatches = %d, want the frozen 4096", MaxMatches)
	}
}
