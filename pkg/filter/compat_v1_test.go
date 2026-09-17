package filter

import (
	"os"
	"path/filepath"
	"testing"
)

// commandFixture is the second v1 fixture: a document carrying one command rule
// beside a normal rule. The task allows it inline, so it stays here rather than
// in testdata.
const commandFixture = `{
  "schema_version": 1,
  "detectors": {"prefix": true},
  "rules": [
    {"id": "keep-regex", "type": "regex", "pattern": "AKIA[0-9A-Z]{16}", "action": "redact"},
    {"id": "risky-cmd", "type": "command", "action": "block", "command": "aws", "subcommand": "s3", "verbs": ["rm", "delete"], "targets": ["/prod/"]}
  ]
}`

func loadV1Pack(t *testing.T) []byte {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("testdata", "v1_pack.json"))
	if err != nil {
		t.Fatalf("read the v1 pack fixture: %v", err)
	}
	return data
}

// TestCompatV1PackDecodes proves the frozen v1 wire document (the
// rules-pack-rich shape) decodes with its field names and wire ids unchanged,
// including the two weakening-vector fields the floor later inspects.
func TestCompatV1PackDecodes(t *testing.T) {
	doc, signal, err := DecodeDocumentWithSignal(loadV1Pack(t))
	if err != nil {
		t.Fatalf("a v1 pack must decode: %v", err)
	}
	if !doc.RemotePack {
		t.Error("the fixture carries serial + key_id, so it must decode as a remote pack")
	}
	if doc.Channel != "stable" || doc.SchemaVersion != 1 || doc.MinBinaryVersion != "0.3.0" {
		t.Errorf("envelope = (%q, %d, %q)", doc.Channel, doc.SchemaVersion, doc.MinBinaryVersion)
	}
	if doc.Serial != 4 || doc.KeyID != "rules-2026-09" {
		t.Errorf("serial/key = (%d, %q), want (4, rules-2026-09)", doc.Serial, doc.KeyID)
	}
	if !doc.Detectors["email"] || !doc.Detectors["prefix"] || len(doc.Detectors) != 2 {
		t.Errorf("Detectors = %v, want email+prefix on", doc.Detectors)
	}
	if len(doc.DisabledCategories) != 1 || doc.DisabledCategories[0] != "internal_only" {
		t.Errorf("DisabledCategories = %v, want [internal_only]", doc.DisabledCategories)
	}
	if len(doc.Allowlist) != 1 || doc.Allowlist[0] != "example.com" {
		t.Errorf("Allowlist = %v, want [example.com]", doc.Allowlist)
	}
	if len(doc.Blocklist) != 1 || doc.Blocklist[0] != "TOKENHUSH_BLOCK" {
		t.Errorf("Blocklist = %v, want [TOKENHUSH_BLOCK]", doc.Blocklist)
	}
	if len(doc.Rules) != 2 {
		t.Fatalf("decoded %d rules, want 2", len(doc.Rules))
	}

	regex, keyword := doc.Rules[0], doc.Rules[1]
	if regex.ID != "proj" || regex.Type != TypeRegex || regex.Pattern != `PROJ-[0-9]{4,}` {
		t.Errorf("regex rule = (%q, %q, %q)", regex.ID, regex.Type, regex.Pattern)
	}
	if regex.Action != ActionWarn || regex.Confidence != 0.85 {
		t.Errorf("regex action/confidence = (%q, %v)", regex.Action, regex.Confidence)
	}
	if keyword.ID != "secret" || keyword.Type != TypeKeyword || !keyword.CaseSensitive {
		t.Errorf("keyword rule = (%q, %q, case=%v)", keyword.ID, keyword.Type, keyword.CaseSensitive)
	}
	if len(keyword.Keywords) != 2 || keyword.Keywords[0] != "secret" || keyword.Keywords[1] != "token" {
		t.Errorf("Keywords = %v, want [secret token]", keyword.Keywords)
	}
	if len(keyword.Allowlist) != 1 || keyword.Allowlist[0] != "not-a-secret" {
		t.Errorf("rule Allowlist = %v, want [not-a-secret]", keyword.Allowlist)
	}

	// A v1 rule carries none of the new extension fields: their absence must
	// decode to the documented defaults, never to a decode error.
	if regex.Category != CategoryCustom || regex.Scope != ScopeRequest || regex.Priority != DefaultPriority {
		t.Errorf("v1 defaults = (%q, %q, %d), want (custom, request, %d)",
			regex.Category, regex.Scope, regex.Priority, DefaultPriority)
	}
	if signal == nil || signal.Present() || signal.Count != 0 || len(signal.RuleIDs) != 0 {
		t.Errorf("signal = %+v, want no command rules in this pack", signal)
	}
}

// TestCompatV1CommandRuleSignals proves a command rule produces a non-fatal
// typed signal naming its id while the rest of the document stays intact.
func TestCompatV1CommandRuleSignals(t *testing.T) {
	doc, signal, err := DecodeDocumentWithSignal([]byte(commandFixture))
	if err != nil {
		t.Fatalf("a command rule must never be a decode error at this layer: %v", err)
	}
	if len(doc.Rules) != 2 {
		t.Fatalf("decoded %d rules, want the command rule kept beside the rest", len(doc.Rules))
	}
	if signal == nil {
		t.Fatal("decoding a command document must produce a signal")
	}
	if signal.Count != 1 || len(signal.RuleIDs) != 1 || signal.RuleIDs[0] != "risky-cmd" {
		t.Fatalf("signal = %+v, want exactly [risky-cmd]", signal)
	}
	if !signal.Present() {
		t.Error("Present() must report the command signal")
	}

	command := doc.Rules[1]
	if command.Command != "aws" || command.Subcommand != "s3" {
		t.Errorf("command/subcommand = (%q, %q), want (aws, s3)", command.Command, command.Subcommand)
	}
	if len(command.Verbs) != 2 || command.Verbs[0] != "rm" || command.Verbs[1] != "delete" {
		t.Errorf("Verbs = %v, want [rm delete]", command.Verbs)
	}
	if len(command.Targets) != 1 || command.Targets[0] != "/prod/" {
		t.Errorf("Targets = %v, want [/prod/]", command.Targets)
	}
	if !command.ExcludedFromEvaluation {
		t.Error("the command rule must be marked excluded from evaluation")
	}

	rest := doc.Rules[0]
	if rest.ID != "keep-regex" || rest.Type != TypeRegex || rest.ExcludedFromEvaluation {
		t.Errorf("the remaining rule changed: %+v", rest)
	}
}

// TestCompatV1CommandRuleIsNeverADecodeError pins the layering decision: every
// command document decodes, no rule is dropped, and the signal carries exactly
// the command ids.
func TestCompatV1CommandRuleIsNeverADecodeError(t *testing.T) {
	cases := []struct {
		name    string
		doc     string
		wantIDs []string
		command []string
	}{
		{
			name:    "minimal command rule",
			doc:     `{"rules":[{"id":"bare-cmd","type":"command","command":"rm"}]}`,
			wantIDs: []string{"bare-cmd"},
			command: []string{"bare-cmd"},
		},
		{
			name:    "mixed document",
			doc:     commandFixture,
			wantIDs: []string{"keep-regex", "risky-cmd"},
			command: []string{"risky-cmd"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			doc, signal, err := DecodeDocumentWithSignal([]byte(tc.doc))
			if err != nil {
				t.Fatalf("command document rejected at decode: %v", err)
			}
			var ids []string
			for _, rule := range doc.Rules {
				ids = append(ids, rule.ID)
			}
			if len(ids) != len(tc.wantIDs) {
				t.Fatalf("decoded ids = %v, want %v (no rule may be dropped)", ids, tc.wantIDs)
			}
			for i, want := range tc.wantIDs {
				if ids[i] != want {
					t.Errorf("ids[%d] = %q, want %q", i, ids[i], want)
				}
			}
			if signal.Count != len(tc.command) {
				t.Fatalf("signal.Count = %d, want %d", signal.Count, len(tc.command))
			}
			for i, want := range tc.command {
				if signal.RuleIDs[i] != want {
					t.Errorf("signal.RuleIDs[%d] = %q, want %q", i, signal.RuleIDs[i], want)
				}
			}
		})
	}
}
