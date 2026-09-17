package filter

// compile_test.go pins the load-time compiler: every rejection is typed and
// names the offending rule id, the direction contract is enforced here, a
// mixed document compiles to an immutable set, and that set is safe for
// concurrent readers.

import (
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"sync"
	"testing"
)

// mixedDoc is the canonical mixed document: a regex rule, a keyword rule with
// a per-rule allowlist, a primitive-typed rule and a parse-only command rule,
// plus a global allowlist and blocklist. Every rule carries the same default
// priority, so the compiled order is the id tie-break.
const mixedDoc = `{
  "allowlist": ["global-literal"],
  "blocklist": ["global-block"],
  "rules": [
    {"id": "proj", "type": "regex", "pattern": "PROJ-[0-9]{4,}", "action": "warn"},
    {"id": "secret", "type": "keyword", "keywords": ["secret", "token"], "action": "redact", "allowlist": ["not-a-secret"]},
    {"id": "mail", "type": "email", "action": "redact"},
    {"id": "risky-cmd", "type": "command", "action": "block", "command": "aws", "verbs": ["rm"]}
  ]
}`

// rulesDoc builds an in-memory document, the shape a decoded document has once
// the decoder has applied its presence-only defaults.
func rulesDoc(rules ...RuleDoc) *Document {
	return &Document{Rules: rules}
}

func decodeDoc(t *testing.T, doc string) *Document {
	t.Helper()
	parsed, err := DecodeDocument([]byte(doc))
	if err != nil {
		t.Fatalf("DecodeDocument: %v", err)
	}
	return parsed
}

func compileDoc(t *testing.T, doc string) *Compiled {
	t.Helper()
	set, err := Compile(decodeDoc(t, doc))
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	return set
}

// compiledIDs reports the compiled invocation order, used to pin the
// priority-then-id ordering of the set itself.
func compiledIDs(set *Compiled) []string {
	ids := make([]string, 0, len(set.rules))
	for i := range set.rules {
		ids = append(ids, set.rules[i].id)
	}
	return ids
}

// TestCompileRejectsInvalidRules covers every load-time rejection: each one is
// a *CompileError whose RuleID and message name the offending rule, every one
// also matches ErrCompile, and a rejected document never yields a set.
func TestCompileRejectsInvalidRules(t *testing.T) {
	cases := []struct {
		name string
		doc  *Document
		id   string
		kind error
	}{
		{"bad regex", rulesDoc(RuleDoc{ID: "bad-regex", Type: TypeRegex, Pattern: "(", Action: ActionWarn}), "bad-regex", ErrCompile},
		{"empty-matching regex", rulesDoc(RuleDoc{ID: "empty-match", Type: TypeRegex, Pattern: "a*", Action: ActionWarn}), "empty-match", ErrCompile},
		{"regex without a pattern", rulesDoc(RuleDoc{ID: "no-pattern", Type: TypeRegex, Action: ActionWarn}), "no-pattern", ErrCompile},
		{"keyword rule without keywords", rulesDoc(RuleDoc{ID: "no-keywords", Type: TypeKeyword, Action: ActionWarn}), "no-keywords", ErrCompile},
		{"regex rule carrying keywords", rulesDoc(RuleDoc{ID: "regex-keywords", Type: TypeRegex, Pattern: "a+", Keywords: []string{"a"}, Action: ActionWarn}), "regex-keywords", ErrCompile},
		{"keyword rule carrying a pattern", rulesDoc(RuleDoc{ID: "keyword-pattern", Type: TypeKeyword, Pattern: "a+", Keywords: []string{"a"}, Action: ActionWarn}), "keyword-pattern", ErrCompile},
		{"case_sensitive on a regex rule", rulesDoc(RuleDoc{ID: "folded-regex", Type: TypeRegex, Pattern: "a+", CaseSensitive: true, Action: ActionWarn}), "folded-regex", ErrCompile},
		{"keywords on a primitive rule", rulesDoc(RuleDoc{ID: "email-keywords", Type: TypeEmail, Keywords: []string{"a"}, Action: ActionWarn}), "email-keywords", ErrCompile},
		{"duplicate ids", rulesDoc(
			RuleDoc{ID: "dup", Type: TypeRegex, Pattern: "a+", Action: ActionWarn},
			RuleDoc{ID: "dup", Type: TypeKeyword, Keywords: []string{"b"}, Action: ActionWarn},
		), "dup", ErrCompile},
		{"unknown detector type", rulesDoc(RuleDoc{ID: "mystery", Type: "mystery", Action: ActionWarn}), "mystery", ErrCompile},
		{"invalid rule id", rulesDoc(RuleDoc{ID: "Bad ID", Type: TypeKeyword, Keywords: []string{"x"}, Action: ActionWarn}), "Bad ID", ErrCompile},
		{"unknown action", rulesDoc(RuleDoc{ID: "bad-action", Type: TypeKeyword, Keywords: []string{"x"}, Action: "nope"}), "bad-action", ErrCompile},
		{"response scope with redact", rulesDoc(RuleDoc{ID: "response-redact", Type: TypeKeyword, Keywords: []string{"x"}, Scope: ScopeResponse, Action: ActionRedact}), "response-redact", ErrDirection},
		{"both scope with redact", rulesDoc(RuleDoc{ID: "both-redact", Type: TypeKeyword, Keywords: []string{"x"}, Scope: ScopeBoth, Action: ActionRedact}), "both-redact", ErrDirection},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			set, err := Compile(tc.doc)
			if err == nil {
				t.Fatalf("Compile accepted an invalid rule: %+v", tc.doc.Rules)
			}
			if set != nil {
				t.Error("a rejected document must not return a rule set")
			}
			if !errors.Is(err, tc.kind) {
				t.Errorf("errors.Is(%v, %v) = false", err, tc.kind)
			}
			if !errors.Is(err, ErrCompile) {
				t.Errorf("every compile rejection must also match ErrCompile, got %v", err)
			}
			var compileErr *CompileError
			if !errors.As(err, &compileErr) {
				t.Fatalf("error %v is not a *CompileError", err)
			}
			if compileErr.RuleID != tc.id {
				t.Errorf("CompileError.RuleID = %q, want %q", compileErr.RuleID, tc.id)
			}
			if !strings.Contains(err.Error(), tc.id) {
				t.Errorf("error %q must name the rule id %q", err, tc.id)
			}
		})
	}
}

// TestCompileRejectsNilDocument pins the typed failure for a nil input.
func TestCompileRejectsNilDocument(t *testing.T) {
	set, err := Compile(nil)
	if err == nil || !errors.Is(err, ErrInvalidValue) {
		t.Fatalf("Compile(nil) = (%v, %v), want a typed ErrInvalidValue", set, err)
	}
	if set != nil {
		t.Error("Compile(nil) must not return a set")
	}
}

// TestCompileRequestRedactIsAllowed is the positive half of the direction
// contract: only the response phase is barred from redacting.
func TestCompileRequestRedactIsAllowed(t *testing.T) {
	set := compileDoc(t, `{"rules":[{"id":"req-redact","type":"keyword","keywords":["x"],"action":"redact"}]}`)
	if set.Len() != 1 {
		t.Fatalf("Len() = %d, want 1", set.Len())
	}
	if got := set.rules[0].scope; got != ScopeRequest {
		t.Errorf("scope = %q, want the request default", got)
	}
	if got := set.rules[0].action; got != ActionRedact {
		t.Errorf("action = %q, want redact", got)
	}
}

// TestCompileMixedSetCountAndCommandSignal proves the compiled count excludes
// the parse-only command rule while the W3.2 command signal stays reachable
// through the compiled set, and that the set itself is priority/id ordered.
func TestCompileMixedSetCountAndCommandSignal(t *testing.T) {
	parsed, signal, err := DecodeDocumentWithSignal([]byte(mixedDoc))
	if err != nil {
		t.Fatalf("DecodeDocumentWithSignal: %v", err)
	}
	set, err := Compile(parsed)
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	if set.Len() != 3 {
		t.Errorf("Len() = %d, want the three evaluable rules (command rule excluded)", set.Len())
	}
	got := set.Commands()
	if !got.Present() || got.Count != 1 || !reflect.DeepEqual(got.RuleIDs, []string{"risky-cmd"}) {
		t.Errorf("Commands() = %+v, want the W3.2 signal for [risky-cmd]", got)
	}
	if signal.Count != got.Count || !reflect.DeepEqual(signal.RuleIDs, got.RuleIDs) {
		t.Errorf("compiled signal %+v must carry the decoder signal %+v", got, signal)
	}
	if ids := compiledIDs(set); !reflect.DeepEqual(ids, []string{"mail", "proj", "secret"}) {
		t.Errorf("compiled order = %v, want ascending priority then id", ids)
	}
}

// TestCompileExcludesCommandRulesEvenUnmarked proves the exclusion keys off the
// rule type, not only the decoder's flag: a hand-built command rule is carried
// by the signal and never becomes an evaluable rule.
func TestCompileExcludesCommandRulesEvenUnmarked(t *testing.T) {
	set, err := Compile(rulesDoc(RuleDoc{ID: "cmd", Type: TypeCommand, Action: ActionBlock, Command: "aws"}))
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	if set.Len() != 0 {
		t.Errorf("Len() = %d, want 0 evaluable rules", set.Len())
	}
	if got := set.Commands(); got.Count != 1 || !reflect.DeepEqual(got.RuleIDs, []string{"cmd"}) {
		t.Errorf("Commands() = %+v, want [cmd]", got)
	}
}

// TestCompileResultIsImmutable proves Compile deep-copies: mutating every
// byte-bearing field of the input document afterwards (and the document
// itself) changes neither the compiled set nor its behavior, and the compiled
// set exposes no exported mutable field.
func TestCompileResultIsImmutable(t *testing.T) {
	parsed := decodeDoc(t, mixedDoc)
	before, err := json.Marshal(parsed)
	if err != nil {
		t.Fatalf("json.Marshal(doc): %v", err)
	}
	set, err := Compile(parsed)
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	after, err := json.Marshal(parsed)
	if err != nil {
		t.Fatalf("json.Marshal(doc): %v", err)
	}
	if string(before) != string(after) {
		t.Errorf("Compile mutated the input document:\n%s\n%s", before, after)
	}

	snapshot := []string{
		string(set.allowlist[0]),
		string(set.blocklist[0]),
		set.rules[1].re.String(),
		string(set.rules[2].keywords[0]),
		string(set.rules[2].keywords[1]),
		string(set.rules[2].allow[0]),
	}
	parsed.Allowlist[0] = "mutated"
	parsed.Blocklist[0] = "mutated"
	parsed.Rules[0].Pattern = "ZZZ"
	parsed.Rules[0].Keywords = []string{"mutated"}
	parsed.Rules[1].Keywords[0] = "mutated"
	parsed.Rules[1].Keywords[1] = "mutated"
	parsed.Rules[1].Allowlist[0] = "mutated"
	parsed.Rules = nil
	parsed.Allowlist = nil
	parsed.Blocklist = nil

	afterMutation := []string{
		string(set.allowlist[0]),
		string(set.blocklist[0]),
		set.rules[1].re.String(),
		string(set.rules[2].keywords[0]),
		string(set.rules[2].keywords[1]),
		string(set.rules[2].allow[0]),
	}
	if !reflect.DeepEqual(snapshot, afterMutation) {
		t.Errorf("compiled state changed after the document was mutated:\nbefore %v\nafter  %v", snapshot, afterMutation)
	}

	typ := reflect.TypeOf(Compiled{})
	if typ.NumField() == 0 {
		t.Fatal("Compiled has no fields")
	}
	for i := 0; i < typ.NumField(); i++ {
		if typ.Field(i).IsExported() {
			t.Errorf("Compiled field %q is exported; the set must not expose mutable state", typ.Field(i).Name)
		}
	}

	signal := set.Commands()
	signal.RuleIDs[0] = "mutated"
	if got := set.Commands(); !reflect.DeepEqual(got.RuleIDs, []string{"risky-cmd"}) {
		t.Errorf("Commands() must return a copy, got %v after mutating the previous result", got.RuleIDs)
	}
}

// TestCompileConcurrentConstructionAndReadsRaceFree runs construction, reads
// and the command-signal copy concurrently. The W3.4 requirement that
// concurrent Evaluate be race-free is completed by evaluate_test.go, where
// Evaluate exists; run this package with -race.
func TestCompileConcurrentConstructionAndReadsRaceFree(t *testing.T) {
	parsed := decodeDoc(t, mixedDoc)
	set, err := Compile(parsed)
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	var wg sync.WaitGroup
	for worker := 0; worker < 8; worker++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 50; i++ {
				if got := set.Len(); got != 3 {
					t.Errorf("Len() = %d, want 3", got)
				}
				if got := set.Commands(); got.Count != 1 {
					t.Errorf("Commands().Count = %d, want 1", got.Count)
				}
				if _, err := Compile(parsed); err != nil {
					t.Errorf("concurrent Compile: %v", err)
				}
			}
		}()
	}
	wg.Wait()
}
