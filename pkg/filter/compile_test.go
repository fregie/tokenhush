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

// ---------------------------------------------------------------------------
// Todo 7: the parameterized primitive builder channel. The compiler re-runs the
// options contract and binds every primitive-typed rule's matcher through
// primitiveBuilders, so a hand-built document cannot skip the options contract
// and an options-carrying email rule matches its effective suffix set. Fixtures
// here are this file's own fresh addresses (example.com / corp.com), and the
// primitive baits are built at run time, so the builder tests never depend on
// another test file's literals or on fixture reconciliation.

// builderAddr* are this file's fresh email fixtures: one built-in .com address,
// one under the declared .corp.com suffix, a label-boundary lookalike, one
// under the declared corp.example suffix and a .example lookalike.
const (
	builderAddrBuiltin = "alice" + "@" + "example.com"
	builderAddrCorp    = "bob" + "@" + "sub.corp.com"
	builderAddrEvil    = "carol" + "@" + "evilcorp.com"
	builderAddrExample = "dave" + "@" + "sub.corp.example"
	builderAddrEvilEx  = "erin" + "@" + "evilcorp.example"
)

// builderSpanOf returns the span of addr inside content, so an expected span is
// computed from the fixture and a missing fixture fails loudly instead of
// silently pointing nowhere.
func builderSpanOf(t *testing.T, content []byte, addr string) Span {
	t.Helper()
	start := strings.Index(string(content), addr)
	if start < 0 {
		t.Fatalf("fixture %q is absent from the content", addr)
	}
	return Span{Start: start, End: start + len(addr)}
}

// builderPEMBlock is this file's own one-line PEM fixture, so the builder tests
// never depend on a helper owned by another test file.
func builderPEMBlock(kind string) string {
	return "-----BEGIN " + kind + "-----\nMIIEfake\n-----END " + kind + "-----"
}

// TestCompileEmailOptions pins the email builder end to end: an additive
// declared suffix extends the built-in set, a replace list narrows to the
// normalized declared suffixes only, a hand-built document's options are
// re-validated and canonicalized by the compiler, and an options-less rule
// matches exactly what the built-in inspectEmail path matches.
func TestCompileEmailOptions(t *testing.T) {
	additiveContent := []byte("a " + builderAddrBuiltin + " b " + builderAddrExample + " c " + builderAddrEvilEx + " d")
	replaceContent := []byte("a " + builderAddrBuiltin + " b " + builderAddrCorp + " c " + builderAddrEvil + " d")

	t.Run("decoded additive options extend the built-in set", func(t *testing.T) {
		set := compileDoc(t, `{"rules":[{"id":"mail","type":"email","action":"warn","options":{"email":{"suffixes":["corp.example"]}}}]}`)
		matcher := set.rules[0].inspect
		if matcher == nil {
			t.Fatal("an email rule with options compiled without an inspect matcher")
		}
		want := []Span{builderSpanOf(t, additiveContent, builderAddrBuiltin), builderSpanOf(t, additiveContent, builderAddrExample)}
		if got := matcher(additiveContent); !reflect.DeepEqual(got, want) {
			t.Errorf("additive matcher spans = %v, want the built-in address plus the declared-suffix address %v", got, want)
		}
		if got := matcher([]byte("x " + builderAddrEvilEx + " y")); len(got) != 0 {
			t.Errorf("an address at a shared byte tail must not match a declared suffix, got %v", got)
		}
	})

	t.Run("decoded replace options narrow to the normalized declared set", func(t *testing.T) {
		set := compileDoc(t, `{"rules":[{"id":"mail","type":"email","action":"warn","options":{"email":{"suffixes":["Corp.COM"],"replace":true}}}]}`)
		matcher := set.rules[0].inspect
		if matcher == nil {
			t.Fatal("an email rule with replace options compiled without an inspect matcher")
		}
		want := []Span{builderSpanOf(t, replaceContent, builderAddrCorp)}
		if got := matcher(replaceContent); !reflect.DeepEqual(got, want) {
			t.Errorf("replace matcher spans = %v, want only the canonical .corp.com address %v", got, want)
		}
	})

	t.Run("hand-built options are re-validated and canonicalized", func(t *testing.T) {
		set, err := Compile(rulesDoc(RuleDoc{
			ID: "mail-hand", Type: TypeEmail, Action: ActionWarn,
			Options: &RuleOptions{Email: &EmailOptions{Suffixes: []string{"Corp.COM"}, Replace: true}},
		}))
		if err != nil {
			t.Fatalf("Compile: %v", err)
		}
		matcher := set.rules[0].inspect
		if matcher == nil {
			t.Fatal("an email rule with hand-built options compiled without an inspect matcher")
		}
		want := []Span{builderSpanOf(t, replaceContent, builderAddrCorp)}
		if got := matcher(replaceContent); !reflect.DeepEqual(got, want) {
			t.Errorf("hand-built replace matcher spans = %v, want the canonical .corp.com address %v", got, want)
		}
	})

	t.Run("no options runs the built-in path", func(t *testing.T) {
		base := []byte("mail " + builderAddrBuiltin + " and user@example and " + builderAddrCorp + " end")
		set, err := Compile(rulesDoc(RuleDoc{ID: "mail-default", Type: TypeEmail, Action: ActionWarn}))
		if err != nil {
			t.Fatalf("Compile: %v", err)
		}
		matcher := set.rules[0].inspect
		if matcher == nil {
			t.Fatal("an options-less email rule compiled without an inspect matcher")
		}
		want := inspectEmail(base, set.Budget())
		if len(want) == 0 {
			t.Fatal("the built-in path matched nothing; the equality assertion would be vacuous")
		}
		if got := matcher(base); !reflect.DeepEqual(got, want) {
			t.Errorf("options-less matcher spans = %v, want the built-in inspectEmail spans %v", got, want)
		}
		if want[0] != builderSpanOf(t, base, builderAddrBuiltin) {
			t.Errorf("built-in span = %v, want the exact %s span", want[0], builderAddrBuiltin)
		}
	})
}

// TestCompileRejectsOptionsOnNonEmail pins the typed rejection of an email
// sub-object on every non-email rule type, and the acceptance of a non-nil
// options object without a sub-object (the decoder's `options: {}` form) as
// "no options" on every type.
func TestCompileRejectsOptionsOnNonEmail(t *testing.T) {
	nonEmailTypes := []string{TypeRegex, TypeKeyword, TypePrefix, TypeLuhn, TypeJWT, TypePEM, TypeEntropy}
	carrier := &RuleOptions{Email: &EmailOptions{Suffixes: []string{"corp.example"}}}
	for _, typ := range nonEmailTypes {
		rule := RuleDoc{ID: "opt-" + typ, Type: typ, Action: ActionWarn, Options: carrier}
		switch typ {
		case TypeRegex:
			rule.Pattern = "a+"
		case TypeKeyword:
			rule.Keywords = []string{"a"}
		}
		t.Run(typ, func(t *testing.T) {
			set, err := Compile(rulesDoc(rule))
			if err == nil {
				t.Fatalf("Compile accepted email options on a %s rule", typ)
			}
			if set != nil {
				t.Error("a rejected document must not return a set")
			}
			if !errors.Is(err, ErrCompile) {
				t.Errorf("errors.Is(%v, ErrCompile) = false; every compile rejection must match the sentinel", err)
			}
			var compileErr *CompileError
			if !errors.As(err, &compileErr) {
				t.Fatalf("error %v is not a *CompileError", err)
			}
			if compileErr.RuleID != rule.ID {
				t.Errorf("RuleID = %q, want %q", compileErr.RuleID, rule.ID)
			}
			if !strings.Contains(err.Error(), ".options.email") {
				t.Errorf("error %q must name the offending options path", err)
			}
		})
	}

	for _, typ := range nonEmailTypes {
		rule := RuleDoc{ID: "empty-" + typ, Type: typ, Action: ActionWarn, Options: &RuleOptions{}}
		switch typ {
		case TypeRegex:
			rule.Pattern = "a+"
		case TypeKeyword:
			rule.Keywords = []string{"a"}
		}
		t.Run("empty-"+typ, func(t *testing.T) {
			set, err := Compile(rulesDoc(rule))
			if err != nil {
				t.Fatalf("an empty options object declares no settings and must compile on a %s rule, got %v", typ, err)
			}
			if set.Len() != 1 {
				t.Fatalf("Len() = %d, want 1", set.Len())
			}
			if typ != TypeRegex && typ != TypeKeyword && set.rules[0].inspect == nil {
				t.Error("a primitive rule compiled without an inspect matcher")
			}
		})
	}
}

// TestCompileRejectsMalformedSuffix pins that a hand-built document cannot skip
// the options contract: every malformed suffix is rejected by the compiler's
// re-run normalization as a *CompileError matching ErrCompile and naming both
// the rule and the offending suffix path.
func TestCompileRejectsMalformedSuffix(t *testing.T) {
	cases := []struct {
		name   string
		suffix string
	}{
		{"dot run", "a..b"},
		{"empty after trimming", "  "},
		{"internal whitespace", "a b"},
		{"non-ASCII byte", "caf\u00e9.example"},
		{"over-length canonical form", strings.Repeat("a", MaxLiteralBytes)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			set, err := Compile(rulesDoc(RuleDoc{
				ID: "bad-suffix", Type: TypeEmail, Action: ActionWarn,
				Options: &RuleOptions{Email: &EmailOptions{Suffixes: []string{tc.suffix}}},
			}))
			if err == nil {
				t.Fatalf("Compile accepted the malformed suffix %q", tc.suffix)
			}
			if set != nil {
				t.Error("a rejected document must not return a set")
			}
			if !errors.Is(err, ErrCompile) {
				t.Errorf("errors.Is(%v, ErrCompile) = false; every compile rejection must match the sentinel", err)
			}
			var compileErr *CompileError
			if !errors.As(err, &compileErr) {
				t.Fatalf("error %v is not a *CompileError", err)
			}
			if compileErr.RuleID != "bad-suffix" {
				t.Errorf("RuleID = %q, want bad-suffix", compileErr.RuleID)
			}
			if !strings.Contains(err.Error(), "rules[0].options.email.suffixes[0]") {
				t.Errorf("error %q must name the offending suffix path", err)
			}
		})
	}
}

// TestCompileRejectsOptionCountBound pins the one options bound the builder
// path alone cannot enforce: a hand-built document with more suffixes than the
// decoder's entry bound is rejected at compile by the re-run options contract,
// so it never reaches a matcher over an unbounded set.
func TestCompileRejectsOptionCountBound(t *testing.T) {
	suffixes := make([]string, MaxEmailSuffixes+1)
	for i := range suffixes {
		suffixes[i] = strings.Repeat("a", 3)
	}
	set, err := Compile(rulesDoc(RuleDoc{
		ID: "too-many-suffixes", Type: TypeEmail, Action: ActionWarn,
		Options: &RuleOptions{Email: &EmailOptions{Suffixes: suffixes}},
	}))
	if err == nil {
		t.Fatalf("Compile accepted %d suffixes, above the %d-entry bound", len(suffixes), MaxEmailSuffixes)
	}
	if set != nil {
		t.Error("a rejected document must not return a set")
	}
	if !errors.Is(err, ErrCompile) {
		t.Errorf("errors.Is(%v, ErrCompile) = false; every compile rejection must match the sentinel", err)
	}
	var compileErr *CompileError
	if !errors.As(err, &compileErr) {
		t.Fatalf("error %v is not a *CompileError", err)
	}
	if compileErr.RuleID != "too-many-suffixes" {
		t.Errorf("RuleID = %q, want too-many-suffixes", compileErr.RuleID)
	}
	if !strings.Contains(err.Error(), "exceed") {
		t.Errorf("error %q must name the bound violation", err)
	}
}

// TestPrimitiveBuildersCoverEveryPrimitiveType pins the channel's completeness
// and its per-type options policy: the map holds exactly the six primitive
// types, every entry returns a non-nil closure, every compiled non-regex and
// non-keyword type resolves to an entry, and a builder rejects an email
// sub-object it cannot honor while accepting an options object without one.
func TestPrimitiveBuildersCoverEveryPrimitiveType(t *testing.T) {
	primitiveTypes := []string{TypePrefix, TypeEmail, TypeLuhn, TypeJWT, TypePEM, TypeEntropy}
	if len(primitiveBuilders) != len(primitiveTypes) {
		t.Errorf("primitiveBuilders has %d entries, want the six primitive types", len(primitiveBuilders))
	}
	for _, typ := range primitiveTypes {
		builder, ok := primitiveBuilders[typ]
		if !ok || builder == nil {
			t.Errorf("primitiveBuilders[%q] is missing", typ)
			continue
		}
		matcher, err := builder(nil, 0)
		if err != nil {
			t.Errorf("%s: builder(nil, 0) error = %v, want nil", typ, err)
		}
		if matcher == nil {
			t.Errorf("%s: builder(nil, 0) returned a nil matcher", typ)
		}
	}
	for typ := range compiledTypes {
		if typ == TypeRegex || typ == TypeKeyword {
			continue
		}
		if _, ok := primitiveBuilders[typ]; !ok {
			t.Errorf("compiled type %q has no primitive builder", typ)
		}
	}

	opts := &RuleOptions{Email: &EmailOptions{Suffixes: []string{"corp.example"}}}
	for _, typ := range []string{TypePrefix, TypeLuhn, TypeJWT, TypePEM, TypeEntropy} {
		if _, err := primitiveBuilders[typ](opts, 0); err == nil {
			t.Errorf("%s: builder accepted an email sub-object it cannot honor", typ)
		} else if !errors.Is(err, ErrInvalidValue) {
			t.Errorf("%s: builder error %v does not match ErrInvalidValue", typ, err)
		}
		if matcher, err := primitiveBuilders[typ](&RuleOptions{}, 0); err != nil || matcher == nil {
			t.Errorf("%s: builder rejected an empty options object: err %v, matcher nil = %t", typ, err, matcher == nil)
		}
	}
}

// nonEmailInspectOracle is the test-local oracle of the deleted production
// primitive dispatch map: the surviving top-level inspect functions, one per
// primitive type.
var nonEmailInspectOracle = map[string]func([]byte, int) []Span{
	TypePrefix:  inspectPrefix,
	TypeEmail:   inspectEmail,
	TypeLuhn:    inspectLuhn,
	TypeJWT:     inspectJWT,
	TypePEM:     inspectPEM,
	TypeEntropy: inspectEntropy,
}

// TestCompileNonEmailMatcherOutputUnchanged proves the builder channel changed
// no non-email matcher: for every primitive type the compiled rule's inspect
// output is byte-identical to a direct call of the surviving top-level inspect
// function under the same budget (the deleted map was a pure alias of these),
// and a regex or keyword rule still carries no inspect
// matcher. Every bait is asserted non-empty, so the equality is never vacuous.
func TestCompileNonEmailMatcherOutputUnchanged(t *testing.T) {
	const budget = 64
	baits := map[string][]byte{
		TypePrefix:  []byte("key " + "sk-" + strings.Repeat("A1b2", 8)),
		TypeEmail:   []byte("mail " + builderAddrBuiltin + " end"),
		TypeLuhn:    []byte("card " + "4111 " + "1111 " + "1111 " + "1111" + " end"),
		TypeJWT:     []byte("jwt " + "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9" + "." + strings.Repeat("a", 16) + ".c2ln"),
		TypePEM:     []byte(builderPEMBlock("RSA PRIVATE KEY")),
		TypeEntropy: []byte("ent " + "aB3dE6gH9jK2mN5pQ8sT" + "1vW4yZ7bC0fI" + " end"),
	}
	for _, typ := range []string{TypePrefix, TypeEmail, TypeLuhn, TypeJWT, TypePEM, TypeEntropy} {
		bait := baits[typ]
		set, err := CompileWithBudget(rulesDoc(RuleDoc{ID: "r-" + typ, Type: typ, Action: ActionRedact}), budget)
		if err != nil {
			t.Fatalf("%s: CompileWithBudget: %v", typ, err)
		}
		rule := &set.rules[0]
		if rule.inspect == nil {
			t.Fatalf("%s: compiled rule has no inspect matcher", typ)
		}
		got := rule.inspect(bait)
		if len(got) == 0 {
			t.Fatalf("%s: the bait yields no spans, so equality would be vacuous", typ)
		}
		want := nonEmailInspectOracle[typ](bait, budget)
		if !reflect.DeepEqual(got, want) {
			t.Errorf("%s: builder spans %v, pre-builder dispatch spans %v", typ, got, want)
		}
	}

	set, err := Compile(rulesDoc(
		RuleDoc{ID: "re-rule", Type: TypeRegex, Pattern: "a+", Action: ActionWarn},
		RuleDoc{ID: "kw-rule", Type: TypeKeyword, Keywords: []string{"a"}, Action: ActionWarn},
	))
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	for i := range set.rules {
		if set.rules[i].inspect != nil {
			t.Errorf("%s: a %s rule must not grow an inspect matcher", set.rules[i].id, set.rules[i].typ)
		}
	}
}
