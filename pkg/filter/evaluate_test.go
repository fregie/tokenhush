package filter

// evaluate_test.go pins the evaluator over the leaf model: byte spans instead
// of content, a deterministic (leaf, start, end) order that does not depend on
// declaration order, allowlist suppression (global and per-rule), blocklist
// findings that no allowlist can suppress and that fire in both phases, the
// hard MaxMatches bound with no partial results, and race-free concurrent
// evaluation.

import (
	"errors"
	"reflect"
	"regexp"
	"strings"
	"sync"
	"testing"

	"github.com/fregie/tokenhush/pkg/protocol"
)

func mustEvaluate(t *testing.T, set *Compiled, leaves []protocol.Leaf, phase Scope) []Finding {
	t.Helper()
	findings, err := set.Evaluate(leaves, phase)
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	return findings
}

func leaf(value string) protocol.Leaf {
	return protocol.Leaf{Value: []byte(value), Length: len(value)}
}

// TestEvaluateSpansAndOrdering pins the finding shape: no content bytes, a
// leaf index and a byte span, ordered by (leaf, start, end).
func TestEvaluateSpansAndOrdering(t *testing.T) {
	set := compileDoc(t, `{"rules":[{"id":"k","type":"keyword","keywords":["ab"],"action":"warn"}]}`)
	leaves := []protocol.Leaf{leaf("xxabxxab"), leaf("abab")}
	got := mustEvaluate(t, set, leaves, ScopeRequest)
	want := []Finding{
		{RuleID: "k", Category: CategoryCustom, Action: ActionWarn, LeafIndex: 0, Start: 2, End: 4, Confidence: DefaultConfidence},
		{RuleID: "k", Category: CategoryCustom, Action: ActionWarn, LeafIndex: 0, Start: 6, End: 8, Confidence: DefaultConfidence},
		{RuleID: "k", Category: CategoryCustom, Action: ActionWarn, LeafIndex: 1, Start: 0, End: 2, Confidence: DefaultConfidence},
		{RuleID: "k", Category: CategoryCustom, Action: ActionWarn, LeafIndex: 1, Start: 2, End: 4, Confidence: DefaultConfidence},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("findings = %+v, want %+v", got, want)
	}
	for _, finding := range got {
		if match := leaves[finding.LeafIndex].Value[finding.Start:finding.End]; string(match) != "ab" {
			t.Errorf("span [%d,%d) in leaf %d = %q, want the matched bytes", finding.Start, finding.End, finding.LeafIndex, match)
		}
	}
}

// TestEvaluateGlobalAndPerRuleAllowlist pins suppression semantics: a match
// contained in an occurrence of an allowlist literal yields no finding, global
// lists suppress every rule and a per-rule list suppresses only its own rule.
func TestEvaluateGlobalAndPerRuleAllowlist(t *testing.T) {
	set := compileDoc(t, `{
	  "allowlist": ["user@example.com"],
	  "rules": [
	    {"id": "mail", "type": "email", "category": "email", "action": "warn"},
	    {"id": "kw", "type": "keyword", "keywords": ["secret"], "action": "warn", "allowlist": ["topsecretstuff"]},
	    {"id": "free", "type": "keyword", "keywords": ["secret"], "action": "warn"}
	  ]
	}`)
	leaves := []protocol.Leaf{leaf("user@example.com other@example.org topsecretstuff secret")}
	got := mustEvaluate(t, set, leaves, ScopeRequest)
	want := []Finding{
		{RuleID: "mail", Category: CategoryEmail, Action: ActionWarn, LeafIndex: 0, Start: 17, End: 34, Confidence: DefaultConfidence},
		{RuleID: "free", Category: CategoryCustom, Action: ActionWarn, LeafIndex: 0, Start: 38, End: 44, Confidence: DefaultConfidence},
		{RuleID: "free", Category: CategoryCustom, Action: ActionWarn, LeafIndex: 0, Start: 50, End: 56, Confidence: DefaultConfidence},
		{RuleID: "kw", Category: CategoryCustom, Action: ActionWarn, LeafIndex: 0, Start: 50, End: 56, Confidence: DefaultConfidence},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("findings = %+v, want %+v (global suppression, per-rule suppression, and the shared tie-break order)", got, want)
	}
}

// TestEvaluateBlocklistNeverSuppressed pins the blocklist contract:
// a global blocklist hit becomes a Block finding at confidence 1 in BOTH
// content phases, an allowlist cannot suppress it even when it names the same
// literal, and the marker is not one of the six detector categories.
func TestEvaluateBlocklistNeverSuppressed(t *testing.T) {
	set := compileDoc(t, `{
	  "allowlist": ["TOKENHUSH_BLOCK"],
	  "blocklist": ["TOKENHUSH_BLOCK"],
	  "rules": [{"id": "k", "type": "keyword", "keywords": ["TOKENHUSH_BLOCK"], "action": "warn"}]
	}`)
	leaves := []protocol.Leaf{leaf("x TOKENHUSH_BLOCK y")}
	want := []Finding{
		{RuleID: RuleIDBlocklist, Category: CategoryCustom, Action: ActionBlock, LeafIndex: 0, Start: 2, End: 17, Confidence: 1},
	}
	for _, phase := range []Scope{ScopeRequest, ScopeResponse} {
		got := mustEvaluate(t, set, leaves, phase)
		if !reflect.DeepEqual(got, want) {
			t.Errorf("phase %q: findings = %+v, want the Block finding %+v", phase, got, want)
		}
	}
	for _, detectorCategory := range []string{CategoryAPIKey, CategoryEmail, CategoryCreditCard, CategoryPrivateKey, CategoryJWT, CategoryHighEntropy} {
		if want[0].Category == detectorCategory {
			t.Errorf("the blocklist marker must not be the detector category %q", detectorCategory)
		}
	}
}

// TestEvaluateIndependentOfDeclarationOrder: the same rules declared in the
// opposite order produce byte-identical findings, including exact-span ties.
func TestEvaluateIndependentOfDeclarationOrder(t *testing.T) {
	first := compileDoc(t, `{"rules":[
	  {"id": "zulu", "type": "keyword", "keywords": ["ab"], "action": "warn"},
	  {"id": "alpha", "type": "keyword", "keywords": ["ab"], "action": "warn"}
	]}`)
	second := compileDoc(t, `{"rules":[
	  {"id": "alpha", "type": "keyword", "keywords": ["ab"], "action": "warn"},
	  {"id": "zulu", "type": "keyword", "keywords": ["ab"], "action": "warn"}
	]}`)
	leaves := []protocol.Leaf{leaf("ab")}
	gotFirst := mustEvaluate(t, first, leaves, ScopeRequest)
	gotSecond := mustEvaluate(t, second, leaves, ScopeRequest)
	if !reflect.DeepEqual(gotFirst, gotSecond) {
		t.Fatalf("declaration order changed the findings:\n%+v\n%+v", gotFirst, gotSecond)
	}
	if len(gotFirst) != 2 || gotFirst[0].RuleID != "alpha" || gotFirst[1].RuleID != "zulu" {
		t.Fatalf("equal-span ties must break on rule id, got %+v", gotFirst)
	}
}

// TestEvaluatePriorityOrdersInvocation pins priority ascending: a lower
// priority number is invoked first even when its id would sort later, and equal
// priorities fall back to the id.
func TestEvaluatePriorityOrdersInvocation(t *testing.T) {
	set := compileDoc(t, `{"rules":[
	  {"id": "alpha", "type": "keyword", "keywords": ["ab"], "action": "warn", "priority": 20},
	  {"id": "zulu", "type": "keyword", "keywords": ["ab"], "action": "warn", "priority": 10}
	]}`)
	got := mustEvaluate(t, set, []protocol.Leaf{leaf("ab")}, ScopeRequest)
	if len(got) != 2 || got[0].RuleID != "zulu" || got[1].RuleID != "alpha" {
		t.Fatalf("findings = %+v, want zulu (priority 10) before alpha (priority 20)", got)
	}
}

// TestEvaluatePhaseScoping: a request-scoped rule never runs in the response
// phase and vice versa; a both-scoped rule runs in either.
func TestEvaluatePhaseScoping(t *testing.T) {
	set := compileDoc(t, `{"rules":[
	  {"id": "req", "type": "keyword", "keywords": ["aaa"], "action": "warn", "scope": "request"},
	  {"id": "resp", "type": "keyword", "keywords": ["bbb"], "action": "block", "scope": "response"},
	  {"id": "both", "type": "keyword", "keywords": ["ccc"], "action": "warn", "scope": "both"}
	]}`)
	leaves := []protocol.Leaf{leaf("aaa bbb ccc")}
	gotRequest := mustEvaluate(t, set, leaves, ScopeRequest)
	wantRequest := []Finding{
		{RuleID: "req", Category: CategoryCustom, Action: ActionWarn, LeafIndex: 0, Start: 0, End: 3, Confidence: DefaultConfidence},
		{RuleID: "both", Category: CategoryCustom, Action: ActionWarn, LeafIndex: 0, Start: 8, End: 11, Confidence: DefaultConfidence},
	}
	if !reflect.DeepEqual(gotRequest, wantRequest) {
		t.Errorf("request findings = %+v, want %+v", gotRequest, wantRequest)
	}
	gotResponse := mustEvaluate(t, set, leaves, ScopeResponse)
	wantResponse := []Finding{
		{RuleID: "resp", Category: CategoryCustom, Action: ActionBlock, LeafIndex: 0, Start: 4, End: 7, Confidence: DefaultConfidence},
		{RuleID: "both", Category: CategoryCustom, Action: ActionWarn, LeafIndex: 0, Start: 8, End: 11, Confidence: DefaultConfidence},
	}
	if !reflect.DeepEqual(gotResponse, wantResponse) {
		t.Errorf("response findings = %+v, want %+v", gotResponse, wantResponse)
	}
}

// TestEvaluateMaxMatchesBound: exactly MaxMatches findings pass, one more fails
// with ErrMatchLimit and NO partial result, for rules and for the blocklist.
func TestEvaluateMaxMatchesBound(t *testing.T) {
	ruleSet := compileDoc(t, `{"rules":[{"id":"k","type":"keyword","keywords":["ab"],"action":"warn"}]}`)
	atBound := []protocol.Leaf{leaf(strings.Repeat("ab", MaxMatches))}
	got, err := ruleSet.Evaluate(atBound, ScopeRequest)
	if err != nil {
		t.Fatalf("exactly MaxMatches findings must be accepted: %v", err)
	}
	if len(got) != MaxMatches {
		t.Fatalf("findings = %d, want %d", len(got), MaxMatches)
	}
	overBound := []protocol.Leaf{leaf(strings.Repeat("ab", MaxMatches+1))}
	got, err = ruleSet.Evaluate(overBound, ScopeRequest)
	if err == nil || !errors.Is(err, ErrMatchLimit) {
		t.Fatalf("one match more than the bound: error = %v, want ErrMatchLimit", err)
	}
	if got != nil {
		t.Errorf("a bound failure must return no partial results, got %d findings", len(got))
	}

	blocklistSet := compileDoc(t, `{"blocklist":["ab"],"rules":[{"id":"k","type":"keyword","keywords":["zz"],"action":"warn"}]}`)
	got, err = blocklistSet.Evaluate(overBound, ScopeRequest)
	if err == nil || !errors.Is(err, ErrMatchLimit) {
		t.Fatalf("blocklist one match more than the bound: error = %v, want ErrMatchLimit", err)
	}
	if got != nil {
		t.Errorf("a blocklist bound failure must return no partial results, got %d findings", len(got))
	}
}

// TestEvaluateDeterminism: repeated evaluation of the same input returns
// identical findings.
func TestEvaluateDeterminism(t *testing.T) {
	set := compileDoc(t, mixedDoc)
	leaves := []protocol.Leaf{
		leaf("mail user@example.org key sk-AAAAAAAAAAAAAAAAAAAA"),
		leaf("PROJ-1234 and global-block"),
	}
	first := mustEvaluate(t, set, leaves, ScopeRequest)
	if len(first) == 0 {
		t.Fatal("the fixture must produce findings")
	}
	for i := 0; i < 4; i++ {
		if got := mustEvaluate(t, set, leaves, ScopeRequest); !reflect.DeepEqual(got, first) {
			t.Fatalf("run %d = %+v, want %+v", i, got, first)
		}
	}
}

// TestEvaluateConcurrentRaceFree runs Evaluate from many goroutines over one
// shared compiled set and shared leaves. Run with -race: it completes the W3.4
// race requirement now that Evaluate exists.
func TestEvaluateConcurrentRaceFree(t *testing.T) {
	set := compileDoc(t, mixedDoc)
	leaves := []protocol.Leaf{leaf("secret user@example.org global-block"), leaf("PROJ-4321")}
	want := mustEvaluate(t, set, leaves, ScopeRequest)
	var wg sync.WaitGroup
	for worker := 0; worker < 8; worker++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 50; i++ {
				got, err := set.Evaluate(leaves, ScopeRequest)
				if err != nil {
					t.Errorf("concurrent Evaluate: %v", err)
					return
				}
				if !reflect.DeepEqual(got, want) {
					t.Errorf("concurrent findings = %+v, want %+v", got, want)
					return
				}
			}
		}()
	}
	wg.Wait()
}

// TestEvaluateNeverDecodesOrNormalizes: the evaluator inspects the bytes it is
// handed, so a base64 rendering of a secret is not a secret and an encoded leaf
// is searched exactly as stored.
func TestEvaluateNeverDecodesOrNormalizes(t *testing.T) {
	set := compileDoc(t, `{"rules":[{"id":"kw","type":"keyword","keywords":["secret"],"action":"warn"}]}`)
	encoded := protocol.Leaf{Value: []byte("c2VjcmV0"), Length: 8, Encoded: true}
	if got := mustEvaluate(t, set, []protocol.Leaf{encoded}, ScopeRequest); len(got) != 0 {
		t.Errorf("a base64 rendering must not be decoded, got %+v", got)
	}
	raw := mustEvaluate(t, set, []protocol.Leaf{leaf("secret")}, ScopeRequest)
	if len(raw) != 1 || raw[0].Start != 0 || raw[0].End != 6 {
		t.Errorf("raw secret findings = %+v, want one span [0,6)", raw)
	}
}

// TestEvaluateReadsValueLeavesOnly: the leaf model already drops keys, so a
// keyword that only appears as an object key never produces a finding.
func TestEvaluateReadsValueLeavesOnly(t *testing.T) {
	leaves, err := protocol.Walk([]byte(`{"token":"hello","nested":{"secret":"value"}}`))
	if err != nil {
		t.Fatalf("protocol.Walk: %v", err)
	}
	keyOnly := compileDoc(t, `{"rules":[{"id":"key","type":"keyword","keywords":["token","nested","secret"],"action":"warn"}]}`)
	if got := mustEvaluate(t, keyOnly, leaves, ScopeRequest); len(got) != 0 {
		t.Errorf("keys must never be inspected, got %+v", got)
	}
	valueRule := compileDoc(t, `{"rules":[{"id":"val","type":"keyword","keywords":["hello"],"action":"warn"}]}`)
	got := mustEvaluate(t, valueRule, leaves, ScopeRequest)
	if len(got) != 1 || got[0].LeafIndex != 0 || string(leaves[0].Value[got[0].Start:got[0].End]) != "hello" {
		t.Errorf("value findings = %+v, want the /token value", got)
	}
}

// TestEvaluateRejectsInvalidInput pins the typed failures for a nil set and a
// phase that is not one content phase.
func TestEvaluateRejectsInvalidInput(t *testing.T) {
	set := compileDoc(t, `{"rules":[{"id":"k","type":"keyword","keywords":["ab"],"action":"warn"}]}`)
	for _, phase := range []Scope{ScopeBoth, "", Scope("bogus")} {
		if _, err := set.Evaluate(nil, phase); err == nil || !errors.Is(err, ErrInvalidValue) {
			t.Errorf("phase %q: error = %v, want ErrInvalidValue", phase, err)
		}
	}
	var nilSet *Compiled
	if _, err := nilSet.Evaluate([]protocol.Leaf{leaf("ab")}, ScopeRequest); err == nil || !errors.Is(err, ErrInvalidValue) {
		t.Errorf("nil set: error = %v, want ErrInvalidValue", err)
	}
	if got, err := set.Evaluate(nil, ScopeRequest); err != nil || got != nil {
		t.Errorf("no leaves = (%v, %v), want (nil, nil)", got, err)
	}
}

// TestEvaluateFindingCarriesNoContentBytes pins the finding shape: offsets and
// metadata only, never a byte slice, map or content-named field.
func TestEvaluateFindingCarriesNoContentBytes(t *testing.T) {
	contentName := regexp.MustCompile(`(?i)content|match|value|text|body|bytes|raw|data`)
	typ := reflect.TypeOf(Finding{})
	if typ.NumField() == 0 {
		t.Fatal("Finding has no fields")
	}
	for i := 0; i < typ.NumField(); i++ {
		field := typ.Field(i)
		switch field.Type.Kind() {
		case reflect.Slice, reflect.Array, reflect.Map, reflect.Pointer, reflect.Interface, reflect.Func:
			t.Errorf("Finding field %q has kind %v; findings must carry metadata and offsets only", field.Name, field.Type.Kind())
		}
		if contentName.MatchString(field.Name) {
			t.Errorf("Finding field %q names matched content", field.Name)
		}
	}
}

// TestEvaluateEmailOptions pins the evaluator's final dispatch end to end: a
// compiled primitive rule evaluates through the matcher the compiler bound from
// its type and options, so a declared additive suffix finds the address the
// built-in table rejects while a shared byte tail still does not match, and the
// global and per-rule allowlists, the never-suppressed blocklist and phase
// scoping are unchanged. The fixtures are fresh readable addresses assembled
// from parts.
func TestEvaluateEmailOptions(t *testing.T) {
	const at = "@"
	const (
		evalAddrBuiltin  = "alice" + at + "example.com"     // .com: a built-in suffix
		evalAddrAdditive = "bob" + at + "sub.corp.example"  // .corp.example: declared suffix only
		evalAddrGlobal   = "carol" + at + "example.com"     // covered by the global allowlist
		evalAddrRule     = "dave" + at + "sub.corp.example" // covered by the mail rule's allowlist
		evalAddrTail     = "erin" + at + "evilcorp.example" // shared byte tail of the declared suffix
		evalAddrBlocked  = "frank" + at + "example.com"     // blocklisted and globally allowlisted
	)
	set := compileDoc(t, `{
	  "allowlist": ["`+evalAddrGlobal+`", "`+evalAddrBlocked+`"],
	  "blocklist": ["`+evalAddrBlocked+`"],
	  "rules": [
	    {"id": "mail", "type": "email", "category": "email", "action": "warn",
	     "allowlist": ["`+evalAddrRule+`"],
	     "options": {"email": {"suffixes": ["corp.example"]}}},
	    {"id": "resp-mail", "type": "email", "category": "email", "action": "warn", "scope": "response"}
	  ]
	}`)
	content := strings.Join([]string{evalAddrAdditive, evalAddrBuiltin, evalAddrGlobal, evalAddrRule, evalAddrTail, evalAddrBlocked}, " ")
	for _, addr := range []string{evalAddrAdditive, evalAddrBuiltin, evalAddrGlobal, evalAddrRule, evalAddrTail, evalAddrBlocked} {
		if !strings.Contains(content, addr) {
			t.Fatalf("fixture %q is absent from the content, so its assertion would be vacuous", addr)
		}
	}
	leaves := []protocol.Leaf{leaf(content)}
	contentBytes := []byte(content)
	additiveSpan := builderSpanOf(t, contentBytes, evalAddrAdditive)
	builtinSpan := builderSpanOf(t, contentBytes, evalAddrBuiltin)
	blockedSpan := builderSpanOf(t, contentBytes, evalAddrBlocked)

	gotRequest := mustEvaluate(t, set, leaves, ScopeRequest)
	wantRequest := []Finding{
		{RuleID: "mail", Category: CategoryEmail, Action: ActionWarn, LeafIndex: 0, Start: additiveSpan.Start, End: additiveSpan.End, Confidence: DefaultConfidence},
		{RuleID: "mail", Category: CategoryEmail, Action: ActionWarn, LeafIndex: 0, Start: builtinSpan.Start, End: builtinSpan.End, Confidence: DefaultConfidence},
		{RuleID: RuleIDBlocklist, Category: CategoryCustom, Action: ActionBlock, LeafIndex: 0, Start: blockedSpan.Start, End: blockedSpan.End, Confidence: 1},
	}
	if !reflect.DeepEqual(gotRequest, wantRequest) {
		t.Errorf("request findings = %+v, want the additive and built-in mail findings (the global- and rule-allowlisted occurrences and the shared-tail lookalike suppressed) plus the block finding %+v", gotRequest, wantRequest)
	}

	gotResponse := mustEvaluate(t, set, leaves, ScopeResponse)
	wantResponse := []Finding{
		{RuleID: "resp-mail", Category: CategoryEmail, Action: ActionWarn, LeafIndex: 0, Start: builtinSpan.Start, End: builtinSpan.End, Confidence: DefaultConfidence},
		{RuleID: RuleIDBlocklist, Category: CategoryCustom, Action: ActionBlock, LeafIndex: 0, Start: blockedSpan.Start, End: blockedSpan.End, Confidence: 1},
	}
	if !reflect.DeepEqual(gotResponse, wantResponse) {
		t.Errorf("response findings = %+v, want the response-scoped rule and the block finding only %+v", gotResponse, wantResponse)
	}
}
