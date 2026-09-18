package filter

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
)

// decodeRuleDoc decodes one rule object through the public document decoder by
// wrapping it in a minimal local document, so each options observation is made
// at its real document path (rules[0]...).
func decodeRuleDoc(t *testing.T, rule string) (*Document, error) {
	t.Helper()
	return DecodeDocument([]byte(`{"schema_version":1,"rules":[` + rule + `]}`))
}

// TestRuleOptionsDecode pins the happy path of the options channel: a typed
// options object decodes, every email suffix is replaced in place by its
// canonical form, an explicit empty options object is accepted on any rule
// type, and a v1 pack with no options key keeps decoding unchanged.
func TestRuleOptionsDecode(t *testing.T) {
	t.Run("email suffixes decode and canonicalize in place", func(t *testing.T) {
		doc, err := decodeRuleDoc(t, `{"id":"corp-email","type":"email","action":"redact","options":{"email":{"suffixes":["corp.com","Corp.ORG"]}}}`)
		if err != nil {
			t.Fatalf("an email rule with options must decode: %v", err)
		}
		options := doc.Rules[0].Options
		if options == nil || options.Email == nil {
			t.Fatalf("Options = %+v, want the email sub-object", options)
		}
		got := options.Email.Suffixes
		if len(got) != 2 || got[0] != ".corp.com" || got[1] != ".corp.org" {
			t.Errorf("Suffixes = %v, want the canonical [.corp.com .corp.org]", got)
		}
		if options.Email.Replace {
			t.Error("Replace must default to false")
		}
	})

	t.Run("a replace declaration decodes", func(t *testing.T) {
		doc, err := decodeRuleDoc(t, `{"id":"corp-email","type":"email","action":"redact","options":{"email":{"suffixes":["corp.com"],"replace":true}}}`)
		if err != nil {
			t.Fatalf("replace:true must decode: %v", err)
		}
		if !doc.Rules[0].Options.Email.Replace {
			t.Error("Replace = false, want true")
		}
	})

	t.Run("an explicit empty options object is accepted", func(t *testing.T) {
		doc, err := decodeRuleDoc(t, `{"id":"plain","type":"regex","pattern":"PROJ-[0-9]{4,}","action":"redact","options":{}}`)
		if err != nil {
			t.Fatalf("options:{} must decode: %v", err)
		}
		if doc.Rules[0].Options == nil {
			t.Error("an explicit empty options object must decode to a non-nil Options")
		} else if doc.Rules[0].Options.Email != nil {
			t.Error("an empty options object must carry no email sub-object")
		}
	})

	t.Run("a v1 pack with no options key still decodes", func(t *testing.T) {
		doc, err := DecodeDocument(loadV1Pack(t))
		if err != nil {
			t.Fatalf("the v1 pack must keep decoding: %v", err)
		}
		for i := range doc.Rules {
			if doc.Rules[i].Options != nil {
				t.Errorf("rules[%d].Options = %+v, want nil for a v1 rule", i, doc.Rules[i].Options)
			}
		}
	})
}

// TestRuleOptionsRejectUnknown pins that an unknown key inside the options
// object, or inside its email sub-object, is rejected by name at the exact
// document path instead of being silently ignored.
func TestRuleOptionsRejectUnknown(t *testing.T) {
	tests := []struct {
		name string
		rule string
		path string
	}{
		{
			name: "unknown key inside the email sub-object",
			rule: `{"id":"corp-email","type":"email","action":"redact","options":{"email":{"foo":true}}}`,
			path: "rules[0].options.email.foo",
		},
		{
			name: "unknown key inside the options object",
			rule: `{"id":"corp-email","type":"email","action":"redact","options":{"foo":{}}}`,
			path: "rules[0].options.foo",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := decodeRuleDoc(t, tt.rule)
			if !errors.Is(err, ErrUnknownField) {
				t.Fatalf("error = %v, want ErrUnknownField", err)
			}
			var fieldErr *FieldError
			if !errors.As(err, &fieldErr) || fieldErr.Path != tt.path {
				t.Errorf("error = %v, want field path %q", err, tt.path)
			}
		})
	}
}

// TestRuleOptionsTypeMismatch pins that a present email sub-object on a
// non-email rule is rejected as an invalid value, naming the sub-object path.
func TestRuleOptionsTypeMismatch(t *testing.T) {
	tests := []struct {
		name string
		rule string
	}{
		{
			name: "prefix rule",
			rule: `{"id":"prefix-rule","type":"prefix","pattern":"sk-","action":"redact","options":{"email":{"suffixes":["x.com"]}}}`,
		},
		{
			name: "regex rule",
			rule: `{"id":"regex-rule","type":"regex","pattern":"PROJ-[0-9]{4,}","action":"redact","options":{"email":{"suffixes":["x.com"]}}}`,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := decodeRuleDoc(t, tt.rule)
			if !errors.Is(err, ErrInvalidValue) {
				t.Fatalf("error = %v, want ErrInvalidValue", err)
			}
			var fieldErr *FieldError
			if !errors.As(err, &fieldErr) || fieldErr.Path != "rules[0].options.email" {
				t.Errorf("error = %v, want field path rules[0].options.email", err)
			}
		})
	}
}

// TestRuleOptionsRejectCommand pins the command rule's exact options boundary:
// a present email sub-object is rejected because the validation call runs
// before the command early-return, while an explicit empty options object
// declares no settings and is accepted on every rule type, command included.
func TestRuleOptionsRejectCommand(t *testing.T) {
	t.Run("email options on a command rule are rejected", func(t *testing.T) {
		_, err := decodeRuleDoc(t, `{"id":"risky-cmd","type":"command","action":"block","command":"aws","options":{"email":{"suffixes":["x.com"]}}}`)
		if !errors.Is(err, ErrInvalidValue) {
			t.Fatalf("error = %v, want ErrInvalidValue", err)
		}
		if errors.Is(err, ErrUnknownField) {
			t.Errorf("error = %v, a command options rejection must not read as an unknown field", err)
		}
	})

	t.Run("an empty options object is accepted on a command rule", func(t *testing.T) {
		doc, err := decodeRuleDoc(t, `{"id":"risky-cmd","type":"command","action":"block","command":"aws","options":{}}`)
		if err != nil {
			t.Fatalf("options:{} on a command rule must decode: %v", err)
		}
		rule := doc.Rules[0]
		if !rule.ExcludedFromEvaluation {
			t.Error("a command rule must stay parse-only")
		}
		if rule.Options == nil || rule.Options.Email != nil {
			t.Errorf("Options = %+v, want a non-nil options object with no email sub-object", rule.Options)
		}
	})
}

// TestRuleOptionsBound pins the MaxEmailSuffixes boundary at the document
// decoder: exactly the bound is accepted and canonicalized, one entry above it
// fails with ErrBoundExceeded at the suffixes path, and a canonical form above
// the literal byte bound keeps its ErrBoundExceeded sentinel through the
// index-named field error.
func TestRuleOptionsBound(t *testing.T) {
	rule := func(t *testing.T, suffixes []string) string {
		t.Helper()
		encoded, err := json.Marshal(suffixes)
		if err != nil {
			t.Fatalf("marshal suffixes: %v", err)
		}
		return `{"id":"corp-email","type":"email","action":"redact","options":{"email":{"suffixes":` + string(encoded) + `}}}`
	}

	t.Run("exactly MaxEmailSuffixes entries are accepted", func(t *testing.T) {
		suffixes := make([]string, MaxEmailSuffixes)
		for i := range suffixes {
			suffixes[i] = fmt.Sprintf("s%d.example.com", i)
		}
		doc, err := decodeRuleDoc(t, rule(t, suffixes))
		if err != nil {
			t.Fatalf("%d suffixes must decode: %v", MaxEmailSuffixes, err)
		}
		got := doc.Rules[0].Options.Email.Suffixes
		if len(got) != MaxEmailSuffixes {
			t.Fatalf("decoded %d suffixes, want %d", len(got), MaxEmailSuffixes)
		}
		if got[0] != ".s0.example.com" || got[MaxEmailSuffixes-1] != fmt.Sprintf(".s%d.example.com", MaxEmailSuffixes-1) {
			t.Errorf("boundary suffixes = (%q, %q), want canonical forms", got[0], got[MaxEmailSuffixes-1])
		}
	})

	t.Run("one entry above the bound is rejected", func(t *testing.T) {
		suffixes := make([]string, MaxEmailSuffixes+1)
		for i := range suffixes {
			suffixes[i] = fmt.Sprintf("s%d.example.com", i)
		}
		_, err := decodeRuleDoc(t, rule(t, suffixes))
		if !errors.Is(err, ErrBoundExceeded) {
			t.Fatalf("error = %v, want ErrBoundExceeded", err)
		}
		var fieldErr *FieldError
		if !errors.As(err, &fieldErr) || fieldErr.Path != "rules[0].options.email.suffixes" {
			t.Errorf("error = %v, want field path rules[0].options.email.suffixes", err)
		}
	})

	t.Run("an over-length canonical suffix keeps ErrBoundExceeded", func(t *testing.T) {
		// MaxLiteralBytes raw bytes with no leading dot canonicalize to one byte
		// more, so the literal bound passes and only normalization rejects it.
		suffixes := []string{strings.Repeat("a", MaxLiteralBytes)}
		_, err := decodeRuleDoc(t, rule(t, suffixes))
		if !errors.Is(err, ErrBoundExceeded) {
			t.Fatalf("error = %v, want ErrBoundExceeded", err)
		}
		var fieldErr *FieldError
		if !errors.As(err, &fieldErr) || fieldErr.Path != "rules[0].options.email.suffixes[0]" {
			t.Errorf("error = %v, want field path rules[0].options.email.suffixes[0]", err)
		}
	})
}

// TestRuleOptionsMalformed pins the remaining malformed-input observations: a
// null options value and a null email sub-object are shape failures rejected at
// their own path, and a malformed suffix string is rejected with the index of
// the offending entry so the caller learns which one failed.
func TestRuleOptionsMalformed(t *testing.T) {
	tests := []struct {
		name string
		rule string
		path string
	}{
		{
			name: "a null options value is rejected",
			rule: `{"id":"corp-email","type":"email","action":"redact","options":null}`,
			path: "rules[0].options",
		},
		{
			name: "a null email sub-object is rejected",
			rule: `{"id":"corp-email","type":"email","action":"redact","options":{"email":null}}`,
			path: "rules[0].options.email",
		},
		{
			name: "a malformed suffix is rejected with its index",
			rule: `{"id":"corp-email","type":"email","action":"redact","options":{"email":{"suffixes":["ok.com","has space"]}}}`,
			path: "rules[0].options.email.suffixes[1]",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := decodeRuleDoc(t, tt.rule)
			if !errors.Is(err, ErrInvalidValue) {
				t.Fatalf("error = %v, want ErrInvalidValue", err)
			}
			var fieldErr *FieldError
			if !errors.As(err, &fieldErr) || fieldErr.Path != tt.path {
				t.Errorf("error = %v, want field path %q", err, tt.path)
			}
		})
	}
}
