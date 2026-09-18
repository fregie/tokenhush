package filter

// primitive_builders.go owns the compile-time channel from a rule's typed
// options to the matcher a compiled rule evaluates through: one builder per
// primitive detector type, each returning a non-nil closure over the compiled
// set's per-primitive byte budget. A builder rejects any option sub-object its
// type cannot honor instead of accepting and ignoring it. The builders live in
// this file so compile.go stays under the 250-pure-LOC ceiling; compileRule
// re-runs the options contract and wraps every builder rejection in a
// *CompileError.

import "fmt"

// primitiveBuilder builds one primitive rule's matcher from the rule's options
// and the compiled set's per-primitive byte budget. On success it returns a
// non-nil, stateless, concurrency-safe closure; on a rejected option it returns
// a typed error and a nil matcher, so no caller can install a matcher over
// options the detector could not honor.
type primitiveBuilder func(opts *RuleOptions, budget int) (func([]byte) []Span, error)

// buildOptionlessPrimitive returns the builder of one primitive type that
// declares no options sub-object of its own. A nil options object and an
// options object without a sub-object both mean "no settings" and are accepted,
// matching the decoder's `options: {}` contract; a present email sub-object is
// rejected with ErrInvalidValue because silently dropping it would ignore an
// operator's declared intent. The closure normalizes the budget once and
// delegates to the bundled algorithm, so its spans are identical to a direct
// call of that algorithm under the same budget.
func buildOptionlessPrimitive(typ string, inspect func([]byte, int) []Span) primitiveBuilder {
	return func(opts *RuleOptions, budget int) (func([]byte) []Span, error) {
		if opts != nil && opts.Email != nil {
			return nil, fmt.Errorf("%w: email options are only valid on an email rule, got type %q", ErrInvalidValue, typ)
		}
		budget = normalizeBudget(budget)
		return func(content []byte) []Span { return inspect(content, budget) }, nil
	}
}

// buildEmailPrimitive is the email builder: with an email sub-object it binds
// the rule's effective suffix set through buildEmailMatcher; without one it
// binds the built-in path, so an options-less email rule matches exactly what
// inspectEmail matches.
func buildEmailPrimitive(opts *RuleOptions, budget int) (func([]byte) []Span, error) {
	if opts == nil || opts.Email == nil {
		budget = normalizeBudget(budget)
		return func(content []byte) []Span { return inspectEmail(content, budget) }, nil
	}
	return buildEmailMatcher(opts.Email, budget)
}

// primitiveBuilders maps the six primitive detector types onto their builders,
// the single dispatch compileRule binds a compiled rule's inspect matcher
// through. Every entry returns a non-nil closure on success.
var primitiveBuilders = map[string]primitiveBuilder{
	TypePrefix:  buildOptionlessPrimitive(TypePrefix, inspectPrefix),
	TypeEmail:   buildEmailPrimitive,
	TypeLuhn:    buildOptionlessPrimitive(TypeLuhn, inspectLuhn),
	TypeJWT:     buildOptionlessPrimitive(TypeJWT, inspectJWT),
	TypePEM:     buildOptionlessPrimitive(TypePEM, inspectPEM),
	TypeEntropy: buildOptionlessPrimitive(TypeEntropy, inspectEntropy),
}
