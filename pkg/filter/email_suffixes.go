package filter

// email_suffixes.go owns the built-in email public-suffix table, the
// single-owner effective-suffix union, and the label-boundary domain matcher
// that gates the email detector's candidates. The table is PROVISIONAL: it is
// a curated list of real public suffixes, and todo 6 reconciles it against the
// repository's positive fixtures before freezing it. It deliberately contains
// no reserved or special-use name (localhost, test, example, invalid), because
// a matcher that accepted those would treat every documentation address as a
// secret. A frozen marker is added only when todo 6 lands.

import (
	"slices"
	"strings"
)

// builtinEmailSuffixes is the PROVISIONAL curated public-suffix list, in
// dot-prefixed canonical form. It contains REAL public suffixes only: the
// reserved and special-use names (localhost, test, example, invalid) and the
// bare reserved TLDs are deliberately absent. Compound entries such as .co.uk
// are redundant given .uk and are kept as documentation of intent. The list is
// NOT frozen until todo 6 has reconciled it with the repository's email
// fixtures; only normalizeEmailSuffix canonicalization and this table's own
// accessors may read it.
var builtinEmailSuffixes = []string{
	".com", ".org", ".net", ".edu", ".gov", ".mil", ".int",
	".info", ".biz", ".name", ".pro", ".app", ".dev", ".io", ".ai",
	".co", ".me", ".tv", ".cc", ".xyz", ".online", ".site", ".tech", ".cloud", ".email",
	".cn", ".com.cn", ".net.cn", ".org.cn", ".gov.cn",
	".hk", ".com.hk", ".tw", ".com.tw", ".jp", ".co.jp", ".kr", ".co.kr",
	".uk", ".co.uk", ".de", ".fr", ".it", ".es", ".nl", ".be", ".ch", ".at", ".se", ".no", ".dk", ".fi", ".pl", ".cz", ".ro", ".hu", ".gr", ".pt", ".ie", ".ru",
	".br", ".com.br", ".mx", ".com.mx", ".ar", ".com.ar", ".cl",
	".in", ".co.in", ".au", ".com.au", ".nz", ".co.nz", ".sg", ".com.sg", ".my", ".com.my", ".id", ".co.id", ".th", ".co.th", ".ph", ".vn", ".tr", ".za", ".co.za", ".ae", ".sa", ".il", ".us", ".eu", ".ca",
}

// BuiltinEmailSuffixes returns a fresh clone of the built-in suffix table, so
// a caller can sort, filter or append to the result without ever mutating the
// package table or another caller's view of it.
func BuiltinEmailSuffixes() []string {
	return slices.Clone(builtinEmailSuffixes)
}

// effectiveEmailSuffixes returns the suffix set one email rule matches
// against, and is the single owner of the built-in/declared union. With no
// options, or with additive options, the result is a COPY of the built-in
// table unioned with the normalized declared suffixes; it is never
// append(builtinEmailSuffixes, ...), which could write into the package
// slice's spare capacity and corrupt a later reader. With Replace the result
// is the normalized declared suffixes only. Each declared entry is
// canonicalized by normalizeEmailSuffix and the first failure is returned
// unchanged, so the caller can pin the document or rule path. The union
// deduplicates by first occurrence, so a declared repeat of a built-in entry
// does not grow the set.
func effectiveEmailSuffixes(opts *EmailOptions) ([]string, error) {
	var declared []string
	replace := false
	if opts != nil {
		declared = opts.Suffixes
		replace = opts.Replace
	}

	out := make([]string, 0, len(builtinEmailSuffixes)+len(declared))
	if !replace {
		out = append(out, builtinEmailSuffixes...)
	}
	seen := make(map[string]struct{}, len(out)+len(declared))
	for _, suffix := range out {
		seen[suffix] = struct{}{}
	}
	for _, raw := range declared {
		canonical, err := normalizeEmailSuffix(raw)
		if err != nil {
			return nil, err
		}
		if _, duplicate := seen[canonical]; duplicate {
			continue
		}
		seen[canonical] = struct{}{}
		out = append(out, canonical)
	}
	return out, nil
}

// domainHasSuffix reports whether domain is, or is a subdomain of, one of the
// canonical suffixes. The domain is lowercased first. A canonical suffix is
// dot-prefixed, so domain == suffix[1:] matches the bare label sequence
// ("corp.com" against ".corp.com") and strings.HasSuffix(domain, suffix)
// matches every deeper subdomain ("a.corp.com" against ".corp.com") at a label
// boundary, never at a shared byte tail ("evilcorp.com" does not match
// ".corp.com"). Suffixes shorter than two bytes are skipped: an empty string
// would panic on suffix[1:], and normalizeEmailSuffix may return a lone ".",
// which carries no label and must stay inert. An empty suffix list matches
// nothing.
func domainHasSuffix(domain string, suffixes []string) bool {
	domain = strings.ToLower(domain)
	for _, suffix := range suffixes {
		if len(suffix) < 2 {
			continue
		}
		if domain == suffix[1:] || strings.HasSuffix(domain, suffix) {
			return true
		}
	}
	return false
}
