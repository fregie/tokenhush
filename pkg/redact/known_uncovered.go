package redact

// knownUncoveredEncodings is the canonical honesty list for the outbound
// encoding re-check. It mirrors testdata/known_uncovered_encodings.txt, the
// documentation artifact the security documentation cites; a test asserts the
// two stay byte-for-byte equal, so neither side can drift from the other.
//
// The re-check is high-confidence interception, not a closed guarantee. This
// list states the residual risk explicitly instead of implying completeness.
var knownUncoveredEncodings = []string{
	"arbitrary multi-layer custom or non-standard encodings (the decoder set is a fixed enumeration, not a grammar)",
	"encodings nested deeper than NormalizeMaxRounds (each round peels one layer)",
	"inputs larger than NormalizeMaxInputBytes (the body is not scanned at all)",
	"od -tu1 output produced without -v (a run of sixteen identical bytes collapses to '*', silently dropping sixteen bytes; only the od -tu1 -v layout is covered)",
	"a payload that straddles a candidate window cut for inputs larger than NormalizeMaxCandidateBytes",
	"password-protected or encrypted containers (gzip without a passphrase is covered; an encrypted payload is opaque)",
	"steganographic or lossy transforms (re-typing, image or audio embedding, token reordering)",
	"encodings whose bytes the extractor cannot bound (a secret split across unrelated JSON fields or interleaved with other data)",
}

// KnownUncoveredEncodings returns a copy of the encoding classes the outbound
// re-check deliberately does not cover.
//
// Callers that must describe the re-check's limits — the security
// documentation, for example — should cite this list rather than restate it, so
// the code and the prose cannot diverge. The list is not a claim that
// everything else is covered: an entry marks a boundary of a fixed decoder
// enumeration, and the covered set is enumerated in NormalizeCandidates.
func KnownUncoveredEncodings() []string {
	out := make([]string, len(knownUncoveredEncodings))
	copy(out, knownUncoveredEncodings)
	return out
}
