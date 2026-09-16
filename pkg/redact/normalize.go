package redact

import "bytes"

// The outbound re-check bounds. Every limit is a hard ceiling: the normaliser is
// on the request hot path, so its worst-case cost must be statically known.
const (
	// NormalizeMaxInputBytes caps the input the normaliser scans. A body larger
	// than this yields no candidates at all rather than a truncated scan: the
	// caller is expected to short-circuit large bodies for cost, and declining
	// to scan keeps the normaliser's own work independent of input size.
	NormalizeMaxInputBytes = 1 << 18 // 256 KiB

	// NormalizeMaxCandidates caps how many candidate forms one call may return,
	// summed over every decoder and every decode round.
	NormalizeMaxCandidates = 256

	// NormalizeMaxCandidateBytes caps the length of a single returned candidate.
	// A decoder result longer than this is dropped, never truncated, so callers
	// never reason about half-decoded material. It also caps decompression: a
	// gzip output larger than this is rejected rather than materialised.
	NormalizeMaxCandidateBytes = 8192

	// NormalizeMaxRounds caps how many times the decoder set is applied to its
	// own output, so nested encodings are peeled one bounded layer per round.
	NormalizeMaxRounds = 4
)

// NormalizeCandidates returns a bounded, deterministic set of decoded forms of
// b, including b itself when it is short enough to be a candidate.
//
// It is the decoder half of the outbound re-check: after redaction the request
// body is run through this function and every candidate is tested for
// membership of the secrets the engine just mapped. The design is deliberately
// a set of decoders rather than one canonical normalisation: a caller only has
// to pick a single encoding to bypass a single normal form, so each covered
// form contributes its own decoder and its own candidate.
//
// Candidate extraction is part of the job. A secret embedded in a larger JSON
// or text body is recovered by having each decoder locate its own candidate
// runs inside b (hex runs, base64 runs, decimal byte runs, printable runs) and
// decode each run, instead of decoding b as a whole. Each decoder's output is
// fed back through the whole decoder set for up to NormalizeMaxRounds rounds,
// so a payload carried inside a second encoding is peeled one layer per round.
//
// Cost is bounded on every axis. Input over NormalizeMaxInputBytes yields no
// candidates; at most NormalizeMaxCandidates are returned; no candidate exceeds
// NormalizeMaxCandidateBytes; decompression of any candidate is capped at
// NormalizeMaxCandidateBytes; runs considered per decoder and windows per
// decoder are capped. Results are deduplicated and ordered by the fixed decoder
// order, so the output is deterministic and independent of map iteration.
//
// Coverage is not complete. This is high-confidence interception, not a closed
// guarantee; KnownUncoveredEncodings lists the classes deliberately left out.
//
// The function is pure and safe for concurrent use: it keeps no state between
// calls, never mutates its input, and does not panic on arbitrary bytes.
func NormalizeCandidates(b []byte) [][]byte {
	if len(b) == 0 || len(b) > NormalizeMaxInputBytes {
		return nil
	}
	set := newCandidateSet()
	set.add(b)
	frontier := [][]byte{b}
	for round := 0; round < NormalizeMaxRounds && !set.full(); round++ {
		var next [][]byte
		for _, in := range frontier {
			for _, out := range decodeAll(in) {
				if set.add(out) {
					next = append(next, out)
				}
			}
		}
		if len(next) == 0 {
			break
		}
		frontier = next
	}
	return set.list()
}

// decodeAll runs every decoder over in in the fixed decoder order and returns
// their combined output. The order is part of the contract: it makes the
// membership scan and any truncation at NormalizeMaxCandidates deterministic.
func decodeAll(in []byte) [][]byte {
	var out [][]byte
	for _, decode := range normalizers {
		out = append(out, decode(in)...)
	}
	return out
}

// normalizers is the decoder set. It is initialised once and never mutated, so
// concurrent calls only read it.
var normalizers = []func([]byte) [][]byte{
	decodeSeparators,
	decodeEscapes,
	decodeHex,
	decodeBase64,
	decodeBase32,
	decodePercent,
	decodeRot13,
	decodeAtbash,
	decodeRot47,
	decodeDecimalBytes,
	decodeUTF16,
	decodeGzip,
}

// candidateSet accumulates decoded candidates in first-seen order. It drops
// empty input, input over NormalizeMaxCandidateBytes, duplicates, and anything
// once NormalizeMaxCandidates is reached, which is the short-circuit that keeps
// an expanding decode from growing without bound.
type candidateSet struct {
	seen  map[string]struct{}
	items [][]byte
}

func newCandidateSet() *candidateSet {
	return &candidateSet{seen: make(map[string]struct{}, NormalizeMaxCandidates)}
}

func (c *candidateSet) full() bool { return len(c.items) >= NormalizeMaxCandidates }

// add reports whether b was newly stored. The stored copy is independent of the
// caller's buffer, so a decoder may reuse its scratch space freely.
func (c *candidateSet) add(b []byte) bool {
	if len(b) == 0 || len(b) > NormalizeMaxCandidateBytes || c.full() {
		return false
	}
	key := string(b)
	if _, dup := c.seen[key]; dup {
		return false
	}
	c.seen[key] = struct{}{}
	c.items = append(c.items, bytes.Clone(b))
	return true
}

func (c *candidateSet) list() [][]byte {
	if len(c.items) == 0 {
		return nil
	}
	return c.items
}

// Bounds shared by the individual decoders. They are kept next to the
// extraction helpers because they bound extraction, not the public API.
const (
	// maxRunsPerDecoder caps how many runs one decoder considers per input.
	maxRunsPerDecoder = 64

	// maxWindows caps how many windows a whole-body transform is applied to
	// when the input is larger than a single candidate.
	maxWindows = 32

	// maxRunBytes is the largest run a decoder materialises before decoding.
	maxRunBytes = 2 * NormalizeMaxCandidateBytes

	// odSuffixStarts caps the suffix extraction applied to a decoded byte run,
	// so a run of decimal byte tokens cannot cost quadratic time.
	odSuffixStarts = 32
)

// findRuns returns the maximal runs of in whose bytes satisfy pred and whose
// length is at least minLen, in ascending order and capped at maxRunsPerDecoder.
func findRuns(in []byte, pred func(byte) bool, minLen int) [][]byte {
	var out [][]byte
	i := 0
	for i < len(in) && len(out) < maxRunsPerDecoder {
		for i < len(in) && !pred(in[i]) {
			i++
		}
		start := i
		for i < len(in) && pred(in[i]) {
			i++
		}
		if i-start >= minLen {
			out = append(out, in[start:i])
		}
	}
	return out
}

// boundedWindows returns run itself when it fits in max bytes, otherwise its
// first and last max bytes. It keeps one run's contribution to a decoder
// bounded no matter how long the run is.
func boundedWindows(run []byte, max int) [][]byte {
	if len(run) <= max {
		return [][]byte{run}
	}
	return [][]byte{run[:max], run[len(run)-max:]}
}

// windows cuts in into non-overlapping windows of at most
// NormalizeMaxCandidateBytes bytes, plus the tail, capped at maxWindows. It is
// the extraction fallback for whole-body transforms on inputs larger than a
// single candidate; a payload that straddles a cut is missed (see the known
// uncovered list).
func windows(in []byte) [][]byte {
	var out [][]byte
	for start := 0; start < len(in) && len(out) < maxWindows; start += NormalizeMaxCandidateBytes {
		end := min(start+NormalizeMaxCandidateBytes, len(in))
		out = append(out, in[start:end])
	}
	return out
}

// applyTransform maps every byte of in through f into a fresh slice.
func applyTransform(in []byte, f func(byte) byte) []byte {
	out := make([]byte, len(in))
	for i, c := range in {
		out[i] = f(c)
	}
	return out
}

// transformCandidates applies a per-byte transform to in when it fits in one
// candidate, or to bounded windows of in otherwise. The nil result for an
// input the transform leaves unchanged keeps the identity out of the set.
func transformCandidates(in []byte, f func(byte) byte) [][]byte {
	if len(in) > NormalizeMaxCandidateBytes {
		var out [][]byte
		for _, w := range windows(in) {
			out = append(out, applyTransform(w, f))
		}
		return out
	}
	out := applyTransform(in, f)
	if bytes.Equal(out, in) {
		return nil
	}
	return [][]byte{out}
}
