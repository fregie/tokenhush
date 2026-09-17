package protocol

// SSEBackfillHoldbackBytes is the hard cap on how many trailing bytes a
// BackfillWriter may hold back while it waits to see whether a token
// completes. It is invariant 8: a huge or hostile stream can never make the
// gateway buffer without limit, so once the held window would exceed this
// bound the oldest held bytes are released literally and progress resumes.
const SSEBackfillHoldbackBytes = 256 * 1024

// TokenMatcher recognises caller-defined tokens in a byte stream. The
// BackfillWriter is grammar-agnostic: it holds back exactly the trailing
// bytes the matcher still considers part of a possible token.
type TokenMatcher interface {
	// PrefixLen returns the length of the longest prefix of p that is also
	// a prefix of some token, or 0 when p cannot begin a token.
	PrefixLen(p []byte) int

	// TokenLen returns the byte length of the complete token at the start
	// of p, or 0 when p does not begin with a complete token.
	TokenLen(p []byte) int

	// MaxTokenLen returns the longest token the matcher can recognise,
	// bounding how far a partial token can reach into the stream.
	MaxTokenLen() int
}

// ReplaceFunc maps one complete token to its replacement. It returns nil to
// forward the token unchanged.
type ReplaceFunc func(token []byte) []byte

// BackfillWriter restores tokens a caller split across stream deltas. It
// buffers the trailing bytes that could still become a token, replaces each
// complete token exactly once however many Feed calls it arrived in, and
// never emits a fragment of a token. Held bytes are bounded by
// SSEBackfillHoldbackBytes; past that bound the oldest held bytes leave
// literally and in order, so the writer always makes progress.
type BackfillWriter struct {
	matcher TokenMatcher
	replace ReplaceFunc
	held    []byte
}

// NewBackfillWriter returns a writer that recognises tokens with m and
// rewrites each complete token through replace. A nil replace forwards
// tokens unchanged.
func NewBackfillWriter(m TokenMatcher, replace ReplaceFunc) *BackfillWriter {
	return &BackfillWriter{matcher: m, replace: replace}
}

// Feed appends p and returns the bytes that became safe to emit, which may
// be nil.
func (w *BackfillWriter) Feed(p []byte) []byte {
	w.held = append(w.held, p...)
	return w.release()
}

// Flush releases every still-held byte literally and returns them. Held
// bytes are empty afterwards, so a second Flush returns nothing extra.
func (w *BackfillWriter) Flush() []byte {
	out := w.held
	w.held = nil
	return out
}

// Held reports how many bytes the writer is currently holding back.
func (w *BackfillWriter) Held() int { return len(w.held) }

// release emits every complete token and every byte that can no longer
// begin one, then trims the held window to its bound. Only a trailing run
// that is still a prefix of some token is allowed to linger.
func (w *BackfillWriter) release() []byte {
	var out []byte
	i := 0
	for i < len(w.held) {
		if n := w.matcher.TokenLen(w.held[i:]); n > 0 && n <= len(w.held)-i {
			out = append(out, w.replacement(w.held[i:i+n])...)
			i += n
			continue
		}
		// A token can only start at i if the whole remaining tail is a
		// prefix of one; a shorter longest-prefix proves no token starts
		// here, because the byte that stopped the match can never be part
		// of any token either.
		if pl := w.matcher.PrefixLen(w.held[i:]); pl >= len(w.held)-i {
			break
		}
		out = append(out, w.held[i])
		i++
	}
	tail := w.held[i:]
	if limit := w.holdbackLimit(); len(tail) > limit {
		drop := len(tail) - limit
		out = append(out, tail[:drop]...)
		tail = tail[drop:]
	}
	w.held = w.held[:copy(w.held, tail)]
	return out
}

// holdbackLimit is the effective hold-back bound: the named constant, or
// the matcher's longest possible token when that is smaller.
func (w *BackfillWriter) holdbackLimit() int {
	limit := SSEBackfillHoldbackBytes
	if n := w.matcher.MaxTokenLen(); n > 0 && n < limit {
		limit = n
	}
	return limit
}

// replacement returns the bytes to emit for a complete token.
func (w *BackfillWriter) replacement(token []byte) []byte {
	if w.replace == nil {
		return token
	}
	if rep := w.replace(token); rep != nil {
		return rep
	}
	return token
}
