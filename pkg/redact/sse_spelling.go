package redact

import (
	"bytes"
	"encoding/json"

	"github.com/fregie/tokenhush/pkg/protocol"
)

// feedSpelling is one feed's restore context: the spelled replacement for each
// complete token found in a JSON leaf of the data value being fed, plus whether
// that value is a JSON document at all.
type feedSpelling struct {
	spelled map[string][]byte
	json    bool
}

// spellFeed records the escaping context of the data value about to be fed to
// the writer. A token the writer completes during this feed lands in this
// value, so this value's spelling is the authoritative one.
func (s *SSEBackfiller) spellFeed(value []byte) {
	s.feed = feedSpelling{}
	if !bytes.Contains(value, []byte(placeholderPrefix)) {
		return
	}
	if leaves, err := protocol.Walk(value); err == nil {
		for _, leaf := range leaves {
			for _, token := range leafTokens(leaf.Value) {
				secret := s.restorer.Backfill(token)
				if s.feed.spelled == nil {
					s.feed.spelled = make(map[string][]byte)
				}
				s.feed.spelled[string(token)] = leaf.RawSpelling(secret)
			}
		}
	}
	s.feed.json = json.Valid(value)
}

// replace maps one complete token to the bytes spliced into the current feed's
// data value: a token found in a leaf carries that leaf's spelling, a token in
// a valid JSON document carries one escaping level (a key, which Walk never
// emits), and any other shape keeps the raw secret.
func (s *SSEBackfiller) replace(token []byte) []byte {
	if spelled, ok := s.feed.spelled[string(token)]; ok {
		return spelled
	}
	raw := s.restorer.Backfill(token)
	if s.feed.json {
		return protocol.EscapeJSONString(raw)
	}
	return raw
}

// leafTokens returns every complete placeholder token occurring in value.
func leafTokens(value []byte) [][]byte {
	var tokens [][]byte
	for i := 0; i < len(value); {
		j := bytes.Index(value[i:], []byte(placeholderPrefix))
		if j < 0 {
			return tokens
		}
		start := i + j
		if n := (placeholderMatcher{}).TokenLen(value[start:]); n > 0 {
			tokens = append(tokens, value[start:start+n])
			i = start + n
			continue
		}
		i = start + 1
	}
	return tokens
}
