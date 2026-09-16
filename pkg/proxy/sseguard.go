package proxy

import "encoding/json"

// W6.4: bounded tool-call guard for the SSE response path.
//
// The SSE path bypasses transformResponse, so before W6.4 a streamed tool call
// reached the client with no policy check at all. The guard gives every
// tool-call `arguments` path — the same field the buffered guard protects (see
// mutationChannelArgumentsField) — a bounded accumulation of its decoded
// fragments, and refuses that one tool call by replacing its whole arguments
// value with mutationChannelRefusalNotice when a W6.2 pattern matches after
// accumulation, when the accumulation reaches SSEGuardCap without a decision,
// or when a not-yet-decided path is released by forceFlush/stream end.
//
// The guard state lives on the existing pathState (b.paths) rather than in a
// side map, because forceFlush and Flush only walk b.paths: a side map would be
// invisible to them, and afterEvent — which releases any path whose placeholder
// window is empty — would drain the path as original bytes first.

// SSEGuardCap bounds the per-path accumulation of a streamed tool call's
// `arguments`, in bytes. It is frozen at or below sseBackfillMaxHoldbackBytes:
// once the held bytes pass the holdback the backfiller force-flushes and
// releases paths, so a cap above the holdback could never be reached and the
// guard would silently pass instead of failing closed.
//
// When a path's accumulation reaches the cap without a decision the tool call is
// refused. That is the accepted cost W6.6 documents: an extremely large LEGAL
// tool call is refused too.
const SSEGuardCap = 64 << 10

// Refusal reasons reported to the guard observer. They separate a pattern match
// from the two fail-closed paths (the cap, and a release without a decision) so
// W6.5 can count them independently.
const (
	sseGuardReasonMatch     = "match"
	sseGuardReasonCap       = "cap"
	sseGuardReasonUndecided = "undecided"
)

// setToolCallGuard installs the W6.4 streaming guard. detect is the W6.2 entry
// point — the pipeline passes DetectMutationChannel, which honours the
// self-protection switch and the enabled mode list; onRefusal, when set,
// observes every refusal with the matched channel class ("" when no pattern
// matched) and one of the sseGuardReason* values.
//
// A nil backfiller or a nil detect is a no-op, so every pre-W6.4 backfiller
// construction keeps its byte-for-byte behaviour.
func (b *sseBackfiller) setToolCallGuard(detect func(text string) (class string, matched bool), onRefusal func(class, reason string)) {
	if b == nil {
		return
	}
	b.guardDetect = detect
	b.onGuardRefusal = onRefusal
	if detect == nil {
		return
	}
	// Arm paths that already exist, so installing the guard after a path was
	// created (or re-installing it) cannot leave a path unguarded.
	for _, p := range b.paths {
		if p.kind == kindJSON && isMutationChannelArgumentsPath(p.key) {
			p.guardArmed = true
		}
	}
}

// guardArms reports whether key names a tool-call arguments path the guard must
// accumulate, when the guard is installed.
func (b *sseBackfiller) guardArms(kind pathKind, key string) bool {
	return b.guardDetect != nil && kind == kindJSON && isMutationChannelArgumentsPath(key)
}

// guardReleasable reports whether the event-boundary release may decide this
// path. A guarded path is held until it is decided clean: releasing a hit path
// here would emit its later original fragments before a refusal, and releasing
// an undecided path would emit the fragments that make a split command match.
// Only a path change, the cap or forceFlush/Flush resolves those.
func (p *pathState) guardReleasable() bool {
	return !p.guardArmed || (p.guardDecided && !p.guardHit)
}

// guardReset clears a path's guard state when the path (re)activates. A guarded
// path is released only after a decision, so a fresh activation is a new tool
// call on the same path.
func (b *sseBackfiller) guardReset(p *pathState) {
	if !p.guardArmed {
		return
	}
	p.guardAccum = p.guardAccum[:0]
	p.guardDecided = false
	p.guardHit = false
}

// guardConsume appends chunk to a guarded path's bounded accumulation and
// decides the tool call as soon as the accumulated arguments match the mutation
// channel or the accumulation reaches SSEGuardCap. It reports whether this chunk
// must be withheld from the placeholder writer (the path is already refused, or
// this chunk decided the refusal).
//
// The cap bounds memory independently of the placeholder window: the window
// keeps at most maxPlaceholderLen bytes, while the guard needs the whole
// accumulated arguments to see a command split across events.
func (b *sseBackfiller) guardConsume(p *pathState, chunk []byte) bool {
	if !p.guardArmed {
		return false
	}
	if p.guardDecided {
		return p.guardHit
	}
	if room := SSEGuardCap - len(p.guardAccum); room > 0 {
		if len(chunk) > room {
			p.guardAccum = append(p.guardAccum, chunk[:room]...)
		} else {
			p.guardAccum = append(p.guardAccum, chunk...)
		}
	}
	if class, matched := b.guardDetect(string(p.guardAccum)); matched {
		p.guardDecided, p.guardHit = true, true
		b.noteGuardRefusal(class, sseGuardReasonMatch)
		return true
	}
	if len(p.guardAccum) >= SSEGuardCap {
		// Fail closed: a tool call whose arguments reached the cap without a
		// finished decision is refused. That includes an extremely large LEGAL
		// call — the accepted cost W6.6 documents.
		p.guardDecided, p.guardHit = true, true
		b.noteGuardRefusal("", sseGuardReasonCap)
		return true
	}
	return false
}

// guardClose decides and releases every guarded path the current event did not
// continue: a tool-call arguments path stops receiving fragments at a path
// change, so its accumulation is complete. Reaching an event boundary is NOT a
// completion signal on its own: a matching command split across events has a
// prefix that looks exactly like a finished unrelated value, so releasing on the
// boundary would drain that prefix as original bytes. A path is decided clean
// only when its accumulation is a syntactically complete JSON value; any other
// accumulation (including a non-JSON terminal arguments prefix) stays undecided
// and held, so the existing fail-closed release refuses it at the cap or stream
// end. A path that already matched was refused when it matched.
func (b *sseBackfiller) guardClose() error {
	if b.guardDetect == nil {
		return nil
	}
	current := b.nextSeq - 1
	for _, p := range b.paths {
		if !p.guardArmed || !p.active || p.lastSeq == current {
			continue
		}
		if !p.guardDecided {
			if !json.Valid(p.guardAccum) {
				continue
			}
			p.guardDecided, p.guardHit = true, false
		}
		// Flush before releasing, exactly like forceFlush: a tail still buffered
		// in the window must become literal, not be dropped with the run.
		if err := p.w.Flush(); err != nil {
			return err
		}
		b.releasePath(p)
	}
	return nil
}

// noteGuardRefusal reports one refused streamed tool call: metadata only, never
// a path and never an argument byte.
func (b *sseBackfiller) noteGuardRefusal(class, reason string) {
	if b == nil || b.onGuardRefusal == nil {
		return
	}
	b.onGuardRefusal(class, reason)
}

// StreamGuardRefusals reports how many streamed tool calls the W6.4 SSE guard
// refused since the pipeline was built: every pattern match, every cap-exhausted
// refusal and every release without a decision. It carries no content or path
// and is safe to expose (for example on a status endpoint). A nil receiver
// returns 0.
func (p *Pipeline) StreamGuardRefusals() uint64 {
	if p == nil {
		return 0
	}
	return p.streamGuardRefusals.Load()
}

// StreamGuardFailClosed reports the subset of StreamGuardRefusals that were
// refused without a matching pattern: the SSEGuardCap exhaustion and the
// release of a not-yet-decided path. Those are the refusals an extremely large
// LEGAL tool call can also produce, so W6.5 counts them separately. A nil
// receiver returns 0.
func (p *Pipeline) StreamGuardFailClosed() uint64 {
	if p == nil {
		return 0
	}
	return p.streamGuardFailClosed.Load()
}

// noteStreamingGuardRefusal records one refused streamed tool call: it
// increments the pipeline counters, emits the same metadata-only event W6.3
// emits on the buffered path and writes the matching metadata-only audit row,
// so W6.5 has one interception signal for both. The matched class and the
// refusal reason are metadata; no argument byte, path or content is recorded.
func (p *Pipeline) noteStreamingGuardRefusal(class, reason string) {
	if p == nil {
		return
	}
	p.streamGuardRefusals.Add(1)
	if reason == sseGuardReasonCap || reason == sseGuardReasonUndecided {
		p.streamGuardFailClosed.Add(1)
	}
	p.reportMutationChannelBlock(class)
	p.recordGuardRefusal(class, auditSurfaceStream, reason)
}
