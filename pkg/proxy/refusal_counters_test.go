package proxy

// Refusal-counter contract: every refusal class increments exactly the counter
// `tokenhush status` exposes for it, on the same *Pipeline the status closure
// reads, and a clean release increments nothing. The W6.3/W6.4 C8 paths live
// here; the control-plane allowlist-mutation counter is a gateway-local counter
// and stays pinned by pkg/gateway's TestStatusAllowlistMutationCounterAndRow.
//
// This is the consolidated lock for the accounting that was audited after the
// "refusal observed, counter zero" report. The report turned out to be an
// instance mismatch (the refusal was served by an isolated harness on a
// different port while `status` read the real session); the counters themselves
// were already correct. This table makes that correctness explicit per class, so
// a future edit that drops an increment fails here.

import (
	"encoding/hex"
	"testing"

	"github.com/fregie/tokenhush/pkg/redact"
)

// refusalCounts is the /status counter subset a refusal class can move.
type refusalCounts struct {
	self       uint64
	stream     uint64
	failClosed uint64
	egress     uint64
}

// readRefusalCounts snapshots the four counters from one pipeline, exactly as
// the gateway's ControlStatus closure reads them.
func readRefusalCounts(p *Pipeline) refusalCounts {
	return refusalCounts{
		self:       p.SelfProtectionInterceptions(),
		stream:     p.StreamGuardRefusals(),
		failClosed: p.StreamGuardFailClosed(),
		egress:     p.EgressBlocks(),
	}
}

// TestRefusalCounterContract is the table-driven accounting lock: one case per
// refusal class asserts the increment (and that the other counters stay put),
// and the clean cases assert nothing moves.
func TestRefusalCounterContract(t *testing.T) {
	const (
		mutationArgs = `{"cmd":"tokenhush allowlist add evil.example"}`
		legalArgs    = `{"cmd":"ls -la /tmp"}`
	)

	cases := []struct {
		name string
		run  func(t *testing.T) refusalCounts
		want refusalCounts
	}{
		{
			name: "buffered_match_increments_self_protection_interceptions",
			run: func(t *testing.T) refusalCounts {
				pipe := w63Pipeline(t)
				out, err := pipe.transformResponse(w63Body(t, mutationArgs), pipe.tool)
				if err != nil {
					t.Fatalf("transformResponse = %v, want nil", err)
				}
				w63WantArgs(t, out, w63Refusal(MutationChannelCLI))
				return readRefusalCounts(pipe)
			},
			want: refusalCounts{self: 1},
		},
		{
			name: "streamed_match_increments_stream_guard_refusals",
			run: func(t *testing.T) refusalCounts {
				pipe := w63Pipeline(t)
				w, _ := w14SSEWriter(t, pipe)
				fragments := []string{"token", "hush allow", "list add evil.example MARK-CTR"}
				input := append(w64ArgumentsStream(t, fragments), w64FinishEvent...)
				input = append(input, w64DoneEvent...)
				if _, err := w.backfill.Write(input); err != nil {
					t.Fatalf("Write: %v", err)
				}
				if err := w.backfill.Flush(); err != nil {
					t.Fatalf("Flush: %v", err)
				}
				return readRefusalCounts(pipe)
			},
			want: refusalCounts{stream: 1},
		},
		{
			name: "streamed_cap_exhaustion_increments_both_stream_counters",
			run: func(t *testing.T) refusalCounts {
				pipe := w63Pipeline(t)
				w, _ := w14SSEWriter(t, pipe)
				input := append(w64ArgumentsStream(t, w64BigLegalArguments()), w64FinishEvent...)
				input = append(input, w64DoneEvent...)
				if _, err := w.backfill.Write(input); err != nil {
					t.Fatalf("Write: %v", err)
				}
				if err := w.backfill.Flush(); err != nil {
					t.Fatalf("Flush: %v", err)
				}
				return readRefusalCounts(pipe)
			},
			want: refusalCounts{stream: 1, failClosed: 1},
		},
		{
			// The stream-end decision branch (releasePathAtStreamEnd ->
			// decideUndecided(failClosed=false)) refuses a complete accumulation
			// that matches only at stream end. It is exercised directly because
			// the incremental guard otherwise decides the same accumulation on
			// the fragment that completes it.
			name: "stream_end_undecided_match_increments_stream_guard_refusals",
			run: func(t *testing.T) refusalCounts {
				pipe := w63Pipeline(t)
				w, _ := w14SSEWriter(t, pipe)
				if _, err := w.backfill.Write(w64ArgumentsStream(t, []string{"seed"})); err != nil {
					t.Fatalf("Write: %v", err)
				}
				var path *pathState
				for _, cand := range w.backfill.paths {
					if cand.guardArmed {
						path = cand
						break
					}
				}
				if path == nil {
					t.Fatal("no armed arguments path was created")
				}
				path.guardDecided, path.guardHit = false, false
				path.guardAccum = []byte(mutationArgs)
				w.backfill.decideUndecided(path, false)
				return readRefusalCounts(pipe)
			},
			want: refusalCounts{stream: 1},
		},
		{
			name: "egress_block_increments_egress_blocks",
			run: func(t *testing.T) refusalCounts {
				engine, secret := egressMappedEngine(t)
				pipe := w45Pipeline(t, PipelineConfig{Registry: w45Registry(t), Engine: engine})
				body := egressEncodedBody(t, []byte(hex.EncodeToString([]byte(secret))))
				if _, err := pipe.RequestTransform()(body); err == nil {
					t.Fatal("an encoded known secret was forwarded, want an egress block")
				}
				return readRefusalCounts(pipe)
			},
			want: refusalCounts{egress: 1},
		},
		{
			// The key-position backstop: a known secret re-sent as an object key
			// is not rewritten by the value detectors, so the outbound re-check's
			// key-position carve-out (secretUsedAsObjectKey) is what refuses it.
			name: "key_position_backstop_increments_egress_blocks",
			run: func(t *testing.T) refusalCounts {
				secret := "kR8mQ2vZ9pL4wX7nT1bY6cH3jF5dS0aG"
				engine := w45Engine(t)
				engine.Placeholder(secret, "api_key")
				pipe := w45Pipeline(t, PipelineConfig{
					Registry: w45Registry(t, redact.NewPrefixDetector()),
					Engine:   engine,
					Tool:     "ctr-key-position",
				})
				if _, err := pipe.RequestTransform()(kgKeyBody(t, secret, "value")); err == nil {
					t.Fatal("a known secret used as an object key was forwarded, want an egress block")
				}
				return readRefusalCounts(pipe)
			},
			want: refusalCounts{egress: 1},
		},
		{
			name: "clean_buffered_release_increments_nothing",
			run: func(t *testing.T) refusalCounts {
				pipe := w63Pipeline(t)
				out, err := pipe.transformResponse(w63Body(t, legalArgs), pipe.tool)
				if err != nil {
					t.Fatalf("transformResponse(legal) = %v, want nil", err)
				}
				w63WantArgs(t, out, legalArgs)
				return readRefusalCounts(pipe)
			},
			want: refusalCounts{},
		},
		{
			name: "clean_streamed_release_increments_nothing",
			run: func(t *testing.T) refusalCounts {
				pipe := w63Pipeline(t)
				w, _ := w14SSEWriter(t, pipe)
				input := append(w64ArgumentsStream(t, []string{`{"cmd":"ls `, `-la /tmp"}`}), w64FinishEvent...)
				input = append(input, w64DoneEvent...)
				if _, err := w.backfill.Write(input); err != nil {
					t.Fatalf("Write: %v", err)
				}
				if err := w.backfill.Flush(); err != nil {
					t.Fatalf("Flush: %v", err)
				}
				return readRefusalCounts(pipe)
			},
			want: refusalCounts{},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := tc.run(t)
			if got != tc.want {
				t.Fatalf("counters = %+v, want %+v", got, tc.want)
			}
			t.Logf("counters self=%d stream=%d fail_closed=%d egress=%d",
				got.self, got.stream, got.failClosed, got.egress)
		})
	}
}
