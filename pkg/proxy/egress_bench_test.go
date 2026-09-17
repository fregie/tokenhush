package proxy

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"testing"

	"github.com/fregie/tokenhush/pkg/extension"
	"github.com/fregie/tokenhush/pkg/redact"
)

// W2.5 performance guardrail for the outbound re-check (egress.go).
//
// The benchmark measures the unit the re-check's cost rides on: the whole
// request transform (walk -> detectors -> policy -> redact), not a no-op
// stand-in, so the overhead is relative to the transform's real cost. The two
// asserted scenarios are the two cheap paths W2.5 adds:
//
//   - NoSecrets: the engine has never mapped a secret (KnownSecrets is empty),
//     the fallback case, so the re-check must return before doing any work.
//   - CleanBodyWithSecrets: the engine knows a secret and the body is a
//     realistic long-context provider request with no hit, so the body-size
//     bound keeps the re-check off the normalisation pass.
//   - CleanSmallBodyWithSecrets: the same engine over a short body, below the
//     size bound, so the re-check actually runs its normalisation pass. This
//     case is deliberately NOT asserted: its delta is large (that pass costs
//     tens of milliseconds regardless of body size), and bench_egress.sh
//     reports it as an explicitly informational metric so the asserted <15%
//     bound on the case above cannot be read as "the enabled path is cheap".
//
// The baseline for all three is the same binary with the test-only
// egressRecheckDisabled switch set to true (the zero-overhead path); the
// checked path runs with its default false. pkg/proxy/bench_egress.sh captures
// both files, asserts the plan's bounds (<5% and <15%) on the first two cases
// and reports the third as INFO (not a bound).
const (
	// benchTypicalBodyKiB is a typical short chat/completion request: below the
	// body-size bound, so NoSecrets exercises the empty-secret short-circuit
	// and CleanSmallBodyWithSecrets exercises the full normalisation pass (the
	// re-check's below-threshold cost).
	benchTypicalBodyKiB = 4

	// benchLongContextBodyKiB is a realistic long-context request (a coding
	// agent's context, on the order of 80k tokens) and sits above the size
	// bound, so CleanBodyWithSecrets exercises the oversized-body
	// short-circuit. It must stay above egressRecheckMaxBodyBytes (256 KiB):
	// at 192 KiB it stopped being an oversized body when the bound rose to the
	// normaliser's cap, and the measured delta jumped to +102%. See egress.go.
	benchLongContextBodyKiB = 320
)

// benchParagraph is realistic, detector-clean request prose: no credential
// prefixes, no email addresses, no long digit runs and no high-entropy tokens,
// so the transform leaves a fixture body byte-identical (benchTransform
// asserts that before timing).
const benchParagraph = "Please review the deployment checklist for the staging cluster before we continue. " +
	"The team agreed to move one region at a time and to keep a canary window of fifteen minutes between regions. " +
	"Summarise the risks, confirm the rollback procedure, and note anything that would block the migration."

// benchEngine returns a fresh placeholder engine for one benchmark.
func benchEngine(tb testing.TB) *redact.PlaceholderEngine {
	tb.Helper()
	engine, err := redact.NewPlaceholderEngine()
	if err != nil {
		tb.Fatalf("NewPlaceholderEngine: %v", err)
	}
	return engine
}

// benchRegistry registers the built-in detector set in config order, the same
// registry a production pipeline is built from (pkg/gateway.buildRegistry).
func benchRegistry(tb testing.TB) *extension.Registry {
	tb.Helper()
	reg := extension.NewRegistry()
	for _, p := range []extension.Plugin{
		redact.NewPrefixDetector(),
		redact.NewHighEntropyDetector(),
		redact.NewJWTDetector(),
		redact.NewPrivateKeyDetector(),
		redact.NewLuhnDetector(),
		redact.NewEmailDetector(),
	} {
		if err := reg.Register(p); err != nil {
			tb.Fatalf("Register(%T): %v", p, err)
		}
	}
	return reg
}

// benchPipeline builds a pipeline over benchRegistry.
func benchPipeline(tb testing.TB, engine *redact.PlaceholderEngine) *Pipeline {
	tb.Helper()
	pipe, err := NewPipeline(PipelineConfig{Registry: benchRegistry(tb), Engine: engine})
	if err != nil {
		tb.Fatalf("NewPipeline: %v", err)
	}
	return pipe
}

// benchProviderBody builds a deterministic provider-shaped request body of at
// least kib KiB: the shape a chat/completion client sends (model, max_tokens,
// a messages array of realistic prose).
func benchProviderBody(tb testing.TB, kib int) []byte {
	tb.Helper()
	one, err := json.Marshal(map[string]any{"role": "user", "content": benchParagraph})
	if err != nil {
		tb.Fatalf("marshal one message: %v", err)
	}
	target := kib * 1024
	n := target/len(one) + 1
	var body []byte
	for {
		messages := make([]map[string]any, 0, n)
		for i := 0; i < n; i++ {
			messages = append(messages, map[string]any{"role": "user", "content": benchParagraph})
		}
		body, err = json.Marshal(map[string]any{
			"model":      "gpt-4o",
			"max_tokens": 4096,
			"messages":   messages,
		})
		if err != nil {
			tb.Fatalf("marshal benchmark body: %v", err)
		}
		if len(body) >= target {
			return body
		}
		n++
	}
}

// benchTransform times pipe's request transform over body. The one untimed
// call first proves the fixture is clean: the transform must leave it
// byte-identical, so the body carries no secret the detectors would rewrite
// mid-benchmark.
func benchTransform(b *testing.B, pipe *Pipeline, body []byte) {
	b.Helper()
	transform := pipe.RequestTransform()
	if out, err := transform(body); err != nil {
		b.Fatalf("fixture is not clean: %v", err)
	} else if !bytes.Equal(out, body) {
		b.Fatalf("fixture is not clean: the transform rewrote %d of %d bytes", len(out), len(body))
	}

	b.SetBytes(int64(len(body)))
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		out, err := transform(body)
		if err != nil {
			b.Fatalf("transform: %v", err)
		}
		if !bytes.Equal(out, body) {
			b.Fatalf("transform changed the body on iteration %d", i)
		}
	}
}

// BenchmarkEgressRecheck is the W2.5 benchmark: the whole request transform,
// with and without a known secret, measured against the zero-overhead baseline
// (egressRecheckDisabled = true) captured by pkg/proxy/bench_egress.sh.
// CleanSmallBodyWithSecrets is the informational below-threshold companion: the
// script prints it as INFO, never as a bound.
//
//	go test ./pkg/proxy/ -run '^$' -bench BenchmarkEgressRecheck -benchtime 2s -count 6
func BenchmarkEgressRecheck(b *testing.B) {
	b.Run("NoSecrets", func(b *testing.B) {
		body := benchProviderBody(b, benchTypicalBodyKiB)
		benchTransform(b, benchPipeline(b, benchEngine(b)), body)
	})

	b.Run("CleanBodyWithSecrets", func(b *testing.B) {
		body := benchProviderBody(b, benchLongContextBodyKiB)
		engine := benchEngine(b)
		engine.Placeholder(egressSecret(), "api_key")
		benchTransform(b, benchPipeline(b, engine), body)
	})

	// CleanSmallBodyWithSecrets prices the re-check when it actually runs: the
	// engine knows a secret and the body is short, so the size bound does not
	// apply and the normalisation pass is paid. It is informational only (see
	// the file comment); the guard keeps it that way: if this fixture ever grew
	// past the bound, the metric would silently become the skipped path again.
	b.Run("CleanSmallBodyWithSecrets", func(b *testing.B) {
		body := benchProviderBody(b, benchTypicalBodyKiB)
		if egressRecheckMaxBodyBytes != 0 && len(body) > egressRecheckMaxBodyBytes {
			b.Fatalf("fixture is %d bytes, above egressRecheckMaxBodyBytes=%d: the below-threshold metric would measure the skipped path",
				len(body), egressRecheckMaxBodyBytes)
		}
		engine := benchEngine(b)
		engine.Placeholder(egressSecret(), "api_key")
		benchTransform(b, benchPipeline(b, engine), body)
	})
}

// TestEgressRecheckDisabledSwitch pins the test-only switch contract: it must
// default to false, so production always runs the full outbound re-check, and
// setting it true must short-circuit egressRecheck (the zero-overhead baseline
// the benchmark compares against). Flipping it must not change anything else:
// with the switch restored, the same encoded body blocks again.
func TestEgressRecheckDisabledSwitch(t *testing.T) {
	if egressRecheckDisabled {
		t.Fatal("egressRecheckDisabled must default to false: production always runs the outbound re-check")
	}

	secret := egressSecret()
	engine := w45Engine(t)
	engine.Placeholder(secret, "api_key")
	pipe := w45Pipeline(t, PipelineConfig{
		Registry: w45Registry(t, redact.NewPrefixDetector()),
		Engine:   engine,
	})
	body := egressEncodedBody(t, []byte(hex.EncodeToString([]byte(secret))))

	if _, err := pipe.RequestTransform()(body); err == nil {
		t.Fatal("the encoded secret was not blocked with the switch at its default")
	}
	if got := pipe.EgressBlocks(); got != 1 {
		t.Fatalf("EgressBlocks = %d, want 1 after the default-path block", got)
	}

	egressRecheckDisabled = true
	defer func() { egressRecheckDisabled = false }()
	got, err := pipe.RequestTransform()(body)
	egressRecheckDisabled = false
	if err != nil {
		t.Fatalf("switch on: transform failed: %v", err)
	}
	if !bytes.Equal(got, body) {
		t.Fatal("switch on: the body was not passed through byte-identically")
	}
	if n := pipe.EgressBlocks(); n != 1 {
		t.Fatalf("EgressBlocks = %d, want 1: the switch must only skip the re-check", n)
	}

	if _, err := pipe.RequestTransform()(body); err == nil {
		t.Fatal("the encoded secret was not blocked after restoring the switch")
	}
	if got := pipe.EgressBlocks(); got != 2 {
		t.Fatalf("EgressBlocks = %d, want 2 after restoring the switch", got)
	}
}
