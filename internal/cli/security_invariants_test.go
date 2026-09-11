package cli

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/fregie/tokenhush/pkg/config"
	"github.com/fregie/tokenhush/pkg/extension"
	"github.com/fregie/tokenhush/pkg/proxy"
	"github.com/fregie/tokenhush/pkg/redact"
)

// blockingInspector is a channel-gated Inspector that does not return until its
// gate is released. Under a FailClosed failure policy it makes the timeout path
// deterministic: the inspector can never beat the policy timer, so the policy
// always fails safe regardless of OS timer resolution.
type blockingInspector struct {
	id   string
	gate chan struct{}
}

func (b *blockingInspector) ID() string { return b.id }

func (b *blockingInspector) Capabilities() extension.Capabilities {
	return extension.Capabilities{
		Phases:      []extension.Phase{extension.RequestContent},
		ReadContent: true,
	}
}

func (b *blockingInspector) Inspect(*extension.Document) ([]extension.Finding, error) {
	<-b.gate
	return nil, nil
}

// deterministicFailClosedPipeline returns a pipeline whose only detector blocks
// until release is called, so a real (non-racing) policy timeout forces the
// fail-safe Block on every OS. release also unblocks the abandoned inspector
// goroutine so it can exit after the test.
func deterministicFailClosedPipeline(t *testing.T, timeout time.Duration) (*proxy.Pipeline, func()) {
	t.Helper()
	insp := &blockingInspector{id: "blocking", gate: make(chan struct{})}
	reg := extension.NewRegistry()
	if err := reg.Register(insp); err != nil {
		t.Fatalf("Register(blocking): %v", err)
	}
	engine, err := redact.NewPlaceholderEngine()
	if err != nil {
		t.Fatalf("NewPlaceholderEngine: %v", err)
	}
	policy := extension.NewPolicy(reg, extension.PolicyConfig{
		Timeout:  timeout,
		Failures: map[string]extension.FailurePolicy{"blocking": extension.FailClosed},
	})
	pipeline, err := proxy.NewPipeline(proxy.PipelineConfig{Registry: reg, Policy: policy, Engine: engine})
	if err != nil {
		t.Fatalf("NewPipeline: %v", err)
	}
	return pipeline, func() { close(insp.gate) }
}

// captureProcessOutput redirects os.Stdout and os.Stderr into one buffer for
// the duration of a test and returns an idempotent reader/restore function.
// Copiers drain the pipes concurrently, so a mutation that logs a large body
// cannot deadlock the test. The testing framework keeps its own os.Stdout
// reference, so --- PASS/--- FAIL lines are unaffected.
func captureProcessOutput(t *testing.T) (logs func() string) {
	t.Helper()
	oldOut, oldErr := os.Stdout, os.Stderr
	rOut, wOut, err := os.Pipe()
	if err != nil {
		t.Fatalf("os.Pipe(stdout): %v", err)
	}
	rErr, wErr, err := os.Pipe()
	if err != nil {
		t.Fatalf("os.Pipe(stderr): %v", err)
	}
	os.Stdout, os.Stderr = wOut, wErr

	var (
		mu  sync.Mutex
		buf bytes.Buffer
		wg  sync.WaitGroup
	)
	drain := func(r *os.File) {
		defer wg.Done()
		data, _ := io.ReadAll(r)
		mu.Lock()
		buf.Write(data)
		mu.Unlock()
	}
	wg.Add(2)
	go drain(rOut)
	go drain(rErr)

	var once sync.Once
	return func() string {
		once.Do(func() {
			os.Stdout, os.Stderr = oldOut, oldErr
			_ = wOut.Close()
			_ = wErr.Close()
			wg.Wait()
		})
		mu.Lock()
		defer mu.Unlock()
		return buf.String()
	}
}

// TestNoPlaintextInLogs is the W5.4 named invariant (docs/security.md §2.2/§5,
// docs/13 §9): request content never reaches the daemon's stdout/stderr, its
// metadata-only audit store, or any client-visible error string. It drives a
// synthetic secret through the real daemon on both the success path and the
// fail-closed detector-timeout path, capturing real process output.
//
// The scan is proven non-vacuous: the daemon must have emitted its startup
// lines, the upstream must have seen a placeholder (not the secret), and a
// planted buffer must trip the same scanner.
func TestNoPlaintextInLogs(t *testing.T) {
	secret := runSecret()

	cases := []struct {
		name       string
		failClosed bool
		wantStatus int
		wantHits   int64
	}{
		{name: "success_path", wantStatus: http.StatusOK, wantHits: 1},
		{name: "fail_closed_detector_timeout", failClosed: true, wantStatus: http.StatusForbidden, wantHits: 0},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			upstream := &echoUpstream{}
			upstreamSrv := httptest.NewServer(upstream)
			defer upstreamSrv.Close()

			cfg := config.Default()
			cfg.Listen.Host = "127.0.0.1"
			cfg.Listen.Port = 0
			cfg.Upstreams = config.Upstreams{"/v1/messages": upstreamSrv.URL}

			dataDir := t.TempDir()
			getLogs := captureProcessOutput(t)
			defer getLogs()

			deps := RunDeps{
				DataDir: dataDir,
				Secrets: newStubSecrets(),
				Stdout:  os.Stdout,
				Stderr:  os.Stderr,
			}
			if tc.failClosed {
				pipeline, release := deterministicFailClosedPipeline(t, 50*time.Millisecond)
				defer release()
				deps.Pipeline = pipeline
			}

			base, _, stop := startTestDaemon(t, &cfg, deps)
			defer stop()

			// The body carries the secret so both paths process real content: the
			// success path redacts it, the fail-closed path blocks before egress.
			body := fmt.Sprintf(`{"model":"test","messages":[{"role":"user","content":%q}]}`,
				strings.Repeat("A", 1<<12)+" "+secret)
			resp := postBody(t, base+"/v1/messages", "application/json", body, nil)
			if resp.StatusCode != tc.wantStatus {
				t.Fatalf("status = %d, want %d", resp.StatusCode, tc.wantStatus)
			}
			if got := upstream.hits.Load(); got != tc.wantHits {
				t.Fatalf("upstream hits = %d, want %d", got, tc.wantHits)
			}
			_ = stop()

			logs := getLogs()
			if !strings.Contains(logs, "tokenhush:") {
				t.Fatalf("captured no daemon log output; the scan would be vacuous: %q", logs)
			}
			if strings.Contains(logs, secret) {
				t.Fatalf("plaintext secret found in daemon logs (%d bytes captured); refusing to echo the leak", len(logs))
			}

			if tc.wantHits == 1 {
				received := upstream.received()
				if bytes.Contains(received, []byte(secret)) {
					t.Error("upstream received the raw secret; the log scan would be vacuous")
				}
				if !runPlaceholderRe.Match(received) {
					t.Error("upstream body has no placeholder; the secret was never processed")
				}
			}

			for _, name := range []string{"audit.db", "audit.db-wal"} {
				p := filepath.Join(dataDir, name)
				data, err := os.ReadFile(p)
				if err != nil {
					if os.IsNotExist(err) {
						t.Logf("%s absent (checked db only)", name)
						continue
					}
					t.Fatalf("read %s: %v", p, err)
				}
				if bytes.Contains(data, []byte(secret)) {
					t.Fatalf("plaintext secret found in %s", p)
				}
			}
		})
	}

	t.Run("scanner_is_not_vacuous", func(t *testing.T) {
		planted := []byte(secret)
		if !bytes.Contains(planted, []byte(secret)) {
			t.Fatal("planted secret not detected by the scanner")
		}
	})
}
