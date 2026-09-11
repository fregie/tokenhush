//go:build ignore

// oauth-matrix-upstream is a dependency-free fake provider endpoint used by
// scripts/oauth-matrix.sh. It records the wire shape of every request it
// receives (method, path, auth scheme, tracked headers, JSON body keys) and
// answers with a minimal provider-shaped 200 so client probes can complete.
//
// It is excluded from the module build (//go:build ignore); build and run it
// through the script, or directly:
//
//	go run scripts/oauth-matrix-upstream.go \
//	    -mode claude-oauth -ready /tmp/ready -out /tmp/requests.jsonl -expect 2
//
// Flags:
//
//	-mode    label stored in every record (required)
//	-ready   file that receives the bound 127.0.0.1:PORT once listening (required)
//	-out     JSONL artifact path, appended to (required)
//	-expect  exit 0 after N requests; 0 runs until SIGINT/SIGTERM (default 0)
//	-addr    listen address (default 127.0.0.1:0, i.e. an ephemeral port)
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/signal"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

const maxBody = 1 << 20

// trackedHeaders are recorded by presence only; authorization and x-api-key
// values are never written to the artifact.
var trackedHeaders = []string{
	"accept", "anthropic-beta", "anthropic-version", "authorization",
	"chatgpt-account-id", "content-type", "openai-beta", "originator",
	"user-agent", "x-api-key", "x-app",
}

type record struct {
	Mode      string   `json:"mode"`
	Seq       int      `json:"seq"`
	Method    string   `json:"method"`
	Path      string   `json:"path"`
	Query     string   `json:"query,omitempty"`
	Auth      string   `json:"auth"`
	Headers   []string `json:"headers"`
	Beta      string   `json:"beta,omitempty"`
	UserAgent string   `json:"user_agent,omitempty"`
	BodyKeys  []string `json:"body_keys"`
	Stream    bool     `json:"stream"`
	Model     string   `json:"model,omitempty"`
	Bytes     int      `json:"bytes"`
}

type recorder struct {
	mode   string
	expect int
	file   *os.File
	mu     sync.Mutex
	seq    atomic.Int64
	done   chan struct{}
	once   sync.Once
}

func main() {
	mode := flag.String("mode", "", "mode label stored in every record (required)")
	ready := flag.String("ready", "", "file that receives the bound 127.0.0.1:PORT (required)")
	out := flag.String("out", "", "JSONL artifact path, appended (required)")
	expect := flag.Int("expect", 0, "exit after this many requests; 0 = until signal")
	addr := flag.String("addr", "127.0.0.1:0", "listen address")
	flag.Parse()
	if *mode == "" || *ready == "" || *out == "" {
		fatal("flags -mode, -ready and -out are required")
	}

	ln, err := net.Listen("tcp", *addr)
	if err != nil {
		fatal("listen: %v", err)
	}
	file, err := os.OpenFile(*out, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		fatal("open artifact: %v", err)
	}
	defer file.Close()
	if err := os.WriteFile(*ready, []byte(ln.Addr().String()), 0o644); err != nil {
		fatal("write ready file: %v", err)
	}

	rec := &recorder{mode: *mode, expect: *expect, file: file, done: make(chan struct{})}
	srv := &http.Server{
		Handler:           rec,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      15 * time.Second,
		IdleTimeout:       30 * time.Second,
	}

	stopped := make(chan struct{})
	go func() {
		sig := make(chan os.Signal, 1)
		signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
		select {
		case <-sig:
		case <-rec.done:
		}
		close(stopped)
	}()

	serveErr := make(chan error, 1)
	go func() { serveErr <- srv.Serve(ln) }()

	<-stopped
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	_ = srv.Shutdown(ctx)
	if err := <-serveErr; err != nil && err != http.ErrServerClosed {
		fatal("serve: %v", err)
	}
	fmt.Printf("DONE mode=%s received=%d\n", *mode, rec.seq.Load())
}

func (r *recorder) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	n := int(r.seq.Add(1))
	body, _ := io.ReadAll(io.LimitReader(req.Body, maxBody))
	_ = req.Body.Close()

	rec := record{
		Mode:      r.mode,
		Seq:       n,
		Method:    req.Method,
		Path:      req.URL.Path,
		Query:     req.URL.RawQuery,
		Auth:      classifyAuth(req.Header),
		Headers:   presentHeaders(req.Header),
		Beta:      truncate(firstHeader(req.Header, "anthropic-beta", "openai-beta"), 160),
		UserAgent: truncate(req.Header.Get("user-agent"), 120),
		BodyKeys:  []string{},
		Bytes:     len(body),
	}
	var fields map[string]json.RawMessage
	if len(body) > 0 && json.Unmarshal(body, &fields) == nil {
		for key := range fields {
			rec.BodyKeys = append(rec.BodyKeys, key)
		}
		sort.Strings(rec.BodyKeys)
		if raw, ok := fields["stream"]; ok {
			_ = json.Unmarshal(raw, &rec.Stream)
		}
		if raw, ok := fields["model"]; ok {
			_ = json.Unmarshal(raw, &rec.Model)
		}
	}

	if line, err := json.Marshal(rec); err == nil {
		r.mu.Lock()
		_, werr := r.file.Write(append(line, '\n'))
		r.mu.Unlock()
		if werr != nil {
			fmt.Fprintf(os.Stderr, "oauth-matrix-upstream: artifact write: %v\n", werr)
		}
	}
	fmt.Printf("REQ mode=%s seq=%d method=%s path=%s auth=%s\n", rec.Mode, rec.Seq, rec.Method, rec.Path, rec.Auth)

	respond(w, req.URL.Path)
	if r.expect > 0 && n >= r.expect {
		r.once.Do(func() { close(r.done) })
	}
}

func respond(w http.ResponseWriter, path string) {
	w.Header().Set("content-type", "application/json")
	switch {
	case strings.Contains(path, "responses"):
		io.WriteString(w, `{"id":"resp_oauth_matrix","object":"response","status":"completed","output":[]}`)
	case strings.Contains(path, "chat/completions"):
		io.WriteString(w, `{"id":"chatcmpl-oauth-matrix","object":"chat.completion","created":0,"model":"oauth-matrix","choices":[{"index":0,"message":{"role":"assistant","content":"ok"},"finish_reason":"stop"}]}`)
	default:
		io.WriteString(w, `{"id":"msg_oauth_matrix","type":"message","role":"assistant","model":"oauth-matrix","content":[{"type":"text","text":"ok"}],"stop_reason":"end_turn","usage":{"input_tokens":1,"output_tokens":1}}`)
	}
}

func classifyAuth(h http.Header) string {
	authz := strings.TrimSpace(h.Get("Authorization"))
	apiKey := strings.TrimSpace(h.Get("X-Api-Key"))
	switch {
	case authz != "" && apiKey != "":
		return schemeClass(authz) + "+x-api-key"
	case authz != "":
		return schemeClass(authz)
	case apiKey != "":
		return "x-api-key:" + tokenClass(apiKey)
	default:
		return "none"
	}
}

func schemeClass(v string) string {
	scheme, token, _ := strings.Cut(v, " ")
	scheme = strings.ToLower(scheme)
	if token == "" {
		return scheme
	}
	return scheme + ":" + tokenClass(token)
}

func tokenClass(t string) string {
	switch {
	case strings.HasPrefix(t, "sk-ant-oat01-"):
		return "oauth"
	case strings.HasPrefix(t, "sk-ant-api03-"):
		return "api-key"
	case strings.HasPrefix(t, "sk-ant-"):
		return "anthropic"
	case strings.HasPrefix(t, "sk-"):
		return "api-key"
	case strings.HasPrefix(t, "oa-matrix-"), strings.HasPrefix(t, "codex-matrix-"):
		return "placeholder"
	default:
		return "other"
	}
}

func presentHeaders(h http.Header) []string {
	out := make([]string, 0, len(trackedHeaders))
	for _, name := range trackedHeaders {
		if h.Get(name) != "" {
			out = append(out, name)
		}
	}
	sort.Strings(out)
	return out
}

func firstHeader(h http.Header, names ...string) string {
	for _, name := range names {
		if v := h.Get(name); v != "" {
			return v
		}
	}
	return ""
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}

func fatal(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "oauth-matrix-upstream: "+format+"\n", args...)
	os.Exit(2)
}
