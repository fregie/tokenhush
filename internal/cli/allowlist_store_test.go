package cli

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/fregie/tokenhush/pkg/allowlist"
	"github.com/fregie/tokenhush/pkg/config"
)

// writeStoreFile 在 dataDir 下写入一个合法的持久化白名单文件（W5.1 格式）。
func writeStoreFile(t *testing.T, dataDir string, entries ...string) {
	t.Helper()
	raw, err := json.Marshal(struct {
		SchemaVersion int      `json:"schema_version"`
		Entries       []string `json:"entries"`
	}{SchemaVersion: allowlist.SchemaVersion, Entries: entries})
	if err != nil {
		t.Fatalf("marshal store file: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dataDir, allowlist.FileName), raw, 0o600); err != nil {
		t.Fatalf("write store file: %v", err)
	}
}

// TestRunServerConstructsAllowlistStoreFromDataDir 证明生产装配（RunServer）真的
// 构造了持久化白名单 store 并把同一实例接进 detector 路径：<DataDir>/allowlist.json
// 中的条目在真实请求上生效（不再脱敏）。这关闭的是 W5.1 之前"生产传 nil，C7 是
// 死代码"的缺口；对照子测试证明同一请求在没有该条目时仍被脱敏（非真空）。
func TestRunServerConstructsAllowlistStoreFromDataDir(t *testing.T) {
	secret := runSecret()
	entry := "keep." + secret + ".keep"
	body := fmt.Sprintf(`{"model":"test","messages":[{"role":"user","content":%q}]}`, entry)

	newDaemon := func(t *testing.T, withEntry bool) (*echoUpstream, string, string, func() error) {
		t.Helper()
		upstream := &echoUpstream{}
		upstreamSrv := httptest.NewServer(upstream)
		t.Cleanup(upstreamSrv.Close)

		cfg := config.Default()
		cfg.Listen.Host = "127.0.0.1"
		cfg.Listen.Port = 0
		cfg.Upstreams = config.Upstreams{"/v1/messages": upstreamSrv.URL}

		dataDir := t.TempDir()
		if withEntry {
			writeStoreFile(t, dataDir, entry)
		}
		base, _, stop := startTestDaemon(t, &cfg, RunDeps{DataDir: dataDir})
		return upstream, base, dataDir, stop
	}

	t.Run("persisted_store_entry_takes_effect", func(t *testing.T) {
		upstream, base, dataDir, stop := newDaemon(t, true)
		resp := postBody(t, base+"/v1/messages", "application/json", body, nil)
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("data-plane status = %d, want 200", resp.StatusCode)
		}
		upstreamBody := upstream.received()
		if !bytes.Contains(upstreamBody, []byte(secret)) {
			t.Fatalf("allowlist store entry did not take effect: upstream = %q, want the raw value passed through", upstreamBody)
		}
		if bytes.Contains(upstreamBody, []byte("__PII_")) {
			t.Fatalf("upstream body still carries a placeholder: %q", upstreamBody)
		}
		if err := stop(); err != nil {
			t.Fatalf("RunServer returned %v after cancel, want nil", err)
		}
		// 非 session file：干净退出（含会话清理）之后持久化文件必须仍在。
		if _, err := os.Stat(filepath.Join(dataDir, allowlist.FileName)); err != nil {
			t.Errorf("allowlist.json did not survive a clean shutdown: %v", err)
		}
	})

	t.Run("without_the_entry_redaction_still_happens", func(t *testing.T) {
		upstream, base, _, stop := newDaemon(t, false)
		defer func() { _ = stop() }()
		resp := postBody(t, base+"/v1/messages", "application/json", body, nil)
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("data-plane status = %d, want 200", resp.StatusCode)
		}
		upstreamBody := upstream.received()
		if bytes.Contains(upstreamBody, []byte(secret)) {
			t.Fatalf("upstream received the raw secret without a store entry: %q", upstreamBody)
		}
		if !runPlaceholderRe.Match(upstreamBody) {
			t.Fatalf("upstream body %q has no placeholder", upstreamBody)
		}
	})
}

// TestRunServerDegradesOnRejectedAllowlistStore 加载失败不得阻止 daemon 启动：
// 被拒绝（版本不符）的 <DataDir>/allowlist.json → daemon 照常 Ready 并服务、
// Stderr 收到显式告警、原文件逐字节不变；同一请求仍被脱敏（拒绝 ≠ 静默接受或
// 静默重置）。
func TestRunServerDegradesOnRejectedAllowlistStore(t *testing.T) {
	secret := runSecret()
	body := fmt.Sprintf(`{"model":"test","messages":[{"role":"user","content":%q}]}`, secret)

	upstream := &echoUpstream{}
	upstreamSrv := httptest.NewServer(upstream)
	defer upstreamSrv.Close()

	cfg := config.Default()
	cfg.Listen.Host = "127.0.0.1"
	cfg.Listen.Port = 0
	cfg.Upstreams = config.Upstreams{"/v1/messages": upstreamSrv.URL}

	dataDir := t.TempDir()
	rejected := []byte(`{"schema_version":999,"entries":["` + secret + `"]}`)
	if err := os.WriteFile(filepath.Join(dataDir, allowlist.FileName), rejected, 0o600); err != nil {
		t.Fatalf("write rejected store file: %v", err)
	}

	var stderr bytes.Buffer
	// startTestDaemon 在 Ready 之前失败会 t.Fatal，故"能启动"本身即证据。
	base, _, stop := startTestDaemon(t, &cfg, RunDeps{DataDir: dataDir, Stderr: &stderr})
	defer func() { _ = stop() }()

	resp := postBody(t, base+"/v1/messages", "application/json", body, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("data-plane status = %d, want 200", resp.StatusCode)
	}
	upstreamBody := upstream.received()
	if bytes.Contains(upstreamBody, []byte(secret)) {
		t.Fatalf("the rejected store file still took effect: %q", upstreamBody)
	}
	if !runPlaceholderRe.Match(upstreamBody) {
		t.Fatalf("upstream body %q has no placeholder", upstreamBody)
	}
	if !strings.Contains(stderr.String(), "schema_version 999") {
		t.Fatalf("degradation was not announced on Stderr: %q", stderr.String())
	}
	after, err := os.ReadFile(filepath.Join(dataDir, allowlist.FileName))
	if err != nil {
		t.Fatalf("read store file after startup: %v", err)
	}
	if !bytes.Equal(after, rejected) {
		t.Fatalf("rejected store file was rewritten:\nbefore = %q\nafter  = %q", rejected, after)
	}
}
