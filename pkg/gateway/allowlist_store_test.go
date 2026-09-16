package gateway

import (
	"bytes"
	"errors"
	"io"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/fregie/tokenhush/pkg/allowlist"
	"github.com/fregie/tokenhush/pkg/proxy"
)

// 编译期：pkg/allowlist.Store 以结构化方式满足冻结的 gateway.AllowlistStore
// （pkg/allowlist 不 import pkg/gateway，反向依赖在此被钉死；interface 归属
// pkg/gateway 的理由见 ADR-0012 A2）。
var _ AllowlistStore = (*allowlist.Store)(nil)

// TestBuildPipelineYAMLOnlyAllowlistEntryStillSuppresses 用生产装配路径
// （BuildPipeline）锁定"仅存在于 tokenhush.yaml 的条目仍生效"：该条目在启动时
// 被导入 store 作为种子（Entries() 含它），且 detector 路径的静态键 + store 来源
// 并集接缝照常抑制脱敏。
func TestBuildPipelineYAMLOnlyAllowlistEntryStillSuppresses(t *testing.T) {
	entry := "keep." + seamTestKey() + ".keep"
	dataDir := t.TempDir()

	store, err := allowlist.Open(dataDir, []string{entry}, io.Discard)
	if err != nil {
		t.Fatalf("allowlist.Open: %v", err)
	}
	if store == nil {
		t.Fatal("allowlist.Open returned a nil store")
	}
	if !slices.Contains(store.Entries(), entry) {
		t.Fatalf("store.Entries() = %v, want the YAML-only seed entry", store.Entries())
	}

	pipe := mustBuildPipeline(t, BuildOptions{
		Detectors:      allBuiltinDetectorIDs(),
		Allowlist:      []string{entry}, // tokenhush.yaml 的原键继续被读取
		AllowlistStore: store,           // 同一实例：种子已导入（并集）
		Tool:           "w5.1-test",
	})
	body := []byte(`{"model":"test","messages":[{"role":"user","content":"` + entry + `"}]}`)
	if out := mustTransformRequest(t, pipe, body); !bytes.Equal(out, body) {
		t.Fatalf("YAML-only allowlist entry did not suppress redaction:\n got %s\nwant %s", out, body)
	}
}

// TestCleanupSessionFilesKeepsAllowlistStore 冻结"allowlist.json 不是 session
// file"：会话清理只删 run.json 与 control.token，<DataDir>/allowlist.json 必须
// 存留（干净退出不删；W5.1 的持久化前提）。
func TestCleanupSessionFilesKeepsAllowlistStore(t *testing.T) {
	dir := t.TempDir()
	for _, name := range []string{allowlist.FileName, RunStateFileName, proxy.ControlTokenFileName} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("x"), 0o600); err != nil {
			t.Fatalf("write %s: %v", name, err)
		}
	}

	cleanupSessionFiles(dir)

	if _, err := os.Stat(filepath.Join(dir, allowlist.FileName)); err != nil {
		t.Errorf("cleanupSessionFiles removed the allowlist store: %v", err)
	}
	for _, name := range []string{RunStateFileName, proxy.ControlTokenFileName} {
		if _, err := os.Stat(filepath.Join(dir, name)); !errors.Is(err, os.ErrNotExist) {
			t.Errorf("session file %s survived cleanup (err=%v)", name, err)
		}
	}
}
