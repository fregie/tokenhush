package gateway

import (
	"io"
	"path/filepath"
	"testing"

	"github.com/fregie/tokenhush/pkg/allowlist"
	"github.com/fregie/tokenhush/pkg/proxy"
)

// TestInstallSelfProtectionInstallsChannelContext 锁定 W6.2 的装配接缝：
// gateway 在监听器绑定后（port 与 dataDir 已知）必须把运行时变更通道上下文
// ——绑定的控制端口 + <DataDir>/allowlist.json 绝对路径——装到 pipeline 上，
// 供 W6.3 在响应路径消费。零值 context 会让控制端口类与精确路径类失效，因此
// 这里既断言安装值，也用真实文本断言判定行为。
func TestInstallSelfProtectionInstallsChannelContext(t *testing.T) {
	pipe := mustBuildPipeline(t, BuildOptions{
		Detectors: allBuiltinDetectorIDs(),
		Tool:      "w6.2-test",
		SelfProtection: SelfProtectionConfig{
			Enabled: true,
			Modes:   []string{"cli-command", "control-port", "file-write"},
		},
	})
	if got := pipe.MutationChannelContext(); got != (proxy.MutationChannelContext{}) {
		t.Fatalf("安装前 context = %+v，want 零值", got)
	}

	const port = 43210
	home := t.TempDir()
	installSelfProtection(pipe, "session-token-value", port, home, nil, io.Discard)

	ctx := pipe.MutationChannelContext()
	if ctx.ControlPort != port {
		t.Fatalf("ControlPort = %d，want %d", ctx.ControlPort, port)
	}
	wantPath := filepath.Join(home, allowlist.FileName)
	if ctx.AllowlistPath != wantPath {
		t.Fatalf("AllowlistPath = %q，want %q", ctx.AllowlistPath, wantPath)
	}

	if class, matched := pipe.DetectMutationChannel("curl -sS http://127.0.0.1:43210/allowlist"); !matched || class != proxy.MutationChannelControlPort {
		t.Fatalf("控制端口判定 = (%q, %v)，want (%q, true)", class, matched, proxy.MutationChannelControlPort)
	}
	if class, matched := pipe.DetectMutationChannel("echo '{}' > " + wantPath); !matched || class != proxy.MutationChannelFileWrite {
		t.Fatalf("文件写入判定 = (%q, %v)，want (%q, true)", class, matched, proxy.MutationChannelFileWrite)
	}
	// 边界：其它端口不得被 context 误报。
	if class, matched := pipe.DetectMutationChannel("curl http://127.0.0.1:8080/allowlist"); matched {
		t.Fatalf("其它端口被误报为 %q", class)
	}
}
