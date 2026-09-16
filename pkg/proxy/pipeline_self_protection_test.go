package proxy

import (
	"reflect"
	"testing"

	"github.com/fregie/tokenhush/pkg/redact"
)

// TestNewPipelineStoresSelfProtectionSeam 锁定 W0.3 的 C8 承载接缝：NewPipeline
// 必须把 PipelineConfig 的四个原语存到 Pipeline 上供 W6.1–W6.4 消费；零值必须
// 保持零值（完全无操作）。本测试只锁定「承载」，不锁定任何行为——W0.3 没有拦截。
func TestNewPipelineStoresSelfProtectionSeam(t *testing.T) {
	engine, err := redact.NewPlaceholderEngine()
	if err != nil {
		t.Fatalf("NewPlaceholderEngine() error = %v", err)
	}
	exclusions := [][]byte{[]byte("control-token-value"), []byte(`{"entries":["x"]}`)}
	pipe, err := NewPipeline(PipelineConfig{
		Engine:                engine,
		SelfProtectionEnabled: true,
		SelfProtectionModes:   []string{"cli-command", "control-port", "file-write"},
		Exclusions:            exclusions,
		ControlToken:          "control-token-value",
	})
	if err != nil {
		t.Fatalf("NewPipeline() error = %v", err)
	}
	if !pipe.selfProtectionEnabled {
		t.Error("selfProtectionEnabled = false，want true")
	}
	if want := []string{"cli-command", "control-port", "file-write"}; !reflect.DeepEqual(pipe.selfProtectionModes, want) {
		t.Errorf("selfProtectionModes = %#v，want %#v", pipe.selfProtectionModes, want)
	}
	if !reflect.DeepEqual(pipe.exclusions, exclusions) {
		t.Errorf("exclusions = %#v，want %#v", pipe.exclusions, exclusions)
	}
	if pipe.controlToken != "control-token-value" {
		t.Errorf("controlToken = %q，want %q", pipe.controlToken, "control-token-value")
	}

	zero, err := NewPipeline(PipelineConfig{Engine: engine})
	if err != nil {
		t.Fatalf("NewPipeline() error = %v", err)
	}
	if zero.selfProtectionEnabled || zero.selfProtectionModes != nil || zero.exclusions != nil || zero.controlToken != "" {
		t.Errorf("零值接缝被改写：enabled=%v modes=%#v exclusions=%#v token=%q",
			zero.selfProtectionEnabled, zero.selfProtectionModes, zero.exclusions, zero.controlToken)
	}
}
