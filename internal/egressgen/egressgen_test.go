package egressgen

import (
	"bytes"
	"encoding/json"
	"go/format"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/goccy/go-yaml"
)

// testUpdated 是固定日期，保证所有渲染断言与 egress.yaml 的实际内容解耦。
const testUpdated = "2026-09-13"

// fieldsFor 返回一份新的字段切片，避免多个条目共享底层数组。
func fieldsFor() []Field {
	return []Field{
		{Name: "channel", Kind: KindSent, Description: Localized{EN: "release channel", ZH: "发布通道"}},
		{Name: "ip", Kind: KindObserved, Description: Localized{EN: "source ip", ZH: "来源 IP"}},
		{Name: "timestamp", Kind: KindObserved, Description: Localized{EN: "request time", ZH: "请求时间"}},
		{Name: "access_logs", Kind: KindObserved, Description: Localized{EN: "cloudflare logs", ZH: "Cloudflare 日志"}},
	}
}

// validManifest 构造一份通过校验的清单，作为各负向用例的基线。
func validManifest() *Manifest {
	return &Manifest{
		Version: 1,
		Updated: testUpdated,
		Items: []Item{
			{
				ID:        "update-check",
				Status:    StatusPlanned,
				Host:      "updates.example.test",
				Title:     Localized{EN: "Update check", ZH: "更新检查"},
				Purpose:   Localized{EN: "check for signed releases", ZH: "检查已签名版本"},
				Fields:    fieldsFor(),
				Switch:    Localized{EN: "auto_update: false", ZH: "auto_update: false"},
				Default:   DefaultEnabled,
				Retention: Localized{EN: "30 days", ZH: "30 天"},
			},
			{
				ID:        "rule-sync",
				Status:    StatusPlanned,
				Host:      "rules.example.test",
				Title:     Localized{EN: "Rule sync", ZH: "规则同步"},
				Purpose:   Localized{EN: "sync signed rule bundles", ZH: "同步已签名规则包"},
				Fields:    fieldsFor(),
				Switch:    Localized{EN: "rules_sync: false", ZH: "rules_sync: false"},
				Default:   DefaultEnabled,
				Retention: Localized{EN: "30 days", ZH: "30 天"},
			},
		},
	}
}

func hasObserved(it Item, name string) bool {
	for _, f := range it.Fields {
		if f.Kind == KindObserved && f.Name == name {
			return true
		}
	}
	return false
}

func removeField(fields []Field, name string) []Field {
	out := make([]Field, 0, len(fields))
	for _, f := range fields {
		if f.Name != name {
			out = append(out, f)
		}
	}
	return out
}

// TestLoadManifest 校验真实 egress.yaml 能被解析并通过所有不变量。
func TestLoadManifest(t *testing.T) {
	m, err := Load(filepath.Join("..", "..", "egress.yaml"))
	if err != nil {
		t.Fatalf("Load(egress.yaml): %v", err)
	}
	if m.Version != 1 {
		t.Errorf("Version = %d, want 1", m.Version)
	}
	if m.Updated != testUpdated {
		t.Errorf("Updated = %q, want %q", m.Updated, testUpdated)
	}
	if len(m.Items) != 2 {
		t.Fatalf("len(Items) = %d, want 2 (only update-check and rule-sync)", len(m.Items))
	}

	byID := map[string]Item{}
	for _, it := range m.Items {
		byID[it.ID] = it
	}
	// B9：rule-sync 已由 `tokenhush rules sync` 落地为 active；update-check 的自更新
	// 引擎尚未接线到 CLI，按 ADR-0022 保持 planned，不得写成现有行为。
	if got := byID["rule-sync"].Status; got != StatusActive {
		t.Errorf("rule-sync status = %q, want %q", got, StatusActive)
	}
	if got := byID["update-check"].Status; got != StatusPlanned {
		t.Errorf("update-check status = %q, want %q", got, StatusPlanned)
	}

	upd, ok := byID["update-check"]
	if !ok {
		t.Fatal("missing update-check item")
	}
	if !strings.Contains(upd.Purpose.EN, "revocation") || !strings.Contains(upd.Purpose.EN, "key-list") {
		t.Errorf("update-check purpose must describe its revocation document and key-list: %q", upd.Purpose.EN)
	}
	for _, want := range []string{"ip", "timestamp", "access_logs"} {
		if !hasObserved(upd, want) {
			t.Errorf("update-check is missing observed field %q", want)
		}
	}
	if _, ok := byID["rule-sync"]; !ok {
		t.Fatal("missing rule-sync item")
	}
}

// TestValidateRejects 覆盖非法/缺失字段：每一项都必须被 Validate 拒绝。
func TestValidateRejects(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*Manifest)
	}{
		{"wrong version", func(m *Manifest) { m.Version = 2 }},
		{"third category", func(m *Manifest) { m.Items[0].ID = "telemetry-upload" }},
		{"duplicate id", func(m *Manifest) { m.Items[1].ID = m.Items[0].ID }},
		{"missing one category", func(m *Manifest) { m.Items = m.Items[:1] }},
		{"bad status", func(m *Manifest) { m.Items[1].Status = "on" }},
		{"empty host", func(m *Manifest) { m.Items[0].Host = "" }},
		{"empty title en", func(m *Manifest) { m.Items[0].Title.EN = "" }},
		{"missing purpose zh", func(m *Manifest) { m.Items[1].Purpose.ZH = "" }},
		{"missing switch en", func(m *Manifest) { m.Items[0].Switch.EN = "" }},
		{"missing retention zh", func(m *Manifest) { m.Items[1].Retention.ZH = "" }},
		{"bad default", func(m *Manifest) { m.Items[0].Default = "sometimes" }},
		{"no fields", func(m *Manifest) { m.Items[0].Fields = nil }},
		{"bad field kind", func(m *Manifest) { m.Items[0].Fields[0].Kind = "guessed" }},
		{"field missing description en", func(m *Manifest) { m.Items[0].Fields[0].Description.EN = "" }},
		{"missing observed ip", func(m *Manifest) { m.Items[0].Fields = removeField(m.Items[0].Fields, "ip") }},
		{"missing observed access_logs", func(m *Manifest) { m.Items[1].Fields = removeField(m.Items[1].Fields, "access_logs") }},
		{"empty updated", func(m *Manifest) { m.Updated = "" }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := validManifest()
			tt.mutate(m)
			if err := m.Validate(); err == nil {
				t.Fatalf("Validate() = nil, want an error for %s", tt.name)
			}
		})
	}
}

// TestValidateAcceptsValid 确保基线清单本身通过。
func TestValidateAcceptsValid(t *testing.T) {
	if err := validManifest().Validate(); err != nil {
		t.Fatalf("Validate() = %v, want nil", err)
	}
}

// TestRenderDeterministic 断言同一清单多次渲染逐字节一致（幂等 ⇒ 守卫可靠）。
func TestRenderDeterministic(t *testing.T) {
	m := validManifest()
	renders := map[string]func(*Manifest) ([]byte, error){
		"cli":       func(m *Manifest) ([]byte, error) { s, err := RenderCLI(m); return []byte(s), err },
		"core-doc":  func(m *Manifest) ([]byte, error) { s, err := RenderCoreDoc(m); return []byte(s), err },
		"pro-doc":   func(m *Manifest) ([]byte, error) { s, err := RenderProDoc(m); return []byte(s), err },
		"web-json":  RenderWebJSON,
		"go-source": RenderGoFile,
	}
	for name, render := range renders {
		t.Run(name, func(t *testing.T) {
			first, err := render(m)
			if err != nil {
				t.Fatalf("render: %v", err)
			}
			second, err := render(m)
			if err != nil {
				t.Fatalf("render (2): %v", err)
			}
			if !bytes.Equal(first, second) {
				t.Fatal("rendered output is not deterministic")
			}
			if len(bytes.TrimSpace(first)) == 0 {
				t.Fatal("rendered output is empty")
			}
		})
	}
}

// TestRenderDistinguishesStatus 断言 active 与 planned 在 CLI/文档/官网里显式区分。
func TestRenderDistinguishesStatus(t *testing.T) {
	m := validManifest()
	m.Items[0].Status = StatusActive // update-check active, rule-sync 仍 planned

	cli, err := RenderCLI(m)
	if err != nil {
		t.Fatalf("RenderCLI: %v", err)
	}
	if !strings.Contains(cli, "[ACTIVE]") || !strings.Contains(cli, "[PLANNED]") {
		t.Errorf("CLI must label both active and planned; got:\n%s", cli)
	}
	if !strings.Contains(cli, "updates.example.test") || !strings.Contains(cli, "rules.example.test") {
		t.Error("CLI must print both hosts")
	}
	if !strings.Contains(cli, "access_logs") || !strings.Contains(cli, "30 days") {
		t.Error("CLI must disclose observed fields and retention")
	}

	coreDoc, err := RenderCoreDoc(m)
	if err != nil {
		t.Fatalf("RenderCoreDoc: %v", err)
	}
	if !strings.Contains(coreDoc, "## Active") || !strings.Contains(coreDoc, "## Planned") {
		t.Errorf("core doc must separate active and planned sections; got:\n%s", coreDoc)
	}

	proDoc, err := RenderProDoc(m)
	if err != nil {
		t.Fatalf("RenderProDoc: %v", err)
	}
	if !strings.Contains(proDoc, "已生效") || !strings.Contains(proDoc, "计划中") {
		t.Errorf("Pro doc must label 已生效 and 计划中; got:\n%s", proDoc)
	}

	raw, err := RenderWebJSON(m)
	if err != nil {
		t.Fatalf("RenderWebJSON: %v", err)
	}
	var decoded Manifest
	if err := json.Unmarshal(raw, &decoded); err != nil {
		t.Fatalf("web json is not valid JSON: %v", err)
	}
	if decoded.Items[0].Status != StatusActive || decoded.Items[1].Status != StatusPlanned {
		t.Errorf("web json statuses = %q/%q, want active/planned", decoded.Items[0].Status, decoded.Items[1].Status)
	}
	if decoded.Items[0].Title.EN == "" || decoded.Items[0].Title.ZH == "" {
		t.Error("web json must carry both locales")
	}
}

// TestRenderAllPlannedHasNoActive 断言 Plan A（全 planned）时 CLI 不出现 active 标签。
func TestRenderAllPlannedHasNoActive(t *testing.T) {
	cli, err := RenderCLI(validManifest())
	if err != nil {
		t.Fatalf("RenderCLI: %v", err)
	}
	if strings.Contains(cli, "[ACTIVE]") {
		t.Fatalf("all-planned manifest must not print an ACTIVE label:\n%s", cli)
	}
	if !strings.Contains(cli, "[PLANNED]") {
		t.Fatalf("all-planned manifest must print PLANNED labels:\n%s", cli)
	}
}

// TestRenderGoFileIsGofmtClean 断言生成的 Go 源码可被 go/format 解析。
func TestRenderGoFileIsGofmtClean(t *testing.T) {
	raw, err := RenderGoFile(validManifest())
	if err != nil {
		t.Fatalf("RenderGoFile: %v", err)
	}
	if _, err := format.Source(raw); err != nil {
		t.Fatalf("generated Go source is not parseable: %v\n%s", err, raw)
	}
	for _, want := range []string{"package cli", "egressGeneratedText", "egressGeneratedJSON"} {
		if !strings.Contains(string(raw), want) {
			t.Errorf("generated Go source is missing %q", want)
		}
	}
}

// TestLoadRejectsUnknownField 覆盖 new_input_parsing：未知字段必须报错。
func TestLoadRejectsUnknownField(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "egress.yaml")
	raw, err := yaml.Marshal(validManifest())
	if err != nil {
		t.Fatalf("marshal fixture: %v", err)
	}
	raw = append(raw, []byte("\nunexpected_key: true\n")...)
	if err := os.WriteFile(path, raw, 0o644); err != nil {
		t.Fatalf("write fixture: %v", err)
	}
	if _, err := Load(path); err == nil {
		t.Fatal("Load() = nil, want an unknown-field error")
	}
}

// TestLoadRejectsMissingFile 与非法 YAML 都要报错。
func TestLoadRejectsMissingFile(t *testing.T) {
	if _, err := Load(filepath.Join(t.TempDir(), "nope.yaml")); err == nil {
		t.Fatal("Load() = nil, want an error for a missing file")
	}
}

// TestRunCheckDetectsDrift 端到端验证 -check：手改生成物必须导致 Run 失败。
func TestRunCheckDetectsDrift(t *testing.T) {
	dir := t.TempDir()
	raw, err := yaml.Marshal(validManifest())
	if err != nil {
		t.Fatalf("marshal fixture: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "egress.yaml"), raw, 0o644); err != nil {
		t.Fatalf("write manifest: %v", err)
	}

	opts := Options{CoreRoot: dir}
	if err := Run(opts); err != nil {
		t.Fatalf("Run(write) = %v, want nil", err)
	}
	goPath := filepath.Join(dir, "internal", "cli", "egress_generated.go")
	docPath := filepath.Join(dir, "docs", "generated", "network-egress.md")
	for _, p := range []string{goPath, docPath} {
		if _, err := os.Stat(p); err != nil {
			t.Fatalf("expected generated file %s: %v", p, err)
		}
	}

	check := Options{CoreRoot: dir, Check: true}
	if err := Run(check); err != nil {
		t.Fatalf("Run(check) after generation = %v, want nil (idempotent)", err)
	}

	// 手工把 planned 改成 active，守卫必须失败。
	body, err := os.ReadFile(goPath)
	if err != nil {
		t.Fatalf("read generated go: %v", err)
	}
	tampered := bytes.ReplaceAll(body, []byte("planned"), []byte("active"))
	if bytes.Equal(tampered, body) {
		t.Fatal("expected generated output to contain 'planned'")
	}
	if err := os.WriteFile(goPath, tampered, 0o644); err != nil {
		t.Fatalf("tamper: %v", err)
	}
	if err := Run(check); err == nil {
		t.Fatal("Run(check) = nil after tampering, want a mismatch error")
	}
}
