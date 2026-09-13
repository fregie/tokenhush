// Package egressgen turns the machine-readable egress manifest (egress.yaml)
// into every user-facing disclosure: the `tokenhush privacy` CLI output, the
// core documentation fragment, the Pro documentation fragment, and the website
// data file. One manifest and one generator, so the surfaces cannot drift.
package egressgen

import (
	"bytes"
	"encoding/json"
	"fmt"
	"go/format"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/goccy/go-yaml"
)

// StatusActive 表示该外发类别在当前构建中已生效。
const StatusActive = "active"

// StatusPlanned 表示该外发类别已披露但尚未实现（已披露 ≠ 现有行为）。
const StatusPlanned = "planned"

// KindSent 表示客户端发送给服务端的字段。
const KindSent = "sent"

// KindObserved 表示服务端可观察到的字段。
const KindObserved = "observed"

// DefaultEnabled 表示该外发类别生效后默认开启（可关闭）。
const DefaultEnabled = "enabled"

// DefaultDisabled 表示该外发类别生效后默认关闭。
const DefaultDisabled = "disabled"

// allowedCategoryIDs 是外发类别的封闭集合。新增第三项外发必须先改既定的外发
// 披露决策；校验会拒绝集合之外的任何 id。
var allowedCategoryIDs = []string{"update-check", "rule-sync"}

// requiredObservedFields 是服务端必然可见、必须逐项披露的字段。
var requiredObservedFields = []string{"ip", "timestamp", "access_logs"}

// Localized 是一段中英双语文案。
type Localized struct {
	EN string `yaml:"en" json:"en"`
	ZH string `yaml:"zh" json:"zh"`
}

// Field 是外发中传输或可被服务端观察到的单个字段。
type Field struct {
	Name        string    `yaml:"name" json:"name"`
	Kind        string    `yaml:"kind" json:"kind"`
	Description Localized `yaml:"description" json:"description"`
}

// Item 是一个外发类别及其全部披露信息。
type Item struct {
	ID        string    `yaml:"id" json:"id"`
	Status    string    `yaml:"status" json:"status"`
	Host      string    `yaml:"host" json:"host"`
	Title     Localized `yaml:"title" json:"title"`
	Purpose   Localized `yaml:"purpose" json:"purpose"`
	Fields    []Field   `yaml:"fields" json:"fields"`
	Switch    Localized `yaml:"switch" json:"switch"`
	Default   string    `yaml:"default" json:"default"`
	Retention Localized `yaml:"retention" json:"retention"`
}

// Manifest 是 egress.yaml 的内存表示，也是官网数据文件的 JSON 形状。
type Manifest struct {
	Version int    `yaml:"version" json:"version"`
	Updated string `yaml:"updated" json:"updated"`
	Items   []Item `yaml:"items" json:"items"`
}

// Load 读取并校验 egress.yaml。未知字段会被拒绝，防止清单与生成器悄悄漂移。
func Load(path string) (*Manifest, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("egress manifest: %w", err)
	}
	var m Manifest
	if err := yaml.UnmarshalWithOptions(data, &m, yaml.DisallowUnknownField()); err != nil {
		return nil, fmt.Errorf("egress manifest %s: %w", path, err)
	}
	if err := m.Validate(); err != nil {
		return nil, fmt.Errorf("egress manifest %s: %w", path, err)
	}
	return &m, nil
}

// Validate 强制 egress.yaml 的全部不变量：唯二外发类别、字段完整、状态合法，
// 且服务端可见的 IP / 时间戳 / 访问日志必须逐项披露。
func (m *Manifest) Validate() error {
	if m.Version != 1 {
		return fmt.Errorf("version = %d, want 1", m.Version)
	}
	if strings.TrimSpace(m.Updated) == "" {
		return fmt.Errorf("updated is required")
	}
	allowed := make(map[string]bool, len(allowedCategoryIDs))
	for _, id := range allowedCategoryIDs {
		allowed[id] = true
	}
	seen := make(map[string]bool, len(m.Items))
	for _, it := range m.Items {
		if !allowed[it.ID] {
			return fmt.Errorf("item %q is not one of the allowed egress categories %v", it.ID, allowedCategoryIDs)
		}
		if seen[it.ID] {
			return fmt.Errorf("duplicate egress category %q", it.ID)
		}
		seen[it.ID] = true
		if err := it.validate(); err != nil {
			return fmt.Errorf("item %q: %w", it.ID, err)
		}
	}
	for _, id := range allowedCategoryIDs {
		if !seen[id] {
			return fmt.Errorf("missing egress category %q", id)
		}
	}
	return nil
}

func (it Item) validate() error {
	switch it.Status {
	case StatusActive, StatusPlanned:
	default:
		return fmt.Errorf("status = %q, want %q or %q", it.Status, StatusActive, StatusPlanned)
	}
	if strings.TrimSpace(it.Host) == "" {
		return fmt.Errorf("host is required")
	}
	if err := it.Title.require("title"); err != nil {
		return err
	}
	if err := it.Purpose.require("purpose"); err != nil {
		return err
	}
	if err := it.Switch.require("switch"); err != nil {
		return err
	}
	if err := it.Retention.require("retention"); err != nil {
		return err
	}
	switch it.Default {
	case DefaultEnabled, DefaultDisabled:
	default:
		return fmt.Errorf("default = %q, want %q or %q", it.Default, DefaultEnabled, DefaultDisabled)
	}
	if len(it.Fields) == 0 {
		return fmt.Errorf("fields must not be empty")
	}
	observed := make(map[string]bool, len(requiredObservedFields))
	for i, f := range it.Fields {
		if strings.TrimSpace(f.Name) == "" {
			return fmt.Errorf("field %d: name is required", i)
		}
		switch f.Kind {
		case KindSent:
		case KindObserved:
			observed[f.Name] = true
		default:
			return fmt.Errorf("field %q: kind = %q, want %q or %q", f.Name, f.Kind, KindSent, KindObserved)
		}
		if err := f.Description.require("description of field " + f.Name); err != nil {
			return err
		}
	}
	for _, name := range requiredObservedFields {
		if !observed[name] {
			return fmt.Errorf("missing observed field %q (server-visible information must be disclosed)", name)
		}
	}
	return nil
}

func (l Localized) require(what string) error {
	if strings.TrimSpace(l.EN) == "" {
		return fmt.Errorf("%s.en is required", what)
	}
	if strings.TrimSpace(l.ZH) == "" {
		return fmt.Errorf("%s.zh is required", what)
	}
	return nil
}

// RenderCLI 渲染 `tokenhush privacy` 的人类可读输出。每个类别都明确标注
// [ACTIVE] 或 [PLANNED]，绝不把计划中的外发写成现有行为。
func RenderCLI(m *Manifest) (string, error) {
	var b strings.Builder
	b.WriteString("Tokenhush network egress disclosure\n")
	b.WriteString("===================================\n")
	fmt.Fprintf(&b, "Generated from egress.yaml (version %d, updated %s). Do not edit by hand.\n\n", m.Version, m.Updated)
	b.WriteString("Vendor-bound requests are limited to the two switchable categories below.\n")
	b.WriteString("Each can be switched off. Categories marked [PLANNED] are not active in this build.\n\n")
	for _, it := range m.Items {
		writeCLIItem(&b, it)
	}
	return strings.TrimRight(b.String(), "\n") + "\n", nil
}

func writeCLIItem(b *strings.Builder, it Item) {
	label := "[PLANNED]"
	if it.Status == StatusActive {
		label = "[ACTIVE]"
	}
	fmt.Fprintf(b, "%s %s (%s)\n", label, it.Title.EN, it.ID)
	fmt.Fprintf(b, "  Host: %s\n", it.Host)
	fmt.Fprintf(b, "  Purpose: %s\n", it.Purpose.EN)
	b.WriteString("  Sent to the server:\n")
	writeCLIFields(b, it, KindSent)
	b.WriteString("  Server can observe:\n")
	writeCLIFields(b, it, KindObserved)
	fmt.Fprintf(b, "  How to switch off: %s\n", it.Switch.EN)
	fmt.Fprintf(b, "  Default (when active): %s\n", it.Default)
	fmt.Fprintf(b, "  Retention: %s\n\n", it.Retention.EN)
}

func writeCLIFields(b *strings.Builder, it Item, kind string) {
	for _, f := range it.Fields {
		if f.Kind == kind {
			fmt.Fprintf(b, "    - %s: %s\n", f.Name, f.Description.EN)
		}
	}
}

// RenderCoreDoc 渲染核心文档片段（英文 Markdown），由核心 README 与安全文档链接。
func RenderCoreDoc(m *Manifest) (string, error) {
	var b strings.Builder
	b.WriteString("# Network egress disclosure\n\n")
	b.WriteString("<!-- Code generated by cmd/egress-gen from egress.yaml. DO NOT EDIT. -->\n\n")
	b.WriteString("Tokenhush lists every request it sends to the vendor here. This page is generated\n")
	b.WriteString("from the machine-readable manifest [`egress.yaml`](../../egress.yaml); the CLI\n")
	b.WriteString("(`tokenhush privacy`), the documentation, and the website are all generated from\n")
	b.WriteString("that one file.\n\n")
	b.WriteString("Vendor-bound requests are limited to the two switchable categories below. Each can\n")
	b.WriteString("be switched off. Categories marked **planned** are not active in this build; they\n")
	b.WriteString("become active only after the corresponding release.\n\n")
	writeDocSection(&b, "Active", m, StatusActive)
	writeDocSection(&b, "Planned", m, StatusPlanned)
	return strings.TrimRight(b.String(), "\n") + "\n", nil
}

func writeDocSection(b *strings.Builder, heading string, m *Manifest, status string) {
	fmt.Fprintf(b, "## %s\n\n", heading)
	count := 0
	for _, it := range m.Items {
		if it.Status != status {
			continue
		}
		count++
		writeDocItem(b, it)
	}
	if count == 0 {
		b.WriteString("None in this build.\n\n")
	}
}

func writeDocItem(b *strings.Builder, it Item) {
	fmt.Fprintf(b, "### %s (`%s`)\n\n", it.Title.EN, it.ID)
	fmt.Fprintf(b, "- **Host:** `%s`\n", it.Host)
	fmt.Fprintf(b, "- **Purpose:** %s\n", it.Purpose.EN)
	fmt.Fprintf(b, "- **Default when active:** `%s`\n", it.Default)
	fmt.Fprintf(b, "- **Switch off:** %s\n", it.Switch.EN)
	b.WriteString("- **Server can observe:**\n")
	writeDocFields(b, it, KindObserved)
	b.WriteString("- **Sent to the server:**\n")
	writeDocFields(b, it, KindSent)
	fmt.Fprintf(b, "- **Retention:** %s\n\n", it.Retention.EN)
}

func writeDocFields(b *strings.Builder, it Item, kind string) {
	for _, f := range it.Fields {
		if f.Kind == kind {
			fmt.Fprintf(b, "  - `%s` — %s\n", f.Name, f.Description.EN)
		}
	}
}

// RenderProDoc 渲染 Pro 文档片段（中文 Markdown，docs/engineering/08-network-egress.md）。
func RenderProDoc(m *Manifest) (string, error) {
	var b strings.Builder
	b.WriteString("# 网络外发披露\n\n")
	b.WriteString("<!-- 本文件由核心 `cmd/egress-gen` 依据核心仓库根的 `egress.yaml` 生成，请勿手改。 -->\n\n")
	b.WriteString("本文件如实列出 Tokenhush 向厂商发起的请求。核心 CLI `tokenhush privacy`、本文档与\n")
	b.WriteString("官网数据文件由公开核心仓库根的同一份机器可读清单 `egress.yaml` 生成，口径一致。\n\n")
	b.WriteString("向厂商的外发仅限以下两个可关闭类别。标注 **计划中（planned）** 的类别在当前构建中\n")
	b.WriteString("尚未生效，仅在对应版本落地后才生效；不得把计划中写成现有行为。语义与边界见\n")
	b.WriteString("[ADR-0022](../decisions/0022-network-egress-disclosure.md)。\n\n")
	writeProSection(&b, "已生效（active）", m, StatusActive)
	writeProSection(&b, "计划中（planned）", m, StatusPlanned)
	return strings.TrimRight(b.String(), "\n") + "\n", nil
}

func writeProSection(b *strings.Builder, heading string, m *Manifest, status string) {
	fmt.Fprintf(b, "## %s\n\n", heading)
	count := 0
	for _, it := range m.Items {
		if it.Status != status {
			continue
		}
		count++
		writeProItem(b, it)
	}
	if count == 0 {
		b.WriteString("当前构建无此类目。\n\n")
	}
}

func writeProItem(b *strings.Builder, it Item) {
	fmt.Fprintf(b, "### %s（`%s`）\n\n", it.Title.ZH, it.ID)
	fmt.Fprintf(b, "- **Host：** `%s`\n", it.Host)
	fmt.Fprintf(b, "- **目的：** %s\n", it.Purpose.ZH)
	fmt.Fprintf(b, "- **生效时默认：** `%s`\n", it.Default)
	fmt.Fprintf(b, "- **关闭方法：** %s\n", it.Switch.ZH)
	b.WriteString("- **服务端可见：**\n")
	writeProFields(b, it, KindObserved)
	b.WriteString("- **传输字段：**\n")
	writeProFields(b, it, KindSent)
	fmt.Fprintf(b, "- **保留期：** %s\n\n", it.Retention.ZH)
}

func writeProFields(b *strings.Builder, it Item, kind string) {
	for _, f := range it.Fields {
		if f.Kind == kind {
			fmt.Fprintf(b, "  - `%s` — %s\n", f.Name, f.Description.ZH)
		}
	}
}

// RenderWebJSON 渲染官网数据文件（清单的 JSON 副本），使网站呈现与 CLI / 文档
// 相同的外发披露。
func RenderWebJSON(m *Manifest) ([]byte, error) {
	raw, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("marshal egress manifest: %w", err)
	}
	return append(raw, '\n'), nil
}

// RenderGoFile 渲染 internal/cli/egress_generated.go：`tokenhush privacy`
// 打印的内嵌披露。输出保证 gofmt 规范。
func RenderGoFile(m *Manifest) ([]byte, error) {
	text, err := RenderCLI(m)
	if err != nil {
		return nil, err
	}
	webJSON, err := RenderWebJSON(m)
	if err != nil {
		return nil, err
	}
	var b strings.Builder
	b.WriteString("// Code generated by cmd/egress-gen from egress.yaml. DO NOT EDIT.\n\n")
	b.WriteString("package cli\n\n")
	b.WriteString("// egressGeneratedText 是 `tokenhush privacy` 打印的人类可读披露。\n")
	fmt.Fprintf(&b, "const egressGeneratedText = %s\n\n", goStringLiteral(text))
	b.WriteString("// egressGeneratedJSON 是 `tokenhush privacy --json` 打印的机器可读披露。\n")
	fmt.Fprintf(&b, "const egressGeneratedJSON = %s\n", goStringLiteral(string(webJSON)))
	src, err := format.Source([]byte(b.String()))
	if err != nil {
		return nil, fmt.Errorf("format generated Go source: %w", err)
	}
	return src, nil
}

// goStringLiteral 把多行文本渲染为可安全嵌入 Go 源码的字面量：按行拆分为已
// 转义的字符串拼接，既能容纳反引号，又保持可读。
func goStringLiteral(value string) string {
	var b strings.Builder
	b.WriteString(`""`)
	for _, line := range strings.SplitAfter(value, "\n") {
		if line == "" {
			continue
		}
		b.WriteString(" +\n\t")
		b.WriteString(strconv.Quote(line))
	}
	return b.String()
}

// Options 控制一次生成器运行。
type Options struct {
	ManifestPath string
	CoreRoot     string
	ProRoot      string
	WebRoot      string
	Check        bool
}

type output struct {
	path    string
	content []byte
}

// Run 从清单重新生成全部披露。Check 为真时只校验已提交文件、不写盘，因此手改
// 生成物或清单漂移会直接失败而不会被重新生成悄悄掩盖。
func Run(opts Options) error {
	coreRoot := opts.CoreRoot
	if coreRoot == "" {
		coreRoot = "."
	}
	manifestPath := opts.ManifestPath
	if manifestPath == "" {
		manifestPath = filepath.Join(coreRoot, "egress.yaml")
	}
	m, err := Load(manifestPath)
	if err != nil {
		return err
	}
	goSrc, err := RenderGoFile(m)
	if err != nil {
		return err
	}
	coreDoc, err := RenderCoreDoc(m)
	if err != nil {
		return err
	}
	outputs := []output{
		{filepath.Join(coreRoot, "internal", "cli", "egress_generated.go"), goSrc},
		{filepath.Join(coreRoot, "docs", "generated", "network-egress.md"), []byte(coreDoc)},
	}
	if opts.ProRoot != "" {
		proDoc, err := RenderProDoc(m)
		if err != nil {
			return err
		}
		outputs = append(outputs, output{
			filepath.Join(opts.ProRoot, "docs", "engineering", "08-network-egress.md"),
			[]byte(proDoc),
		})
	}
	if opts.WebRoot != "" {
		webJSON, err := RenderWebJSON(m)
		if err != nil {
			return err
		}
		outputs = append(outputs, output{
			filepath.Join(opts.WebRoot, "src", "data", "egress.generated.json"),
			webJSON,
		})
	}
	for _, o := range outputs {
		if opts.Check {
			existing, err := os.ReadFile(o.path)
			if err != nil {
				return fmt.Errorf("%s: %w", o.path, err)
			}
			if !bytes.Equal(existing, o.content) {
				return fmt.Errorf("%s 与 %s 不一致；请运行 `go run ./cmd/egress-gen` 重新生成", o.path, manifestPath)
			}
			continue
		}
		if err := os.MkdirAll(filepath.Dir(o.path), 0o755); err != nil {
			return fmt.Errorf("mkdir %s: %w", filepath.Dir(o.path), err)
		}
		if err := os.WriteFile(o.path, o.content, 0o644); err != nil {
			return fmt.Errorf("write %s: %w", o.path, err)
		}
	}
	return nil
}
