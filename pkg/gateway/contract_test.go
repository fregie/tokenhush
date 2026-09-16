package gateway

import (
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"
)

// optionsContractPath is the committed golden of the frozen ADR-0012 assembly
// contract. TestOptionsContractDoc reflects over the exported struct fields and
// fails when one is added, removed, renamed or retyped.
var optionsContractPath = filepath.Join("testdata", "options_contract.txt")

// contractTypes are the structs the ADR freezes.
func contractTypes() []reflect.Type {
	return []reflect.Type{
		reflect.TypeOf(Deps{}),
		reflect.TypeOf(Options{}),
		reflect.TypeOf(BuildOptions{}),
		reflect.TypeOf(RequestStats{}),
	}
}

// describeContract renders one "Struct Field Type" line per exported field,
// sorted so the golden is independent of declaration order.
func describeContract(types []reflect.Type) []string {
	var lines []string
	for _, typ := range types {
		for i := 0; i < typ.NumField(); i++ {
			field := typ.Field(i)
			if field.PkgPath != "" {
				continue // unexported
			}
			lines = append(lines, typ.Name()+" "+field.Name+" "+field.Type.String())
		}
	}
	sort.Strings(lines)
	return lines
}

// readContractGolden loads the golden and strips its comment/blank lines.
func readContractGolden(t *testing.T) []string {
	t.Helper()
	raw, err := os.ReadFile(optionsContractPath)
	if err != nil {
		t.Fatalf("read contract golden %s: %v", optionsContractPath, err)
	}
	var lines []string
	for _, line := range strings.Split(string(raw), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		lines = append(lines, line)
	}
	sort.Strings(lines)
	return lines
}

// TestOptionsContractDoc pins the exported fields of the four frozen structs
// against the ADR-0012 golden. Removing one golden field, adding a struct
// field, renaming one or changing a type all change the reflected "Struct
// Field Type" line set and fail the comparison.
func TestOptionsContractDoc(t *testing.T) {
	got := describeContract(contractTypes())
	want := readContractGolden(t)

	gotText := strings.Join(got, "\n")
	wantText := strings.Join(want, "\n")
	if gotText != wantText {
		t.Errorf("pkg/gateway assembly contract drifted from %s\n--- golden ---\n%s\n--- reflected ---\n%s",
			optionsContractPath, wantText, gotText)
	}
}

// pinnedField 是硬编码期望清单中的一项：字段名 + reflect.Type.String() 的确切拼写。
type pinnedField struct {
	name string
	typ  string
}

// pinnedContractFields 是 ADR-0012 冻结的四个结构体的完整期望字段清单，按声明
// 顺序逐字段固化（名称 + 类型）。它独立于 golden 与活结构体，构成
// TestOptionsContractPinnedFields 与二者对照的第三份锚点。
var pinnedContractFields = map[string][]pinnedField{
	"Deps": {
		{"DataDir", "string"},
		{"Token", "string"},
		{"Requests", "*atomic.Uint64"},
		{"Redactions", "*atomic.Uint64"},
	},
	"Options": {
		{"Core", "config.Config"},
		{"Router", "extension.Router"},
		{"CostSink", "extension.CostSink"},
		{"Sink", "audit.AuditSink"},
		{"Pipeline", "*proxy.Pipeline"},
		{"PolicyTimeout", "time.Duration"},
		{"Setup", "func(*gateway.Deps) error"},
		{"Mount", "func(*http.ServeMux, *gateway.Deps)"},
		{"WrapDataPlane", "func(http.Handler, *gateway.Deps) http.Handler"},
		{"Teardown", "func(*gateway.Deps)"},
		{"Stdout", "io.Writer"},
		{"Stderr", "io.Writer"},
		{"Ready", "func(gateway.RunInfo)"},
		{"AllowlistStore", "gateway.AllowlistStore"},
		{"SelfProtection", "gateway.SelfProtectionConfig"},
	},
	"BuildOptions": {
		{"Detectors", "[]string"},
		{"Allowlist", "[]string"},
		{"Sink", "audit.AuditSink"},
		{"Timeout", "time.Duration"},
		{"Tool", "string"},
		{"AllowlistStore", "gateway.AllowlistStore"},
		{"SelfProtection", "gateway.SelfProtectionConfig"},
	},
	"RequestStats": {
		{"Provider", "string"},
		{"Path", "string"},
		{"Method", "string"},
		{"ReqBytes", "int"},
		{"Redactions", "int"},
		{"Detectors", "[]string"},
		{"Proxied", "bool"},
	},
}

// TestOptionsContractPinnedFields 是 ADR-0012 契约的硬编码证伪门：① 按声明顺序
// 把活结构体的导出字段逐项（名称 + 类型 + 位置）与硬编码清单比对，捕获新增 /
// 删除 / 改名 / 改类型 / 重排；② 把硬编码清单投影成 golden 行集合并与 golden 做
// 集合比对，捕获 golden 的增行 / 删行 / 拼写漂移。
//
// TestOptionsContractDoc 只做「活结构体 ↔ golden」两侧比对，两侧同时漂移会静默
// 通过；本测试引入第三份硬编码清单，任一单独漂移即失败。
func TestOptionsContractPinnedFields(t *testing.T) {
	types := contractTypes()
	if len(pinnedContractFields) != len(types) {
		t.Fatalf("硬编码清单覆盖 %d 个结构体，冻结结构体有 %d 个", len(pinnedContractFields), len(types))
	}

	var projected []string
	for _, typ := range types {
		pinned, ok := pinnedContractFields[typ.Name()]
		if !ok {
			t.Fatalf("硬编码清单缺少冻结结构体 %s", typ.Name())
		}
		t.Run(typ.Name(), func(t *testing.T) {
			exported := 0
			for i := 0; i < typ.NumField(); i++ {
				field := typ.Field(i)
				if field.PkgPath != "" {
					continue
				}
				if exported >= len(pinned) {
					t.Fatalf("%s 新增了硬编码清单之外的导出字段 %s", typ.Name(), field.Name)
				}
				want := pinned[exported]
				got := field.Name + " " + field.Type.String()
				wantLine := want.name + " " + want.typ
				if got != wantLine {
					t.Errorf("%s 声明位置 %d 漂移：got %q，want %q", typ.Name(), exported, got, wantLine)
				}
				projected = append(projected, typ.Name()+" "+wantLine)
				exported++
			}
			if exported != len(pinned) {
				t.Fatalf("%s 有 %d 个导出字段，硬编码清单 %d 个", typ.Name(), exported, len(pinned))
			}
		})
	}

	sort.Strings(projected)
	got := readContractGolden(t)
	if gotText, wantText := strings.Join(got, "\n"), strings.Join(projected, "\n"); gotText != wantText {
		t.Errorf("golden 与硬编码期望清单不一致\n--- golden ---\n%s\n--- pinned ---\n%s", gotText, wantText)
	}
}
