package allowlist

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/fregie/tokenhush/pkg/extension"
	"github.com/fregie/tokenhush/pkg/redact"
)

// allowlistStoreShape 是 gateway.AllowlistStore 冻结形状的本地镜像：本包不得
// import pkg/gateway（接口正是为此做成结构化满足，见 ADR-0012 A2）。真实
// gateway 侧的编译期断言在 pkg/gateway/allowlist_store_test.go。
type allowlistStoreShape interface {
	Entries() []string
	Add(entry string) error
	Remove(entry string) error
}

var _ allowlistStoreShape = (*Store)(nil)

// testEntry 生成一个会被 prefix 检测器（sk- 前缀）命中的测试密钥字面量；
// 运行期拼接，避免提交中出现连续密钥字面量（gitleaks）。
func testSecret() string {
	return strings.Join([]string{"sk-", "proj-", strings.Repeat("T3stOnly", 2), "Key012"}, "")
}

// testEntry 是"把密钥包进白名单字面量"的形态：匹配语义是字节精确包含，finding
// 的 span 落在字面量内即被抑制。
func testEntry() string { return "keep." + testSecret() + ".keep" }

// storeFile 返回冻结的持久化路径。
func storeFile(dir string) string { return filepath.Join(dir, FileName) }

// mustOpen 打开 store 并要求成功。
func mustOpen(t *testing.T, dir string, seed []string, warn io.Writer) *Store {
	t.Helper()
	s, err := Open(dir, seed, warn)
	if err != nil {
		t.Fatalf("Open(%q) error = %v", dir, err)
	}
	if s == nil {
		t.Fatal("Open returned a nil store")
	}
	return s
}

// writeRaw 直接写入持久化文件（模拟磁盘上的任意内容）。
func writeRaw(t *testing.T, dir, raw string) {
	t.Helper()
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatalf("mkdir %s: %v", dir, err)
	}
	if err := os.WriteFile(storeFile(dir), []byte(raw), 0o600); err != nil {
		t.Fatalf("write %s: %v", storeFile(dir), err)
	}
}

// readFile 读回持久化文件的原始字节。
func readFile(t *testing.T, dir string) []byte {
	t.Helper()
	raw, err := os.ReadFile(storeFile(dir))
	if err != nil {
		t.Fatalf("read %s: %v", storeFile(dir), err)
	}
	return raw
}

// docOf 构造一个带内容叶的请求 Document，模拟 detector 的真实输入形态。
func docOf(contents ...string) *extension.Document {
	leaves := make([]extension.Leaf, len(contents))
	for i, c := range contents {
		leaves[i] = extension.Leaf{
			Path:    fmt.Sprintf("#/messages/%d/content", i),
			Content: []byte(c),
			Len:     len(c),
		}
	}
	return &extension.Document{Phase: extension.RequestContent, Tool: "w5.1-test", Leaves: leaves}
}

// findings 运行 inspector 并要求无错误。
func findings(t *testing.T, insp extension.Inspector, doc *extension.Document) []extension.Finding {
	t.Helper()
	got, err := insp.Inspect(doc)
	if err != nil {
		t.Fatalf("%s: Inspect() error = %v", insp.ID(), err)
	}
	return got
}

// tempFiles 列出目录里的原子写临时文件残骸。
func tempFiles(t *testing.T, dir string) []string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read dir %s: %v", dir, err)
	}
	var out []string
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), ".tmp-") {
			out = append(out, e.Name())
		}
	}
	return out
}

// TestFileNameIsFrozen 冻结持久化文件的位置：<DataDir>/allowlist.json，且它不是
// 任何 session file（session 清理名单见 pkg/gateway/runstate.go 与 pkg/proxy）。
func TestFileNameIsFrozen(t *testing.T) {
	if FileName != "allowlist.json" {
		t.Fatalf("FileName = %q, want %q", FileName, "allowlist.json")
	}
	if FileName == "run.json" || FileName == "control.token" {
		t.Fatalf("FileName %q collides with a session file", FileName)
	}
	if got, want := storeFile("/data"), filepath.Join("/data", "allowlist.json"); got != want {
		t.Fatalf("storeFile = %q, want %q", got, want)
	}
}

// TestOpenRejectsBlankDataDir 唯一的硬错误：数据根不可用（空/仅空白）。
func TestOpenRejectsBlankDataDir(t *testing.T) {
	for _, dir := range []string{"", "   "} {
		s, err := Open(dir, nil, io.Discard)
		if err == nil {
			t.Fatalf("Open(%q) error = nil, want a hard error", dir)
		}
		if s != nil {
			t.Fatalf("Open(%q) returned a store alongside the error", dir)
		}
	}
}

// TestOpenMissingFileStartsEmpty 首次运行：文件缺失 = 空运行期集合、无告警、
// 不写盘（Open 绝不创建文件）。
func TestOpenMissingFileStartsEmpty(t *testing.T) {
	dir := t.TempDir()
	var warn bytes.Buffer
	s := mustOpen(t, dir, nil, &warn)
	if got := s.Entries(); len(got) != 0 {
		t.Fatalf("Entries() = %v, want empty", got)
	}
	if warn.Len() != 0 {
		t.Fatalf("missing file produced a warning: %q", warn.String())
	}
	if _, err := os.Stat(storeFile(dir)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("Open created %s (stat err=%v), want no file", storeFile(dir), err)
	}
}

// TestOpenNilWarnWriterIsSafe 告警流可省略：正常与降级路径都不得 panic。
func TestOpenNilWarnWriterIsSafe(t *testing.T) {
	t.Run("missing_file", func(t *testing.T) {
		s := mustOpen(t, t.TempDir(), nil, nil)
		if got := s.Entries(); len(got) != 0 {
			t.Fatalf("Entries() = %v, want empty", got)
		}
	})
	t.Run("degraded_load", func(t *testing.T) {
		dir := t.TempDir()
		writeRaw(t, dir, `{"schema_version":999,"entries":["x"]}`)
		s := mustOpen(t, dir, nil, nil)
		if got := s.Entries(); len(got) != 0 {
			t.Fatalf("Entries() = %v, want empty after degradation", got)
		}
	})
}

// TestAddPersistsAndRoundTrips 读写往返 + 确定性顺序：Add 之后重开 store 仍在，
// 且 Entries() 按字节序排序、去重。
func TestAddPersistsAndRoundTrips(t *testing.T) {
	dir := t.TempDir()
	s := mustOpen(t, dir, nil, io.Discard)
	if err := s.Add("b-entry"); err != nil {
		t.Fatalf("Add(b-entry) error = %v", err)
	}
	if err := s.Add("a-entry"); err != nil {
		t.Fatalf("Add(a-entry) error = %v", err)
	}
	want := []string{"a-entry", "b-entry"}
	if got := s.Entries(); !slices.Equal(got, want) {
		t.Fatalf("Entries() = %v, want %v (sorted, deterministic)", got, want)
	}

	var doc struct {
		SchemaVersion int      `json:"schema_version"`
		Entries       []string `json:"entries"`
	}
	if err := json.Unmarshal(readFile(t, dir), &doc); err != nil {
		t.Fatalf("persisted file is not valid JSON: %v", err)
	}
	if doc.SchemaVersion != SchemaVersion {
		t.Fatalf("persisted schema_version = %d, want %d", doc.SchemaVersion, SchemaVersion)
	}
	if !slices.Equal(doc.Entries, want) {
		t.Fatalf("persisted entries = %v, want %v", doc.Entries, want)
	}

	reopened := mustOpen(t, dir, nil, io.Discard)
	if got := reopened.Entries(); !slices.Equal(got, want) {
		t.Fatalf("reopened Entries() = %v, want %v (round trip)", got, want)
	}
}

// TestSeedIsImportedAsUnion 合并语义 = 并集：静态种子在启动时导入 store（Entries()
// 含它），持久化文件中的运行期条目不被替换，且 Open 不重写文件。
func TestSeedIsImportedAsUnion(t *testing.T) {
	dir := t.TempDir()
	writeRaw(t, dir, `{"schema_version":1,"entries":["runtime-entry","yaml-only"]}`)
	before := readFile(t, dir)

	var warn bytes.Buffer
	s := mustOpen(t, dir, []string{"yaml-only", "seed-entry"}, &warn)
	want := []string{"runtime-entry", "seed-entry", "yaml-only"}
	if got := s.Entries(); !slices.Equal(got, want) {
		t.Fatalf("Entries() = %v, want the union %v", got, want)
	}
	if warn.Len() != 0 {
		t.Fatalf("valid union load produced a warning: %q", warn.String())
	}
	if after := readFile(t, dir); !bytes.Equal(before, after) {
		t.Fatalf("Open rewrote the file:\nbefore = %q\nafter  = %q", before, after)
	}
}

// TestSchemaVersionMatchAccepted 版本相符 → 正常加载，无告警。
func TestSchemaVersionMatchAccepted(t *testing.T) {
	dir := t.TempDir()
	writeRaw(t, dir, `{"schema_version":1,"entries":["a"]}`)
	var warn bytes.Buffer
	s := mustOpen(t, dir, nil, &warn)
	if got, want := s.Entries(), []string{"a"}; !slices.Equal(got, want) {
		t.Fatalf("Entries() = %v, want %v", got, want)
	}
	if warn.Len() != 0 {
		t.Fatalf("matching version produced a warning: %q", warn.String())
	}
}

// TestSchemaVersionMismatchRejectedWithFileIntact 版本不符（含缺失 = 0）→ 拒绝 +
// 显式告警，绝不静默重置：原文件保持逐字节不变，store 仍可用。
func TestSchemaVersionMismatchRejectedWithFileIntact(t *testing.T) {
	cases := []struct {
		name string
		raw  string
		sub  string
	}{
		{name: "future_version", raw: `{"schema_version":999,"entries":["x"]}`, sub: "schema_version 999"},
		{name: "missing_version", raw: `{"entries":["x"]}`, sub: "schema_version 0"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			writeRaw(t, dir, tc.raw)
			before := readFile(t, dir)

			var warn bytes.Buffer
			s := mustOpen(t, dir, nil, &warn)
			if got := s.Entries(); len(got) != 0 {
				t.Fatalf("Entries() = %v, want empty after a version rejection", got)
			}
			if !strings.Contains(warn.String(), tc.sub) {
				t.Fatalf("warning %q does not mention %q", warn.String(), tc.sub)
			}
			if !strings.Contains(warn.String(), "want 1") {
				t.Fatalf("warning %q does not state the supported version", warn.String())
			}
			if !strings.Contains(warn.String(), "tokenhush: allowlist:") {
				t.Fatalf("warning %q lacks the stable prefix", warn.String())
			}
			if after := readFile(t, dir); !bytes.Equal(before, after) {
				t.Fatalf("rejected file was modified:\nbefore = %q\nafter  = %q", before, after)
			}
			// 降级不是死路：显式变更仍然可用（写入合法的下一代文件）。
			if err := s.Add("later"); err != nil {
				t.Fatalf("Add on a degraded store error = %v", err)
			}
			reopened := mustOpen(t, dir, nil, io.Discard)
			if got, want := reopened.Entries(), []string{"later"}; !slices.Equal(got, want) {
				t.Fatalf("reopened Entries() = %v, want %v", got, want)
			}
		})
	}
}

// TestCorruptFileDegradesToUsableStore 损坏文件 → 可用 store + 显式告警 + 原文件
// 不变（daemon 启动不被阻止）。
func TestCorruptFileDegradesToUsableStore(t *testing.T) {
	dir := t.TempDir()
	writeRaw(t, dir, `{not json`)
	before := readFile(t, dir)

	var warn bytes.Buffer
	s := mustOpen(t, dir, nil, &warn)
	if got := s.Entries(); len(got) != 0 {
		t.Fatalf("Entries() = %v, want empty", got)
	}
	for _, sub := range []string{"corrupt", "tokenhush: allowlist:"} {
		if !strings.Contains(warn.String(), sub) {
			t.Fatalf("warning %q does not mention %q", warn.String(), sub)
		}
	}
	if after := readFile(t, dir); !bytes.Equal(before, after) {
		t.Fatalf("corrupt file was rewritten:\nbefore = %q\nafter  = %q", before, after)
	}

	if err := s.Add("recovered"); err != nil {
		t.Fatalf("Add on a corrupt-file store error = %v", err)
	}
	if got, want := mustOpen(t, dir, nil, io.Discard).Entries(), []string{"recovered"}; !slices.Equal(got, want) {
		t.Fatalf("Entries() after recovery = %v, want %v", got, want)
	}
}

// TestEmptyEntryRejected 空条目在变更路径被拒绝（与 pkg/config 的静态校验同一
// 判定），且失败不产生任何写盘。
func TestEmptyEntryRejected(t *testing.T) {
	dir := t.TempDir()
	s := mustOpen(t, dir, nil, io.Discard)
	if err := s.Add(""); !errors.Is(err, ErrInvalidEntry) {
		t.Fatalf("Add(\"\") error = %v, want ErrInvalidEntry", err)
	}
	if _, err := os.Stat(storeFile(dir)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("a rejected Add wrote %s (stat err=%v)", storeFile(dir), err)
	}
}

// TestControlCharactersRejected 控制字符：变更路径拒绝（ErrInvalidEntry）、加载
// 路径整体拒绝 + 告警 + 原文件不变。
func TestControlCharactersRejected(t *testing.T) {
	t.Run("mutation_path", func(t *testing.T) {
		dir := t.TempDir()
		s := mustOpen(t, dir, nil, io.Discard)
		for _, entry := range []string{"a\x00b", "line\nbreak", "tab\there", "del\x7f"} {
			if err := s.Add(entry); !errors.Is(err, ErrInvalidEntry) {
				t.Fatalf("Add(%q) error = %v, want ErrInvalidEntry", entry, err)
			}
		}
		if got := s.Entries(); len(got) != 0 {
			t.Fatalf("Entries() = %v, want empty", got)
		}
	})

	t.Run("load_path", func(t *testing.T) {
		dir := t.TempDir()
		writeRaw(t, dir, `{"schema_version":1,"entries":["ok","a\u0000b"]}`)
		before := readFile(t, dir)
		var warn bytes.Buffer
		s := mustOpen(t, dir, nil, &warn)
		if got := s.Entries(); len(got) != 0 {
			t.Fatalf("Entries() = %v, want empty (whole file rejected, no partial import)", got)
		}
		if !strings.Contains(warn.String(), "control characters") {
			t.Fatalf("warning %q does not mention control characters", warn.String())
		}
		if after := readFile(t, dir); !bytes.Equal(before, after) {
			t.Fatalf("rejected file was modified:\nbefore = %q\nafter  = %q", before, after)
		}
	})
}

// TestEntryLengthLimit 长度上限（4096 字节，与 pkg/config 的 maxConfigEntryBytes
// 一致）：边界内接受，超限拒绝；加载路径超限 → 降级 + 告警。
func TestEntryLengthLimit(t *testing.T) {
	s := mustOpen(t, t.TempDir(), nil, io.Discard)

	atLimit := strings.Repeat("x", maxEntryBytes)
	if err := s.Add(atLimit); err != nil {
		t.Fatalf("Add(exactly %d bytes) error = %v, want nil", maxEntryBytes, err)
	}
	overLimit := strings.Repeat("x", maxEntryBytes+1)
	if err := s.Add(overLimit); !errors.Is(err, ErrInvalidEntry) {
		t.Fatalf("Add(%d bytes) error = %v, want ErrInvalidEntry", maxEntryBytes+1, err)
	}
	if got := len(s.Entries()); got != 1 {
		t.Fatalf("len(Entries()) = %d, want 1 (the over-limit entry must not be added)", got)
	}

	t.Run("load_path", func(t *testing.T) {
		dir := t.TempDir()
		raw := `{"schema_version":1,"entries":["` + overLimit + `"]}`
		writeRaw(t, dir, raw)
		before := readFile(t, dir)
		var warn bytes.Buffer
		degraded := mustOpen(t, dir, nil, &warn)
		if got := degraded.Entries(); len(got) != 0 {
			t.Fatalf("Entries() = %v, want empty", got)
		}
		if !strings.Contains(warn.String(), "at most 4096 bytes") {
			t.Fatalf("warning %q does not state the limit", warn.String())
		}
		if after := readFile(t, dir); !bytes.Equal(before, after) {
			t.Fatalf("rejected file was modified")
		}
	})
}

// TestDuplicatesCollapsed 去重：加载时折叠重复条目（文件不被重写，也不告警——
// 这是等价归一化，不是失败）；变更路径的重复新增返回 ErrDuplicate。
func TestDuplicatesCollapsed(t *testing.T) {
	t.Run("load_collapses", func(t *testing.T) {
		dir := t.TempDir()
		writeRaw(t, dir, `{"schema_version":1,"entries":["a","a","b","b","a"]}`)
		before := readFile(t, dir)
		var warn bytes.Buffer
		s := mustOpen(t, dir, nil, &warn)
		if got, want := s.Entries(), []string{"a", "b"}; !slices.Equal(got, want) {
			t.Fatalf("Entries() = %v, want %v", got, want)
		}
		if warn.Len() != 0 {
			t.Fatalf("duplicate collapse produced a warning: %q", warn.String())
		}
		if after := readFile(t, dir); !bytes.Equal(before, after) {
			t.Fatalf("load rewrote the file instead of normalizing in memory")
		}
	})

	t.Run("add_duplicate_rejected", func(t *testing.T) {
		dir := t.TempDir()
		s := mustOpen(t, dir, []string{"seeded"}, io.Discard)
		if err := s.Add("seeded"); !errors.Is(err, ErrDuplicate) {
			t.Fatalf("Add(seeded) error = %v, want ErrDuplicate (the static seed counts as present)", err)
		}
		if err := s.Add("fresh"); err != nil {
			t.Fatalf("Add(fresh) error = %v", err)
		}
		if err := s.Add("fresh"); !errors.Is(err, ErrDuplicate) {
			t.Fatalf("second Add(fresh) error = %v, want ErrDuplicate", err)
		}
	})
}

// TestRemove semantics：不存在 → ErrNotFound；运行期条目移除后持久化（重启不复现）；
// 静态种子条目可被移除（立即从 Entries() 消失），但 YAML 在下一次启动时重新导入它
// —— 这是冻结的 Remove-a-seed 决策。
func TestRemove(t *testing.T) {
	t.Run("absent_returns_not_found", func(t *testing.T) {
		s := mustOpen(t, t.TempDir(), nil, io.Discard)
		if err := s.Remove("nope"); !errors.Is(err, ErrNotFound) {
			t.Fatalf("Remove(nope) error = %v, want ErrNotFound", err)
		}
	})

	t.Run("runtime_entry_stays_removed_after_restart", func(t *testing.T) {
		dir := t.TempDir()
		s := mustOpen(t, dir, nil, io.Discard)
		if err := s.Add("runtime"); err != nil {
			t.Fatalf("Add error = %v", err)
		}
		if err := s.Remove("runtime"); err != nil {
			t.Fatalf("Remove error = %v", err)
		}
		if got := s.Entries(); len(got) != 0 {
			t.Fatalf("Entries() = %v, want empty", got)
		}
		if got := mustOpen(t, dir, nil, io.Discard).Entries(); len(got) != 0 {
			t.Fatalf("removed runtime entry came back after restart: %v", got)
		}
	})

	t.Run("seed_entry_is_removed_but_reseeded_next_start", func(t *testing.T) {
		dir := t.TempDir()
		writeRaw(t, dir, `{"schema_version":1,"entries":["runtime"]}`)
		s := mustOpen(t, dir, []string{"seeded"}, io.Discard)
		if got, want := s.Entries(), []string{"runtime", "seeded"}; !slices.Equal(got, want) {
			t.Fatalf("Entries() = %v, want %v", got, want)
		}
		if err := s.Remove("seeded"); err != nil {
			t.Fatalf("Remove(seeded) error = %v, want nil (a seed is removable from the effective set)", err)
		}
		if got, want := s.Entries(), []string{"runtime"}; !slices.Equal(got, want) {
			t.Fatalf("Entries() = %v, want %v", got, want)
		}
		// 种子条目从不写入磁盘：文件里只有运行期集合。
		var doc struct {
			Entries []string `json:"entries"`
		}
		if err := json.Unmarshal(readFile(t, dir), &doc); err != nil {
			t.Fatalf("persisted file invalid: %v", err)
		}
		if !slices.Equal(doc.Entries, []string{"runtime"}) {
			t.Fatalf("persisted entries = %v, want [runtime] (seeds are not persisted)", doc.Entries)
		}
		// 下一次启动：tokenhush.yaml 仍然列出该条目 → 重新导入（冻结语义）。
		reopened := mustOpen(t, dir, []string{"seeded"}, io.Discard)
		if got, want := reopened.Entries(), []string{"runtime", "seeded"}; !slices.Equal(got, want) {
			t.Fatalf("reopened Entries() = %v, want %v (YAML re-seeds on the next start)", got, want)
		}
	})
}

// TestPersistWritesOnlyRuntimeEntries 持久化文件只承载运行期条目：静态种子不进盘
// （YAML 始终是它自己条目的唯一事实源，从 YAML 删除条目在重启后即刻生效）。
func TestPersistWritesOnlyRuntimeEntries(t *testing.T) {
	dir := t.TempDir()
	s := mustOpen(t, dir, []string{"yaml-only"}, io.Discard)
	if err := s.Add("runtime"); err != nil {
		t.Fatalf("Add error = %v", err)
	}
	var doc struct {
		SchemaVersion int      `json:"schema_version"`
		Entries       []string `json:"entries"`
	}
	if err := json.Unmarshal(readFile(t, dir), &doc); err != nil {
		t.Fatalf("persisted file invalid: %v", err)
	}
	if doc.SchemaVersion != SchemaVersion {
		t.Fatalf("schema_version = %d, want %d", doc.SchemaVersion, SchemaVersion)
	}
	if !slices.Equal(doc.Entries, []string{"runtime"}) {
		t.Fatalf("persisted entries = %v, want [runtime] (the YAML seed must not be persisted)", doc.Entries)
	}
}

// TestFilePermissionsAre0600 每次写入之后文件权限都是 0600。
func TestFilePermissionsAre0600(t *testing.T) {
	dir := t.TempDir()
	s := mustOpen(t, dir, nil, io.Discard)
	if err := s.Add("first"); err != nil {
		t.Fatalf("Add error = %v", err)
	}
	assertMode0600(t, storeFile(dir))
	if err := s.Add("second"); err != nil {
		t.Fatalf("Add error = %v", err)
	}
	assertMode0600(t, storeFile(dir))
	if err := s.Remove("first"); err != nil {
		t.Fatalf("Remove error = %v", err)
	}
	assertMode0600(t, storeFile(dir))
}

func assertMode0600(t *testing.T, path string) {
	t.Helper()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat %s: %v", path, err)
	}
	if got := info.Mode().Perm(); got != 0o600 {
		t.Fatalf("%s mode = %o, want 600", path, got)
	}
}

// TestAtomicWriteLeavesNoTempFiles 原子性：成功写入不留下 temp 残骸，文件始终是
// 完整 JSON；写入失败（目标路径是目录）时不产生半截文件、不留下 temp、内存状态
// 不变（回滚），清理后仍可恢复。
func TestAtomicWriteLeavesNoTempFiles(t *testing.T) {
	t.Run("success_leaves_no_temp", func(t *testing.T) {
		dir := t.TempDir()
		s := mustOpen(t, dir, nil, io.Discard)
		for _, entry := range []string{"a", "b", "c"} {
			if err := s.Add(entry); err != nil {
				t.Fatalf("Add(%s) error = %v", entry, err)
			}
		}
		if got := tempFiles(t, dir); len(got) != 0 {
			t.Fatalf("temp files left behind: %v", got)
		}
		var doc struct {
			Entries []string `json:"entries"`
		}
		if err := json.Unmarshal(readFile(t, dir), &doc); err != nil {
			t.Fatalf("persisted file is torn/incomplete: %v", err)
		}
		if !slices.Equal(doc.Entries, []string{"a", "b", "c"}) {
			t.Fatalf("persisted entries = %v", doc.Entries)
		}
	})

	t.Run("rename_failure_rolls_back_and_cleans_temp", func(t *testing.T) {
		dir := t.TempDir()
		s := mustOpen(t, dir, nil, io.Discard)
		// 目标路径被一个目录占据 → rename 必然失败。
		if err := os.Mkdir(storeFile(dir), 0o700); err != nil {
			t.Fatalf("mkdir %s: %v", storeFile(dir), err)
		}
		err := s.Add("doomed")
		if err == nil {
			t.Fatal("Add succeeded although the target path is a directory")
		}
		if got := s.Entries(); len(got) != 0 {
			t.Fatalf("Entries() = %v, want empty after a failed persist (in-memory rollback)", got)
		}
		if got := tempFiles(t, dir); len(got) != 0 {
			t.Fatalf("temp files left behind after a failed persist: %v", got)
		}
		// 显式恢复路径：清掉占位目录后，同一 store 仍可写入。
		if err := os.Remove(storeFile(dir)); err != nil {
			t.Fatalf("remove placeholder dir: %v", err)
		}
		if err := s.Add("doomed"); err != nil {
			t.Fatalf("Add after recovery error = %v", err)
		}
		if got, want := mustOpen(t, dir, nil, io.Discard).Entries(), []string{"doomed"}; !slices.Equal(got, want) {
			t.Fatalf("Entries() after recovery = %v, want %v", got, want)
		}
	})
}

// TestEntriesReturnsAnIndependentCopy 调用方改写返回值不得影响 store 内部状态
// （detector 与端点共享同一实例）。
func TestEntriesReturnsAnIndependentCopy(t *testing.T) {
	s := mustOpen(t, t.TempDir(), []string{"a"}, io.Discard)
	got := s.Entries()
	got[0] = "mutated"
	if again := s.Entries(); !slices.Equal(again, []string{"a"}) {
		t.Fatalf("Entries() = %v, want [a] (a caller mutated the returned slice)", again)
	}
}

// TestDegradationWarningsAreExplicit 每种加载失败都必须产生一条显式、可检索的
// 告警（含稳定前缀），不得静默。
func TestDegradationWarningsAreExplicit(t *testing.T) {
	cases := []struct {
		name string
		raw  string
		sub  string
	}{
		{name: "version_mismatch", raw: `{"schema_version":999,"entries":[]}`, sub: "schema_version 999"},
		{name: "corrupt_json", raw: `{"schema_version":1,`, sub: "corrupt"},
		{name: "control_character", raw: `{"schema_version":1,"entries":["a\u0001b"]}`, sub: "control characters"},
		{name: "empty_entry", raw: `{"schema_version":1,"entries":[""]}`, sub: "must not be empty"},
		{name: "overlong_entry", raw: `{"schema_version":1,"entries":["` + strings.Repeat("x", maxEntryBytes+1) + `"]}`, sub: "at most 4096 bytes"},
		{name: "wrong_top_level_shape", raw: `["a"]`, sub: "corrupt"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			writeRaw(t, dir, tc.raw)
			var warn bytes.Buffer
			s := mustOpen(t, dir, nil, &warn)
			if got := s.Entries(); len(got) != 0 {
				t.Fatalf("Entries() = %v, want empty", got)
			}
			if !strings.Contains(warn.String(), "tokenhush: allowlist:") {
				t.Fatalf("warning %q lacks the stable prefix", warn.String())
			}
			if !strings.Contains(warn.String(), tc.sub) {
				t.Fatalf("warning %q does not mention %q", warn.String(), tc.sub)
			}
		})
	}
}

// TestInvalidSeedEntriesAreDroppedWithWarning 静态种子中的非法条目被丢弃并告警：
// Open 不得因此失败（config 层已校验，这里是防御性第二道）。
func TestInvalidSeedEntriesAreDroppedWithWarning(t *testing.T) {
	dir := t.TempDir()
	var warn bytes.Buffer
	s := mustOpen(t, dir, []string{"good", "", "a\x00b", strings.Repeat("x", maxEntryBytes+1)}, &warn)
	if got, want := s.Entries(), []string{"good"}; !slices.Equal(got, want) {
		t.Fatalf("Entries() = %v, want %v", got, want)
	}
	if !strings.Contains(warn.String(), "static allowlist entry") {
		t.Fatalf("warning %q does not mention the dropped static entry", warn.String())
	}
}

// TestYAMLOnlyEntryStillSuppressesRedaction 并集语义的行为化锁定：仅存在于
// tokenhush.yaml（种子）的条目被导入 store，且经检测器路径仍然抑制脱敏。
// 三条断言互相咬合：① 种子确实进了 store（Entries() 含它 → 仅靠 store 来源也
// 生效）；② 完整并集接缝（WithAllowlist + WithAllowlistSource）抑制 finding；
// ③ 防空对照：同一密钥不在白名单时确实被检出。
func TestYAMLOnlyEntryStillSuppressesRedaction(t *testing.T) {
	entry := testEntry()
	dir := t.TempDir()
	s := mustOpen(t, dir, []string{entry}, io.Discard)
	content := "value=" + entry + " end"

	t.Run("seed_is_imported_into_the_store", func(t *testing.T) {
		if !slices.Contains(s.Entries(), entry) {
			t.Fatalf("Entries() = %v, want it to contain the YAML-only entry %q", s.Entries(), entry)
		}
		if _, err := os.Stat(storeFile(dir)); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("the YAML-only seed must not require a persisted file (stat err=%v)", err)
		}
	})

	t.Run("store_source_alone_suppresses", func(t *testing.T) {
		det := redact.NewPrefixDetector(redact.WithAllowlistSource(s.Entries))
		if got := findings(t, det, docOf(content)); len(got) != 0 {
			t.Fatalf("findings = %#v, want none (the seed must be visible through the store source)", got)
		}
	})

	t.Run("full_union_options_suppress", func(t *testing.T) {
		det := redact.NewPrefixDetector(
			redact.WithAllowlist(entry), // tokenhush.yaml 的静态键继续被直接读取
			redact.WithAllowlistSource(s.Entries),
		)
		if got := findings(t, det, docOf(content)); len(got) != 0 {
			t.Fatalf("findings = %#v, want none", got)
		}
	})

	t.Run("control_same_key_is_detected_without_the_entry", func(t *testing.T) {
		det := redact.NewPrefixDetector()
		got := findings(t, det, docOf("value="+testSecret()+" end"))
		if len(got) != 1 {
			t.Fatalf("findings = %#v, want exactly 1 (the detector must actually match this key)", got)
		}
	})
}
