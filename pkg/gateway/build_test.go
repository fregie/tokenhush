package gateway

import (
	"bytes"
	"fmt"
	"strings"
	"sync"
	"testing"

	"github.com/fregie/tokenhush/pkg/config"
	"github.com/fregie/tokenhush/pkg/protocol"
	"github.com/fregie/tokenhush/pkg/proxy"
)

// fakeAllowlistStore 是 AllowlistStore 的内存测试替身：种子 + 运行期增删，并记录
// Entries 调用次数，用来证明检测器在请求期读取的是同一实例而非构造期拷贝。
type fakeAllowlistStore struct {
	mu         sync.Mutex
	entries    []string
	entryCalls int
}

var _ AllowlistStore = (*fakeAllowlistStore)(nil)

func newFakeAllowlistStore(seed ...string) *fakeAllowlistStore {
	return &fakeAllowlistStore{entries: append([]string(nil), seed...)}
}

func (s *fakeAllowlistStore) Entries() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.entryCalls++
	return append([]string(nil), s.entries...)
}

func (s *fakeAllowlistStore) Add(entry string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.entries = append(s.entries, entry)
	return nil
}

func (s *fakeAllowlistStore) Remove(entry string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i, e := range s.entries {
		if e == entry {
			s.entries = append(s.entries[:i], s.entries[i+1:]...)
			return nil
		}
	}
	return fmt.Errorf("fake allowlist store: entry %q not found", entry)
}

func (s *fakeAllowlistStore) entryCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.entryCalls
}

// allBuiltinDetectorIDs 返回六个内建检测器的 canonical id。
func allBuiltinDetectorIDs() []string {
	return []string{
		config.DetectorPrefix,
		config.DetectorHighEntropy,
		config.DetectorJWT,
		config.DetectorPrivateKey,
		config.DetectorLuhn,
		config.DetectorEmail,
	}
}

// seamTestKey 在运行期拼接，避免提交中出现连续的密钥字面量（gitleaks）。
func seamTestKey() string {
	return strings.Join([]string{"sk-", "proj-", strings.Repeat("T3stOnly", 2), "Key012"}, "")
}

// mustBuildPipeline 构建 pipeline；任一步失败直接 fail（registry 是安全门，
// 注册失败必须中止启动而非跳过）。
func mustBuildPipeline(t *testing.T, opts BuildOptions) *proxy.Pipeline {
	t.Helper()
	pipe, err := BuildPipeline(opts)
	if err != nil {
		t.Fatalf("BuildPipeline() error = %v", err)
	}
	if pipe == nil {
		t.Fatal("BuildPipeline() 返回 nil pipeline")
	}
	return pipe
}

// mustTransformRequest 走真实请求路径；错误即 fail（本测试的用例都不允许出现
// BlockedError）。
func mustTransformRequest(t *testing.T, pipe *proxy.Pipeline, body []byte) []byte {
	t.Helper()
	out, err := pipe.RequestTransform()(body)
	if err != nil {
		t.Fatalf("RequestTransform(%s) error = %v", body, err)
	}
	return out
}

// assertRedacted 断言密文不再出现且确实生成了占位符（不静默放行）。
func assertRedacted(t *testing.T, out []byte, secret string) {
	t.Helper()
	if bytes.Contains(out, []byte(secret)) {
		t.Fatalf("输出仍含明文 %q：%s", secret, out)
	}
	if !bytes.Contains(out, []byte(protocol.PlaceholderPrefix)) {
		t.Fatalf("输出未生成占位符 %q：%s", protocol.PlaceholderPrefix, out)
	}
}

// TestDetectorOptionsNilStoreKeepsLegacyShape 直接锁定「store == nil 时
// detectorOptions 与接缝引入前逐项一致」：空 allowlist 返回 nil，非空只返回
// WithAllowlist；只有非 nil store 才追加运行期来源。
func TestDetectorOptionsNilStoreKeepsLegacyShape(t *testing.T) {
	store := newFakeAllowlistStore()
	cases := []struct {
		name      string
		allowlist []string
		store     AllowlistStore
		want      int // 负数表示期望返回 nil（区分 nil 与空切片）
	}{
		{name: "nil_store_empty_allowlist_returns_nil", want: -1},
		{name: "nil_store_with_allowlist_returns_one_option", allowlist: []string{"a"}, want: 1},
		{name: "store_without_allowlist_returns_source_only", store: store, want: 1},
		{name: "store_with_allowlist_returns_both", allowlist: []string{"a"}, store: store, want: 2},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := detectorOptions(tc.allowlist, tc.store)
			if tc.want < 0 {
				if got != nil {
					t.Fatalf("detectorOptions(%v, nil) = %#v，want nil（零值必须与接缝前一致）", tc.allowlist, got)
				}
				return
			}
			if len(got) != tc.want {
				t.Fatalf("detectorOptions(%v, store=%v) 返回 %d 个 Option，want %d",
					tc.allowlist, tc.store != nil, len(got), tc.want)
			}
		})
	}
}

// TestPipelineObservesStoreUpdates 证明 BuildPipeline 把 store 实例（而非构造期
// 拷贝）接给了每个 detector：同一进程内 store.Add 之后立即生效，Remove 之后立即
// 恢复。断言基于真实 pipeline 的请求改写结果（占位符出现/消失），不是 mock。
func TestPipelineObservesStoreUpdates(t *testing.T) {
	key := seamTestKey()
	wrapper := "keep." + key + ".keep"
	body := []byte(`{"payload":"` + wrapper + `"}`)

	store := newFakeAllowlistStore()
	pipe := mustBuildPipeline(t, BuildOptions{
		Detectors:      allBuiltinDetectorIDs(),
		Allowlist:      []string{"static-literal"},
		AllowlistStore: store,
		Tool:           "w0.3-test",
	})

	t.Run("redacted_before_store_add", func(t *testing.T) {
		assertRedacted(t, mustTransformRequest(t, pipe, body), key)
	})

	t.Run("detector_observes_store_add_in_process", func(t *testing.T) {
		if err := store.Add(wrapper); err != nil {
			t.Fatalf("store.Add(%q) error = %v", wrapper, err)
		}
		out := mustTransformRequest(t, pipe, body)
		if !bytes.Equal(out, body) {
			t.Fatalf("store.Add 之后期望整段逐字节放行，got %s", out)
		}
		if store.entryCount() == 0 {
			t.Fatal("检测器在请求期未调用 store.Entries（说明读到的是构造期拷贝而非共享句柄）")
		}
	})

	t.Run("redacted_again_after_store_remove", func(t *testing.T) {
		if err := store.Remove(wrapper); err != nil {
			t.Fatalf("store.Remove(%q) error = %v", wrapper, err)
		}
		assertRedacted(t, mustTransformRequest(t, pipe, body), key)
	})
}

// TestBuildPipelineNilStoreKeepsStaticOnly 锁定零值安全默认：nil store 退化为
// 「仅静态白名单」——构造时不额外接线任何来源，且不放行未被白名单覆盖的密钥
// （不静默放行）。逐字节比对只用「无 finding 的请求」：有 finding 时占位符含
// 每 pipeline 随机盐，天然不可跨实例比较。
func TestBuildPipelineNilStoreKeepsStaticOnly(t *testing.T) {
	key := seamTestKey()
	storeOnly := "keep." + key + ".keep"
	suppressed := "covered." + key + ".covered"

	baseline := mustBuildPipeline(t, BuildOptions{
		Detectors: allBuiltinDetectorIDs(),
		Allowlist: []string{suppressed},
		Tool:      "w0.3-test",
	})
	withNil := mustBuildPipeline(t, BuildOptions{
		Detectors:      allBuiltinDetectorIDs(),
		Allowlist:      []string{suppressed},
		AllowlistStore: nil,
		Tool:           "w0.3-test",
	})

	// 无 finding 的请求：两者逐字节一致，且原样放行。
	quietBody := []byte(`{"payload":"` + suppressed + `"}`)
	outBaseline := mustTransformRequest(t, baseline, quietBody)
	outNil := mustTransformRequest(t, withNil, quietBody)
	if !bytes.Equal(outBaseline, outNil) {
		t.Fatalf("nil store 与不传 store 的基线输出不一致：\nbaseline = %s\nnil      = %s", outBaseline, outNil)
	}
	if !bytes.Equal(outNil, quietBody) {
		t.Fatalf("静态 Allowlist 覆盖的请求期望原样放行，got %s", outNil)
	}

	// 不静默放行 + 不承认 store 字面量：body 只有「store 才会知道的字面量」，
	// nil store 下没有任何来源提供它，密钥必须在两条 pipeline 上都被脱敏。
	secretBody := []byte(`{"payload":"` + storeOnly + `"}`)
	assertRedacted(t, mustTransformRequest(t, withNil, secretBody), key)
	assertRedacted(t, mustTransformRequest(t, baseline, secretBody), key)

	// 对照（防空断言）：同一字面量经静态 Allowlist 传入时确实生效，说明上面的
	// 脱敏不是因为「流程失效」，而是 nil store 不承认任何 store 字面量。
	viaStatic := mustBuildPipeline(t, BuildOptions{
		Detectors: allBuiltinDetectorIDs(),
		Allowlist: []string{storeOnly},
		Tool:      "w0.3-test",
	})
	if out := mustTransformRequest(t, viaStatic, secretBody); !bytes.Equal(out, secretBody) {
		t.Fatalf("静态 Allowlist 未放行：%s", out)
	}
}

// TestBuildPipelineZeroSelfProtectionIsNoop 锁定 SelfProtectionConfig 零值 =
// 与完全不传 SelfProtection 逐字节等价（构造成功、不 panic、请求输出一致）。
// 比对用的是「无 finding 的请求」（有 finding 时占位符含每 pipeline 随机盐，
// 天然不可逐字节比较）；另用含密钥的请求断言零值只关闭 C8 接缝，绝不关闭常规
// 脱敏。W0.3 只承载，不实现任何拦截。
func TestBuildPipelineZeroSelfProtectionIsNoop(t *testing.T) {
	suppressed := "keep." + seamTestKey() + ".keep"
	quietBodies := [][]byte{
		[]byte(`{"payload":"hello world"}`),
		[]byte(`{"payload":"` + suppressed + `"}`),
	}
	without := mustBuildPipeline(t, BuildOptions{
		Detectors: allBuiltinDetectorIDs(),
		Allowlist: []string{suppressed},
		Tool:      "w0.3-test",
	})
	zero := mustBuildPipeline(t, BuildOptions{
		Detectors:      allBuiltinDetectorIDs(),
		Allowlist:      []string{suppressed},
		SelfProtection: SelfProtectionConfig{},
		Tool:           "w0.3-test",
	})
	for i, body := range quietBodies {
		outWithout := mustTransformRequest(t, without, body)
		outZero := mustTransformRequest(t, zero, body)
		if !bytes.Equal(outWithout, outZero) {
			t.Fatalf("零值 SelfProtection 改变了请求 %d 的输出：\nwithout = %s\nzero    = %s", i, outWithout, outZero)
		}
		if !bytes.Equal(outZero, body) {
			t.Fatalf("零值 SelfProtection 请求 %d 期望原样放行，got %s", i, outZero)
		}
	}

	assertRedacted(t, mustTransformRequest(t, zero, []byte(`{"payload":"`+seamTestKey()+`"}`)), seamTestKey())

	// 非零配置在 W0.3 也只被承载（没有任何拦截实现）：构造必须成功且不 panic。
	_ = mustBuildPipeline(t, BuildOptions{
		Detectors: allBuiltinDetectorIDs(),
		Tool:      "w0.3-test",
		SelfProtection: SelfProtectionConfig{
			Enabled:      true,
			Modes:        []string{"cli-command"},
			Exclusions:   [][]byte{[]byte("excluded-value")},
			ControlToken: "control-token-value",
		},
	})
}
