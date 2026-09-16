package redact

import (
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/fregie/tokenhush/pkg/extension"
)

// 本文件锁定 W5.2 的冻结契约与运行期替换的并发安全性：
//
//   - TestAllowlistHotSwap 用有界的并发读 + 反复替换证明：来源在请求期被读成
//     "单一快照"，观察到的 finding 集合必须与**某一个**已发布快照逐条一致，绝不能
//     出现两次快照的并集（torn state）；且每个快照都必须真实可见（替换确实生效）。
//   - TestUnionAllowlistFastPath 钉住空来源的快路径：不重建 Allowlist、零分配，
//     且并集语义逐条不变。
//
// 两个测试都是固定迭代 + sync.WaitGroup 的有界结构：无界并发（W2 fix round 的
// 教训）会在 -race 下把整个包拖成不确定的慢测试。

// hotSwapSnapshot 是发布到共享句柄上的一份白名单快照。want 是该快照下 detector
// 应当给出的 finding 集合（预先算好，避免并发期做期望推导）。
type hotSwapSnapshot struct {
	name     string
	literals []string
	want     []span
	bit      uint32
}

// hotSwapSource 模拟生产接缝（allowlist.Store.Entries 的角色）：一个可被原子
// 替换的共享句柄，request goroutine 通过 WithAllowlistSource 读取它的当前值。
type hotSwapSource struct {
	cur atomic.Pointer[hotSwapSnapshot]
}

// publish 原子发布一份新快照。
func (s *hotSwapSource) publish(snap *hotSwapSnapshot) { s.cur.Store(snap) }

// read 是传给 WithAllowlistSource 的来源函数：每次 Inspect 读一次当前快照。
func (s *hotSwapSource) read() []string {
	snap := s.cur.Load()
	if snap == nil {
		return nil
	}
	return snap.literals
}

// 有界参数：读者最多这么多轮、写者最多这么多圈、握手自旋有上限——整个测试的
// 工作量是常数，-race 下也快速收敛（覆盖一旦达成读者立即退出）。
const (
	hotSwapReaders          = 4
	hotSwapReaderIterations = 4000
	// hotSwapReaderMinIterations 是每个读者在允许按覆盖提前退出前的最少观察轮数：
	// 保证读者与写者的替换仍然充分重叠（覆盖本身由握手确定性达成）。
	hotSwapReaderMinIterations = 32
	hotSwapWriterCycles        = 8
	hotSwapWaitSpins           = 20000
)

// waitForHotSwapBit 有界自旋等待某个快照被观察到（让写者按快照逐个推进，使覆盖
// 是确定性结果而不是概率结果）。超时即返回 false，由调用方的最终断言报错。
func waitForHotSwapBit(mask *atomic.Uint32, bit uint32, spins int) bool {
	for i := 0; i < spins; i++ {
		if mask.Load()&bit != 0 {
			return true
		}
		runtime.Gosched()
	}
	return mask.Load()&bit != 0
}

// observeHotSwapSnapshot 在已发布快照里为本次观察找到唯一匹配项，命中的快照位
// 置 1；无匹配返回 false（这正是"torn / union of two snapshots"的判据）。
func observeHotSwapSnapshot(got []extension.Finding, snapshots []hotSwapSnapshot, mask *atomic.Uint32) bool {
	for i := range snapshots {
		if hotSwapFindingsMatch(got, snapshots[i].want) {
			mask.Or(snapshots[i].bit)
			return true
		}
	}
	return false
}

// hotSwapFindingsMatch 断言 finding 的形状与期望逐条一致（leaf、起止都相同）。
func hotSwapFindingsMatch(got []extension.Finding, want []span) bool {
	if len(got) != len(want) {
		return false
	}
	for i, w := range want {
		if got[i].LeafIndex != 0 || got[i].Start != w.start || got[i].End != w.end {
			return false
		}
	}
	return true
}

// runHotSwap 驱动"并发读 + 反复替换"：static 是构造期字面量（可为空），
// snapshots 是写者反复发布的快照序列。读到的 finding 集合必须匹配某一个快照；
// join 后断言每个快照都被观察到（替换确实生效，防"来源恒返回第一份"的假通过）。
func runHotSwap(t *testing.T, static []string, content string, snapshots []hotSwapSnapshot) {
	t.Helper()

	opts := make([]Option, 0, 2)
	if len(static) > 0 {
		opts = append(opts, WithAllowlist(static...))
	}
	src := &hotSwapSource{}
	opts = append(opts, WithAllowlistSource(src.read))
	det := NewEmailDetector(opts...)
	doc := docOf(extension.RequestContent, content)

	var (
		wg           sync.WaitGroup
		start        = make(chan struct{})
		mask         atomic.Uint32
		observations atomic.Uint64
		all          uint32
	)
	for i := range snapshots {
		all |= snapshots[i].bit
	}

	// 写者：反复原子替换共享快照，并按快照逐个等待其被观察到。
	wg.Add(1)
	go func() {
		defer wg.Done()
		<-start
		for cycle := 0; cycle < hotSwapWriterCycles && mask.Load() != all; cycle++ {
			for i := range snapshots {
				src.publish(&snapshots[i])
				waitForHotSwapBit(&mask, snapshots[i].bit, hotSwapWaitSpins)
			}
		}
	}()

	// 读者：并发 Inspect；每次观察必须与某一个已发布快照一致。
	for r := 0; r < hotSwapReaders; r++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			for i := 0; i < hotSwapReaderIterations &&
				(i < hotSwapReaderMinIterations || mask.Load() != all); i++ {
				got, err := det.Inspect(doc)
				if err != nil {
					t.Errorf("Inspect() error = %v", err)
					return
				}
				if !observeHotSwapSnapshot(got, snapshots, &mask) {
					t.Errorf("findings = %#v 与任何已发布快照都不一致：观察到 torn/union 状态（快照替换不是原子的）", got)
					return
				}
				observations.Add(1)
			}
		}()
	}

	close(start)
	wg.Wait()

	t.Logf("并发观察 %d 次，快照位 = %#b，want %#b（每次观察都与某一份已发布快照逐条一致）",
		observations.Load(), mask.Load(), all)
	if got := mask.Load(); got != all {
		t.Fatalf("观察到快照位 = %#b，want %#b：热替换未生效（每个已发布快照都必须可见）", got, all)
	}
}

// TestAllowlistHotSwap 证明运行期替换共享快照是原子的：并发读者的每次
// Inspect 只看到一个快照；"两份快照的并集"这一 torn 状态被判为失败。
func TestAllowlistHotSwap(t *testing.T) {
	const (
		x = "hotswap-alpha@example.com"
		y = "hotswap-beta@example.com"
	)

	t.Run("literal_snapshots_never_tear", func(t *testing.T) {
		// 文档里两个邮箱：x 与 y 各由 1 份快照放行；没有快照能同时放行两者，
		// 因此"两个 finding 都不见了"就是并集（torn）的直接证据。
		content := "alpha " + x + " beta " + y
		spanX := spanIn(t, content, x)
		spanY := spanIn(t, content, y)
		runHotSwap(t, nil, content, []hotSwapSnapshot{
			{name: "x_only", literals: []string{x}, want: []span{spanY}, bit: 1},
			{name: "y_only", literals: []string{y}, want: []span{spanX}, bit: 2},
			{name: "empty_source", literals: nil, want: []span{spanX, spanY}, bit: 4},
		})
	})

	t.Run("static_literals_are_never_replaced_by_the_source", func(t *testing.T) {
		// 静态字面量 x 在每份快照下都必须继续生效（并集，绝不替换）：来源给 y
		// 时 x、y 都被抑制（0 finding）；来源为空时只有 x 被抑制（1 finding: y）。
		// "x 被报出来" = 来源替换掉了静态集合，"两个都被报出来" = 未做并集。
		content := "alpha " + x + " beta " + y
		spanY := spanIn(t, content, y)
		runHotSwap(t, []string{x}, content, []hotSwapSnapshot{
			{name: "source_y", literals: []string{y}, want: nil, bit: 1},
			{name: "source_empty", literals: nil, want: []span{spanY}, bit: 2},
		})
	})
}

// hotSwapSink 强制 unionAllowlist 的返回值逃逸，使 AllocsPerRun 量到的是真实
// 分配而不是被编译器消除的调用。
var hotSwapSink *Allowlist

// TestUnionAllowlistFastPath 钉住空来源快路径：来源没有任何运行期字面量时直接
// 复用（不可变的）静态 Allowlist，不重建、零分配；并集语义与字面量清洗逐条不变。
func TestUnionAllowlistFastPath(t *testing.T) {
	static := NewAllowlist("a@x.co", "b@x.co")

	t.Run("nil_static_and_empty_source_stay_nil", func(t *testing.T) {
		if got := unionAllowlist(nil, nil); got != nil {
			t.Fatalf("unionAllowlist(nil, nil) = %#v，want nil", got)
		}
	})

	t.Run("empty_source_reuses_the_static_allowlist", func(t *testing.T) {
		for _, runtime := range [][]string{nil, {}} {
			if got := unionAllowlist(static, runtime); got != static {
				t.Fatalf("unionAllowlist(static, %#v) 重建了 Allowlist（%p != %p），want 直接复用静态快照",
					runtime, got, static)
			}
		}
	})

	t.Run("non_empty_source_still_unions_and_suppresses", func(t *testing.T) {
		got := unionAllowlist(static, []string{"c@x.co"})
		if got == static {
			t.Fatal("非空来源被当成了空来源：并集没有生效")
		}
		content := "a@x.co b@x.co c@x.co d@x.co"
		for _, lit := range []string{"a@x.co", "b@x.co", "c@x.co"} {
			at := strings.Index(content, lit)
			if at < 0 {
				t.Fatalf("夹具缺少 %q", lit)
			}
			if !got.suppresses([]byte(content), at, at+len(lit)) {
				t.Errorf("并集未抑制 %q（静态 ∪ 运行期都必须生效）", lit)
			}
		}
		const notListed = "d@x.co"
		at := strings.Index(content, notListed)
		if got.suppresses([]byte(content), at, at+len(notListed)) {
			t.Errorf("未列出的字面量 %q 被抑制了", notListed)
		}
	})

	t.Run("empty_literals_from_the_source_are_still_dropped", func(t *testing.T) {
		got := unionAllowlist(static, []string{"", "", "c@x.co", ""})
		if got == nil || len(got.literals) != 3 {
			t.Fatalf("unionAllowlist 保留的字面量 = %#v，want 3 条（空串丢弃）", got.literals)
		}
	})

	t.Run("fast_path_allocates_nothing_and_the_rebuild_is_measurable", func(t *testing.T) {
		runtimeLiterals := []string{"c@x.co"}
		fast := testing.AllocsPerRun(1000, func() { hotSwapSink = unionAllowlist(static, nil) })
		if fast != 0 {
			t.Fatalf("空来源快路径每次分配 %.1f 次，want 0（不应重建）", fast)
		}
		slow := testing.AllocsPerRun(1000, func() { hotSwapSink = unionAllowlist(static, runtimeLiterals) })
		if slow < 1 {
			t.Fatalf("非空来源每次分配 %.1f 次，want ≥ 1：测量没有观察到重建", slow)
		}
	})
}
