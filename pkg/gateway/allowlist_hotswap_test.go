package gateway

import (
	"bytes"
	"errors"
	"io"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/fregie/tokenhush/pkg/allowlist"
)

// 生产接缝（W5.2）：BuildOptions.AllowlistStore → detectorOptions →
// redact.WithAllowlistSource(store.Entries)（build.go:85-114）。本测试用真实
// allowlist.Store + 真实 BuildPipeline 证明：并发 Add/Remove 与请求期读取共享
// 快照之间无数据竞争，且每次变换只看到 store 的某一个当前快照——绝不会看到
// 两个先后快照的并集（torn state）。
//
// 放在 pkg/gateway 的理由：被测的接线本身在 pkg/gateway（build.go 的
// AllowlistStore → Option 映射），而 pkg/allowlist 以结构化方式满足
// gateway.AllowlistStore、从不 import pkg/gateway（ADR-0012 A2），故此处
// import pkg/allowlist 不构成环。
//
// 有界：写者固定圈数、读者固定轮数、握手自旋有上限，全部由 sync.WaitGroup
// 收敛（W2 fix round 的教训：无界并发会把 -race 拖成不确定的慢测试）。
const (
	allowlistHotSwapReaders      = 4
	allowlistHotSwapReaderMax    = 16
	allowlistHotSwapWriterCycles = 6
	allowlistHotSwapWaitSpins    = 200000
)

// allowlistHotSwapClass 是 store 三种状态在出站 body 上的可观察类别。
const (
	classXOnly   uint32 = 1 << iota // store 仅放行 x
	classYOnly                      // store 仅放行 y
	classNeither                    // store 为空：两个都被脱敏
)

// waitForAllowlistClass 有界自旋等待某一类别被观察到，让写者按状态逐个推进，
// 使覆盖成为确定性结果而不是概率结果。超时返回 false，由最终断言报错。
func waitForAllowlistClass(mask *atomic.Uint32, class uint32) bool {
	for i := 0; i < allowlistHotSwapWaitSpins; i++ {
		if mask.Load()&class != 0 {
			return true
		}
		runtime.Gosched()
	}
	return mask.Load()&class != 0
}

// TestAllowlistStoreHotSwap 在真实装配上并发地 Add/Remove 白名单条目并变换请求：
// 每次输出必须与 store 的某一个当前快照一致（"两个白名单字面量同时出现"是并集
// torn 状态的直接证据，判失败）；join 后再断言三种状态都真实出现过，防止"条目
// 永远不生效"式的假通过。
func TestAllowlistStoreHotSwap(t *testing.T) {
	const (
		x = "hotswap-alpha@example.com"
		y = "hotswap-beta@example.com"
	)
	body := []byte(`{"model":"test","messages":[{"role":"user","content":"alpha ` + x + ` beta ` + y + `"}]}`)

	store, err := allowlist.Open(t.TempDir(), nil, io.Discard)
	if err != nil {
		t.Fatalf("allowlist.Open: %v", err)
	}
	pipe := mustBuildPipeline(t, BuildOptions{
		Detectors:      allBuiltinDetectorIDs(),
		AllowlistStore: store,
		Tool:           "w5.2-hot-swap",
	})
	transform := pipe.RequestTransform()

	var (
		wg           sync.WaitGroup
		start        = make(chan struct{})
		mask         atomic.Uint32
		observations atomic.Uint64
		all          = classXOnly | classYOnly | classNeither
	)

	// 写者：沿 {x} → {y} → {} 循环，且**每次转移都经过 {}**（先移除旧条目再新增
	// 新条目），因此 store 永远不会同时持有 x 与 y——"两个都放行"只可能来自撕裂的
	// 快照读，C7 语义下不可出现。
	wg.Add(1)
	go func() {
		defer wg.Done()
		<-start
		set := func(entry string, add bool) {
			var err error
			if add {
				err = store.Add(entry)
				if errors.Is(err, allowlist.ErrDuplicate) {
					err = nil
				}
			} else {
				err = store.Remove(entry)
				if errors.Is(err, allowlist.ErrNotFound) {
					err = nil
				}
			}
			if err != nil {
				t.Errorf("store mutation (%s, add=%v) error = %v", entry, add, err)
			}
		}
		for cycle := 0; cycle < allowlistHotSwapWriterCycles && mask.Load() != all; cycle++ {
			set(y, false)
			set(x, true)
			waitForAllowlistClass(&mask, classXOnly)

			set(x, false)
			set(y, true)
			waitForAllowlistClass(&mask, classYOnly)

			set(y, false)
			waitForAllowlistClass(&mask, classNeither)
		}
	}()

	for r := 0; r < allowlistHotSwapReaders; r++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			for i := 0; i < allowlistHotSwapReaderMax && mask.Load() != all; i++ {
				out, err := transform(body)
				if err != nil {
					t.Errorf("RequestTransform() error = %v", err)
					return
				}
				hasX := bytes.Contains(out, []byte(x))
				hasY := bytes.Contains(out, []byte(y))
				switch {
				case hasX && hasY:
					t.Errorf("输出同时携带两个白名单字面量：读到了两个 store 快照的并集（torn state）：%s", out)
					return
				case hasX:
					mask.Or(classXOnly)
				case hasY:
					mask.Or(classYOnly)
				default:
					mask.Or(classNeither)
				}
				observations.Add(1)
			}
		}()
	}

	close(start)
	wg.Wait()

	t.Logf("并发变换 %d 次，store 快照类别位 = %#b，want %#b（每次输出都与某一份 store 快照一致）",
		observations.Load(), mask.Load(), all)
	if got := mask.Load(); got != all {
		t.Fatalf("观察到的 store 快照类别 = %#b，want %#b：热生效未发生（Add/Remove 必须在请求期可见）", got, all)
	}
	if n := pipe.EgressBlocks(); n != 0 {
		t.Errorf("并发期间出站复核阻断 %d 次，want 0（白名单放行的明文由 C7 豁免，见 egressSecretsVisibleInBody）", n)
	}

	// 并发结束后的确定性断言：store 的当前状态驱动出站内容（也是覆盖断言的对照）。
	if err := store.Add(x); err != nil && !errors.Is(err, allowlist.ErrDuplicate) {
		t.Fatalf("store.Add(%q) after join: %v", x, err)
	}
	out := mustTransformRequest(t, pipe, body)
	if !bytes.Contains(out, []byte(x)) || bytes.Contains(out, []byte(y)) {
		t.Fatalf("store {x} 下输出 = %s，want 只放行 x", out)
	}
	if err := store.Remove(x); err != nil && !errors.Is(err, allowlist.ErrNotFound) {
		t.Fatalf("store.Remove(%q) after join: %v", x, err)
	}
	out = mustTransformRequest(t, pipe, body)
	if bytes.Contains(out, []byte(x)) || bytes.Contains(out, []byte(y)) {
		t.Fatalf("store {} 下输出 = %s，want 两个都被脱敏", out)
	}
}
