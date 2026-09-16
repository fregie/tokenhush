package redact

// WithAllowlistSource 设置运行期白名单来源（W5.2 冻结的共享快照接缝）。
//
// 契约（ADR-0012 A2，均为逐字节行为契约，实现细节不得改变它们）：
//
//   - **请求期读取**：fn 在每次 Inspect 时被调用一次，本次 Inspect 的全部
//     finding 共用这一次取值，因此 detector 构造之后仍可热替换有效集合，无需
//     重建 detector。
//   - **并集，绝不替换**：有效字面量集合 = 静态 WithAllowlist 字面量 ∪ fn() 的
//     当前返回值。来源给什么都无法移除静态集合里的条目。
//   - **快照性**：一次 Inspect 只看到来源的**某一个**当前值，绝不会看到两个不同
//     快照的并集（torn state）。保证"当前值"整体可原子替换的是调用方：本包只
//     负责在 Inspect 开始时读一次。
//   - **fn == nil 是无操作**：与不传本 Option 逐字节一致（构造期被忽略）。
//   - **空串与重复**沿用 NewAllowlist 语义：空串丢弃、重复无副作用；fn 返回 nil
//     或空切片是合法的廉价情形，此时直接复用静态 Allowlist（不重建、零分配），
//     抑制行为与并集后逐条等价。
//   - **并发**：fn 会被多个 request goroutine 并发调用，调用方必须保证共享快照
//     可安全并发读写并整体替换（生产实现是 allowlist.Store.Entries：互斥 + 独立
//     拷贝）。返回的切片在 fn 返回后即可复用或修改——本包立刻把它复制进一份新的
//     Allowlist，不持有调用方的切片，但"读到当前值"这一动作本身必须由调用方做成
//     原子的。
func WithAllowlistSource(fn func() []string) Option {
	return func(cfg *detectorConfig) {
		if fn == nil {
			return
		}
		cfg.allowlistSource = fn
	}
}

// staticLiterals 返回构造期字面量。nil Allowlist（未传 WithAllowlist）没有任何
// 字面量；本方法只读，不改变 Allowlist 的既有语义。
func (a *Allowlist) staticLiterals() []string {
	if a == nil {
		return nil
	}
	return a.literals
}

// unionAllowlist 把静态 Allowlist 与运行期来源的当前字面量合成一次新 Allowlist。
// 每次都从来源重新取值（并复制静态字面量），不保留跨 Inspect 的状态，因此没有
// 任何缓存、也不会无界增长。
//
// 来源没有运行期字面量（nil 或空切片；生产里即 store 当前为空）时直接复用静态
// Allowlist：它是构造期一次成型的只读值（本包从不修改 literals），两个分支的
// 抑制判定逐条等价（nil Allowlist 与空 Allowlist 都抑制不了任何东西），所以这是
// 纯分配优化，不改变任何文档化行为。
func unionAllowlist(static *Allowlist, runtime []string) *Allowlist {
	if len(runtime) == 0 {
		return static
	}
	base := static.staticLiterals()
	literals := make([]string, 0, len(base)+len(runtime))
	literals = append(literals, base...)
	literals = append(literals, runtime...)
	return NewAllowlist(literals...)
}
