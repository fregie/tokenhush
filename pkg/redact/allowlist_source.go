package redact

// WithAllowlistSource 设置运行期白名单来源：fn 在每次 Inspect 时被调用，因此
// 调用方无需重建 detector 就能替换返回的字面量集合（W0.3 的最小接缝；共享快照
// 与原子替换由 W5.2 在本接缝之上加固）。
//
// 语义（ADR-0012 A2 冻结）：
//   - 有效字面量集合 = 静态 WithAllowlist 字面量 ∪ fn() 的返回值；并集，绝不替换
//     静态集合；
//   - fn == nil 被忽略（无操作），此时行为与不传本 Option 完全一致；
//   - 空串与重复字面量沿用 NewAllowlist 的语义：空串丢弃、重复无副作用。
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
// 每次都从来源重新取值（并复制静态字面量），不保留跨 Inspect 的状态。
func unionAllowlist(static *Allowlist, runtime []string) *Allowlist {
	base := static.staticLiterals()
	literals := make([]string, 0, len(base)+len(runtime))
	literals = append(literals, base...)
	literals = append(literals, runtime...)
	return NewAllowlist(literals...)
}
