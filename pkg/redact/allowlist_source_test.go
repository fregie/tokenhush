package redact

import (
	"testing"

	"github.com/fregie/tokenhush/pkg/extension"
)

// TestAllowlistSource 锁定 W0.3 新增的 WithAllowlistSource 接缝：来源函数在每次
// Inspect 时被调用，有效字面量集合 = 静态 WithAllowlist ∪ 来源返回值。断言全部
// 基于真实 detector 的 findings，不依赖 mock。
func TestAllowlistSource(t *testing.T) {
	cases := []struct {
		name    string
		static  []string
		source  func() []string
		content string
		found   []string
	}{
		{
			name:    "source_only_suppresses",
			source:  func() []string { return []string{"user@example.com"} },
			content: "reach user@example.com now",
		},
		{
			name:    "static_only_path_unchanged_by_nil_source",
			static:  []string{"user@example.com"},
			source:  nil,
			content: "reach user@example.com now",
		},
		{
			name:    "static_and_source_form_a_union",
			static:  []string{"a@x.co"},
			source:  func() []string { return []string{"b@x.co"} },
			content: "a@x.co b@x.co c@x.co",
			found:   []string{"c@x.co"},
		},
		{
			name:    "source_result_is_added_to_static_not_replacing_it",
			static:  []string{"a@x.co"},
			source:  func() []string { return []string{"b@x.co"} },
			content: "only a@x.co here",
		},
		{
			name:    "nil_source_without_static_keeps_flagging",
			source:  nil,
			content: "reach user@example.com now",
			found:   []string{"user@example.com"},
		},
		{
			name:    "source_returning_no_literals_keeps_flagging",
			source:  func() []string { return nil },
			content: "reach user@example.com now",
			found:   []string{"user@example.com"},
		},
		{
			name:    "source_returning_empty_literals_is_ignored",
			source:  func() []string { return []string{"", ""} },
			content: "reach user@example.com now",
			found:   []string{"user@example.com"},
		},
		{
			name:    "source_duplicates_are_harmless",
			source:  func() []string { return []string{"user@example.com", "user@example.com"} },
			content: "reach user@example.com now",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			opts := make([]Option, 0, 2)
			if tc.static != nil {
				opts = append(opts, WithAllowlist(tc.static...))
			}
			// 每个用例都显式传 WithAllowlistSource：nil fn 必须被忽略且不改变
			// 任何既有行为。
			opts = append(opts, WithAllowlistSource(tc.source))
			det := NewEmailDetector(opts...)

			got := mustFindings(t, det, docOf(extension.RequestContent, tc.content))
			wants := make([]span, 0, len(tc.found))
			for _, sample := range tc.found {
				wants = append(wants, spanIn(t, tc.content, sample))
			}
			if len(got) != len(wants) {
				t.Fatalf("findings = %#v，want %d 项", got, len(wants))
			}
			for i, w := range wants {
				if got[i].Start != w.start || got[i].End != w.end {
					t.Errorf("finding[%d] = [%d,%d)，want [%d,%d)", i, got[i].Start, got[i].End, w.start, w.end)
				}
			}
		})
	}

	// 来源在每次 Inspect 时被读取：无需重建 detector，替换闭包返回的集合立即
	// 生效，再清空又恢复原状。
	t.Run("source_is_consulted_on_every_inspect", func(t *testing.T) {
		var dynamic string
		det := NewEmailDetector(WithAllowlistSource(func() []string {
			if dynamic == "" {
				return nil
			}
			return []string{dynamic}
		}))
		content := "reach user@example.com now"

		if got := mustFindings(t, det, docOf(extension.RequestContent, content)); len(got) != 1 {
			t.Fatalf("初始 findings = %#v，want 1", got)
		}
		dynamic = "user@example.com"
		if got := mustFindings(t, det, docOf(extension.RequestContent, content)); len(got) != 0 {
			t.Fatalf("来源替换后 findings = %#v，want 0", got)
		}
		dynamic = ""
		if got := mustFindings(t, det, docOf(extension.RequestContent, content)); len(got) != 1 {
			t.Fatalf("来源清空后 findings = %#v，want 1", got)
		}
	})

	// 同一个 Option 对 prefix detector 同样生效（来源字面量包住密钥即抑制）。
	t.Run("prefix_detector_consults_source", func(t *testing.T) {
		det := NewPrefixDetector(WithAllowlistSource(func() []string { return []string{openAIKey} }))
		content := "key=" + openAIKey + " and " + awsKey
		got := mustFindings(t, det, docOf(extension.RequestContent, content))
		want := spanIn(t, content, awsKey)
		if len(got) != 1 || got[0].Start != want.start || got[0].End != want.end {
			t.Fatalf("findings = %#v，want 仅 awsKey [%d,%d)", got, want.start, want.end)
		}
	})
}
