package rules

import (
	"errors"
	"testing"
)

// TestVerifyPackDevBuildSkipsVersionGate 断言源码构建（version="dev"）没有发布
// 版本语义：min_binary_version 门被跳过，合规包必须被接受，而不是被误判为
// malformed。这正是 owner 从源码构建后规则同步被拒的真实缺陷。
func TestVerifyPackDevBuildSkipsVersionGate(t *testing.T) {
	v, priv := testVerifier(t)
	v.CurrentBinaryVersion = "dev"
	p := compliantPack()
	p.MinBinaryVersion = "0.4.0" // a real 0.3.x build would be refused here
	p.Signature = signInput(priv, PackSigningInput(p))
	if _, err := v.VerifyPack(mustJSON(t, p)); err != nil {
		t.Fatalf("dev build must accept a compliant pack, got %v", err)
	}
}

// TestVerifyPackPrereleaseRunningVersionNormalized 断言预发布运行版本在解析前先
// 剥离后缀，按数字核心比较：0.3.0-rc1 当作 0.3.0。
func TestVerifyPackPrereleaseRunningVersionNormalized(t *testing.T) {
	tests := []struct {
		name    string
		min     string
		wantErr error
	}{
		{"equal core accepted", "0.3.0", nil},
		{"higher floor rejected", "0.4.0", ErrIncompatibleBinary},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			v, priv := testVerifier(t)
			v.CurrentBinaryVersion = "0.3.0-rc1"
			p := compliantPack()
			p.MinBinaryVersion = tt.min
			p.Signature = signInput(priv, PackSigningInput(p))
			_, err := v.VerifyPack(mustJSON(t, p))
			if tt.wantErr == nil {
				if err != nil {
					t.Fatalf("error = %v, want nil", err)
				}
				return
			}
			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("error = %v, want %v", err, tt.wantErr)
			}
		})
	}
}

// TestVerifyPackUnparseableDocumentVersionStaysStrict 断言即使运行版本是 dev，
// 文档侧 min_binary_version 规范化后仍不可解析时依旧严格报 malformed：dev 的
// 放行只针对运行版本，绝不放宽清单/包的语义。
func TestVerifyPackUnparseableDocumentVersionStaysStrict(t *testing.T) {
	v, priv := testVerifier(t)
	v.CurrentBinaryVersion = "dev"
	p := compliantPack()
	p.MinBinaryVersion = "banana"
	p.Signature = signInput(priv, PackSigningInput(p))
	if _, err := v.VerifyPack(mustJSON(t, p)); !errors.Is(err, ErrPackMalformed) {
		t.Fatalf("error = %v, want ErrPackMalformed", err)
	}
}
