package update

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
)

// TestApplyDevBuildSkipsVersionGate 断言源码构建（CurrentVersion 无发布版本
// 语义）不会再被版本比较误判为 malformed：Apply 跳过该门并正常安装已验签的
// 更新。dev 字面量、0.0.0-dev 与预发布后缀都覆盖到。
func TestApplyDevBuildSkipsVersionGate(t *testing.T) {
	tests := []struct {
		name    string
		current string
	}{
		{"bare dev", "dev"},
		{"dev pseudo-version", "0.0.0-dev"},
		{"prerelease", "0.3.0-rc1"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			target := filepath.Join(dir, "tokenhush")
			writeBinary(t, target, []byte("ORIGINAL-BINARY"))

			b := newApplyBackend(t)
			b.artifact = []byte("NEW-BINARY-0.4.0")
			v, _, upd := engineVerifier(t, tt.current)
			m := engineManifest(b.artifact, b.artifactURL())
			m.Version, m.Serial = "0.4.0", 10
			b.manifestRaw = marshalDoc(t, upd.signManifest(t, m))
			b.revRaw = marshalDoc(t, upd.signRevocations(t, emptyRevocations()))

			res, err := newEngine(t, v, b, target, "linux", "amd64").Apply(context.Background())
			if err != nil {
				t.Fatalf("Apply(%q): %v", tt.current, err)
			}
			if res.Status != ApplyUpdated || res.Version != "0.4.0" {
				t.Fatalf("result = %+v, want updated 0.4.0", res)
			}
		})
	}
}

// TestApplyRejectsDowngradeForNumericCurrent 断言数字运行版本下低于当前的清单
// 仍被拒绝：dev/规范化放行只针对无发布语义的运行版本，不放松数字版本语义。
func TestApplyRejectsDowngradeForNumericCurrent(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "tokenhush")
	writeBinary(t, target, []byte("ORIGINAL-BINARY"))

	b := newApplyBackend(t)
	b.artifact = []byte("OLDER-BINARY-0.3.0")
	v, _, upd := engineVerifier(t, "1.0.0")
	m := engineManifest(b.artifact, b.artifactURL())
	m.Version, m.Serial = "0.3.0", 11
	b.manifestRaw = marshalDoc(t, upd.signManifest(t, m))
	b.revRaw = marshalDoc(t, upd.signRevocations(t, emptyRevocations()))

	if _, err := newEngine(t, v, b, target, "linux", "amd64").Apply(context.Background()); !errors.Is(err, ErrDowngrade) {
		t.Fatalf("error = %v, want ErrDowngrade", err)
	}
}

// TestApplyRejectsDowngradeForPrereleaseCurrent 断言预发布运行版本规范化后仍
// 拒绝降级：0.4.0-rc1 视为 0.4.0，低于它的 0.3.0 清单不得安装。
func TestApplyRejectsDowngradeForPrereleaseCurrent(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "tokenhush")
	writeBinary(t, target, []byte("ORIGINAL-BINARY"))

	b := newApplyBackend(t)
	b.artifact = []byte("OLDER-BINARY-0.3.0")
	v, _, upd := engineVerifier(t, "0.4.0-rc1")
	m := engineManifest(b.artifact, b.artifactURL())
	m.Version, m.Serial = "0.3.0", 11
	b.manifestRaw = marshalDoc(t, upd.signManifest(t, m))
	b.revRaw = marshalDoc(t, upd.signRevocations(t, emptyRevocations()))

	if _, err := newEngine(t, v, b, target, "linux", "amd64").Apply(context.Background()); !errors.Is(err, ErrDowngrade) {
		t.Fatalf("error = %v, want ErrDowngrade", err)
	}
}
