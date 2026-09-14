package rules

import (
	"strings"
	"testing"
	"time"
)

// TestRevocationPayloadEmptySerialsIsEmptyArray 断言空撤销列表的投影是 `[]` 而
// 非 `null`：线上已发布的撤销文档由 Python 签发方按 `[]` 签名，`null` 会让每个
// 客户端以签名不匹配拒绝该文档（本次生产事故的根因）。
func TestRevocationPayloadEmptySerialsIsEmptyArray(t *testing.T) {
	r := RevocationList{
		Channel:   "stable",
		Serial:    1,
		KeyID:     "rules-2026-09",
		NotBefore: time.Unix(1789344000, 0).UTC(),
		Expires:   time.Unix(1820880000, 0).UTC(),
	}
	payload := string(revocationPayload(r))
	if !strings.Contains(payload, `"revoked_serials":[]`) {
		t.Fatalf("empty revoked_serials must marshal as `[]`, got %s", payload)
	}
	if strings.Contains(payload, "null") {
		t.Fatalf("revocation payload must not contain null, got %s", payload)
	}
}
