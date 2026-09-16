package config

import (
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
)

// TestAllowlistEntryValidation pins the entry checks without touching the
// matching semantics (byte-exact contains, owned by pkg/redact): unusable
// entries are rejected at load time as a typed *Error, valid ones load as-is.
func TestAllowlistEntryValidation(t *testing.T) {
	overlong := strings.Repeat("x", maxConfigEntryBytes+1)
	cases := map[string]struct {
		body       string
		wantReason []string
	}{
		"empty_entry": {
			body:       "allowlist: [\"\"]\n",
			wantReason: []string{"entry 0", "empty"},
		},
		"empty_entry_after_valid_one": {
			body:       "allowlist: [sk-live-abc, \"\"]\n",
			wantReason: []string{"entry 1", "empty"},
		},
		"control_char_entry": {
			body:       "allowlist: [\"a\\nb\"]\n",
			wantReason: []string{"entry 0", "control characters"},
		},
		"over_long_entry": {
			body:       "allowlist: [\"" + overlong + "\"]\n",
			wantReason: []string{"entry 0", fmt.Sprintf("%d", maxConfigEntryBytes)},
		},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := LoadFile(writeConfig(t, tc.body))
			if err == nil {
				t.Fatal("LoadFile accepted an unusable allowlist entry")
			}
			var cfgErr *Error
			if !errors.As(err, &cfgErr) {
				t.Fatalf("error is not a typed *config.Error: %T: %v", err, err)
			}
			if !errors.Is(err, ErrInvalidAllowlist) {
				t.Errorf("errors.Is(err, ErrInvalidAllowlist) = false: %v", err)
			}
			if cfgErr.Field != "allowlist" {
				t.Errorf("Field = %q, want allowlist", cfgErr.Field)
			}
			for _, want := range tc.wantReason {
				if !strings.Contains(err.Error(), want) {
					t.Errorf("error %q does not contain %q", err, want)
				}
			}
			t.Logf("rejected: %v", err)
		})
	}

	valid := map[string]string{
		"literals":      "allowlist: [\"sk-live-abc\", \"user@example.com\"]\n",
		"empty_list":    "allowlist: []\n",
		"block_style":   "allowlist:\n  - sk-static-1\n  - value-with,comma\n",
		"unicode_value": "allowlist: [\"密钥值\"]\n",
	}
	for name, body := range valid {
		t.Run(name+"_accepted", func(t *testing.T) {
			if _, err := LoadFile(writeConfig(t, body)); err != nil {
				t.Fatalf("LoadFile: %v", err)
			}
		})
	}
}

// TestAllowlistStaticKeyStillRead is the static half of the frozen union
// semantics: the `allowlist:` key keeps being read at startup and its entries
// keep their exact values and order, because the gateway imports them into the
// runtime store as a seed instead of replacing the key.
func TestAllowlistStaticKeyStillRead(t *testing.T) {
	body := "allowlist:\n  - sk-static-1\n  - value-with,comma\n  - unicode-密钥\n"
	cfg, err := LoadFile(writeConfig(t, body))
	if err != nil {
		t.Fatalf("LoadFile: %v", err)
	}
	want := []string{"sk-static-1", "value-with,comma", "unicode-密钥"}
	if !reflect.DeepEqual(cfg.Allowlist, want) {
		t.Fatalf("Allowlist = %v, want exact round-trip %v", cfg.Allowlist, want)
	}
}
