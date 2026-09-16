package config

import (
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
)

// allSelfProtectionModes is the frozen canonical mode set in
// docs/tool-setup.md order.
var allSelfProtectionModes = []string{
	SelfProtectionModeCLICommand,
	SelfProtectionModeControlPort,
	SelfProtectionModeFileWrite,
}

// TestSelfProtectionDefaultsHardened pins the hardening-by-default posture:
// omitting (or nulling) the self_protection: block keeps every interception
// mode on, and only an explicit enabled: false turns the feature off.
func TestSelfProtectionDefaultsHardened(t *testing.T) {
	t.Run("default_all_three_modes_on", func(t *testing.T) {
		sp := Default().SelfProtection
		if !sp.Enabled {
			t.Fatal("Default().SelfProtection.Enabled = false, want true (hardening by default)")
		}
		if !reflect.DeepEqual(sp.Modes, allSelfProtectionModes) {
			t.Fatalf("Default().SelfProtection.Modes = %v, want %v", sp.Modes, allSelfProtectionModes)
		}
		if sp.ExcludePaths != nil {
			t.Fatalf("Default().SelfProtection.ExcludePaths = %v, want nil", sp.ExcludePaths)
		}
		if got := sp.EnabledModes(); !reflect.DeepEqual(got, allSelfProtectionModes) {
			t.Fatalf("Default().SelfProtection.EnabledModes() = %v, want %v", got, allSelfProtectionModes)
		}
	})

	// The merge-over-Default() in LoadFile must reach a nested block too: a
	// file without self_protection: keeps the hardened defaults.
	for name, body := range map[string]string{
		"absent_block": "listen:\n  port: 9000\n",
		"empty_block":  "self_protection: {}\n",
		"null_block":   "self_protection: null\n",
	} {
		t.Run(name+"_keeps_hardened_defaults", func(t *testing.T) {
			cfg, err := LoadFile(writeConfig(t, body))
			if err != nil {
				t.Fatalf("LoadFile: %v", err)
			}
			if !cfg.SelfProtection.Enabled {
				t.Error("SelfProtection.Enabled = false, want hardened default true")
			}
			if !reflect.DeepEqual(cfg.SelfProtection.Modes, allSelfProtectionModes) {
				t.Errorf("SelfProtection.Modes = %v, want hardened default %v", cfg.SelfProtection.Modes, allSelfProtectionModes)
			}
			if cfg.SelfProtection.ExcludePaths != nil {
				t.Errorf("SelfProtection.ExcludePaths = %v, want nil", cfg.SelfProtection.ExcludePaths)
			}
		})
	}

	t.Run("explicit_disable_is_honoured_without_warning", func(t *testing.T) {
		cfg, err := LoadFile(writeConfig(t, "self_protection:\n  enabled: false\n"))
		if err != nil {
			t.Fatalf("explicit enabled: false must load, got %v", err)
		}
		if cfg.SelfProtection.Enabled {
			t.Error("SelfProtection.Enabled = true, want explicit false")
		}
		if !reflect.DeepEqual(cfg.SelfProtection.Modes, allSelfProtectionModes) {
			t.Errorf("SelfProtection.Modes = %v, want untouched hardening default %v", cfg.SelfProtection.Modes, allSelfProtectionModes)
		}
	})

	t.Run("explicit_modes_subset_is_honoured", func(t *testing.T) {
		cfg, err := LoadFile(writeConfig(t, "self_protection:\n  modes: [file-write]\n"))
		if err != nil {
			t.Fatalf("LoadFile: %v", err)
		}
		if !cfg.SelfProtection.Enabled {
			t.Error("SelfProtection.Enabled = false, want default true")
		}
		if want := []string{SelfProtectionModeFileWrite}; !reflect.DeepEqual(cfg.SelfProtection.Modes, want) {
			t.Errorf("SelfProtection.Modes = %v, want %v", cfg.SelfProtection.Modes, want)
		}
	})

	t.Run("explicit_exclude_paths_round_trip", func(t *testing.T) {
		cfg, err := LoadFile(writeConfig(t, "self_protection:\n  exclude_paths: [/etc/tokenhush/extra.txt]\n"))
		if err != nil {
			t.Fatalf("LoadFile: %v", err)
		}
		if want := []string{"/etc/tokenhush/extra.txt"}; !reflect.DeepEqual(cfg.SelfProtection.ExcludePaths, want) {
			t.Errorf("SelfProtection.ExcludePaths = %v, want %v", cfg.SelfProtection.ExcludePaths, want)
		}
	})
}

// TestSelfProtectionValidation pins the illegal-value table: every case must
// come back as a typed *Error (never a panic), name the offending value, and
// classify under ErrInvalidSelfProtection.
func TestSelfProtectionValidation(t *testing.T) {
	overlong := strings.Repeat("a", maxConfigEntryBytes+1)
	cases := map[string]struct {
		body       string
		wantField  string
		wantReason []string
	}{
		"unknown_mode": {
			body:       "self_protection:\n  modes: [bogus]\n",
			wantField:  "self_protection.modes",
			wantReason: []string{`"bogus"`, SelfProtectionModeCLICommand, SelfProtectionModeControlPort, SelfProtectionModeFileWrite},
		},
		"unknown_mode_among_valid": {
			body:       "self_protection:\n  modes: [cli-command, telepathy, file-write]\n",
			wantField:  "self_protection.modes",
			wantReason: []string{`"telepathy"`, "cli-command"},
		},
		"duplicate_mode": {
			body:       "self_protection:\n  modes: [cli-command, cli-command]\n",
			wantField:  "self_protection.modes",
			wantReason: []string{"duplicate", "cli-command"},
		},
		"empty_exclude_path": {
			body:       "self_protection:\n  exclude_paths: [\"\"]\n",
			wantField:  "self_protection.exclude_paths",
			wantReason: []string{"entry 0", "empty"},
		},
		"control_char_exclude_path": {
			body:       "self_protection:\n  exclude_paths: [\"/tmp/a\\tb\"]\n",
			wantField:  "self_protection.exclude_paths",
			wantReason: []string{"entry 0", "control characters"},
		},
		"over_long_exclude_path": {
			body:       "self_protection:\n  exclude_paths: [\"" + overlong + "\"]\n",
			wantField:  "self_protection.exclude_paths",
			wantReason: []string{"entry 0", fmt.Sprintf("%d", maxConfigEntryBytes)},
		},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := LoadFile(writeConfig(t, tc.body))
			if err == nil {
				t.Fatal("LoadFile accepted an illegal self_protection value")
			}
			var cfgErr *Error
			if !errors.As(err, &cfgErr) {
				t.Fatalf("error is not a typed *config.Error: %T: %v", err, err)
			}
			if !errors.Is(err, ErrInvalidSelfProtection) {
				t.Errorf("errors.Is(err, ErrInvalidSelfProtection) = false: %v", err)
			}
			if cfgErr.Field != tc.wantField {
				t.Errorf("Field = %q, want %q", cfgErr.Field, tc.wantField)
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
		"all_three_modes_and_a_path":  "self_protection:\n  enabled: true\n  modes: [cli-command, control-port, file-write]\n  exclude_paths: [/tmp/extra.txt]\n",
		"explicit_disable_is_allowed": "self_protection:\n  enabled: false\n",
		"empty_exclude_paths":         "self_protection:\n  exclude_paths: []\n",
	}
	for name, body := range valid {
		t.Run(name+"_accepted", func(t *testing.T) {
			cfg, err := LoadFile(writeConfig(t, body))
			if err != nil {
				t.Fatalf("LoadFile: %v", err)
			}
			if !cfg.SelfProtection.Enabled && name != "explicit_disable_is_allowed" {
				t.Error("SelfProtection.Enabled = false, want hardened default true")
			}
		})
	}
}

// TestSelfProtectionEnabledModesCanonicalOrder pins EnabledModes() to the
// frozen docs order regardless of the YAML order, and to "no enabled modes"
// when the master switch is off.
func TestSelfProtectionEnabledModesCanonicalOrder(t *testing.T) {
	cases := map[string]struct {
		sp   SelfProtection
		want []string
	}{
		"reversed_input_is_canonicalised": {
			sp:   SelfProtection{Enabled: true, Modes: []string{SelfProtectionModeFileWrite, SelfProtectionModeCLICommand}},
			want: []string{SelfProtectionModeCLICommand, SelfProtectionModeFileWrite},
		},
		"subset_keeps_canonical_order": {
			sp:   SelfProtection{Enabled: true, Modes: []string{SelfProtectionModeControlPort, SelfProtectionModeCLICommand}},
			want: []string{SelfProtectionModeCLICommand, SelfProtectionModeControlPort},
		},
		"all_three": {
			sp:   SelfProtection{Enabled: true, Modes: allSelfProtectionModes},
			want: allSelfProtectionModes,
		},
		"disabled_has_no_enabled_modes": {
			sp:   SelfProtection{Enabled: false, Modes: allSelfProtectionModes},
			want: nil,
		},
		"absent_modes": {
			sp:   SelfProtection{Enabled: true},
			want: nil,
		},
		"unknown_modes_are_ignored": {
			sp:   SelfProtection{Enabled: true, Modes: []string{"bogus", SelfProtectionModeControlPort}},
			want: []string{SelfProtectionModeControlPort},
		},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			if got := tc.sp.EnabledModes(); !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("EnabledModes() = %v, want %v", got, tc.want)
			}
		})
	}
}
