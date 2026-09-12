package config

import (
	"errors"
	"fmt"
	"strings"
	"testing"
)

func TestLoadFileRejectsNonLoopbackHost(t *testing.T) {
	hosts := []string{
		"0.0.0.0",
		"",
		"*",
		"::",
		"192.168.1.10",
		"example.com",
		"[::1]",
		" 127.0.0.1",
	}
	for _, host := range hosts {
		t.Run(fmt.Sprintf("%q", host), func(t *testing.T) {
			_, err := LoadFile(writeConfig(t, fmt.Sprintf("listen:\n  host: %q\n", host)))
			if !errors.Is(err, ErrInvalidListenHost) {
				t.Fatalf("host %q: want ErrInvalidListenHost, got %v", host, err)
			}
			t.Logf("host %q rejected: %v", host, err)
		})
	}
}

func TestLoadFileRejectsInvalidPort(t *testing.T) {
	cases := map[string]string{
		"non_numeric": "listen:\n  port: abc\n",
		"fractional":  "listen:\n  port: 12.5\n",
		"boolean":     "listen:\n  port: true\n",
		"zero":        "listen:\n  port: 0\n",
		"negative":    "listen:\n  port: -1\n",
		"too_large":   "listen:\n  port: 65536\n",
		"quoted":      "listen:\n  port: \"8080\"\n",
	}
	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := LoadFile(writeConfig(t, body))
			if !errors.Is(err, ErrInvalidListenPort) {
				t.Fatalf("want ErrInvalidListenPort, got %v", err)
			}
		})
	}
}

func TestLoadFileRejectsMalformedYAML(t *testing.T) {
	cases := map[string]string{
		"unterminated_flow":   "listen: [\n",
		"tab_indent":          "listen:\n\tport: 1\n",
		"duplicate_top_level": "listen:\n  port: 1\nlisten:\n  port: 2\n",
		"duplicate_nested":    "listen:\n  port: 1\n  port: 2\n",
	}
	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := LoadFile(writeConfig(t, body))
			if !errors.Is(err, ErrParse) {
				t.Fatalf("want ErrParse, got %v", err)
			}
			t.Logf("malformed YAML rejected: %v", err)
		})
	}
}

func TestLoadFileRejectsWrongShapes(t *testing.T) {
	cases := map[string]string{
		"listen_sequence":    "listen: [1, 2]\n",
		"detectors_sequence": "detectors: [jwt]\n",
		"detectors_scalar":   "detectors: enabled\n",
		"detector_int":       "detectors:\n  jwt: 1\n",
		"detector_string":    "detectors:\n  jwt: \"yes\"\n",
	}
	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := LoadFile(writeConfig(t, body)); !errors.Is(err, ErrParse) {
				t.Fatalf("want ErrParse, got %v", err)
			}
		})
	}
}

func TestLoadFileRejectsUnknownKeys(t *testing.T) {
	cases := map[string]string{
		"detector_id_instead_of_config_key": "detectors:\n  private_key: true\n",
		"unknown_detector":                  "detectors:\n  secretz: true\n",
		"detector_typo":                     "detectors:\n  prefix: true\n",
		"unknown_section":                   "detectorz:\n  jwt: true\n",
		"unknown_listen_key":                "listen:\n  addr: 127.0.0.1\n",
	}
	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := LoadFile(writeConfig(t, body))
			if !errors.Is(err, ErrUnknownField) {
				t.Fatalf("want ErrUnknownField, got %v", err)
			}
			if !strings.Contains(err.Error(), "unknown field") {
				t.Fatalf("error %q does not name the unknown field", err)
			}
			t.Logf("unknown key rejected: %v", err)
		})
	}
}

func TestLoadFileRejectsMalformedUpstreams(t *testing.T) {
	cases := map[string]string{
		"sequence":   "upstreams: [a, b]\n",
		"scalar":     "upstreams: 42\n",
		"not_a_url":  "upstreams:\n  api.example.com: not-a-url\n",
		"relative":   "upstreams:\n  api.example.com: //example.com\n",
		"bad_scheme": "upstreams:\n  api.example.com: ftp://example.com\n",
		"empty_key":  "upstreams:\n  \"\": https://example.com\n",
		"query":      "upstreams:\n  api.example.com: https://example.com?x=1\n",
		"fragment":   "upstreams:\n  api.example.com: https://example.com#frag\n",
		"no_host":    "upstreams:\n  api.example.com: https://\n",
		"key_is_url": "upstreams:\n  https://api.example.com: https://api.example.com\n",
		"spaced_key": "upstreams:\n  \"api example.com\": https://api.example.com\n",
	}
	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := LoadFile(writeConfig(t, body))
			if !errors.Is(err, ErrInvalidUpstream) {
				t.Fatalf("want ErrInvalidUpstream, got %v", err)
			}
			t.Logf("malformed upstreams rejected: %v", err)
		})
	}
}

func TestLoadFileRejectsInvalidLogLevel(t *testing.T) {
	_, err := LoadFile(writeConfig(t, "log:\n  level: verbose\n"))
	if !errors.Is(err, ErrInvalidLogLevel) {
		t.Fatalf("want ErrInvalidLogLevel, got %v", err)
	}
}

func TestLoadFileAuditKeyIsMigrationError(t *testing.T) {
	cases := map[string]string{
		"block":          "audit:\n  retention_days: 0\n",
		"inline_mapping": "audit: {enabled: false}\n",
		"scalar":         "audit: false\n",
	}
	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := LoadFile(writeConfig(t, body))
			if !errors.Is(err, ErrUnknownField) {
				t.Fatalf("want ErrUnknownField, got %v", err)
			}
			if !strings.Contains(err.Error(), "tokenhush-pro") {
				t.Fatalf("error %q does not point at tokenhush-pro", err)
			}
			if !strings.Contains(err.Error(), "delete") {
				t.Fatalf("error %q does not tell the user to delete the block", err)
			}
			t.Logf("audit key rejected with migration guidance: %v", err)
		})
	}
}

func TestLoadFileRejectsOversizedFile(t *testing.T) {
	body := strings.Repeat("# padding padding padding padding\n", 60000) // ~1.8 MiB
	if _, err := LoadFile(writeConfig(t, body)); !errors.Is(err, ErrTooLarge) {
		t.Fatalf("want ErrTooLarge, got %v", err)
	}
}

func TestLoadFileDirectoryIsTypedReadError(t *testing.T) {
	if _, err := LoadFile(t.TempDir()); !errors.Is(err, ErrRead) {
		t.Fatalf("want ErrRead for directory, got %v", err)
	}
}
