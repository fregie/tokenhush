package cli

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

func TestPrivacyCommand(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if code := Run([]string{"privacy"}, &stdout, &stderr); code != ExitOK {
		t.Fatalf("privacy exit = %d, want %d (stderr %q)", code, ExitOK, stderr.String())
	}
	out := stdout.String()
	for _, want := range []string{
		"[PLANNED]",
		"Update check",
		"Rule sync",
		"Server can observe",
		"access_logs",
		"Retention",
		"How to switch off",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("privacy output missing %q", want)
		}
	}
	if strings.Contains(out, "[ACTIVE]") {
		t.Error("Plan A output must not label any category ACTIVE")
	}

	stdout.Reset()
	stderr.Reset()
	if code := Run([]string{"privacy", "--json"}, &stdout, &stderr); code != ExitOK {
		t.Fatalf("privacy --json exit = %d, want %d", code, ExitOK)
	}
	var m struct {
		Items []struct {
			ID     string `json:"id"`
			Status string `json:"status"`
		} `json:"items"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &m); err != nil {
		t.Fatalf("privacy --json is not valid JSON: %v", err)
	}
	if len(m.Items) != 2 {
		t.Fatalf("privacy --json items = %d, want 2", len(m.Items))
	}
	for _, it := range m.Items {
		if it.Status != "planned" {
			t.Errorf("%s status = %q, want planned (Plan A)", it.ID, it.Status)
		}
	}
}

func TestPrivacyCommandHelpIsRecognized(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if code := Run([]string{"privacy", "--help"}, &stdout, &stderr); code != ExitUsage {
		t.Fatalf("privacy --help exit = %d, want %d", code, ExitUsage)
	}
	if !strings.Contains(stderr.String(), "Usage of privacy:") {
		t.Errorf("privacy --help must print its usage; got %q", stderr.String())
	}
}
