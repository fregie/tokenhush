package cli

import (
	"bytes"
	"runtime"
	"strconv"
	"strings"
	"testing"

	"github.com/fregie/tokenhush/pkg/supply"
)

// TestVersionPrintsV050AndBuildInfo pins the OD-1 version line: the binary
// prints v0.5.0 (the single source is supply.Version) plus the Go runtime and
// platform build info.
func TestVersionPrintsV050AndBuildInfo(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if code := versionCommand(nil, &stdout, &stderr); code != exitOK {
		t.Fatalf("version = %d, want %d", code, exitOK)
	}
	out := stdout.String()
	for _, want := range []string{"v0.5.0", runtime.GOOS + "/" + runtime.GOARCH, runtime.Version(), "commit", "built"} {
		if !strings.Contains(out, want) {
			t.Errorf("version output %q is missing %q", out, want)
		}
	}
	if stderr.Len() != 0 {
		t.Errorf("stderr = %q, want nothing", stderr.String())
	}
}

// TestVersionSatisfiesTheMinBinaryVersionGate pins that the value the binary
// reports is the same value the rule-manifest gate evaluates: supply.Version
// is v0.5.0, which is strictly above the 0.4.x line and satisfies the fixture
// manifests' min_binary_version of 0.3.0.
func TestVersionSatisfiesTheMinBinaryVersionGate(t *testing.T) {
	if supply.Version != "0.5.0" {
		t.Fatalf("supply.Version = %q, want 0.5.0", supply.Version)
	}
	if !versionAtLeast(supply.Version, "0.3.0") {
		t.Errorf("v%s does not satisfy the min_binary_version gate 0.3.0", supply.Version)
	}
	if !versionAtLeast(supply.Version, "0.4.0") || supply.Version == "0.4.0" {
		t.Errorf("v%s must be strictly greater than the 0.4.x line", supply.Version)
	}
}

// TestVersionRejectsExtraArguments pins the usage error.
func TestVersionRejectsExtraArguments(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if code := versionCommand([]string{"extra"}, &stdout, &stderr); code != exitUsage {
		t.Fatalf("version extra = %d, want %d", code, exitUsage)
	}
}

// versionAtLeast reports whether got >= required for a dotted numeric version.
func versionAtLeast(got, required string) bool {
	a, b := parseVersion(got), parseVersion(required)
	for i := range a {
		if a[i] != b[i] {
			return a[i] > b[i]
		}
	}
	return true
}

// parseVersion reads up to three numeric segments, missing segments being 0.
func parseVersion(text string) [3]int {
	var parts [3]int
	for i, segment := range strings.SplitN(text, ".", 3) {
		if i >= len(parts) {
			break
		}
		value, err := strconv.Atoi(segment)
		if err != nil {
			return parts
		}
		parts[i] = value
	}
	return parts
}
