package cli

import (
	"bytes"
	"io"
	"strings"
	"testing"
)

// TestDispatchExitCodes pins the frozen dispatcher codes: an unknown command
// and no command at all are usage errors, and the error names the command.
func TestDispatchExitCodes(t *testing.T) {
	var stderr bytes.Buffer
	if code := dispatch([]string{"nosuchtool"}, io.Discard, &stderr); code != exitUsage {
		t.Errorf("dispatch(unknown) = %d, want %d", code, exitUsage)
	}
	if !strings.Contains(stderr.String(), "nosuchtool") {
		t.Errorf("stderr = %q, want it to name the unknown command", stderr.String())
	}

	stderr.Reset()
	if code := dispatch(nil, io.Discard, &stderr); code != exitUsage {
		t.Errorf("dispatch(none) = %d, want %d", code, exitUsage)
	}
	if !strings.Contains(stderr.String(), "usage: tokenhush <") {
		t.Errorf("stderr = %q, want a usage line", stderr.String())
	}
}

// TestMainIsTheDispatcher wraps dispatch for the process entry point.
func TestMainIsTheDispatcher(t *testing.T) {
	if code := Main([]string{"nosuchtool"}); code != exitUsage {
		t.Errorf("Main(unknown) = %d, want %d", code, exitUsage)
	}
}
