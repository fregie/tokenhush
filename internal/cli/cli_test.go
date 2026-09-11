package cli

import (
	"bytes"
	"strings"
	"testing"
)

func TestRun(t *testing.T) {
	if ExitOK != 0 || ExitFailure != 1 || ExitUsage != 2 {
		t.Fatalf("exit-code contract changed: ExitOK=%d ExitFailure=%d ExitUsage=%d, want 0, 1 and 2", ExitOK, ExitFailure, ExitUsage)
	}

	const testVersion = "1.2.3-test"
	previous := Version
	t.Cleanup(func() { Version = previous })
	Version = testVersion

	tests := []struct {
		name        string
		args        []string
		wantCode    int
		wantStdout  []string // substrings; all must appear
		wantStderr  []string // substrings; all must appear
		emptyStdout bool
		emptyStderr bool
	}{
		{
			name:        "version prints build info",
			args:        []string{"version"},
			wantCode:    ExitOK,
			wantStdout:  []string{"tokenhush", testVersion},
			emptyStderr: true,
		},
		{
			name:        "run rejects an unknown flag",
			args:        []string{"run", "--bogus"},
			wantCode:    ExitUsage,
			emptyStdout: true,
		},
		{
			name:        "status is a stub",
			args:        []string{"status"},
			wantCode:    ExitUsage,
			wantStderr:  []string{"not implemented", "usage:"},
			emptyStdout: true,
		},
		{
			name:        "audit is a stub",
			args:        []string{"audit"},
			wantCode:    ExitUsage,
			wantStderr:  []string{"not implemented", "usage:"},
			emptyStdout: true,
		},
		{
			name:        "env is a stub",
			args:        []string{"env"},
			wantCode:    ExitUsage,
			wantStderr:  []string{"not implemented", "usage:"},
			emptyStdout: true,
		},
		{
			name:        "doctor is a stub",
			args:        []string{"doctor"},
			wantCode:    ExitUsage,
			wantStderr:  []string{"not implemented", "usage:"},
			emptyStdout: true,
		},
		{
			name:        "unknown command reports usage",
			args:        []string{"bogus"},
			wantCode:    ExitUsage,
			wantStderr:  []string{"unknown command", "usage:"},
			emptyStdout: true,
		},
		{
			name:        "no args reports usage",
			args:        nil,
			wantCode:    ExitUsage,
			wantStderr:  []string{"usage:"},
			emptyStdout: true,
		},
		{
			name:        "unknown flag is a malformed command, not a panic",
			args:        []string{"--help"},
			wantCode:    ExitUsage,
			wantStderr:  []string{"unknown command", "usage:"},
			emptyStdout: true,
		},
		{
			name:        "empty command is rejected",
			args:        []string{""},
			wantCode:    ExitUsage,
			wantStderr:  []string{"unknown command", "usage:"},
			emptyStdout: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			got := Run(tt.args, &stdout, &stderr)

			if got != tt.wantCode {
				t.Errorf("Run(%q) = %d, want %d", tt.args, got, tt.wantCode)
			}
			for _, want := range tt.wantStdout {
				if !strings.Contains(stdout.String(), want) {
					t.Errorf("stdout = %q, want it to contain %q", stdout.String(), want)
				}
			}
			for _, want := range tt.wantStderr {
				if !strings.Contains(stderr.String(), want) {
					t.Errorf("stderr = %q, want it to contain %q", stderr.String(), want)
				}
			}
			if tt.emptyStdout && stdout.Len() != 0 {
				t.Errorf("stdout = %q, want empty", stdout.String())
			}
			if tt.emptyStderr && stderr.Len() != 0 {
				t.Errorf("stderr = %q, want empty", stderr.String())
			}
		})
	}
}
