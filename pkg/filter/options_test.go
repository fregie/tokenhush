package filter

import (
	"errors"
	"strings"
	"testing"
)

// TestNormalizeEmailSuffix pins the observable (string, error) contract of
// normalizeEmailSuffix: trim, lowercase, one canonical leading dot, and the
// exact sentinel behind each rejection. The table asserts both the returned
// value and the error kind, and each failure case also asserts that the OTHER
// schema sentinel does NOT match, so the two error classes cannot be silently
// conflated. The over-length rows fix the boundary at MaxLiteralBytes canonical
// bytes (inclusive).
func TestNormalizeEmailSuffix(t *testing.T) {
	maxCanonical := strings.Repeat("a", MaxLiteralBytes-1) // "." + 255 bytes == 256 bytes
	overCanonical := strings.Repeat("a", MaxLiteralBytes)  // "." + 256 bytes == 257 bytes

	tests := []struct {
		name  string
		in    string
		want  string
		kind  error // the sentinel the error must satisfy; nil means success
		other error // the sentinel the error must NOT satisfy; nil on success
	}{
		{
			name: "mixed case is lowercased and dotted",
			in:   "Corp.COM",
			want: ".corp.com",
		},
		{
			name: "an already canonical suffix is unchanged",
			in:   ".com",
			want: ".com",
		},
		{
			name: "a bare compound suffix gains the canonical dot",
			in:   "co.uk",
			want: ".co.uk",
		},
		{
			name: "a single label is legal without an inner dot",
			in:   "com",
			want: ".com",
		},
		{
			name: "surrounding whitespace is trimmed",
			in:   " \tCorp.COM\n",
			want: ".corp.com",
		},
		{
			name: "a canonical form of exactly MaxLiteralBytes is accepted",
			in:   maxCanonical,
			want: "." + maxCanonical,
		},
		{
			name: "a lone dot carries zero labels",
			in:   ".",
			want: ".",
		},
		{
			name:  "empty input",
			in:    "",
			want:  "",
			kind:  ErrInvalidValue,
			other: ErrBoundExceeded,
		},
		{
			name:  "whitespace-only input",
			in:    " \t\r\n ",
			want:  "",
			kind:  ErrInvalidValue,
			other: ErrBoundExceeded,
		},
		{
			name:  "internal space",
			in:    "a b.com",
			want:  "",
			kind:  ErrInvalidValue,
			other: ErrBoundExceeded,
		},
		{
			name:  "internal tab",
			in:    "a\tb.com",
			want:  "",
			kind:  ErrInvalidValue,
			other: ErrBoundExceeded,
		},
		{
			name:  "non-ASCII input (CJK labels)",
			in:    "例え.com",
			want:  "",
			kind:  ErrInvalidValue,
			other: ErrBoundExceeded,
		},
		{
			name:  "a dot-dot run",
			in:    "a..b",
			want:  "",
			kind:  ErrInvalidValue,
			other: ErrBoundExceeded,
		},
		{
			name:  "multiple leading dots",
			in:    "..com",
			want:  "",
			kind:  ErrInvalidValue,
			other: ErrBoundExceeded,
		},
		{
			name:  "dot-dot-dot",
			in:    "...",
			want:  "",
			kind:  ErrInvalidValue,
			other: ErrBoundExceeded,
		},
		{
			name:  "one canonical byte above the bound",
			in:    overCanonical,
			want:  "",
			kind:  ErrBoundExceeded,
			other: ErrInvalidValue,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := normalizeEmailSuffix(tt.in)

			if tt.kind == nil {
				if err != nil {
					t.Fatalf("normalizeEmailSuffix(%q) error = %v, want nil", tt.in, err)
				}
				if got != tt.want {
					t.Errorf("normalizeEmailSuffix(%q) = %q, want %q", tt.in, got, tt.want)
				}
				return
			}

			if !errors.Is(err, tt.kind) {
				t.Fatalf("normalizeEmailSuffix(%q) error = %v, want %v", tt.in, err, tt.kind)
			}
			if errors.Is(err, tt.other) {
				t.Errorf("normalizeEmailSuffix(%q) error = %v, must not satisfy %v", tt.in, err, tt.other)
			}
			if got != "" {
				t.Errorf("normalizeEmailSuffix(%q) = %q on error, want the zero value", tt.in, got)
			}
		})
	}
}
