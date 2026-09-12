package gateway

import "testing"

// TestNewPlaceholderStatsCountsAddedPlaceholders pins the metadata-only
// accounting the data plane uses to fill RequestStats and the session
// redaction counter: only placeholders newly introduced by the outbound
// transform count, and only their detector types are reported.
func TestNewPlaceholderStatsCountsAddedPlaceholders(t *testing.T) {
	tests := []struct {
		name      string
		in        string
		out       string
		wantCount int
		wantTypes []string
	}{
		{
			name:      "one new placeholder",
			in:        `{"a":"plain"}`,
			out:       `{"a":"__PII_api_key_0123456789abcdef__"}`,
			wantCount: 1,
			wantTypes: []string{"api_key"},
		},
		{
			name:      "existing placeholder is not re-counted",
			in:        `{"a":"__PII_jwt_0011223344556677__"}`,
			out:       `{"a":"__PII_jwt_0011223344556677__","b":"__PII_email_aabbccddeeff0011__"}`,
			wantCount: 1,
			wantTypes: []string{"email"},
		},
		{
			name:      "removal clamps to zero",
			in:        `{"a":"__PII_jwt_0011223344556677__"}`,
			out:       `{"a":"plain"}`,
			wantCount: 0,
			wantTypes: nil,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			count, types := newPlaceholderStats([]byte(tt.in), []byte(tt.out))
			if count != tt.wantCount {
				t.Errorf("count = %d, want %d", count, tt.wantCount)
			}
			if len(types) != len(tt.wantTypes) {
				t.Fatalf("types = %v, want %v", types, tt.wantTypes)
			}
			for i := range types {
				if types[i] != tt.wantTypes[i] {
					t.Errorf("types = %v, want %v", types, tt.wantTypes)
				}
			}
		})
	}
}

// TestPlaceholderTypeGrammar pins the placeholder token grammar shared with the
// redaction layer: a type made of lowercase letters/digits/underscores and a
// lowercase hex digest of at least eight characters. Anything else is ignored
// so a malformed token never inflates the redaction metadata.
func TestPlaceholderTypeGrammar(t *testing.T) {
	tests := []struct {
		token  string
		want   string
		wantOK bool
	}{
		{token: "api_key_0123456789abcdef", want: "api_key", wantOK: true},
		{token: "high_entropy_0011223344556677", want: "high_entropy", wantOK: true},
		{token: "a_0123456789abcdef", want: "a", wantOK: true},
		{token: "api-key_0123456789abcdef", wantOK: false},
		{token: "Api_key_0123456789abcdef", wantOK: false},
		{token: "api_key_0123", wantOK: false},
		{token: "api_key_0123456789ABCDEF", wantOK: false},
		{token: "api_key_", wantOK: false},
		{token: "_0123456789abcdef", wantOK: false},
		{token: "0123456789abcdef", wantOK: false},
		{token: "", wantOK: false},
	}
	for _, tt := range tests {
		got, ok := placeholderType([]byte(tt.token))
		if ok != tt.wantOK || got != tt.want {
			t.Errorf("placeholderType(%q) = (%q, %v), want (%q, %v)", tt.token, got, ok, tt.want, tt.wantOK)
		}
	}
	if !isLowerHex([]byte("0123456789abcdef")) {
		t.Error("isLowerHex rejected valid lowercase hex")
	}
	for _, bad := range []string{"0123456789ABCDEF", "0123456789abcdefg", "xyz"} {
		if isLowerHex([]byte(bad)) {
			t.Errorf("isLowerHex accepted %q", bad)
		}
	}
}
