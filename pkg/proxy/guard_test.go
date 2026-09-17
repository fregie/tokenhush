package proxy

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

func TestCheckHostOriginAcceptsLoopbackHosts(t *testing.T) {
	allowed := Allowed{Port: 8787}
	for _, host := range []string{
		"127.0.0.1:8787",
		"localhost:8787",
		"[::1]:8787",
		"LOCALHOST:8787",
		" 127.0.0.1:8787 ",
	} {
		if err := CheckHostOrigin(host, "", allowed); err != nil {
			t.Errorf("CheckHostOrigin(%q, \"\", %+v) = %v, want nil", host, allowed, err)
		}
	}
}

func TestCheckHostOriginRejectsForeignHosts(t *testing.T) {
	allowed := Allowed{Port: 8787}
	hosts := []string{
		"evil.example:8787",
		"localhost.evil.example:8787",
		"127.0.0.1.evil.example:8787",
		"0.0.0.0:8787",
		"192.168.1.5:8787",
		"127.0.0.1:9999",
		"localhost",
		"127.0.0.1:notaport",
		"127.0.0.1:8787/path",
		"user@127.0.0.1:8787",
		"::1:8787",
		"",
	}
	for _, host := range hosts {
		err := CheckHostOrigin(host, "", allowed)
		if !errors.Is(err, ErrForeignHost) {
			t.Errorf("CheckHostOrigin(%q, \"\", %+v) = %v, want ErrForeignHost", host, allowed, err)
		}
	}
}

func TestCheckHostOriginOriginTable(t *testing.T) {
	allowed := Allowed{Port: 8787}
	accept := []struct{ host, origin string }{
		{"127.0.0.1:8787", "http://127.0.0.1:8787"},
		{"localhost:8787", "http://localhost:8787"},
		{"[::1]:8787", "http://[::1]:8787"},
		{"127.0.0.1:8787", ""},
	}
	for _, tc := range accept {
		if err := CheckHostOrigin(tc.host, tc.origin, allowed); err != nil {
			t.Errorf("CheckHostOrigin(%q, %q, %+v) = %v, want nil", tc.host, tc.origin, allowed, err)
		}
	}

	reject := []struct{ host, origin string }{
		{"127.0.0.1:8787", "http://evil.example:8787"},
		{"127.0.0.1:8787", "http://127.0.0.1:9999"},
		{"127.0.0.1:8787", "http://127.0.0.1"},
		{"127.0.0.1:8787", "https://127.0.0.1:8787"},
		{"127.0.0.1:8787", "null"},
		{"127.0.0.1:8787", "http://user@127.0.0.1:8787"},
		{"127.0.0.1:8787", "http://127.0.0.1:8787/path"},
		{"127.0.0.1:8787", "http://127.0.0.1:8787?query=1"},
		{"127.0.0.1:8787", "//127.0.0.1:8787"},
		{"127.0.0.1:8787", "http://localhost:8787"},
		{"127.0.0.1:8787", "http://[::1]:8787"},
	}
	for _, tc := range reject {
		err := CheckHostOrigin(tc.host, tc.origin, allowed)
		if !errors.Is(err, ErrCrossOrigin) {
			t.Errorf("CheckHostOrigin(%q, %q, %+v) = %v, want ErrCrossOrigin", tc.host, tc.origin, allowed, err)
		}
	}
}

func TestCheckHostOriginCustomAllowlist(t *testing.T) {
	allowed := Allowed{Hosts: []string{"gateway.local"}, Port: 8080}
	if err := CheckHostOrigin("gateway.local:8080", "", allowed); err != nil {
		t.Errorf("custom allowlist rejected its own host: %v", err)
	}
	if err := CheckHostOrigin("127.0.0.1:8080", "", allowed); !errors.Is(err, ErrForeignHost) {
		t.Errorf("custom allowlist accepted 127.0.0.1: %v", err)
	}
	if err := CheckHostOrigin("127.0.0.1:1234", "", Allowed{}); err != nil {
		t.Errorf("zero Allowed must not check the port: %v", err)
	}
}

func TestTokenMatchesOnlyTheExactCredential(t *testing.T) {
	token, err := NewToken()
	if err != nil {
		t.Fatalf("NewToken: %v", err)
	}
	value := token.String()
	if len(value) != 2*TokenBytes {
		t.Fatalf("token length = %d, want %d hex chars", len(value), 2*TokenBytes)
	}
	if token.IsZero() {
		t.Fatal("NewToken returned the zero token")
	}

	other, err := NewToken()
	if err != nil {
		t.Fatalf("second NewToken: %v", err)
	}
	if value == other.String() {
		t.Fatal("two tokens are identical")
	}

	if !token.Matches(value) {
		t.Error("token does not match its own credential")
	}
	if token.Matches(other.String()) {
		t.Error("token matches another token")
	}
	if token.Matches("") {
		t.Error("token matches the empty credential")
	}
	if token.Matches(value[:len(value)-1]) {
		t.Error("token matches a truncated credential")
	}
	wrong := []byte(value)
	wrong[0] ^= 0x01
	if token.Matches(string(wrong)) {
		t.Error("token matches a one-bit mutation")
	}
	zero := Token{}
	if zero.Matches("") || zero.Matches("anything") {
		t.Error("the zero token must never match")
	}

	if err := token.AuthorizeControl("Bearer " + value); err != nil {
		t.Errorf("AuthorizeControl(exact bearer) = %v, want nil", err)
	}
	for _, header := range []string{"", "Bearer", "Bearer ", "Basic " + value, "Bearer " + other.String(), "bearer", value} {
		if err := token.AuthorizeControl(header); !errors.Is(err, ErrControlUnauthorized) {
			t.Errorf("AuthorizeControl(%q) = %v, want ErrControlUnauthorized", header, err)
		}
	}
}

func TestControlGuardRefusesWithoutToken(t *testing.T) {
	token, err := NewToken()
	if err != nil {
		t.Fatalf("NewToken: %v", err)
	}
	reached := false
	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		reached = true
		w.WriteHeader(http.StatusNoContent)
	})
	guard := ControlGuard(token, next)

	cases := []struct {
		name       string
		header     string
		wantStatus int
		wantNext   bool
	}{
		{"no credential", "", http.StatusUnauthorized, false},
		{"wrong credential", "Bearer " + string(bytes.Repeat([]byte("a"), 2*TokenBytes)), http.StatusForbidden, false},
		{"exact credential", "Bearer " + token.String(), http.StatusNoContent, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			reached = false
			recorder := httptest.NewRecorder()
			request := httptest.NewRequest(http.MethodPost, "/control", nil)
			if tc.header != "" {
				request.Header.Set("Authorization", tc.header)
			}
			guard.ServeHTTP(recorder, request)
			if recorder.Code != tc.wantStatus {
				t.Errorf("status = %d, want %d", recorder.Code, tc.wantStatus)
			}
			if reached != tc.wantNext {
				t.Errorf("next handler reached = %v, want %v", reached, tc.wantNext)
			}
		})
	}
}

func TestWriteSessionIsAtomicTokenFreeAndSixHundred(t *testing.T) {
	dir := t.TempDir()
	token, err := NewToken()
	if err != nil {
		t.Fatalf("NewToken: %v", err)
	}
	state := NewRunState(8787, []string{"127.0.0.1:8787"})
	if err := WriteSession(dir, state, token); err != nil {
		t.Fatalf("WriteSession: %v", err)
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("ReadDir: %v", err)
	}
	if len(entries) != 2 {
		t.Errorf("session dir has %d entries, want exactly run.json and control.token", len(entries))
	}
	for _, entry := range entries {
		info, err := entry.Info()
		if err != nil {
			t.Fatalf("stat %s: %v", entry.Name(), err)
		}
		if info.Mode().Perm() != 0o600 {
			t.Errorf("%s mode = %o, want 600", entry.Name(), info.Mode().Perm())
		}
	}

	runPath, tokenPath := SessionPaths(dir)
	runRaw, err := os.ReadFile(runPath)
	if err != nil {
		t.Fatalf("read run.json: %v", err)
	}
	if bytes.Contains(runRaw, []byte(token.String())) {
		t.Error("run.json contains the control token bytes")
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(runRaw, &fields); err != nil {
		t.Fatalf("decode run.json: %v", err)
	}
	wantKeys := []string{"addrs", "pid", "port", "started_at"}
	if len(fields) != len(wantKeys) {
		t.Fatalf("run.json keys = %v, want exactly %v", fields, wantKeys)
	}
	for _, key := range wantKeys {
		if _, ok := fields[key]; !ok {
			t.Errorf("run.json is missing key %q", key)
		}
	}

	readBack, err := ReadSession(dir)
	if err != nil {
		t.Fatalf("ReadSession: %v", err)
	}
	if readBack.PID != state.PID || readBack.Port != state.Port || readBack.StartedAt != state.StartedAt {
		t.Errorf("ReadSession = %+v, want %+v", readBack, state)
	}

	tokenRaw, err := os.ReadFile(tokenPath)
	if err != nil {
		t.Fatalf("read control.token: %v", err)
	}
	if !bytes.Contains(tokenRaw, []byte(token.String())) {
		t.Error("control.token does not contain the token")
	}
}

func TestRemoveSessionIsIdempotent(t *testing.T) {
	dir := t.TempDir()
	token, err := NewToken()
	if err != nil {
		t.Fatalf("NewToken: %v", err)
	}
	if err := WriteSession(dir, NewRunState(8787, nil), token); err != nil {
		t.Fatalf("WriteSession: %v", err)
	}
	for attempt := 1; attempt <= 2; attempt++ {
		if err := RemoveSession(dir); err != nil {
			t.Fatalf("RemoveSession attempt %d: %v", attempt, err)
		}
	}
	runPath, tokenPath := SessionPaths(dir)
	for _, path := range []string{runPath, tokenPath} {
		if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
			t.Errorf("%s still exists after RemoveSession", filepath.Base(path))
		}
	}
}
