package proxy

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
)

// TestInvariant4LoopbackOnly is the named aggregate check the plan requires:
// invariant 4 (the control surface is reachable only from the machine's own
// loopback interface) holds at every layer -- the bind, the Host allowlist,
// the Origin same-origin rule, the control token, and the on-disk session
// state.
func TestInvariant4LoopbackOnly(t *testing.T) {
	t.Run("a non-loopback bind is impossible", func(t *testing.T) {
		for _, host := range []string{"0.0.0.0", "::", "192.168.1.5", "gateway.example"} {
			listener, addr, err := Listen(host, 0)
			if listener != nil {
				_ = listener.Close()
				t.Errorf("Listen(%q, 0) created a listener", host)
			}
			if addr != "" {
				t.Errorf("Listen(%q, 0) returned address %q", host, addr)
			}
			if !errors.Is(err, ErrNonLoopbackBind) {
				t.Errorf("Listen(%q, 0) error = %v, want ErrNonLoopbackBind", host, err)
			}
		}
	})

	t.Run("a foreign Host is rejected", func(t *testing.T) {
		allowed := Allowed{Port: 8787}
		if err := CheckHostOrigin("evil.example:8787", "", allowed); !errors.Is(err, ErrForeignHost) {
			t.Errorf("foreign host error = %v, want ErrForeignHost", err)
		}
		if err := CheckHostOrigin("127.0.0.1:8787", "", allowed); err != nil {
			t.Errorf("loopback host rejected: %v", err)
		}
	})

	t.Run("a cross-origin request is rejected", func(t *testing.T) {
		allowed := Allowed{Port: 8787}
		if err := CheckHostOrigin("127.0.0.1:8787", "http://evil.example:8787", allowed); !errors.Is(err, ErrCrossOrigin) {
			t.Errorf("cross-origin error = %v, want ErrCrossOrigin", err)
		}
		if err := CheckHostOrigin("127.0.0.1:8787", "http://127.0.0.1:8787", allowed); err != nil {
			t.Errorf("same-origin request rejected: %v", err)
		}
	})

	t.Run("a control request without the token is refused", func(t *testing.T) {
		token, err := NewToken()
		if err != nil {
			t.Fatalf("NewToken: %v", err)
		}
		guard := ControlGuard(token, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusNoContent)
		}))

		bare := httptest.NewRecorder()
		guard.ServeHTTP(bare, httptest.NewRequest(http.MethodPost, "/control", nil))
		if bare.Code != http.StatusUnauthorized {
			t.Errorf("request without a credential: status = %d, want 401", bare.Code)
		}

		wrong := httptest.NewRecorder()
		request := httptest.NewRequest(http.MethodPost, "/control", nil)
		request.Header.Set("Authorization", "Bearer "+token.String()+"x")
		guard.ServeHTTP(wrong, request)
		if wrong.Code != http.StatusForbidden {
			t.Errorf("request with a wrong credential: status = %d, want 403", wrong.Code)
		}

		exact := httptest.NewRecorder()
		authorized := httptest.NewRequest(http.MethodPost, "/control", nil)
		authorized.Header.Set("Authorization", "Bearer "+token.String())
		guard.ServeHTTP(exact, authorized)
		if exact.Code != http.StatusNoContent {
			t.Errorf("request with the exact credential: status = %d, want 204", exact.Code)
		}
	})

	t.Run("the session files are 0600 and token-free", func(t *testing.T) {
		dir := t.TempDir()
		token, err := NewToken()
		if err != nil {
			t.Fatalf("NewToken: %v", err)
		}
		if err := WriteSession(dir, NewRunState(8787, []string{"127.0.0.1:8787"}), token); err != nil {
			t.Fatalf("WriteSession: %v", err)
		}

		runPath, tokenPath := SessionPaths(dir)
		for _, path := range []string{runPath, tokenPath} {
			info, err := os.Stat(path)
			if err != nil {
				t.Fatalf("stat %s: %v", path, err)
			}
			if info.Mode().Perm() != 0o600 {
				t.Errorf("%s mode = %o, want 600", path, info.Mode().Perm())
			}
		}

		raw, err := os.ReadFile(runPath)
		if err != nil {
			t.Fatalf("read run.json: %v", err)
		}
		if bytes.Contains(raw, []byte(token.String())) {
			t.Error("run.json contains the control token bytes")
		}
		var fields map[string]json.RawMessage
		if err := json.Unmarshal(raw, &fields); err != nil {
			t.Fatalf("decode run.json: %v", err)
		}
		if len(fields) != 4 {
			t.Errorf("run.json has keys %v, want exactly pid, port, addrs and started_at", fields)
		}

		if err := RemoveSession(dir); err != nil {
			t.Fatalf("RemoveSession: %v", err)
		}
		for _, path := range []string{runPath, tokenPath} {
			if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
				t.Errorf("%s still exists after a clean shutdown", path)
			}
		}
	})
}
