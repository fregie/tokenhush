package platform

import (
	"errors"
	"strings"
	"testing"
)

// TestServiceStub pins the W2.3 contract (docs/deployment.md §4): the service-lifecycle
// entry points exist but perform no host mutation in V1. Every call must fail
// with a typed error wrapping ErrNotImplemented so callers can classify it via
// errors.Is and print roadmap guidance instead of a raw failure.
func TestServiceStub(t *testing.T) {
	t.Parallel()

	calls := []struct {
		name string
		call func() error
	}{
		{name: "InstallService", call: InstallService},
		{name: "UninstallService", call: UninstallService},
	}

	for _, tc := range calls {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			err := tc.call()
			if err == nil {
				t.Fatalf("%s() error = nil, want an error wrapping ErrNotImplemented", tc.name)
			}
			if !errors.Is(err, ErrNotImplemented) {
				t.Fatalf("%s() error = %v, want errors.Is(err, ErrNotImplemented)", tc.name, err)
			}

			// The message a user sees must say the capability is deferred past
			// V1 and point at the roadmap; a bare sentinel would be unclear.
			msg := err.Error()
			for _, want := range []string{"not implemented in V1", "roadmap"} {
				if !strings.Contains(msg, want) {
					t.Errorf("%s() error = %q, want it to contain %q", tc.name, msg, want)
				}
			}
		})
	}
}
