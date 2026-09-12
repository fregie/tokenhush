package gateway

import (
	"context"
	"errors"
	"net"
	"net/http"

	"github.com/fregie/tokenhush/pkg/config"
	"github.com/fregie/tokenhush/pkg/proxy"
)

// ResolveConfig returns cfg when set, otherwise loads it from path or the
// platform default. A partially populated cfg is never mutated. Both the
// core CLI and the Pro daemon build Options.Core through it.
func ResolveConfig(cfg *config.Config, path string) (*config.Config, error) {
	if cfg != nil {
		return cfg, nil
	}
	if path != "" {
		return config.LoadFile(path)
	}
	return config.Load()
}

// serveUntilDone starts one Serve goroutine per loopback listener and blocks
// until ctx is cancelled or a listener fails. It then shuts the server down
// with a bounded deadline and drains both goroutines, so no request is still
// writing when Run removes the session files.
func serveUntilDone(ctx context.Context, srv *http.Server, ls *proxy.Listeners) error {
	errCh := make(chan error, 2)
	for _, listener := range []net.Listener{ls.V4(), ls.V6()} {
		go func(l net.Listener) { errCh <- srv.Serve(l) }(listener)
	}

	var runErr error
	served := 0
	select {
	case <-ctx.Done():
	case err := <-errCh:
		served++
		if !errors.Is(err, http.ErrServerClosed) {
			runErr = err
		}
	}

	shutdownCtx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
	defer cancel()
	if err := srv.Shutdown(shutdownCtx); err != nil && runErr == nil {
		runErr = err
	}
	for served < 2 {
		err := <-errCh
		served++
		if err != nil && !errors.Is(err, http.ErrServerClosed) && runErr == nil {
			runErr = err
		}
	}
	return runErr
}

// listenerAddrs renders the bound addresses in v4, v6 order.
func listenerAddrs(ls *proxy.Listeners) []string {
	addrs := make([]string, 0, 2)
	for _, addr := range ls.Addrs() {
		addrs = append(addrs, addr.String())
	}
	return addrs
}
