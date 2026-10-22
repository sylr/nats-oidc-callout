package metrics

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"path"
	"strings"
	"time"
)

// DefaultPath is used when no metrics path is configured.
const DefaultPath = "/metrics"

// Health endpoint paths served next to the metrics.
const (
	// LivenessPath answers 200 while the process is up. It deliberately does
	// not depend on NATS, so a broker outage doesn't trigger restart storms.
	LivenessPath = "/healthz"
	// ReadinessPath answers 200 only while the instance can serve
	// authorizations, 503 otherwise.
	ReadinessPath = "/readyz"
)

// Serve exposes the metrics handler at path, plus the LivenessPath and
// ReadinessPath health endpoints, on the given listener until ctx is cancelled,
// then shuts the server down gracefully. ready reports readiness; nil means
// always ready. The caller creates the listener (so bind errors surface at
// startup) and Serve takes ownership of it. Serve blocks; run it in a goroutine.
func (m *Metrics) Serve(ctx context.Context, ln net.Listener, path string, ready func() bool, logger *slog.Logger) error {
	if path == "" {
		path = DefaultPath
	}
	if logger == nil {
		logger = slog.Default()
	}

	srv := &http.Server{
		Handler:           newMux(m.Handler(), path, ready),
		ReadHeaderTimeout: 5 * time.Second,
	}

	errCh := make(chan error, 1)
	go func() {
		logger.Info("metrics endpoint listening", "address", ln.Addr().String(), "path", path)
		if err := srv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
		}
	}()

	select {
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		return srv.Shutdown(shutdownCtx)
	case err := <-errCh:
		return err
	}
}

// newMux routes path to the metrics handler next to the health endpoints. It
// panics if path conflicts with them; ValidatePath checks that up front.
func newMux(metricsHandler http.Handler, path string, ready func() bool) *http.ServeMux {
	mux := http.NewServeMux()
	mux.Handle(path, metricsHandler)
	mux.HandleFunc(LivenessPath, func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("ok\n"))
	})
	mux.HandleFunc(ReadinessPath, func(w http.ResponseWriter, _ *http.Request) {
		if ready != nil && !ready() {
			http.Error(w, "not ready", http.StatusServiceUnavailable)
			return
		}
		_, _ = w.Write([]byte("ok\n"))
	})
	return mux
}

// ValidatePath reports an error if path cannot serve the metrics next to the
// health endpoints: it must be a literal absolute path (no ServeMux method,
// host or wildcard syntax) that does not denote LivenessPath or ReadinessPath,
// even once percent-decoded and cleaned the way ServeMux matches requests.
func ValidatePath(p string) (err error) {
	if !strings.HasPrefix(p, "/") || strings.ContainsAny(p, "{} \t") {
		return fmt.Errorf("metrics path %q must be a literal absolute path", p)
	}
	decoded, err := url.PathUnescape(p)
	if err != nil {
		return fmt.Errorf("metrics path %q: %w", p, err)
	}
	if c := path.Clean(decoded); c == LivenessPath || c == ReadinessPath {
		return fmt.Errorf("metrics path %q is reserved for the health endpoints", p)
	}
	// Catch anything else ServeMux would refuse when Serve registers it.
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("metrics path %q cannot be served: %v", p, r)
		}
	}()
	newMux(http.NotFoundHandler(), p, nil)
	return nil
}
