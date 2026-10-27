package metrics

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"
)

func TestRecordAllowed(t *testing.T) {
	m := New()
	m.RecordAllowed(5 * time.Millisecond)
	m.RecordAllowed(5 * time.Millisecond)
	if got := testutil.ToFloat64(m.requests.WithLabelValues("allowed")); got != 2 {
		t.Errorf("allowed = %v, want 2", got)
	}
	if got := testutil.ToFloat64(m.requests.WithLabelValues("denied")); got != 0 {
		t.Errorf("denied = %v, want 0", got)
	}
}

func TestRecordDenied(t *testing.T) {
	m := New()
	m.RecordDenied(ReasonNoToken, time.Millisecond)
	m.RecordDenied(ReasonVerificationFailed, time.Millisecond)
	m.RecordDenied(ReasonNoToken, time.Millisecond)
	if got := testutil.ToFloat64(m.requests.WithLabelValues("denied")); got != 3 {
		t.Errorf("denied total = %v, want 3", got)
	}
	if got := testutil.ToFloat64(m.denials.WithLabelValues(ReasonNoToken)); got != 2 {
		t.Errorf("denials[no_token] = %v, want 2", got)
	}
	if got := testutil.ToFloat64(m.denials.WithLabelValues(ReasonVerificationFailed)); got != 1 {
		t.Errorf("denials[verification_failed] = %v, want 1", got)
	}
}

func TestNilSafe(t *testing.T) {
	var m *Metrics // nil
	// Must not panic.
	m.RecordAllowed(time.Millisecond)
	m.RecordDenied(ReasonSigningFailed, time.Millisecond)
	m.TrackNATSConnection(func() bool { return true })
}

// TestNATSConnectedGauge asserts the gauge reflects the tracked connection
// state at scrape time, not a value recorded earlier.
func TestNATSConnectedGauge(t *testing.T) {
	const line = "nats_oidc_callout_nats_connected "
	m := New()
	if body := scrape(t, m.Handler()); !strings.Contains(body, line+"0") {
		t.Errorf("untracked nats_connected should be 0:\n%s", body)
	}
	var connected atomic.Bool
	m.TrackNATSConnection(connected.Load)
	if body := scrape(t, m.Handler()); !strings.Contains(body, line+"0") {
		t.Errorf("nats_connected should be 0 while disconnected:\n%s", body)
	}
	connected.Store(true)
	if body := scrape(t, m.Handler()); !strings.Contains(body, line+"1") {
		t.Errorf("nats_connected should be 1 while connected:\n%s", body)
	}
	connected.Store(false)
	if body := scrape(t, m.Handler()); !strings.Contains(body, line+"0") {
		t.Errorf("nats_connected should drop back to 0:\n%s", body)
	}
}

func TestHandlerExposesMetrics(t *testing.T) {
	m := New()
	m.RecordAllowed(time.Millisecond)

	body := scrape(t, m.Handler())
	for _, want := range []string{
		"nats_oidc_callout_authorization_requests_total",
		"nats_oidc_callout_authorization_duration_seconds",
		`nats_oidc_callout_authorization_requests_total{result="allowed"} 1`,
		"go_goroutines", // standard Go collector is registered
	} {
		if !strings.Contains(body, want) {
			t.Errorf("metrics output missing %q", want)
		}
	}
}

func TestServeAndShutdown(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		m := New()
		ln := newPipeListener()
		ctx, cancel := context.WithCancel(t.Context())
		done := make(chan error, 1)
		go func() { done <- m.Serve(ctx, ln, "/metrics", nil, nil) }()

		client := ln.client(t)
		resp, err := client.Get("http://metrics/metrics")
		if err != nil {
			t.Fatalf("GET /metrics: %v", err)
		}
		b, _ := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("status = %d", resp.StatusCode)
		}
		if !strings.Contains(string(b), "nats_oidc_callout_authorization_requests_total") {
			t.Error("scraped body missing the requests metric")
		}

		cancel()
		if err := <-done; err != nil {
			t.Errorf("Serve returned error on shutdown: %v", err)
		}
	})
}

// TestHealthEndpoints asserts liveness is unconditional while readiness follows
// the supplied check.
func TestHealthEndpoints(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		m := New()
		ln := newPipeListener()
		var ready atomic.Bool
		ctx, cancel := context.WithCancel(t.Context())
		done := make(chan error, 1)
		go func() { done <- m.Serve(ctx, ln, "/metrics", ready.Load, nil) }()

		client := ln.client(t)
		status := func(path string) int {
			t.Helper()
			resp, err := client.Get("http://metrics" + path)
			if err != nil {
				t.Fatalf("GET %s: %v", path, err)
			}
			_ = resp.Body.Close()
			return resp.StatusCode
		}

		if got := status(LivenessPath); got != http.StatusOK {
			t.Errorf("%s = %d, want 200", LivenessPath, got)
		}
		if got := status(ReadinessPath); got != http.StatusServiceUnavailable {
			t.Errorf("%s while not ready = %d, want 503", ReadinessPath, got)
		}

		ready.Store(true)
		if got := status(ReadinessPath); got != http.StatusOK {
			t.Errorf("%s while ready = %d, want 200", ReadinessPath, got)
		}
		if got := status(LivenessPath); got != http.StatusOK {
			t.Errorf("%s = %d, want 200", LivenessPath, got)
		}

		cancel()
		if err := <-done; err != nil {
			t.Errorf("Serve returned error on shutdown: %v", err)
		}
	})
}

// TestShutdownClosesUnusedConnection covers a connection that never sends a
// request, as an HTTP transport leaves behind when it dials speculatively and
// then reuses another connection. http.Server.Shutdown treats it as active for
// 5s, as long as the drain timeout, so Serve must force-close it rather than
// return the drain's deadline error.
func TestShutdownClosesUnusedConnection(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		m := New()
		ln := newPipeListener()
		ctx, cancel := context.WithCancel(t.Context())
		done := make(chan error, 1)
		go func() { done <- m.Serve(ctx, ln, "/metrics", nil, nil) }()

		conn, err := ln.DialContext(t.Context(), "tcp", "metrics:80")
		if err != nil {
			t.Fatalf("dial: %v", err)
		}
		defer func() { _ = conn.Close() }()
		synctest.Wait() // the server has accepted conn and is waiting for a request

		cancel()
		if err := <-done; err != nil {
			t.Errorf("Serve returned error on shutdown: %v", err)
		}
		if _, err := conn.Read(make([]byte, 1)); !errors.Is(err, io.EOF) {
			t.Errorf("unused connection read = %v, want EOF after shutdown", err)
		}
	})
}

// TestValidatePath covers paths ServeMux would route to, or refuse next to,
// the health endpoints, including percent-encoded and uncleaned spellings.
func TestValidatePath(t *testing.T) {
	for _, p := range []string{"/metrics", "/", "/internal/metrics", "/healthz/metrics", "/readyz-ish"} {
		if err := ValidatePath(p); err != nil {
			t.Errorf("ValidatePath(%q) = %v, want nil", p, err)
		}
	}
	for _, p := range []string{
		"", "metrics", "GET /metrics", "example.com/metrics", "/{x}", "/a b",
		LivenessPath, ReadinessPath,
		"/%72eadyz", "/%68ealthz", "/./readyz", "//healthz", "/x/../readyz",
		"/%zz",
	} {
		if err := ValidatePath(p); err == nil {
			t.Errorf("ValidatePath(%q) = nil, want an error", p)
		}
	}
}

// pipeListener is an in-memory net.Listener whose connections are net.Pipe
// ends. Unlike loopback sockets, goroutines blocked on them are durably
// blocked, so synctest can advance its fake clock through server timeouts.
type pipeListener struct {
	conns     chan net.Conn
	closed    chan struct{}
	closeOnce sync.Once
}

func newPipeListener() *pipeListener {
	return &pipeListener{conns: make(chan net.Conn), closed: make(chan struct{})}
}

func (l *pipeListener) Accept() (net.Conn, error) {
	select {
	case c := <-l.conns:
		return c, nil
	case <-l.closed:
		return nil, net.ErrClosed
	}
}

func (l *pipeListener) Close() error {
	l.closeOnce.Do(func() { close(l.closed) })
	return nil
}

func (l *pipeListener) Addr() net.Addr { return pipeAddr{} }

// DialContext hands the server end of a new pipe to Accept and returns the
// client end.
func (l *pipeListener) DialContext(ctx context.Context, _, _ string) (net.Conn, error) {
	srv, cli := net.Pipe()
	select {
	case l.conns <- srv:
		return cli, nil
	case <-l.closed:
		return nil, net.ErrClosed
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

// client returns an HTTP client that dials l, whatever the request URL's host.
func (l *pipeListener) client(t *testing.T) *http.Client {
	tr := &http.Transport{DialContext: l.DialContext}
	t.Cleanup(tr.CloseIdleConnections)
	return &http.Client{Transport: tr}
}

type pipeAddr struct{}

func (pipeAddr) Network() string { return "pipe" }
func (pipeAddr) String() string  { return "pipe" }

func scrape(t *testing.T, h http.Handler) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	srv := &http.Server{Handler: h}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { _ = srv.Close() })

	resp, err := http.Get("http://" + ln.Addr().String() + "/")
	if err != nil {
		t.Fatalf("scrape: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	b, _ := io.ReadAll(resp.Body)
	return string(b)
}
