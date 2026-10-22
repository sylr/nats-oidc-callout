package metrics

import (
	"context"
	"io"
	"net"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
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
	m := New()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- m.Serve(ctx, ln, "/metrics", nil, nil) }()

	url := "http://" + ln.Addr().String() + "/metrics"
	resp, err := http.Get(url)
	if err != nil {
		t.Fatalf("GET %s: %v", url, err)
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
	select {
	case err := <-done:
		if err != nil {
			t.Errorf("Serve returned error on shutdown: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Serve did not return after context cancel")
	}
}

// TestHealthEndpoints asserts liveness is unconditional while readiness follows
// the supplied check.
func TestHealthEndpoints(t *testing.T) {
	m := New()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	var ready atomic.Bool
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- m.Serve(ctx, ln, "/metrics", ready.Load, nil) }()
	t.Cleanup(func() {
		cancel()
		<-done
	})

	base := "http://" + ln.Addr().String()
	status := func(path string) int {
		t.Helper()
		resp, err := http.Get(base + path)
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
