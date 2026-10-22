package main

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/nats-io/nats-server/v2/server"
	"github.com/nats-io/nats.go"
	"github.com/nats-io/nkeys"

	"github.com/sylr/nats-oidc-callout/internal/mockoidc"
)

const (
	runAuthUser = "auth"
	runAudience = "nats://callout-run"
	runSubject  = "arn:aws:iam::123456789012:role/AppRole"
)

// runEnv is an embedded NATS server (with auth callout), a mock IdP and a
// service config file wired together, for driving the real run function.
type runEnv struct {
	t            *testing.T
	idp          *mockoidc.Server
	accountPub   string
	xkeyPub      string
	natsPort     int
	srv          *server.Server
	natsConfPath string
	configPath   string
	metricsAddr  string
}

func newRunEnv(t *testing.T) *runEnv {
	t.Helper()
	accountKP, err := nkeys.CreateAccount()
	if err != nil {
		t.Fatalf("create account key: %v", err)
	}
	accountSeed, _ := accountKP.Seed()
	accountPub, _ := accountKP.PublicKey()
	xkeyKP, err := nkeys.CreateCurveKeys()
	if err != nil {
		t.Fatalf("create xkey: %v", err)
	}
	xkeySeed, _ := xkeyKP.Seed()
	xkeyPub, _ := xkeyKP.PublicKey()

	e := &runEnv{
		t:           t,
		idp:         mockoidc.New(t),
		accountPub:  accountPub,
		xkeyPub:     xkeyPub,
		natsPort:    -1,
		metricsAddr: freeAddr(t),
	}
	e.startNATS("authpass")
	e.natsPort = e.srv.Addr().(*net.TCPAddr).Port

	cfg := fmt.Sprintf(`
nats:
  url: %q
  username: %q
  password: "authpass"
issuer_account_seed: %q
xkey_seed: %q
audiences: [%q]
signing_algs: ["RS256"]
issuers:
- url: %q
metrics:
  enabled: true
  address: %q
policy:
  rules:
  - name: app
    match:
      sub: %q
    grant:
      account: APP
`, e.srv.ClientURL(), runAuthUser, accountSeed, xkeySeed, runAudience, e.idp.Issuer(), e.metricsAddr, runSubject)
	e.configPath = filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(e.configPath, []byte(cfg), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	return e
}

// writeNATSConf writes the embedded server's config: the callout service user
// authenticates with password and gets the optional permissions block.
func (e *runEnv) writeNATSConf(password, permissions string) {
	t := e.t
	t.Helper()
	conf := fmt.Sprintf(`
listen: 127.0.0.1:%d
accounts {
  AUTH { users: [ { user: %q, password: %q %s } ] }
  APP {}
  SYS {}
}
system_account: SYS
authorization {
  auth_callout {
    issuer: %q
    account: AUTH
    auth_users: [ %q ]
    xkey: %q
  }
}
`, e.natsPort, runAuthUser, password, permissions, e.accountPub, runAuthUser, e.xkeyPub)
	if err := os.WriteFile(e.natsConfPath, []byte(conf), 0o600); err != nil {
		t.Fatalf("write server conf: %v", err)
	}
}

// startNATS starts the embedded server on the env's port (random the first
// time), accepting the callout service with the given password.
func (e *runEnv) startNATS(password string) {
	t := e.t
	t.Helper()
	e.natsConfPath = filepath.Join(t.TempDir(), "server.conf")
	e.writeNATSConf(password, "")
	opts, err := server.ProcessConfigFile(e.natsConfPath)
	if err != nil {
		t.Fatalf("process server conf: %v", err)
	}
	opts.NoLog = true
	opts.NoSigs = true
	srv, err := server.NewServer(opts)
	if err != nil {
		t.Fatalf("new server: %v", err)
	}
	go srv.Start()
	if !srv.ReadyForConnections(10 * time.Second) {
		t.Fatal("server not ready")
	}
	t.Cleanup(srv.Shutdown)
	e.srv = srv
}

// startRun runs the service in the background and returns its result channel.
func (e *runEnv) startRun(ctx context.Context) <-chan error {
	done := make(chan error, 1)
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	go func() { done <- run(ctx, logger, e.configPath) }()
	return done
}

// status returns the HTTP status of path on the metrics endpoint, or 0 if it
// is not reachable yet.
func (e *runEnv) status(path string) int {
	client := &http.Client{Timeout: time.Second}
	resp, err := client.Get("http://" + e.metricsAddr + path)
	if err != nil {
		return 0
	}
	_ = resp.Body.Close()
	return resp.StatusCode
}

// waitStatus polls path until it returns want.
func (e *runEnv) waitStatus(path string, want int, timeout time.Duration) {
	e.t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if e.status(path) == want {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	e.t.Fatalf("%s did not return %d within %v (last %d)", path, want, timeout, e.status(path))
}

// connectClient attempts a client connection authenticated by the callout.
func (e *runEnv) connectClient() error {
	tok := e.idp.Mint(e.t, mockoidc.TokenOptions{Subject: runSubject, Audience: []string{runAudience}})
	nc, err := nats.Connect(e.srv.ClientURL(), nats.Token(tok), nats.MaxReconnects(0), nats.Timeout(5*time.Second))
	if err != nil {
		return err
	}
	nc.Close()
	return nil
}

// freeAddr returns a currently unused loopback address.
func freeAddr(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	addr := ln.Addr().String()
	_ = ln.Close()
	return addr
}

// TestRunRecoversAfterBrokerOutage stops the broker while the service runs:
// readiness drops (liveness does not), and once the broker is back the service
// reconnects on its own and authorizes again. Shutdown returns nil.
func TestRunRecoversAfterBrokerOutage(t *testing.T) {
	e := newRunEnv(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := e.startRun(ctx)

	e.waitStatus("/readyz", http.StatusOK, 10*time.Second)
	if err := e.connectClient(); err != nil {
		t.Fatalf("connect before outage: %v", err)
	}

	e.srv.Shutdown()
	e.waitStatus("/readyz", http.StatusServiceUnavailable, 10*time.Second)
	if got := e.status("/healthz"); got != http.StatusOK {
		t.Errorf("/healthz during outage = %d, want 200", got)
	}
	if body := scrapeMetrics(t, e.metricsAddr); !strings.Contains(body, "nats_oidc_callout_nats_connected 0") {
		t.Errorf("nats_connected gauge not 0 during outage:\n%s", body)
	}

	e.startNATS("authpass")
	e.waitStatus("/readyz", http.StatusOK, 15*time.Second)
	if err := e.connectClient(); err != nil {
		t.Fatalf("connect after recovery: %v", err)
	}
	if body := scrapeMetrics(t, e.metricsAddr); !strings.Contains(body, "nats_oidc_callout_nats_connected 1") {
		t.Errorf("nats_connected gauge not 1 after recovery:\n%s", body)
	}

	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("run returned %v on shutdown, want nil", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("run did not return after shutdown")
	}
}

// TestRunFailsOnTerminalClose makes the broker come back with credentials the
// service no longer has. The NATS client then gives up and closes the
// connection, and run must return an error rather than idle forever.
func TestRunFailsOnTerminalClose(t *testing.T) {
	e := newRunEnv(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := e.startRun(ctx)
	e.waitStatus("/readyz", http.StatusOK, 10*time.Second)

	e.srv.Shutdown()
	e.startNATS("rotated-password")

	select {
	case err := <-done:
		if err == nil || !strings.Contains(err.Error(), "NATS connection closed permanently") {
			t.Fatalf("run returned %v, want a permanent-closure error", err)
		}
	case <-time.After(30 * time.Second):
		t.Fatal("run did not return after the connection was closed")
	}
}

// TestRunFailsWhenAuthSubscriptionRevoked reloads the broker with a config
// that no longer lets the service subscribe to the auth callout subject. The
// server drops the subscription while the connection stays up, so run must
// return an error rather than stay "ready" with nothing to serve.
func TestRunFailsWhenAuthSubscriptionRevoked(t *testing.T) {
	e := newRunEnv(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := e.startRun(ctx)
	e.waitStatus("/readyz", http.StatusOK, 10*time.Second)

	e.writeNATSConf("authpass", `, permissions: { subscribe: { allow: ">", deny: "$SYS.REQ.USER.AUTH" } }`)
	if err := e.srv.Reload(); err != nil {
		t.Fatalf("reload server: %v", err)
	}

	select {
	case err := <-done:
		if err == nil || !strings.Contains(err.Error(), "auth callout subject revoked") {
			t.Fatalf("run returned %v, want a revoked-subscription error", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("run did not return after the auth subscription was revoked")
	}
}

// TestRunFailsWhenBrokerUnreachable checks startup still fails fast.
func TestRunFailsWhenBrokerUnreachable(t *testing.T) {
	e := newRunEnv(t)
	e.srv.Shutdown()
	select {
	case err := <-e.startRun(context.Background()):
		if err == nil || !strings.Contains(err.Error(), "connect to NATS") {
			t.Fatalf("run returned %v, want a connect error", err)
		}
	case <-time.After(30 * time.Second):
		t.Fatal("run did not fail with the broker down")
	}
}

func scrapeMetrics(t *testing.T, addr string) string {
	t.Helper()
	resp, err := http.Get("http://" + addr + "/metrics")
	if err != nil {
		t.Fatalf("scrape: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	b, _ := io.ReadAll(resp.Body)
	return string(b)
}
