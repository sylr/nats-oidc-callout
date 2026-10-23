// Command nats-oidc-callout is a NATS auth callout service that authenticates
// clients using AWS Web Identity Tokens (from the STS GetWebIdentityToken API).
//
// The client passes its AWS web identity token as the NATS connection token. The
// server delegates authentication to this service, which verifies the token as
// an OIDC token, maps the AWS identity to a NATS account and permissions via a
// policy file, and returns a signed user JWT.
package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"strings"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/nats-io/nats.go"
	"github.com/nats-io/nkeys"
	callout "github.com/synadia-io/callout.go"

	authzcallout "github.com/sylr/nats-oidc-callout/internal/callout"
	"github.com/sylr/nats-oidc-callout/internal/config"
	"github.com/sylr/nats-oidc-callout/internal/metrics"
	"github.com/sylr/nats-oidc-callout/internal/verifier"
)

// Build metadata, injected by goreleaser via -ldflags.
var (
	version = "dev"
	commit  = "none"
	date    = "unknown"
)

func main() {
	configPath := flag.String("config", "", "path to the service config YAML (required)")
	logLevel := flag.String("log-level", "info", "log level: debug, info, warn, error")
	showVersion := flag.Bool("version", false, "print version and exit")
	flag.Parse()

	if *showVersion {
		fmt.Printf("nats-oidc-callout %s (commit %s, built %s)\n", version, commit, date)
		return
	}

	logger := newLogger(*logLevel)

	if *configPath == "" {
		logger.Error("missing required -config flag")
		os.Exit(2)
	}

	if err := run(context.Background(), logger, *configPath); err != nil {
		logger.Error("service exited with error", "error", err)
		os.Exit(1)
	}
}

// run starts the service and blocks until ctx is cancelled or SIGINT/SIGTERM is
// received (returning nil), or until the NATS connection or the callout service
// stops for good (returning an error, so the process exits non-zero and its
// supervisor restarts it).
func run(ctx context.Context, logger *slog.Logger, configPath string) error {
	cfg, err := config.Load(configPath)
	if err != nil {
		return err
	}

	signKey, err := nkeys.FromSeed([]byte(cfg.IssuerAccountSeed))
	if err != nil {
		return fmt.Errorf("load issuer account seed: %w", err)
	}

	var xkey nkeys.KeyPair
	if cfg.XKeySeed != "" {
		xkey, err = nkeys.FromSeed([]byte(cfg.XKeySeed))
		if err != nil {
			return fmt.Errorf("load xkey seed: %w", err)
		}
	}

	// Build the verifier (performs OIDC discovery) before connecting, so a bad
	// issuer config fails fast.
	ctx, cancel := signal.NotifyContext(ctx, syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	v, err := buildVerifier(ctx, cfg)
	if err != nil {
		return err
	}

	// Readiness: the NATS connection is up and the callout service is running.
	// nc and svc are only read once started is set, after both are assigned.
	var (
		nc      *nats.Conn
		svc     *callout.AuthorizationService
		started atomic.Bool
	)
	ready := func() bool {
		return started.Load() && nc.Status() == nats.CONNECTED && !svc.Service.Stopped()
	}

	// Optional Prometheus metrics endpoint, which also serves the health
	// probes. Bind synchronously so a bad address fails startup, then serve in
	// the background.
	var m *metrics.Metrics
	if cfg.Metrics.Enabled {
		m = metrics.New()
		ln, err := net.Listen("tcp", cfg.Metrics.Address)
		if err != nil {
			return fmt.Errorf("metrics listen on %q: %w", cfg.Metrics.Address, err)
		}
		go func() {
			if err := m.Serve(ctx, ln, cfg.Metrics.Path, ready, logger); err != nil {
				logger.Error("metrics server error", "error", err)
			}
		}()
	}

	nc, natsFailed, err := connectNATS(cfg.NATS, logger)
	if err != nil {
		return fmt.Errorf("connect to NATS: %w", err)
	}
	// Deferred so every exit path (shutdown or failure) drains then closes the
	// connection without stopping the callout service; see stopService.
	defer stopService(nc)
	m.TrackNATSConnection(nc.IsConnected)
	logger.Info("connected to NATS", "url", nc.ConnectedUrl())

	authorizer := authzcallout.New(v, &cfg.Policy, signKey, logger, m, cfg.VerifyTimeout)

	// The callout library reports every error through this callback. ErrService
	// marks a failure of the underlying NATS micro service, which then stops
	// itself and no longer receives authorization requests.
	svcFailed := make(chan error, 1)
	opts := []callout.Option{
		callout.Authorizer(authorizer.Authorize),
		callout.ResponseSignerKey(signKey),
		// Async workers: authorizations run concurrently, so one slow request (a
		// JWKS refresh) does not hold up the others.
		callout.AsyncWorkers(cfg.Workers),
		callout.ErrCallback(func(err error) {
			if errors.Is(err, callout.ErrService) {
				select {
				case svcFailed <- err:
				default:
				}
			}
		}),
	}
	if xkey != nil {
		opts = append(opts, callout.EncryptionKey(xkey))
	}

	svc, err = callout.NewAuthorizationService(nc, opts...)
	if err != nil {
		return fmt.Errorf("start callout service: %w", err)
	}
	// The service is never stopped explicitly; see stopService.
	started.Store(true)

	go watchReloads(ctx, configPath, cfg, authorizer, logger)

	logger.Info("auth callout service started; waiting for requests")
	select {
	case <-ctx.Done():
		logger.Info("shutting down")
		return nil
	case err := <-natsFailed:
		return err
	case err := <-svcFailed:
		return fmt.Errorf("callout service stopped: %w", err)
	}
}

// shutdownDrainTimeout bounds how long shutdown waits for the NATS connection
// to drain before closing it.
const shutdownDrainTimeout = 10 * time.Second

// stopService stops authorization traffic on shutdown: it drains the NATS
// connection (bounded by shutdownDrainTimeout), then closes it, which ends
// every subscription delivery.
//
// It deliberately never calls svc.Stop(). With async workers, callout.go's Stop
// closes the worker channel while micro has only started draining the
// subscriptions, and a delivery still in its callback then panics sending on
// the closed channel. Ordering cannot rule that out: Drain is asynchronous and
// can end abnormally (disconnect, drain timeout) before the callbacks return.
// Leaving the channel open makes the panic impossible; the idle workers stay
// blocked on it and end with the process. Requests still queued can no longer
// be answered: the server times them out and the clients retry.
func stopService(nc *nats.Conn) {
	if err := nc.Drain(); err == nil {
		deadline := time.Now().Add(shutdownDrainTimeout)
		for !nc.IsClosed() && time.Now().Before(deadline) {
			time.Sleep(10 * time.Millisecond)
		}
	}
	nc.Close()
}

// buildVerifier constructs the OIDC verifier from the configured issuers
// (performing discovery). Used at startup and on reload.
func buildVerifier(ctx context.Context, cfg *config.Config) (*verifier.Verifier, error) {
	issuers := make([]verifier.IssuerOption, 0, len(cfg.Issuers))
	for _, iss := range cfg.Issuers {
		issuers = append(issuers, verifier.IssuerOption{
			URL:           iss.URL,
			RequireClaims: iss.RequireClaims,
		})
	}

	var rootCAs *x509.CertPool
	if cfg.OIDCCACert != "" {
		pem, err := os.ReadFile(cfg.OIDCCACert)
		if err != nil {
			return nil, fmt.Errorf("read oidc_ca_cert: %w", err)
		}
		rootCAs = x509.NewCertPool()
		if !rootCAs.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("no certificates found in oidc_ca_cert %q", cfg.OIDCCACert)
		}
	}

	return verifier.New(ctx, verifier.Options{
		Issuers:             issuers,
		Audiences:           cfg.Audiences,
		SigningAlgs:         cfg.SigningAlgs,
		HTTPTimeout:         cfg.HTTPTimeout,
		RootCAs:             rootCAs,
		JWKSRefreshInterval: cfg.JWKSRefreshInterval,
	})
}

// watchReloads reloads the verifier and policy on SIGHUP. Reload is best-effort:
// if the new config is invalid (parse error, OIDC discovery failure, bad policy),
// the previous config keeps serving. Settings that can't be hot-swapped (NATS
// connection, signing/xkey seeds, metrics endpoint, workers, verify timeout)
// are reported as needing a restart.
//
// startup is the config the process started with. It is never replaced: the
// restart-only settings it holds are the ones actually in effect, so every
// reload is compared against it rather than against the previous reload.
func watchReloads(ctx context.Context, configPath string, startup *config.Config, a *authzcallout.Authorizer, logger *slog.Logger) {
	hup := make(chan os.Signal, 1)
	signal.Notify(hup, syscall.SIGHUP)
	defer signal.Stop(hup)

	for {
		select {
		case <-ctx.Done():
			return
		case <-hup:
			logger.Info("SIGHUP received; reloading config", "path", configPath)
			reloadConfig(ctx, configPath, startup, a, logger)
		}
	}
}

// reloadConfig performs a single reload: it re-reads configPath, warns about
// restart-only settings that differ from startup, and swaps in the new verifier
// and policy if they build successfully.
func reloadConfig(ctx context.Context, configPath string, startup *config.Config, a *authzcallout.Authorizer, logger *slog.Logger) {
	newCfg, err := config.Load(configPath)
	if err != nil {
		logger.Error("config reload failed; keeping previous config", "error", err)
		return
	}
	warnUnreloadable(startup, newCfg, logger)
	v, err := buildVerifier(ctx, newCfg)
	if err != nil {
		logger.Error("config reload failed; keeping previous config", "error", err)
		return
	}
	a.Reload(v, &newCfg.Policy)
	logger.Info("config reloaded",
		"issuers", len(newCfg.Issuers), "policy_rules", len(newCfg.Policy.Rules))
}

// warnUnreloadable logs a warning for each setting that changed but can only take
// effect after a restart.
func warnUnreloadable(oldCfg, newCfg *config.Config, logger *slog.Logger) {
	if oldCfg.NATS != newCfg.NATS {
		logger.Warn("nats connection settings changed; restart required to apply")
	}
	if oldCfg.IssuerAccountSeed != newCfg.IssuerAccountSeed || oldCfg.XKeySeed != newCfg.XKeySeed {
		logger.Warn("signing/xkey seeds changed; restart required to apply")
	}
	if oldCfg.Metrics != newCfg.Metrics {
		logger.Warn("metrics settings changed; restart required to apply")
	}
	if oldCfg.Workers != newCfg.Workers || oldCfg.VerifyTimeout != newCfg.VerifyTimeout {
		logger.Warn("workers/verify_timeout changed; restart required to apply")
	}
}

// NATS reconnect policy. The service reconnects forever: giving up would leave
// a live process that can no longer authorize anyone.
const (
	natsReconnectWait      = 2 * time.Second
	natsReconnectJitter    = 500 * time.Millisecond
	natsReconnectJitterTLS = time.Second
)

// connectNATS dials NATS with an unlimited reconnect policy and logs connection
// state transitions and asynchronous errors. The returned channel receives an
// error when the connection becomes permanently unusable for the callout:
//   - it is closed for good (on shutdown, or when the client gives up, e.g. the
//     server rejects its credentials twice in a row on reconnect);
//   - the server revokes the subscription to the auth callout subject (a
//     permissions change on reload or reconnect). The connection stays up but
//     no authorization request reaches the service any more, and nats.go only
//     resubscribes after a reconnect, so the process must restart.
func connectNATS(cfg config.NATSConfig, logger *slog.Logger) (*nats.Conn, <-chan error, error) {
	failed := make(chan error, 1)
	fail := func(err error) {
		select {
		case failed <- err:
		default:
		}
	}
	authSubViolation := fmt.Sprintf("Subscription to %q", callout.SysRequestUserAuthSubj)
	opts := []nats.Option{
		nats.Name("nats-oidc-callout/" + version),
		nats.MaxReconnects(-1),
		nats.ReconnectWait(natsReconnectWait),
		nats.ReconnectJitter(natsReconnectJitter, natsReconnectJitterTLS),
		nats.DisconnectErrHandler(func(_ *nats.Conn, err error) {
			logger.Warn("disconnected from NATS; reconnecting", "error", err)
		}),
		nats.ReconnectHandler(func(nc *nats.Conn) {
			logger.Info("reconnected to NATS", "url", nc.ConnectedUrl())
		}),
		nats.ClosedHandler(func(nc *nats.Conn) {
			logger.Info("NATS connection closed", "error", nc.LastError())
			err := errors.New("NATS connection closed permanently")
			if last := nc.LastError(); last != nil {
				err = fmt.Errorf("%w: %w", err, last)
			}
			fail(err)
		}),
		// The callout's micro service wraps this handler and still calls it.
		// Permission violations arrive here with a nil subscription, so micro
		// neither reports them to the callout library nor stops the service.
		nats.ErrorHandler(func(_ *nats.Conn, _ *nats.Subscription, err error) {
			logger.Warn("NATS asynchronous error", "error", err)
			if errors.Is(err, nats.ErrPermissionViolation) && strings.Contains(err.Error(), authSubViolation) {
				fail(fmt.Errorf("subscription to the auth callout subject revoked: %w", err))
			}
		}),
	}
	switch {
	case cfg.Credentials != "":
		opts = append(opts, nats.UserCredentials(cfg.Credentials))
	case cfg.Username != "":
		opts = append(opts, nats.UserInfo(cfg.Username, cfg.Password))
	}

	tlsCfg, err := tlsConfig(cfg)
	if err != nil {
		return nil, nil, err
	}
	if tlsCfg != nil {
		opts = append(opts, nats.Secure(tlsCfg))
	}

	nc, err := nats.Connect(cfg.URL, opts...)
	if err != nil {
		return nil, nil, err
	}
	return nc, failed, nil
}

func tlsConfig(cfg config.NATSConfig) (*tls.Config, error) {
	if cfg.ClientCert == "" && cfg.ClientKey == "" && cfg.CACert == "" {
		return nil, nil
	}
	tlsCfg := &tls.Config{MinVersion: tls.VersionTLS12}
	if cfg.ClientCert != "" || cfg.ClientKey != "" {
		if cfg.ClientCert == "" || cfg.ClientKey == "" {
			return nil, errors.New("both client_cert and client_key are required for mTLS")
		}
		cert, err := tls.LoadX509KeyPair(cfg.ClientCert, cfg.ClientKey)
		if err != nil {
			return nil, fmt.Errorf("load client certificate: %w", err)
		}
		tlsCfg.Certificates = []tls.Certificate{cert}
	}
	if cfg.CACert != "" {
		pool := x509.NewCertPool()
		pem, err := os.ReadFile(cfg.CACert)
		if err != nil {
			return nil, fmt.Errorf("read CA cert: %w", err)
		}
		if !pool.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("no certificates found in CA cert %q", cfg.CACert)
		}
		tlsCfg.RootCAs = pool
	}
	return tlsCfg, nil
}

func newLogger(level string) *slog.Logger {
	var lvl slog.Level
	switch level {
	case "debug":
		lvl = slog.LevelDebug
	case "warn":
		lvl = slog.LevelWarn
	case "error":
		lvl = slog.LevelError
	default:
		lvl = slog.LevelInfo
	}
	return slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{Level: lvl}))
}
