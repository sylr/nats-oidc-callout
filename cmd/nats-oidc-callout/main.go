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
	"syscall"

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

	if err := run(logger, *configPath); err != nil {
		logger.Error("service exited with error", "error", err)
		os.Exit(1)
	}
}

func run(logger *slog.Logger, configPath string) error {
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
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	v, err := buildVerifier(ctx, cfg)
	if err != nil {
		return err
	}

	// Optional Prometheus metrics endpoint. Bind synchronously so a bad address
	// fails startup, then serve in the background.
	var m *metrics.Metrics
	if cfg.Metrics.Enabled {
		m = metrics.New()
		ln, err := net.Listen("tcp", cfg.Metrics.Address)
		if err != nil {
			return fmt.Errorf("metrics listen on %q: %w", cfg.Metrics.Address, err)
		}
		go func() {
			if err := m.Serve(ctx, ln, cfg.Metrics.Path, logger); err != nil {
				logger.Error("metrics server error", "error", err)
			}
		}()
	}

	nc, err := connectNATS(cfg.NATS)
	if err != nil {
		return fmt.Errorf("connect to NATS: %w", err)
	}
	defer nc.Close()
	logger.Info("connected to NATS", "url", nc.ConnectedUrl())

	authorizer := authzcallout.New(v, &cfg.Policy, signKey, logger, m)

	opts := []callout.Option{
		callout.Authorizer(authorizer.Authorize),
		callout.ResponseSignerKey(signKey),
	}
	if xkey != nil {
		opts = append(opts, callout.EncryptionKey(xkey))
	}

	svc, err := callout.NewAuthorizationService(nc, opts...)
	if err != nil {
		return fmt.Errorf("start callout service: %w", err)
	}
	defer func() { _ = svc.Stop() }()

	go watchReloads(ctx, configPath, cfg, authorizer, logger)

	logger.Info("auth callout service started; waiting for requests")
	<-ctx.Done()
	logger.Info("shutting down")
	return nil
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
		Issuers:     issuers,
		Audiences:   cfg.Audiences,
		SigningAlgs: cfg.SigningAlgs,
		HTTPTimeout: cfg.HTTPTimeout,
		RootCAs:     rootCAs,
	})
}

// watchReloads reloads the verifier and policy on SIGHUP. Reload is best-effort:
// if the new config is invalid (parse error, OIDC discovery failure, bad policy),
// the previous config keeps serving. Settings that can't be hot-swapped (NATS
// connection, signing/xkey seeds, metrics endpoint) are reported as needing a
// restart.
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
}

func connectNATS(cfg config.NATSConfig) (*nats.Conn, error) {
	opts := []nats.Option{
		nats.Name("nats-oidc-callout"),
	}
	switch {
	case cfg.Credentials != "":
		opts = append(opts, nats.UserCredentials(cfg.Credentials))
	case cfg.Username != "":
		opts = append(opts, nats.UserInfo(cfg.Username, cfg.Password))
	}

	tlsCfg, err := tlsConfig(cfg)
	if err != nil {
		return nil, err
	}
	if tlsCfg != nil {
		opts = append(opts, nats.Secure(tlsCfg))
	}

	return nats.Connect(cfg.URL, opts...)
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
