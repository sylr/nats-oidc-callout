// Package config loads and validates the callout service configuration and the
// authorization policy file.
package config

import (
	"fmt"
	"os"
	"time"

	"github.com/sylr/nats-oidc-callout/internal/authz"
	"github.com/sylr/nats-oidc-callout/internal/metrics"
)

// Config is the top-level service configuration, loaded from a YAML file and
// optionally overridden by flags/env in cmd.
type Config struct {
	// NATS connection settings for the callout service itself.
	NATS NATSConfig `yaml:"nats"`

	// IssuerAccountSeed is the account nkey seed (SA…) used to sign response
	// user JWTs. Its public key must equal the server's auth_callout.issuer.
	IssuerAccountSeed string `yaml:"issuer_account_seed"`
	// XKeySeed is the curve seed (SX…) used to decrypt auth requests and
	// encrypt responses. Required when the server configures auth_callout.xkey.
	XKeySeed string `yaml:"xkey_seed"`

	// Audiences is the allowlist of acceptable token "aud" values. A token is
	// accepted only if at least one of its audiences is in this list.
	Audiences []string `yaml:"audiences"`

	// SigningAlgs is the allowlist of acceptable JWT signing algorithms
	// (e.g. RS256, ES384). Tokens signed with any other alg are rejected.
	SigningAlgs []string `yaml:"signing_algs"`

	// Issuers is the set of trusted OIDC issuers. A token's "iss" must match
	// one of these exactly; we never perform discovery against an unlisted
	// issuer.
	Issuers []IssuerConfig `yaml:"issuers"`

	// HTTPTimeout bounds OIDC discovery and JWKS fetches.
	HTTPTimeout time.Duration `yaml:"http_timeout"`

	// Workers is the number of authorization requests processed concurrently.
	// Requests beyond that wait in the callout library's fixed queue (5000);
	// when it is full they are dropped and the server times them out.
	Workers int `yaml:"workers"`

	// VerifyTimeout bounds the verification of one token, including any JWKS
	// refresh it waits for. Keep it below the NATS server's authorization
	// timeout (2s by default, the TLS timeout + 1s with TLS).
	VerifyTimeout time.Duration `yaml:"verify_timeout"`

	// JWKSRefreshInterval is the minimum interval between JWKS refreshes of an
	// issuer triggered by a token whose signing key is not cached. A
	// legitimate key rotation is picked up within this interval.
	JWKSRefreshInterval time.Duration `yaml:"jwks_refresh_interval"`

	// OIDCCACert is an optional path to a PEM CA bundle used to verify the TLS
	// of OIDC discovery / JWKS endpoints. Needed for issuers with a private CA,
	// e.g. an in-cluster Kubernetes API server
	// (/var/run/secrets/kubernetes.io/serviceaccount/ca.crt). Empty uses the
	// system roots.
	OIDCCACert string `yaml:"oidc_ca_cert"`

	// Metrics configures the optional Prometheus metrics endpoint.
	Metrics MetricsConfig `yaml:"metrics"`

	// Policy is the authorization policy (loaded from PolicyFile if set,
	// otherwise inline).
	Policy     authz.Policy `yaml:"policy"`
	PolicyFile string       `yaml:"policy_file"`
}

// MetricsConfig configures the optional Prometheus metrics HTTP endpoint.
type MetricsConfig struct {
	// Enabled turns the metrics endpoint on. When false, no metrics are
	// collected or served.
	Enabled bool `yaml:"enabled"`
	// Address is the listen address for the endpoint (e.g. ":9090"). Defaults
	// to DefaultMetricsAddress when enabled and unset.
	Address string `yaml:"address"`
	// Path is the HTTP path the metrics are served at. Defaults to "/metrics".
	// The same endpoint also serves /healthz (liveness) and /readyz
	// (readiness), so Path may not resolve to either of those (see
	// metrics.ValidatePath).
	Path string `yaml:"path"`
}

// NATSConfig holds the callout service's own connection to NATS. At most one
// authentication method may be set: Credentials, Username/Password or NkeySeed.
type NATSConfig struct {
	URL         string `yaml:"url"`
	Credentials string `yaml:"credentials"` // path to a .creds file
	Username    string `yaml:"username"`
	Password    string `yaml:"password"`
	// NkeySeed is a user nkey seed (SU…). The server must list its public key
	// (U…) as a user of the auth callout account and in auth_users.
	NkeySeed string `yaml:"nkey_seed"`
	// TLS enables and configures TLS for the service connection. The AWS token
	// is a bearer credential, so TLS is strongly recommended.
	CACert     string `yaml:"ca_cert"`
	ClientCert string `yaml:"client_cert"`
	ClientKey  string `yaml:"client_key"`
}

// IssuerConfig binds a trusted issuer URL to required claim values.
type IssuerConfig struct {
	// URL is the exact OIDC issuer URL (matches the token "iss" and the
	// discovery document's issuer).
	URL string `yaml:"url"`
	// RequireClaims binds the issuer to specific claim values: every key must
	// equal the given value in the verified token (keys use the flattened
	// namespace, e.g. "aws.aws_account" or "repository_owner"). For GitHub,
	// owner-level binding alone is not sufficient — pin the repository in the
	// policy as well.
	RequireClaims map[string]string `yaml:"require_claims"`
}

// DefaultHTTPTimeout is used when HTTPTimeout is unset.
const DefaultHTTPTimeout = 10 * time.Second

// Defaults for the authorization concurrency and verification settings.
const (
	DefaultWorkers             = 8
	DefaultVerifyTimeout       = 1500 * time.Millisecond
	DefaultJWKSRefreshInterval = 30 * time.Second
)

// DefaultMetricsAddress is used when the metrics endpoint is enabled without an
// explicit address.
const DefaultMetricsAddress = ":9090"

// Load reads and validates the configuration from a YAML file. Unknown fields at
// any level are rejected. If PolicyFile is set, the policy is loaded from there
// and replaces any inline policy.
func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config %q: %w", path, err)
	}
	var cfg Config
	// Strict: an unknown key anywhere (e.g. a misspelt require_claims or a
	// policy field) fails the load rather than silently dropping a restriction.
	if err := authz.DecodeStrict(data, &cfg); err != nil {
		return nil, fmt.Errorf("parse config %q: %w", path, err)
	}

	if cfg.PolicyFile != "" {
		pol, err := authz.LoadPolicy(cfg.PolicyFile)
		if err != nil {
			return nil, err
		}
		cfg.Policy = *pol
	}

	if cfg.HTTPTimeout == 0 {
		cfg.HTTPTimeout = DefaultHTTPTimeout
	}
	if cfg.Workers == 0 {
		cfg.Workers = DefaultWorkers
	}
	if cfg.VerifyTimeout == 0 {
		cfg.VerifyTimeout = DefaultVerifyTimeout
	}
	if cfg.JWKSRefreshInterval == 0 {
		cfg.JWKSRefreshInterval = DefaultJWKSRefreshInterval
	}

	if cfg.Metrics.Enabled {
		if cfg.Metrics.Address == "" {
			cfg.Metrics.Address = DefaultMetricsAddress
		}
		if cfg.Metrics.Path == "" {
			cfg.Metrics.Path = "/metrics"
		}
	}

	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	return &cfg, nil
}

// Validate checks that the configuration is internally consistent and complete
// enough to start the service. It fails fast so a bad config never reaches the
// hot path.
func (c *Config) Validate() error {
	if c.NATS.URL == "" {
		return fmt.Errorf("nats.url is required")
	}
	authMethods := 0
	for _, v := range []string{c.NATS.Credentials, c.NATS.Username, c.NATS.NkeySeed} {
		if v != "" {
			authMethods++
		}
	}
	if authMethods > 1 {
		return fmt.Errorf("nats.credentials, nats.username and nats.nkey_seed are mutually exclusive")
	}
	// Without a username the password is never sent and the service would
	// connect anonymously.
	if c.NATS.Password != "" && c.NATS.Username == "" {
		return fmt.Errorf("nats.password requires nats.username")
	}
	if c.IssuerAccountSeed == "" {
		return fmt.Errorf("issuer_account_seed is required")
	}
	if len(c.Audiences) == 0 {
		return fmt.Errorf("at least one audience is required")
	}
	if len(c.SigningAlgs) == 0 {
		return fmt.Errorf("at least one signing_alg is required")
	}
	if len(c.Issuers) == 0 {
		return fmt.Errorf("at least one issuer is required")
	}
	for i, iss := range c.Issuers {
		if iss.URL == "" {
			return fmt.Errorf("issuers[%d].url is required", i)
		}
	}
	if c.Metrics.Enabled && c.Metrics.Path != "" {
		if err := metrics.ValidatePath(c.Metrics.Path); err != nil {
			return fmt.Errorf("metrics.path: %w", err)
		}
	}
	if c.Workers < 0 {
		return fmt.Errorf("workers must not be negative")
	}
	if c.VerifyTimeout < 0 {
		return fmt.Errorf("verify_timeout must not be negative")
	}
	if c.JWKSRefreshInterval < 0 {
		return fmt.Errorf("jwks_refresh_interval must not be negative")
	}
	if err := c.Policy.Validate(); err != nil {
		return fmt.Errorf("policy: %w", err)
	}
	return nil
}
