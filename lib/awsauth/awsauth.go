// Package awsauth mints AWS web identity tokens (via the STS GetWebIdentityToken
// API) ready to hand to the NATS Go SDK, for authenticating to a NATS server
// protected by an auth-callout service that verifies AWS OIDC tokens.
//
// # Token lifetime and refresh
//
// NATS auth callout runs only at CONNECT; there is no in-band token refresh.
// The AWS web identity token is a one-shot connect credential: the callout
// verifies it once and discards it. The NATS user JWT the callout issues back
// governs the live connection, and its expiry is capped to the AWS token's own
// expiry (typically a few minutes). When that user JWT expires, the server
// closes the connection with an authentication-expired error and the NATS
// client reconnects — and on every (re)connect the client re-invokes its token
// handler to obtain a fresh token.
//
// For this reason [TokenSource.NATSOption] uses nats.TokenHandler (a token is
// minted per connect), never a captured string. A static nats.Token would
// resend the same, now-expired token on reconnect; after two identical auth
// failures on the same server the client gives up reconnecting. Callers must
// therefore keep reconnection enabled (the nats.go default) for long-lived
// connections. Relevant nats.go knobs for resilience: nats.IgnoreAuthErrorAbort
// (keep retrying across auth errors, e.g. transient STS outages that yield an
// empty token), the usual reconnect settings, and nats.RetryOnFailedConnect for
// initial-connect resilience. Do not combine NATSOption with nats.Token or a
// token in the URL: nats.go returns ErrTokenAlreadySet if both are set.
//
// # Caching
//
// Set Config.CachePath to reuse a minted token across separate processes — for
// example successive `nats` CLI invocations, which would otherwise call STS on
// every command. Token returns the cached token (audience permitting) as long
// as it has not expired, calling STS synchronously only on a miss. When the
// cached token is within Config.CacheRefreshBefore of expiry (default 10s),
// Token still returns it but also mints a replacement in the background and
// caches it for subsequent calls. Use DefaultCachePath for a per-audience
// location under the user cache directory. The token is a credential: the cache
// file is written atomically with 0600 permissions.
//
// # Versioning
//
// This is a nested Go module. External consumers import it as
// github.com/sylr/nats-jwt-callout/lib/awsauth and version it with
// subdirectory-prefixed tags (e.g. lib/awsauth/vX.Y.Z), independent of the
// repository's root tags.
package awsauth

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/nats-io/nats.go"
)

// Defaults applied when the corresponding Config field is left zero.
const (
	// DefaultSigningAlgorithm is the JWT signing algorithm requested from STS.
	DefaultSigningAlgorithm = "RS256"
	// DefaultDuration is the requested token lifetime.
	DefaultDuration = 5 * time.Minute
	// DefaultFetchTimeout bounds a single token fetch performed by the
	// nats.Option when NATSOption is called with a non-positive timeout.
	DefaultFetchTimeout = 10 * time.Second
	// DefaultCacheRefreshBefore is how close to expiry a cached token may be
	// before Token refreshes it in the background (see Config.CacheRefreshBefore).
	DefaultCacheRefreshBefore = 10 * time.Second
)

// STS GetWebIdentityToken accepts a requested lifetime in the 60s..3600s window.
// Validate against it so bad values fail locally instead of as a surprise 400.
const (
	minDuration = 60 * time.Second
	maxDuration = 3600 * time.Second

	// maxAudienceLen is the STS-documented maximum length of an audience value.
	maxAudienceLen = 1000
)

// supportedSigningAlgorithms are the JWT signing algorithms STS accepts for
// GetWebIdentityToken; an empty Config.SigningAlgorithm defaults to RS256.
var supportedSigningAlgorithms = map[string]struct{}{
	"RS256": {},
	"ES384": {},
}

// stsAPI is the subset of the STS client used here; an interface so tests can
// inject a fake without touching the network.
type stsAPI interface {
	GetWebIdentityToken(context.Context, *sts.GetWebIdentityTokenInput, ...func(*sts.Options)) (*sts.GetWebIdentityTokenOutput, error)
}

// Config configures a TokenSource.
type Config struct {
	// Audience is the token audience requested from STS. It must match an
	// audience the callout service allows. Required.
	Audience string
	// SigningAlgorithm is the JWT signing algorithm requested from STS.
	// Defaults to DefaultSigningAlgorithm ("RS256") when empty; when set it must
	// be one STS supports ("RS256" or "ES384").
	SigningAlgorithm string
	// Duration is the requested token lifetime, sent as DurationSeconds.
	// Defaults to DefaultDuration (5m) when zero. When set it must be a whole
	// number of seconds within the STS-allowed window (60s..3600s).
	Duration time.Duration
	// CachePath, when non-empty, enables on-disk caching of the minted token so
	// that consecutive processes (e.g. successive CLI invocations) reuse it
	// instead of calling STS each time. The token is read from and written to
	// this file (created with 0600, parent directory with 0700, written
	// atomically). A cached token (with a matching audience) is reused as long
	// as it has not expired; only a missing, corrupt, expired, or wrong-audience
	// cache forces a blocking mint. See DefaultCachePath for a per-audience
	// location under the user cache dir.
	CachePath string
	// CacheRefreshBefore is how close to expiry a cached token may be before
	// Token, having returned it, mints a replacement in the background and
	// caches it for subsequent calls. Defaults to DefaultCacheRefreshBefore
	// (10s). Ignored when CachePath is empty. Note that a process which exits
	// immediately after Token may terminate before the background refresh
	// completes; the next call then mints synchronously once the token expires.
	CacheRefreshBefore time.Duration
}

func (cfg Config) validate() error {
	if cfg.Audience == "" {
		return errors.New("awsauth: Audience is required")
	}
	if len(cfg.Audience) > maxAudienceLen {
		return fmt.Errorf("awsauth: Audience must be at most %d characters, got %d", maxAudienceLen, len(cfg.Audience))
	}
	if cfg.SigningAlgorithm != "" {
		if _, ok := supportedSigningAlgorithms[cfg.SigningAlgorithm]; !ok {
			return fmt.Errorf("awsauth: unsupported SigningAlgorithm %q (want RS256 or ES384)", cfg.SigningAlgorithm)
		}
	}
	if cfg.Duration != 0 {
		if cfg.Duration < minDuration || cfg.Duration > maxDuration {
			return fmt.Errorf("awsauth: Duration must be between %s and %s, got %s", minDuration, maxDuration, cfg.Duration)
		}
		if cfg.Duration%time.Second != 0 {
			return fmt.Errorf("awsauth: Duration must be a whole number of seconds, got %s", cfg.Duration)
		}
	}
	if cfg.CacheRefreshBefore < 0 {
		return fmt.Errorf("awsauth: CacheRefreshBefore must not be negative, got %s", cfg.CacheRefreshBefore)
	}
	return nil
}

// TokenSource mints AWS web identity tokens.
type TokenSource struct {
	client             stsAPI
	audience           string
	signingAlgorithm   string
	duration           time.Duration
	cachePath          string
	cacheRefreshBefore time.Duration

	mu         sync.Mutex
	lastErr    error
	refreshing bool // a background cache refresh is in flight
}

// New loads the default AWS config and builds an STS-backed TokenSource.
//
// Config is validated before any AWS work. A region must resolve from the
// environment or shared config: GetWebIdentityToken is not served on the global
// STS endpoint.
func New(ctx context.Context, cfg Config) (*TokenSource, error) {
	if err := cfg.validate(); err != nil {
		return nil, err
	}
	awsCfg, err := awsconfig.LoadDefaultConfig(ctx)
	if err != nil {
		return nil, fmt.Errorf("awsauth: load AWS config: %w", err)
	}
	return NewFromAWSConfig(awsCfg, cfg)
}

// NewFromAWSConfig builds a TokenSource from a caller-supplied aws.Config, for
// callers that already have one (custom region, profile, credentials, endpoint
// resolver, ...). The same validation and region check as New apply.
func NewFromAWSConfig(awsCfg aws.Config, cfg Config) (*TokenSource, error) {
	if err := cfg.validate(); err != nil {
		return nil, err
	}
	if awsCfg.Region == "" {
		return nil, errors.New("awsauth: AWS region must be set; GetWebIdentityToken is not served on the global STS endpoint")
	}
	return newWithClient(sts.NewFromConfig(awsCfg), cfg)
}

// newWithClient validates cfg, applies defaults, and builds the TokenSource.
// It is the single seam tests use to inject a fake stsAPI.
func newWithClient(client stsAPI, cfg Config) (*TokenSource, error) {
	if err := cfg.validate(); err != nil {
		return nil, err
	}
	alg := cfg.SigningAlgorithm
	if alg == "" {
		alg = DefaultSigningAlgorithm
	}
	dur := cfg.Duration
	if dur == 0 {
		dur = DefaultDuration
	}
	refreshBefore := cfg.CacheRefreshBefore
	if refreshBefore == 0 {
		refreshBefore = DefaultCacheRefreshBefore
	}
	return &TokenSource{
		client:             client,
		audience:           cfg.Audience,
		signingAlgorithm:   alg,
		duration:           dur,
		cachePath:          cfg.CachePath,
		cacheRefreshBefore: refreshBefore,
	}, nil
}

// Token returns a web identity token. When caching is enabled (Config.CachePath)
// it returns the cached token as long as it has not expired; when that token is
// within CacheRefreshBefore of expiry it also kicks off a background refresh so
// later calls get a fresh token. On a cache miss (missing, corrupt, expired, or
// wrong-audience) it mints synchronously and writes the cache (best effort — a
// write failure does not fail the call). With caching disabled it always mints.
func (ts *TokenSource) Token(ctx context.Context) (string, error) {
	if ts.cachePath != "" {
		if tok, exp, ok := ts.readCache(); ok {
			if time.Until(exp) < ts.cacheRefreshBefore {
				ts.refreshAsync()
			}
			return tok, nil
		}
	}
	tok, err := ts.mint(ctx)
	if err != nil {
		return "", err
	}
	if ts.cachePath != "" {
		ts.writeCache(tok)
	}
	return tok, nil
}

// refreshAsync mints a fresh token and writes it to the cache in the background,
// for callers that returned a soon-to-expire cached token. At most one refresh
// runs per TokenSource at a time; a mint failure is recorded via LastError.
func (ts *TokenSource) refreshAsync() {
	ts.mu.Lock()
	if ts.refreshing {
		ts.mu.Unlock()
		return
	}
	ts.refreshing = true
	ts.mu.Unlock()

	go func() {
		defer func() {
			ts.mu.Lock()
			ts.refreshing = false
			ts.mu.Unlock()
		}()
		// The caller's context may already be cancelled by the time this runs,
		// so use an independent, bounded context.
		ctx, cancel := context.WithTimeout(context.Background(), DefaultFetchTimeout)
		defer cancel()
		tok, err := ts.mint(ctx)
		ts.setLastError(err)
		if err != nil {
			return
		}
		ts.writeCache(tok)
	}()
}

// mint always calls STS for a fresh token, bypassing the cache.
func (ts *TokenSource) mint(ctx context.Context) (string, error) {
	alg := ts.signingAlgorithm
	secs := int32(ts.duration / time.Second)
	out, err := ts.client.GetWebIdentityToken(ctx, &sts.GetWebIdentityTokenInput{
		Audience:         []string{ts.audience},
		SigningAlgorithm: &alg,
		DurationSeconds:  &secs,
	})
	if err != nil {
		return "", fmt.Errorf("awsauth: GetWebIdentityToken: %w", err)
	}
	if out == nil || out.WebIdentityToken == nil || *out.WebIdentityToken == "" {
		return "", errors.New("awsauth: STS returned an empty web identity token")
	}
	return *out.WebIdentityToken, nil
}

// readCache returns a cached token, and its expiry, if the file holds one whose
// audience matches and which has not yet expired. Any problem (missing file,
// unparseable token, wrong audience, already expired) is a miss, not an error —
// the caller then mints a fresh token.
func (ts *TokenSource) readCache() (token string, exp time.Time, ok bool) {
	b, err := os.ReadFile(ts.cachePath)
	if err != nil {
		return "", time.Time{}, false
	}
	tok := strings.TrimSpace(string(b))
	if tok == "" {
		return "", time.Time{}, false
	}
	exp, auds, err := unverifiedExpiryAudience(tok)
	if err != nil {
		return "", time.Time{}, false
	}
	if !time.Now().Before(exp) { // expired
		return "", time.Time{}, false
	}
	if !slices.Contains(auds, ts.audience) {
		return "", time.Time{}, false
	}
	return tok, exp, true
}

// writeCache atomically stores tok at cachePath (0600 file, 0700 parent). It is
// best effort: any error is ignored, since the token itself is already valid.
func (ts *TokenSource) writeCache(tok string) {
	dir := filepath.Dir(ts.cachePath)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return
	}
	tmp, err := os.CreateTemp(dir, ".awsauth-*.tmp")
	if err != nil {
		return
	}
	tmpName := tmp.Name()
	defer func() { _ = os.Remove(tmpName) }() // no-op once the rename succeeds
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return
	}
	if _, err := tmp.WriteString(tok); err != nil {
		_ = tmp.Close()
		return
	}
	if err := tmp.Close(); err != nil {
		return
	}
	_ = os.Rename(tmpName, ts.cachePath)
}

// NATSOption returns a nats.Option that mints a fresh token on every
// (re)connect, each fetch bounded by timeout (a non-positive timeout uses
// DefaultFetchTimeout).
//
// nats.AuthTokenHandler is func() string — it cannot return an error — so a
// fetch failure yields an empty token (which fails the connect) and is recorded
// for retrieval via LastError; a successful fetch clears LastError. See the
// package documentation for the refresh model and the reconnect requirement.
func (ts *TokenSource) NATSOption(timeout time.Duration) nats.Option {
	if timeout <= 0 {
		timeout = DefaultFetchTimeout
	}
	return nats.TokenHandler(func() string {
		ctx, cancel := context.WithTimeout(context.Background(), timeout)
		defer cancel()
		tok, err := ts.Token(ctx)
		ts.setLastError(err)
		if err != nil {
			return ""
		}
		return tok
	})
}

// LastError returns the most recent error from a NATSOption token fetch or a
// background cache refresh, or nil if the last such operation succeeded (or none
// has run yet).
func (ts *TokenSource) LastError() error {
	ts.mu.Lock()
	defer ts.mu.Unlock()
	return ts.lastErr
}

func (ts *TokenSource) setLastError(err error) {
	ts.mu.Lock()
	ts.lastErr = err
	ts.mu.Unlock()
}

// DefaultCachePath returns a per-audience cache file path under the user cache
// directory (os.UserCacheDir), suitable for Config.CachePath. Distinct audiences
// map to distinct files, so reusing it for several audiences will not collide.
func DefaultCachePath(audience string) (string, error) {
	dir, err := os.UserCacheDir()
	if err != nil {
		return "", fmt.Errorf("awsauth: locate user cache dir: %w", err)
	}
	sum := sha256.Sum256([]byte(audience))
	name := "awsauth-" + hex.EncodeToString(sum[:8]) + ".jwt"
	return filepath.Join(dir, "nats-jwt-callout", name), nil
}

// unverifiedExpiryAudience decodes a JWT's payload (without verifying its
// signature) to read its exp and aud claims. This is only used to judge cache
// freshness locally; the callout still verifies the token's signature server
// side. aud is accepted as either a string or an array of strings per RFC 7519.
func unverifiedExpiryAudience(token string) (exp time.Time, auds []string, err error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return time.Time{}, nil, errors.New("malformed JWT")
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return time.Time{}, nil, fmt.Errorf("decode JWT payload: %w", err)
	}
	var claims struct {
		Exp int64           `json:"exp"`
		Aud json.RawMessage `json:"aud"`
	}
	if err := json.Unmarshal(payload, &claims); err != nil {
		return time.Time{}, nil, fmt.Errorf("parse JWT claims: %w", err)
	}
	if claims.Exp == 0 {
		return time.Time{}, nil, errors.New("JWT has no exp claim")
	}
	return time.Unix(claims.Exp, 0), parseAudience(claims.Aud), nil
}

// parseAudience reads a JWT aud claim, which may be a single string or an array.
func parseAudience(raw json.RawMessage) []string {
	if len(raw) == 0 {
		return nil
	}
	var one string
	if json.Unmarshal(raw, &one) == nil {
		return []string{one}
	}
	var many []string
	if json.Unmarshal(raw, &many) == nil {
		return many
	}
	return nil
}
