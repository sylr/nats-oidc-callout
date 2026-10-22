// Package verifier validates AWS Web Identity Tokens as OIDC tokens against a
// fixed set of trusted issuers.
//
// Security properties enforced here:
//   - Trusted issuers are configured up front; the token's "iss" is only used to
//     select an already-configured verifier. We never run OIDC discovery or fetch
//     JWKS for an issuer we were not told to trust (avoids SSRF/DoS).
//   - Signing algorithms are restricted to an explicit allowlist.
//   - The audience is checked against an explicit allowlist (go-oidc's ClientID
//     check only ensures containment of a single value).
//   - An issuer may be bound to a specific AWS account; a mismatch is rejected.
package verifier

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"

	"github.com/sylr/nats-oidc-callout/internal/identity"
)

// ErrUntrustedIssuer is returned when a token's issuer is not in the configured
// trust set. Callers should treat it like any other verification failure.
var ErrUntrustedIssuer = errors.New("token issuer is not trusted")

// issuerEntry is a single configured trusted issuer.
type issuerEntry struct {
	verifier      *oidc.IDTokenVerifier
	requireClaims map[string]string
}

// Verifier validates tokens against a fixed set of trusted issuers.
type Verifier struct {
	issuers   map[string]issuerEntry
	audiences map[string]struct{}
}

// Options configures a Verifier.
type Options struct {
	// Issuers is the trust set; each entry must have a unique URL.
	Issuers []IssuerOption
	// Audiences is the allowlist of acceptable "aud" values. A token is
	// accepted only if at least one of its audiences appears here.
	Audiences []string
	// SigningAlgs is the allowlist of acceptable signing algorithms
	// (e.g. oidc.RS256, oidc.ES384).
	SigningAlgs []string
	// HTTPTimeout bounds OIDC discovery and JWKS fetches. Defaults to 10s.
	HTTPTimeout time.Duration
	// RootCAs, when non-nil, is the trust anchor for OIDC discovery / JWKS TLS
	// (e.g. an in-cluster Kubernetes issuer signed by the cluster CA). Nil uses
	// the system roots.
	RootCAs *x509.CertPool
	// JWKSRefreshInterval is the minimum interval between JWKS refreshes of an
	// issuer triggered by a token whose key is not cached. Defaults to
	// DefaultJWKSRefreshInterval.
	JWKSRefreshInterval time.Duration
}

// IssuerOption configures one trusted issuer.
type IssuerOption struct {
	URL string
	// RequireClaims binds the issuer to specific claim values: every k=v must
	// match the verified token (keys use the flattened namespace, e.g.
	// "aws.aws_account" or "repository_owner"). A mismatch rejects the token.
	RequireClaims map[string]string
}

// New performs OIDC discovery for every configured issuer and builds the
// verifiers. It returns an error if any issuer fails discovery, so a
// misconfiguration fails fast at startup rather than on the hot path.
func New(ctx context.Context, opts Options) (*Verifier, error) {
	if len(opts.Issuers) == 0 {
		return nil, errors.New("verifier: at least one issuer is required")
	}
	if len(opts.Audiences) == 0 {
		return nil, errors.New("verifier: at least one audience is required")
	}
	if len(opts.SigningAlgs) == 0 {
		return nil, errors.New("verifier: at least one signing algorithm is required")
	}

	timeout := opts.HTTPTimeout
	if timeout == 0 {
		timeout = 10 * time.Second
	}
	httpClient := &http.Client{Timeout: timeout}
	if opts.RootCAs != nil {
		httpClient.Transport = &http.Transport{
			Proxy:           http.ProxyFromEnvironment,
			TLSClientConfig: &tls.Config{RootCAs: opts.RootCAs, MinVersion: tls.VersionTLS12},
		}
	}
	discoveryCtx := oidc.ClientContext(ctx, httpClient)

	v := &Verifier{
		issuers:   make(map[string]issuerEntry, len(opts.Issuers)),
		audiences: make(map[string]struct{}, len(opts.Audiences)),
	}
	for _, aud := range opts.Audiences {
		v.audiences[aud] = struct{}{}
	}

	for _, iss := range opts.Issuers {
		if _, dup := v.issuers[iss.URL]; dup {
			return nil, fmt.Errorf("verifier: duplicate issuer %q", iss.URL)
		}
		provider, err := oidc.NewProvider(discoveryCtx, iss.URL)
		if err != nil {
			return nil, fmt.Errorf("verifier: OIDC discovery for %q: %w", iss.URL, err)
		}
		var meta struct {
			JWKSURL string `json:"jwks_uri"`
		}
		if err := provider.Claims(&meta); err != nil || meta.JWKSURL == "" {
			return nil, fmt.Errorf("verifier: OIDC discovery for %q: no jwks_uri", iss.URL)
		}
		// Throttled key set instead of the provider's RemoteKeySet, which
		// refetches the JWKS on every unknown key ID (see keySet).
		keys := newKeySet(meta.JWKSURL, httpClient, opts.SigningAlgs, opts.JWKSRefreshInterval)
		// SkipClientIDCheck: audience is validated explicitly against the
		// allowlist in Verify (the token may carry several audiences).
		oidcVerifier := oidc.NewVerifier(iss.URL, keys, &oidc.Config{
			SkipClientIDCheck:    true,
			SupportedSigningAlgs: opts.SigningAlgs,
		})
		v.issuers[iss.URL] = issuerEntry{
			verifier:      oidcVerifier,
			requireClaims: iss.RequireClaims,
		}
	}
	return v, nil
}

// Verify validates a raw token and, on success, returns the verified identity.
// All failures are reported as errors; callers must fail closed.
func (v *Verifier) Verify(ctx context.Context, rawToken string) (*identity.Identity, error) {
	if rawToken == "" {
		return nil, errors.New("empty token")
	}

	// Select the verifier by the unverified issuer. We do NOT discover or fetch
	// keys for an unknown issuer.
	iss, err := unverifiedIssuer(rawToken)
	if err != nil {
		return nil, err
	}
	entry, ok := v.issuers[iss]
	if !ok {
		return nil, ErrUntrustedIssuer
	}

	idToken, err := entry.verifier.Verify(ctx, rawToken)
	if err != nil {
		return nil, fmt.Errorf("token verification failed: %w", err)
	}

	// Explicit audience allowlist: at least one token audience must be allowed.
	if !v.audienceAllowed(idToken.Audience) {
		return nil, fmt.Errorf("token audience %v is not allowed", idToken.Audience)
	}

	var raw json.RawMessage
	if err := idToken.Claims(&raw); err != nil {
		return nil, fmt.Errorf("read token claims: %w", err)
	}
	id, err := identity.Parse(raw)
	if err != nil {
		return nil, err
	}
	// Populate first-class fields from the verified token, not the raw payload.
	id.Issuer = idToken.Issuer
	id.Subject = idToken.Subject
	id.Audience = idToken.Audience
	id.Expiry = idToken.Expiry

	// Bind the issuer to its required claims.
	for k, want := range entry.requireClaims {
		if got, ok := id.Claim(k); !ok || got != want {
			return nil, fmt.Errorf("token claim %q does not match the issuer's required value", k)
		}
	}

	return id, nil
}

func (v *Verifier) audienceAllowed(tokenAudiences []string) bool {
	for _, aud := range tokenAudiences {
		if _, ok := v.audiences[aud]; ok {
			return true
		}
	}
	return false
}

// unverifiedIssuer extracts the "iss" claim from a JWT WITHOUT verifying its
// signature. The result is used only to select a trusted verifier; it is never
// treated as authentic on its own.
func unverifiedIssuer(rawToken string) (string, error) {
	parts := strings.Split(rawToken, ".")
	if len(parts) != 3 {
		return "", errors.New("malformed token: expected three segments")
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return "", fmt.Errorf("malformed token payload: %w", err)
	}
	var claims struct {
		Issuer string `json:"iss"`
	}
	if err := json.Unmarshal(payload, &claims); err != nil {
		return "", fmt.Errorf("malformed token payload: %w", err)
	}
	if claims.Issuer == "" {
		return "", errors.New("token has no issuer")
	}
	return claims.Issuer, nil
}
