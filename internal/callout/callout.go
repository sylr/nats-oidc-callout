// Package callout implements the authorization function invoked by
// synadia-io/callout.go for each NATS connection attempt. It verifies the AWS
// Web Identity Token carried in the connect options, maps the identity to a
// NATS account and permissions via the policy, and issues a signed user JWT.
package callout

import (
	"context"
	"errors"
	"log/slog"
	"sync/atomic"
	"time"

	"github.com/nats-io/jwt/v2"
	"github.com/nats-io/nkeys"

	"github.com/sylr/nats-oidc-callout/internal/authz"
	"github.com/sylr/nats-oidc-callout/internal/metrics"
	"github.com/sylr/nats-oidc-callout/internal/verifier"
)

// errDenied is the generic error returned to the NATS server on any failure.
// The server may surface/log the response error, so it must not leak internals
// or the token; detailed diagnostics go to the structured logger instead.
var errDenied = errors.New("authorization denied")

// DefaultVerifyTimeout is the per-request verification deadline used when New
// is given zero. It stays below the NATS server's default authorization
// timeout (2s, or the TLS timeout + 1s with TLS) so a slow verification is
// answered with a denial rather than left to time out on the server.
const DefaultVerifyTimeout = 1500 * time.Millisecond

// ruleset is the hot-swappable part of the authorizer: the verifier and policy.
// It is replaced atomically on reload.
type ruleset struct {
	verifier *verifier.Verifier
	policy   *authz.Policy
}

// Authorizer issues user JWTs for verified AWS identities.
type Authorizer struct {
	state   atomic.Pointer[ruleset] // verifier + policy, swapped atomically on Reload
	signKey nkeys.KeyPair           // issuer account key (SA…); also signs the response
	logger  *slog.Logger
	metrics *metrics.Metrics // nil-safe; nil disables instrumentation
	// verifyTimeout bounds the per-request token verification (JWKS fetch on a
	// cold cache or key rotation, etc.).
	verifyTimeout time.Duration
}

// New builds an Authorizer. signKey must be the account key whose public key
// equals the server's auth_callout.issuer. m may be nil to disable metrics.
// verifyTimeout bounds each token verification; zero means
// DefaultVerifyTimeout.
func New(v *verifier.Verifier, policy *authz.Policy, signKey nkeys.KeyPair, logger *slog.Logger, m *metrics.Metrics, verifyTimeout time.Duration) *Authorizer {
	if logger == nil {
		logger = slog.Default()
	}
	if verifyTimeout <= 0 {
		verifyTimeout = DefaultVerifyTimeout
	}
	a := &Authorizer{
		signKey:       signKey,
		logger:        logger,
		metrics:       m,
		verifyTimeout: verifyTimeout,
	}
	a.state.Store(&ruleset{verifier: v, policy: policy})
	return a
}

// Reload atomically swaps the verifier and policy used for subsequent
// authorizations. It is safe to call concurrently with Authorize; in-flight
// requests finish against the ruleset they loaded.
func (a *Authorizer) Reload(v *verifier.Verifier, policy *authz.Policy) {
	a.state.Store(&ruleset{verifier: v, policy: policy})
}

// Authorize is the synadia-io/callout.go AuthorizerFn. It returns an encoded,
// signed user JWT on success, or a generic error (fail closed) on any failure.
func (a *Authorizer) Authorize(req *jwt.AuthorizationRequest) (string, error) {
	start := time.Now()
	ctx, cancel := context.WithTimeout(context.Background(), a.verifyTimeout)
	defer cancel()

	// Snapshot the current verifier+policy for the whole request, so a concurrent
	// Reload can't swap them mid-evaluation.
	st := a.state.Load()

	// The AWS token is carried as the connection auth_token.
	token := req.ConnectOptions.Token
	if token == "" {
		a.logger.Warn("connection rejected: no token", "user_nkey", req.UserNkey)
		a.metrics.RecordDenied(metrics.ReasonNoToken, time.Since(start))
		return "", errDenied
	}

	id, err := st.verifier.Verify(ctx, token)
	if err != nil {
		a.logger.Warn("connection rejected: token verification failed",
			"user_nkey", req.UserNkey, "error", err)
		a.metrics.RecordDenied(metrics.ReasonVerificationFailed, time.Since(start))
		return "", errDenied
	}

	decision, err := st.policy.Evaluate(id)
	if err != nil {
		a.logger.Warn("connection rejected: no policy match",
			"user_nkey", req.UserNkey, "iss", id.Issuer, "sub", id.Subject,
			"error", err)
		a.metrics.RecordDenied(metrics.ReasonPolicyNoMatch, time.Since(start))
		return "", errDenied
	}

	uc := jwt.NewUserClaims(req.UserNkey)
	uc.Name = id.Subject
	// Bind the user to the granted account by NAME (server-config mode). Do not
	// set IssuerAccount: we sign directly with the issuer account key.
	uc.Audience = decision.Account
	uc.UserPermissionLimits = decision.Permissions
	uc.Expires = cappedExpiry(id.Expiry, decision.MaxExpiry).Unix()

	userJWT, err := uc.Encode(a.signKey)
	if err != nil {
		a.logger.Error("connection rejected: failed to sign user JWT",
			"user_nkey", req.UserNkey, "error", err)
		return "", errDenied
	}

	a.logger.Info("connection authorized",
		"user_nkey", req.UserNkey, "iss", id.Issuer, "sub", id.Subject,
		"account", decision.Account, "rule", decision.RuleName)
	a.metrics.RecordAllowed(time.Since(start))
	return userJWT, nil
}

// cappedExpiry returns the user JWT expiry: never later than the verified
// token's own expiry, and never later than now+maxExpiry when a policy cap is set.
func cappedExpiry(tokenExpiry time.Time, maxExpiry time.Duration) time.Time {
	exp := tokenExpiry
	if maxExpiry > 0 {
		if cap := time.Now().Add(maxExpiry); cap.Before(exp) {
			exp = cap
		}
	}
	return exp
}
