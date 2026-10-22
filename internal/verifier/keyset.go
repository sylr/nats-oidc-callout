package verifier

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"

	jose "github.com/go-jose/go-jose/v4"
)

// DefaultJWKSRefreshInterval is used when Options.JWKSRefreshInterval is unset.
const DefaultJWKSRefreshInterval = 30 * time.Second

// maxJWKSSize bounds the JWKS response body.
const maxJWKSSize = 1 << 20

// errRefreshThrottled is returned when a token's key is not cached and a JWKS
// refresh is not allowed right now.
var errRefreshThrottled = errors.New("signing key not cached and JWKS refresh is throttled")

// keySet is an oidc.KeySet that caches an issuer's JWKS and throttles remote
// refreshes. It replaces go-oidc's RemoteKeySet, which refetches on every cache
// miss: since anyone can mint a token with a trusted "iss" and a random "kid"
// (no valid signature needed), that turned every bogus token into an outbound
// request that also delayed unrelated authorizations.
//
// Behavior:
//   - Tokens whose key is cached verify locally, never waiting on the network.
//   - On a miss, at most one refresh runs at a time and refreshes start at most
//     once per interval (counted from the previous attempt, successful or not),
//     so a legitimate key rotation is picked up within the interval.
//   - The request that starts a refresh waits for it (bounded by its context).
//     Other misses fail immediately while a refresh is in flight or throttled,
//     unless no keys were ever fetched (nothing cached to protect yet).
//   - Signatures are verified by go-jose; any failure is an error (fail closed).
type keySet struct {
	jwksURL  string
	client   *http.Client
	algs     []jose.SignatureAlgorithm
	interval time.Duration

	mu        sync.Mutex
	keys      []jose.JSONWebKey
	lastFetch time.Time      // start of the last refresh attempt
	inflight  *refreshResult // non-nil while a refresh is running
}

type refreshResult struct {
	done chan struct{}
	err  error // valid once done is closed
}

func newKeySet(jwksURL string, client *http.Client, algs []string, interval time.Duration) *keySet {
	joseAlgs := make([]jose.SignatureAlgorithm, 0, len(algs))
	for _, a := range algs {
		joseAlgs = append(joseAlgs, jose.SignatureAlgorithm(a))
	}
	if interval <= 0 {
		interval = DefaultJWKSRefreshInterval
	}
	return &keySet{jwksURL: jwksURL, client: client, algs: joseAlgs, interval: interval}
}

// VerifySignature implements oidc.KeySet.
func (k *keySet) VerifySignature(ctx context.Context, rawToken string) ([]byte, error) {
	jws, err := jose.ParseSigned(rawToken, k.algs)
	if err != nil {
		return nil, fmt.Errorf("malformed jwt: %w", err)
	}
	if len(jws.Signatures) != 1 {
		return nil, errors.New("jwt must carry exactly one signature")
	}
	kid := jws.Signatures[0].Header.KeyID

	k.mu.Lock()
	keys := k.keys
	k.mu.Unlock()
	if payload, ok := verifyWith(jws, kid, keys); ok {
		return payload, nil
	}

	if err := k.refresh(ctx); err != nil {
		return nil, err
	}

	k.mu.Lock()
	keys = k.keys
	k.mu.Unlock()
	if payload, ok := verifyWith(jws, kid, keys); ok {
		return payload, nil
	}
	return nil, errors.New("failed to verify token signature")
}

// verifyWith tries every key matching kid (all keys when kid is empty).
func verifyWith(jws *jose.JSONWebSignature, kid string, keys []jose.JSONWebKey) ([]byte, bool) {
	for i := range keys {
		if kid != "" && keys[i].KeyID != kid {
			continue
		}
		if payload, err := jws.Verify(&keys[i]); err == nil {
			return payload, true
		}
	}
	return nil, false
}

// refresh fetches the JWKS if allowed, and waits for the outcome (or ctx). See
// keySet for the throttling rules.
func (k *keySet) refresh(ctx context.Context) error {
	k.mu.Lock()
	r := k.inflight
	switch {
	case r != nil && len(k.keys) > 0:
		k.mu.Unlock()
		return errRefreshThrottled
	case r == nil && !k.lastFetch.IsZero() && time.Since(k.lastFetch) < k.interval:
		k.mu.Unlock()
		return errRefreshThrottled
	case r == nil:
		r = &refreshResult{done: make(chan struct{})}
		k.inflight = r
		k.lastFetch = time.Now()
		// The fetch is detached from ctx: if this request gives up, the result
		// still lands in the cache for the next one. It is bounded by the HTTP
		// client timeout.
		go func() {
			keys, err := k.fetch()
			k.mu.Lock()
			if err == nil {
				k.keys = keys
			}
			k.inflight = nil
			k.mu.Unlock()
			r.err = err
			close(r.done)
		}()
	}
	k.mu.Unlock()

	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-r.done:
		return r.err
	}
}

func (k *keySet) fetch() ([]jose.JSONWebKey, error) {
	req, err := http.NewRequest(http.MethodGet, k.jwksURL, nil)
	if err != nil {
		return nil, fmt.Errorf("build JWKS request: %w", err)
	}
	req.Header.Set("Cache-Control", "no-cache")
	resp, err := k.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetch JWKS: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("fetch JWKS: unexpected status %s", resp.Status)
	}
	var set jose.JSONWebKeySet
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxJWKSSize)).Decode(&set); err != nil {
		return nil, fmt.Errorf("decode JWKS: %w", err)
	}
	return set.Keys, nil
}
