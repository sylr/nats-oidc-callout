package e2e

import (
	"context"
	"testing"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/nats-io/nats.go"

	"github.com/sylr/nats-oidc-callout/internal/mockoidc"
	"github.com/sylr/nats-oidc-callout/internal/verifier"
)

// TestStalledJWKSRefreshDoesNotBlockCachedIdentity reproduces audit finding
// F02 through the full callout path: while a token with an unknown kid holds a
// JWKS refresh open, a client whose signing key is already cached must still
// be authorized well within the server's 2s authorization timeout.
func TestStalledJWKSRefreshDoesNotBlockCachedIdentity(t *testing.T) {
	policy := appPolicy(testARN)
	h := setup(t, policy, awsRequire)

	// Swap in a verifier with a short refresh interval so the unknown kid below
	// is allowed to trigger a refresh.
	v, err := verifier.New(context.Background(), verifier.Options{
		Issuers:             []verifier.IssuerOption{{URL: h.idp.Issuer(), RequireClaims: awsRequire}},
		Audiences:           []string{testAudience},
		SigningAlgs:         []string{oidc.RS256},
		HTTPTimeout:         5 * time.Second,
		JWKSRefreshInterval: 50 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("verifier.New: %v", err)
	}
	h.authorizer.Reload(v, policy)

	// Warm the key cache.
	if _, err := h.connectClient(t, h.validToken(t)); err != nil {
		t.Fatalf("warm-up connect: %v", err)
	}
	time.Sleep(100 * time.Millisecond)

	entered, release := h.idp.HoldJWKS(t)
	bogus := h.idp.Mint(t, mockoidc.TokenOptions{
		Subject: testARN, Audience: []string{testAudience}, AWSAccount: testAccount,
		KidOverride: "attacker-kid",
	})
	bogusDone := make(chan error, 1)
	go func() {
		nc, err := nats.Connect(h.srv.ClientURL(), nats.Token(bogus), nats.MaxReconnects(0), nats.Timeout(5*time.Second))
		if err == nil {
			nc.Close()
		}
		bogusDone <- err
	}()
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("unknown kid did not trigger a JWKS refresh")
	}

	start := time.Now()
	if _, err := h.connectClient(t, h.validToken(t)); err != nil {
		t.Fatalf("cached identity rejected during a stalled JWKS refresh after %v: %v", time.Since(start), err)
	}
	if d := time.Since(start); d > time.Second {
		t.Errorf("cached identity took %v to authorize, want under 1s", d)
	}

	release()
	if err := <-bogusDone; err == nil {
		t.Fatal("unknown-kid token was authorized")
	}
}
