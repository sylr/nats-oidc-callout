package verifier_test

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"

	"github.com/sylr/nats-oidc-callout/internal/mockoidc"
	"github.com/sylr/nats-oidc-callout/internal/verifier"
)

func newThrottledVerifier(t *testing.T, idp *mockoidc.Server, interval time.Duration) *verifier.Verifier {
	t.Helper()
	v, err := verifier.New(context.Background(), verifier.Options{
		Issuers:             []verifier.IssuerOption{{URL: idp.Issuer()}},
		Audiences:           []string{testAudience},
		SigningAlgs:         []string{oidc.RS256},
		HTTPTimeout:         5 * time.Second,
		JWKSRefreshInterval: interval,
	})
	if err != nil {
		t.Fatalf("verifier.New: %v", err)
	}
	return v
}

func mintValid(t *testing.T, idp *mockoidc.Server) string {
	t.Helper()
	return idp.Mint(t, mockoidc.TokenOptions{Subject: testARN, Audience: []string{testAudience}})
}

func mintUnknownKid(t *testing.T, idp *mockoidc.Server, kid string) string {
	t.Helper()
	return idp.Mint(t, mockoidc.TokenOptions{Subject: testARN, Audience: []string{testAudience}, KidOverride: kid})
}

// verifyWithin verifies tok with a deadline and fails the test if it takes
// longer than max.
func verifyWithin(t *testing.T, v *verifier.Verifier, tok string, max time.Duration) error {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	start := time.Now()
	_, err := v.Verify(ctx, tok)
	if d := time.Since(start); d > max {
		t.Fatalf("Verify took %v, want under %v (err: %v)", d, max, err)
	}
	return err
}

// TestCachedKeyNotBlockedByStalledRefresh reproduces audit finding F02: with a
// warm cache, a token with an unknown kid starts a JWKS refresh that stalls.
// A token signed by a cached key must still verify promptly, and further
// unknown kids must fail fast instead of piling up behind the refresh.
func TestCachedKeyNotBlockedByStalledRefresh(t *testing.T) {
	idp := mockoidc.New(t)
	v := newThrottledVerifier(t, idp, 50*time.Millisecond)

	if err := verifyWithin(t, v, mintValid(t, idp), 2*time.Second); err != nil {
		t.Fatalf("warm-up verify: %v", err)
	}
	time.Sleep(100 * time.Millisecond) // let the refresh interval elapse

	entered, release := idp.HoldJWKS(t)
	stalled := make(chan error, 1)
	bogus := mintUnknownKid(t, idp, "attacker-kid")
	go func() {
		_, err := v.Verify(context.Background(), bogus)
		stalled <- err
	}()
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("unknown kid did not trigger a JWKS refresh")
	}

	if err := verifyWithin(t, v, mintValid(t, idp), 500*time.Millisecond); err != nil {
		t.Fatalf("cached token rejected during a stalled refresh: %v", err)
	}
	if err := verifyWithin(t, v, mintUnknownKid(t, idp, "attacker-kid-2"), 500*time.Millisecond); err == nil {
		t.Fatal("second unknown kid accepted")
	}

	release()
	if err := <-stalled; err == nil {
		t.Fatal("unknown kid accepted after refresh")
	}
	if got := idp.JWKSRequests(); got != 2 {
		t.Errorf("JWKS requests = %d, want 2 (warm-up + one refresh)", got)
	}
}

// TestUnknownKidsBoundJWKSRequests sends identical and varying unknown kids:
// only one refresh may happen per interval.
func TestUnknownKidsBoundJWKSRequests(t *testing.T) {
	idp := mockoidc.New(t)
	v := newThrottledVerifier(t, idp, time.Hour)

	if _, err := v.Verify(context.Background(), mintValid(t, idp)); err != nil {
		t.Fatalf("warm-up verify: %v", err)
	}
	for i := range 20 {
		kid := "same-kid"
		if i%2 == 1 {
			kid = fmt.Sprintf("kid-%d", i)
		}
		if err := verifyWithin(t, v, mintUnknownKid(t, idp, kid), 500*time.Millisecond); err == nil {
			t.Fatalf("unknown kid %q accepted", kid)
		}
	}
	if got := idp.JWKSRequests(); got != 1 {
		t.Errorf("JWKS requests = %d, want 1 (no refresh within the interval)", got)
	}

	// Concurrent unknown kids are bounded as well.
	var wg sync.WaitGroup
	for i := range 20 {
		tok := mintUnknownKid(t, idp, fmt.Sprintf("c-%d", i))
		wg.Go(func() { _, _ = v.Verify(context.Background(), tok) })
	}
	wg.Wait()
	if got := idp.JWKSRequests(); got != 1 {
		t.Errorf("JWKS requests after concurrent misses = %d, want 1", got)
	}
}

// TestRotationThrottledWithinInterval rotates the IdP's signing key right after
// the cache was filled: within the refresh interval the new key is rejected
// without another JWKS fetch. The interval is long enough that it cannot elapse
// during the test, however slow the machine (RSA key generation under -race).
func TestRotationThrottledWithinInterval(t *testing.T) {
	idp := mockoidc.New(t)
	v := newThrottledVerifier(t, idp, time.Hour)

	if _, err := v.Verify(context.Background(), mintValid(t, idp)); err != nil {
		t.Fatalf("warm-up verify: %v", err)
	}

	idp.AddKey(t, "key-2")
	idp.SetDefaultKey("key-2")
	if _, err := v.Verify(context.Background(), mintValid(t, idp)); err == nil {
		t.Fatal("rotated key accepted before the refresh interval elapsed")
	}
	if got := idp.JWKSRequests(); got != 1 {
		t.Errorf("JWKS requests = %d, want 1 (no refresh within the interval)", got)
	}
}

// TestRotationRecoversAfterInterval rotates the IdP's signing key right after
// the cache was filled: once the refresh interval has elapsed the new key is
// accepted, and tokens signed by the old key keep working.
func TestRotationRecoversAfterInterval(t *testing.T) {
	const interval = 100 * time.Millisecond
	idp := mockoidc.New(t)
	v := newThrottledVerifier(t, idp, interval)

	oldTok := mintValid(t, idp)
	if _, err := v.Verify(context.Background(), oldTok); err != nil {
		t.Fatalf("warm-up verify: %v", err)
	}

	idp.AddKey(t, "key-2")
	idp.SetDefaultKey("key-2")
	newTok := mintValid(t, idp)

	time.Sleep(interval + 100*time.Millisecond)
	if _, err := v.Verify(context.Background(), newTok); err != nil {
		t.Fatalf("rotated key rejected after the refresh interval: %v", err)
	}
	if _, err := v.Verify(context.Background(), oldTok); err != nil {
		t.Fatalf("old key rejected after rotation: %v", err)
	}
}

// TestForgedSignatureRejected uses a cached kid with a signature from a key
// the IdP never published: it must be rejected, including after a refresh.
func TestForgedSignatureRejected(t *testing.T) {
	idp := mockoidc.New(t)
	v := newThrottledVerifier(t, idp, time.Millisecond)
	if _, err := v.Verify(context.Background(), mintValid(t, idp)); err != nil {
		t.Fatalf("warm-up verify: %v", err)
	}

	// Mint with an unpublished key but claim the published kid.
	other := mockoidc.New(t)
	forged := other.Mint(t, mockoidc.TokenOptions{
		Subject: testARN, Audience: []string{testAudience},
		IssuerOverride: idp.Issuer(), KidOverride: "key-1",
	})
	time.Sleep(10 * time.Millisecond)
	if _, err := v.Verify(context.Background(), forged); err == nil {
		t.Fatal("forged signature accepted")
	}
}

// TestColdCacheConcurrentRequestsWait checks that requests arriving while the
// very first JWKS fetch is in flight wait for it instead of failing.
func TestColdCacheConcurrentRequestsWait(t *testing.T) {
	idp := mockoidc.New(t)
	v := newThrottledVerifier(t, idp, time.Hour)

	entered, release := idp.HoldJWKS(t)
	errs := make(chan error, 3)
	for range 3 {
		tok := mintValid(t, idp)
		go func() {
			_, err := v.Verify(context.Background(), tok)
			errs <- err
		}()
	}
	<-entered
	time.Sleep(50 * time.Millisecond) // let the other requests queue behind the fetch
	release()
	for range 3 {
		if err := <-errs; err != nil {
			t.Errorf("cold-cache verify: %v", err)
		}
	}
	if got := idp.JWKSRequests(); got != 1 {
		t.Errorf("JWKS requests = %d, want 1", got)
	}
}
