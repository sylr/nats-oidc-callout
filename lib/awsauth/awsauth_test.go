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
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/nats-io/nats.go"
)

// fakeSTS is a concurrency-safe in-memory stsAPI. It records the last input,
// honours an already cancelled context (so timeout behaviour is observable),
// and returns either a canned token or a canned error.
type fakeSTS struct {
	mu    sync.Mutex
	in    *sts.GetWebIdentityTokenInput
	token string
	err   error
	calls int
}

func (f *fakeSTS) GetWebIdentityToken(ctx context.Context, in *sts.GetWebIdentityTokenInput, _ ...func(*sts.Options)) (*sts.GetWebIdentityTokenOutput, error) {
	f.mu.Lock()
	f.in = in
	f.calls++
	tok, fakeErr := f.token, f.err
	f.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if fakeErr != nil {
		return nil, fakeErr
	}
	return &sts.GetWebIdentityTokenOutput{WebIdentityToken: &tok}, nil
}

func (f *fakeSTS) lastInput() *sts.GetWebIdentityTokenInput {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.in
}

func (f *fakeSTS) callCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls
}

// fakeJWT builds an unsigned JWT carrying the given exp and aud, enough for the
// cache's local freshness/audience checks (the signature is never verified here).
func fakeJWT(exp time.Time, aud string) string {
	enc := base64.RawURLEncoding.EncodeToString
	header := enc([]byte(`{"alg":"RS256","typ":"JWT"}`))
	payload := enc(fmt.Appendf(nil, `{"exp":%d,"aud":[%q]}`, exp.Unix(), aud))
	return header + "." + payload + "." + enc([]byte("sig"))
}

func TestConfigValidate(t *testing.T) {
	cases := []struct {
		name    string
		cfg     Config
		wantErr bool
	}{
		{"empty audience", Config{}, true},
		{"audience too long", Config{Audience: strings.Repeat("a", maxAudienceLen+1)}, true},
		{"valid default duration", Config{Audience: "aud"}, false},
		{"valid explicit duration", Config{Audience: "aud", Duration: 300 * time.Second}, false},
		{"duration min boundary", Config{Audience: "aud", Duration: minDuration}, false},
		{"duration max boundary", Config{Audience: "aud", Duration: maxDuration}, false},
		{"duration too small", Config{Audience: "aud", Duration: 30 * time.Second}, true},
		{"duration too large", Config{Audience: "aud", Duration: 2 * time.Hour}, true},
		{"duration negative", Config{Audience: "aud", Duration: -time.Second}, true},
		{"duration sub-second", Config{Audience: "aud", Duration: 1500 * time.Millisecond}, true},
		{"signing alg ES384", Config{Audience: "aud", SigningAlgorithm: "ES384"}, false},
		{"signing alg unsupported", Config{Audience: "aud", SigningAlgorithm: "HS256"}, true},
		{"cache refresh before negative", Config{Audience: "aud", CacheRefreshBefore: -time.Second}, true},
		{"cache config valid", Config{Audience: "aud", CachePath: "/tmp/x", CacheRefreshBefore: time.Minute}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := newWithClient(&fakeSTS{}, tc.cfg)
			if tc.wantErr != (err != nil) {
				t.Fatalf("newWithClient err = %v, wantErr = %v", err, tc.wantErr)
			}
		})
	}
}

func TestNewValidatesBeforeAWS(t *testing.T) {
	// An empty Audience must fail without attempting to load AWS config.
	if _, err := New(context.Background(), Config{}); err == nil {
		t.Fatal("expected error for empty Audience")
	}
}

func TestTokenDefaults(t *testing.T) {
	f := &fakeSTS{token: "tok"}
	ts, err := newWithClient(f, Config{Audience: "aud"})
	if err != nil {
		t.Fatalf("newWithClient: %v", err)
	}
	if _, err := ts.Token(context.Background()); err != nil {
		t.Fatalf("Token: %v", err)
	}
	in := f.lastInput()
	if got := in.Audience; len(got) != 1 || got[0] != "aud" {
		t.Errorf("Audience = %v, want [aud]", got)
	}
	if got := derefString(in.SigningAlgorithm); got != DefaultSigningAlgorithm {
		t.Errorf("SigningAlgorithm = %q, want %q", got, DefaultSigningAlgorithm)
	}
	if got := derefInt32(in.DurationSeconds); got != 300 {
		t.Errorf("DurationSeconds = %d, want 300", got)
	}
}

func TestTokenOverrides(t *testing.T) {
	f := &fakeSTS{token: "tok"}
	ts, err := newWithClient(f, Config{Audience: "aud", SigningAlgorithm: "ES384", Duration: 600 * time.Second})
	if err != nil {
		t.Fatalf("newWithClient: %v", err)
	}
	if _, err := ts.Token(context.Background()); err != nil {
		t.Fatalf("Token: %v", err)
	}
	in := f.lastInput()
	if got := derefString(in.SigningAlgorithm); got != "ES384" {
		t.Errorf("SigningAlgorithm = %q, want ES384", got)
	}
	if got := derefInt32(in.DurationSeconds); got != 600 {
		t.Errorf("DurationSeconds = %d, want 600", got)
	}
}

func TestNewFromAWSConfigRequiresRegion(t *testing.T) {
	if _, err := NewFromAWSConfig(aws.Config{}, Config{Audience: "aud"}); err == nil {
		t.Fatal("expected error when region is empty")
	}
	if _, err := NewFromAWSConfig(aws.Config{Region: "us-east-1"}, Config{Audience: "aud"}); err != nil {
		t.Fatalf("unexpected error with region set: %v", err)
	}
	// Config validation runs before the region check.
	if _, err := NewFromAWSConfig(aws.Config{}, Config{}); err == nil {
		t.Fatal("expected error for empty Audience")
	}
}

func TestNATSOptionConcurrent(t *testing.T) {
	ts := mustSource(t, &fakeSTS{token: "tok"}, Config{Audience: "aud"})
	opt := ts.NATSOption(time.Second)
	var opts nats.Options
	if err := opt(&opts); err != nil {
		t.Fatalf("apply option: %v", err)
	}

	// The token handler is invoked from reconnect goroutines; exercise it
	// concurrently so `go test -race` can catch unsynchronised state.
	const n = 16
	var wg sync.WaitGroup
	wg.Add(n)
	for range n {
		go func() {
			defer wg.Done()
			if got := opts.TokenHandler(); got != "tok" {
				t.Errorf("handler token = %q, want tok", got)
			}
			_ = ts.LastError()
		}()
	}
	wg.Wait()
}

func TestTokenSuccess(t *testing.T) {
	ts := mustSource(t, &fakeSTS{token: "the-token"}, Config{Audience: "aud"})
	got, err := ts.Token(context.Background())
	if err != nil {
		t.Fatalf("Token: %v", err)
	}
	if got != "the-token" {
		t.Errorf("Token = %q, want the-token", got)
	}
}

func TestTokenWrapsError(t *testing.T) {
	sentinel := errors.New("boom")
	ts := mustSource(t, &fakeSTS{err: sentinel}, Config{Audience: "aud"})
	_, err := ts.Token(context.Background())
	if err == nil {
		t.Fatal("expected error")
	}
	if !errors.Is(err, sentinel) {
		t.Errorf("error %v does not wrap sentinel", err)
	}
}

func TestTokenEmpty(t *testing.T) {
	ts := mustSource(t, &fakeSTS{token: ""}, Config{Audience: "aud"})
	if _, err := ts.Token(context.Background()); err == nil {
		t.Fatal("expected error for empty token")
	}
}

func TestNATSOptionSuccessClearsLastError(t *testing.T) {
	ts := mustSource(t, &fakeSTS{token: "tok"}, Config{Audience: "aud"})
	ts.setLastError(errors.New("stale"))

	// NATSOption(0) must default the timeout; with a non-positive timeout the
	// fetch context would be already cancelled and the fake would return "".
	if got := applyTokenHandler(t, ts.NATSOption(0)); got != "tok" {
		t.Fatalf("handler token = %q, want tok", got)
	}
	if err := ts.LastError(); err != nil {
		t.Errorf("LastError = %v, want nil after success", err)
	}
}

func TestNATSOptionRecordsError(t *testing.T) {
	ts := mustSource(t, &fakeSTS{err: errors.New("boom")}, Config{Audience: "aud"})
	if got := applyTokenHandler(t, ts.NATSOption(time.Second)); got != "" {
		t.Fatalf("handler token = %q, want empty on error", got)
	}
	if ts.LastError() == nil {
		t.Error("LastError = nil, want non-nil after failed fetch")
	}
}

func TestCacheDisabledAlwaysMints(t *testing.T) {
	f := &fakeSTS{token: "tok"}
	ts := mustSource(t, f, Config{Audience: "aud"}) // no CachePath
	for range 3 {
		if _, err := ts.Token(context.Background()); err != nil {
			t.Fatalf("Token: %v", err)
		}
	}
	if got := f.callCount(); got != 3 {
		t.Errorf("STS calls = %d, want 3 (caching disabled)", got)
	}
}

func TestCacheHitAcrossSources(t *testing.T) {
	path := filepath.Join(t.TempDir(), "tok.jwt")
	token := fakeJWT(time.Now().Add(5*time.Minute), "aud")

	// First source mints once and writes the cache.
	f1 := &fakeSTS{token: token}
	ts1 := mustSource(t, f1, Config{Audience: "aud", CachePath: path})
	if _, err := ts1.Token(context.Background()); err != nil {
		t.Fatalf("first Token: %v", err)
	}
	if f1.callCount() != 1 {
		t.Fatalf("first source STS calls = %d, want 1", f1.callCount())
	}

	// A fresh source (new process) reading the same cache must not call STS.
	f2 := &fakeSTS{token: token}
	ts2 := mustSource(t, f2, Config{Audience: "aud", CachePath: path})
	got, err := ts2.Token(context.Background())
	if err != nil {
		t.Fatalf("second Token: %v", err)
	}
	if got != token {
		t.Errorf("cached token = %q, want %q", got, token)
	}
	if f2.callCount() != 0 {
		t.Errorf("second source STS calls = %d, want 0 (cache hit)", f2.callCount())
	}
}

func TestCacheExpiredReMints(t *testing.T) {
	path := filepath.Join(t.TempDir(), "tok.jwt")
	// An already-expired cached token is a miss → blocking mint.
	if err := os.WriteFile(path, seedEntry(fakeJWT(time.Now().Add(-time.Second), "aud"), testAKID), 0o600); err != nil {
		t.Fatalf("seed cache: %v", err)
	}
	fresh := fakeJWT(time.Now().Add(5*time.Minute), "aud")
	f := &fakeSTS{token: fresh}
	ts := mustSource(t, f, Config{Audience: "aud", CachePath: path})

	got, err := ts.Token(context.Background())
	if err != nil {
		t.Fatalf("Token: %v", err)
	}
	if got != fresh {
		t.Errorf("token = %q, want freshly minted %q", got, fresh)
	}
	if f.callCount() != 1 {
		t.Errorf("STS calls = %d, want 1 (cached token expired)", f.callCount())
	}
}

// TestCacheNearExpiryBackgroundRefresh: a non-expired token within
// CacheRefreshBefore of expiry is returned immediately, and a background refresh
// then replaces it in the cache for subsequent calls.
func TestCacheNearExpiryBackgroundRefresh(t *testing.T) {
	path := filepath.Join(t.TempDir(), "tok.jwt")
	stale := fakeJWT(time.Now().Add(5*time.Second), "aud") // valid, but < default 10s
	if err := os.WriteFile(path, seedEntry(stale, testAKID), 0o600); err != nil {
		t.Fatalf("seed cache: %v", err)
	}
	fresh := fakeJWT(time.Now().Add(5*time.Minute), "aud")
	f := &fakeSTS{token: fresh}
	ts := mustSource(t, f, Config{Audience: "aud", CachePath: path})

	// The call returns the still-valid stale token without blocking on STS.
	got, err := ts.Token(context.Background())
	if err != nil {
		t.Fatalf("Token: %v", err)
	}
	if got != stale {
		t.Errorf("returned token = %q, want the still-valid cached %q", got, stale)
	}

	// The background refresh then mints once and rewrites the cache with fresh.
	if !eventually(2*time.Second, func() bool {
		b, err := os.ReadFile(path)
		return err == nil && string(b) == string(seedEntry(fresh, testAKID))
	}) {
		t.Fatalf("cache not refreshed in background; STS calls=%d", f.callCount())
	}
	if got := f.callCount(); got != 1 {
		t.Errorf("STS calls = %d, want 1 (single background refresh)", got)
	}
}

func eventually(timeout time.Duration, cond func() bool) bool {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if cond() {
			return true
		}
		time.Sleep(5 * time.Millisecond)
	}
	return cond()
}

func TestCacheAudienceMismatchReMints(t *testing.T) {
	path := filepath.Join(t.TempDir(), "tok.jwt")
	if err := os.WriteFile(path, seedEntry(fakeJWT(time.Now().Add(5*time.Minute), "other"), testAKID), 0o600); err != nil {
		t.Fatalf("seed cache: %v", err)
	}
	f := &fakeSTS{token: fakeJWT(time.Now().Add(5*time.Minute), "aud")}
	ts := mustSource(t, f, Config{Audience: "aud", CachePath: path})

	if _, err := ts.Token(context.Background()); err != nil {
		t.Fatalf("Token: %v", err)
	}
	if f.callCount() != 1 {
		t.Errorf("STS calls = %d, want 1 (cached token has wrong audience)", f.callCount())
	}
}

func TestCacheCorruptFileReMints(t *testing.T) {
	path := filepath.Join(t.TempDir(), "tok.jwt")
	if err := os.WriteFile(path, []byte("not-a-jwt"), 0o600); err != nil {
		t.Fatalf("seed cache: %v", err)
	}
	f := &fakeSTS{token: fakeJWT(time.Now().Add(5*time.Minute), "aud")}
	ts := mustSource(t, f, Config{Audience: "aud", CachePath: path})

	if _, err := ts.Token(context.Background()); err != nil {
		t.Fatalf("Token: %v", err)
	}
	if f.callCount() != 1 {
		t.Errorf("STS calls = %d, want 1 (corrupt cache ignored)", f.callCount())
	}
}

func TestCacheWritesFileWith0600(t *testing.T) {
	// Cache path in a not-yet-existing nested dir: writeCache must create it.
	path := filepath.Join(t.TempDir(), "nested", "dir", "tok.jwt")
	f := &fakeSTS{token: fakeJWT(time.Now().Add(5*time.Minute), "aud")}
	ts := mustSource(t, f, Config{Audience: "aud", CachePath: path})

	if _, err := ts.Token(context.Background()); err != nil {
		t.Fatalf("Token: %v", err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("cache file not written: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Errorf("cache file perms = %o, want 600", perm)
	}
}

// TestCachePrincipalSwitchDoesNotReuseToken reproduces audit finding F06: two
// sources sharing audience and cache path but holding different credentials
// must not share a token.
func TestCachePrincipalSwitchDoesNotReuseToken(t *testing.T) {
	path := filepath.Join(t.TempDir(), "tok.jwt")
	admin := fakeJWT(time.Now().Add(5*time.Minute), "aud")
	reader := fakeJWT(time.Now().Add(6*time.Minute), "aud")

	fAdmin := &fakeSTS{token: admin}
	tsAdmin := withCredentials(mustSource(t, fAdmin, Config{Audience: "aud", CachePath: path}), "admin")
	if _, err := tsAdmin.Token(context.Background()); err != nil {
		t.Fatalf("admin Token: %v", err)
	}

	fReader := &fakeSTS{token: reader}
	tsReader := withCredentials(mustSource(t, fReader, Config{Audience: "aud", CachePath: path}), "reader")
	got, err := tsReader.Token(context.Background())
	if err != nil {
		t.Fatalf("reader Token: %v", err)
	}
	if got != reader {
		t.Errorf("reader got %q, want its own token %q", got, reader)
	}
	if fReader.callCount() != 1 {
		t.Errorf("reader STS calls = %d, want 1", fReader.callCount())
	}

	// The cache now belongs to the reader: switching back mints again.
	fBack := &fakeSTS{token: admin}
	tsBack := withCredentials(mustSource(t, fBack, Config{Audience: "aud", CachePath: path}), "admin")
	if _, err := tsBack.Token(context.Background()); err != nil {
		t.Fatalf("admin (again) Token: %v", err)
	}
	if fBack.callCount() != 1 {
		t.Errorf("admin (again) STS calls = %d, want 1", fBack.callCount())
	}
}

func TestCacheSamePrincipalReused(t *testing.T) {
	path := filepath.Join(t.TempDir(), "tok.jwt")
	token := fakeJWT(time.Now().Add(5*time.Minute), "aud")

	ts1 := withCredentials(mustSource(t, &fakeSTS{token: token}, Config{Audience: "aud", CachePath: path}), "same")
	if _, err := ts1.Token(context.Background()); err != nil {
		t.Fatalf("first Token: %v", err)
	}
	f2 := &fakeSTS{token: "unused"}
	ts2 := withCredentials(mustSource(t, f2, Config{Audience: "aud", CachePath: path}), "same")
	got, err := ts2.Token(context.Background())
	if err != nil {
		t.Fatalf("second Token: %v", err)
	}
	if got != token || f2.callCount() != 0 {
		t.Errorf("got %q with %d STS calls, want cached token and 0 calls", got, f2.callCount())
	}
}

// TestCacheBackgroundRefreshKeepsPrincipal: the refreshed entry stays bound to
// the credentials that requested it.
func TestCacheBackgroundRefreshKeepsPrincipal(t *testing.T) {
	path := filepath.Join(t.TempDir(), "tok.jwt")
	near := fakeJWT(time.Now().Add(2*time.Second), "aud")
	if err := os.WriteFile(path, seedEntry(near, "p1"), 0o600); err != nil {
		t.Fatalf("seed cache: %v", err)
	}
	fresh := fakeJWT(time.Now().Add(5*time.Minute), "aud")
	f := &fakeSTS{token: fresh}
	ts := withCredentials(mustSource(t, f, Config{Audience: "aud", CachePath: path, CacheRefreshBefore: time.Minute}), "p1")
	if got, err := ts.Token(context.Background()); err != nil || got != near {
		t.Fatalf("Token = %q, %v; want cached %q", got, err, near)
	}
	if !eventually(2*time.Second, func() bool {
		b, _ := os.ReadFile(path)
		return string(b) == string(seedEntry(fresh, "p1"))
	}) {
		t.Error("background refresh did not rewrite the entry bound to p1")
	}
}

func TestCacheUnresolvableCredentialsBypassesCache(t *testing.T) {
	path := filepath.Join(t.TempDir(), "tok.jwt")
	f := &fakeSTS{token: fakeJWT(time.Now().Add(5*time.Minute), "aud")}
	ts := mustSource(t, f, Config{Audience: "aud", CachePath: path})
	ts.credentials = aws.CredentialsProviderFunc(func(context.Context) (aws.Credentials, error) {
		return aws.Credentials{}, errors.New("no creds")
	})

	if _, err := ts.Token(context.Background()); err != nil {
		t.Fatalf("Token: %v", err)
	}
	if _, err := os.Stat(path); err == nil {
		t.Error("cache written although credentials could not be resolved")
	}
}

func TestCacheLegacyRawTokenIgnored(t *testing.T) {
	path := filepath.Join(t.TempDir(), "tok.jwt")
	if err := os.WriteFile(path, []byte(fakeJWT(time.Now().Add(5*time.Minute), "aud")), 0o600); err != nil {
		t.Fatalf("seed cache: %v", err)
	}
	f := &fakeSTS{token: fakeJWT(time.Now().Add(5*time.Minute), "aud")}
	ts := mustSource(t, f, Config{Audience: "aud", CachePath: path})
	if _, err := ts.Token(context.Background()); err != nil {
		t.Fatalf("Token: %v", err)
	}
	if f.callCount() != 1 {
		t.Errorf("STS calls = %d, want 1 (pre-binding cache format is a miss)", f.callCount())
	}
}

// TestCachePinsCredentialsForSigning: a provider that would yield a different
// principal on a second Retrieve must not split the fingerprint from the
// signature; the minted token and its recorded binding both name the first.
func TestCachePinsCredentialsForSigning(t *testing.T) {
	path := filepath.Join(t.TempDir(), "tok.jwt")
	creds := &seqCreds{ids: []string{"A", "B"}}
	ts, err := newWithClient(&credSTS{base: creds, exp: time.Now().Add(5 * time.Minute)}, Config{Audience: "aud", CachePath: path})
	if err != nil {
		t.Fatalf("newWithClient: %v", err)
	}
	ts.credentials = creds

	tok, err := ts.Token(context.Background())
	if err != nil {
		t.Fatalf("Token: %v", err)
	}
	if !strings.Contains(decodePayload(t, tok), `"sub":"A"`) {
		t.Errorf("token not signed by A: %s", decodePayload(t, tok))
	}
	if e := readEntry(t, path); e.Credential != fingerprint("A") {
		t.Errorf("entry bound to %q, want fingerprint of A", e.Credential)
	}
	if n := creds.retrievals(); n != 1 {
		t.Errorf("credential retrievals = %d, want 1 (resolved once per mint)", n)
	}
}

// TestCacheBackgroundRefreshResolvesCredentialsAtRefreshTime: the caller hits an
// entry bound to A; by the time the background refresh runs the provider yields
// B. B's token must be written under B's fingerprint, never under A's.
func TestCacheBackgroundRefreshResolvesCredentialsAtRefreshTime(t *testing.T) {
	path := filepath.Join(t.TempDir(), "tok.jwt")
	near := fakeJWTSub(time.Now().Add(2*time.Second), "aud", "A")
	if err := os.WriteFile(path, seedEntry(near, "A"), 0o600); err != nil {
		t.Fatalf("seed cache: %v", err)
	}
	creds := &seqCreds{ids: []string{"A", "B"}} // Token's lookup sees A, the refresh sees B
	ts, err := newWithClient(&credSTS{base: creds, exp: time.Now().Add(5 * time.Minute)}, Config{Audience: "aud", CachePath: path, CacheRefreshBefore: time.Minute})
	if err != nil {
		t.Fatalf("newWithClient: %v", err)
	}
	ts.credentials = creds

	if got, err := ts.Token(context.Background()); err != nil || got != near {
		t.Fatalf("Token = %q, %v; want A's cached %q", got, err, near)
	}
	if !eventually(2*time.Second, func() bool {
		b, _ := os.ReadFile(path)
		var e cacheEntry
		return json.Unmarshal(b, &e) == nil && e.Credential == fingerprint("B")
	}) {
		t.Fatalf("refresh did not rebind the entry to B: %+v", readEntry(t, path))
	}
	e := readEntry(t, path)
	if !strings.Contains(decodePayload(t, e.Token), `"sub":"B"`) {
		t.Errorf("entry bound to B holds a token not signed by B: %s", decodePayload(t, e.Token))
	}
}

func decodePayload(t *testing.T, token string) string {
	t.Helper()
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		t.Fatalf("malformed token %q", token)
	}
	b, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatalf("decode payload: %v", err)
	}
	return string(b)
}

// TestNewFromAWSConfigServiceOptionsCredentials: aws.Config.ServiceOptions may
// replace the STS client's credentials; the cache binding must follow what the
// client really signs with, not awsCfg.Credentials.
func TestNewFromAWSConfigServiceOptionsCredentials(t *testing.T) {
	cfg := aws.Config{
		Region:      "us-east-1",
		Credentials: staticCreds("CFG"),
		ServiceOptions: []func(string, any){func(_ string, o any) {
			if so, ok := o.(*sts.Options); ok {
				so.Credentials = staticCreds("OVERRIDE")
			}
		}},
	}
	ts, err := NewFromAWSConfig(cfg, Config{Audience: "aud"})
	if err != nil {
		t.Fatalf("NewFromAWSConfig: %v", err)
	}
	id, _, err := ts.pinCredentials(context.Background())
	if err != nil {
		t.Fatalf("pinCredentials: %v", err)
	}
	if id != fingerprint("OVERRIDE") {
		t.Errorf("fingerprint = %q, want the ServiceOptions override's (%q), not awsCfg.Credentials'", id, fingerprint("OVERRIDE"))
	}
}

// oldReadCache is the previous library version's cache read path (bare JWT,
// whitespace-trimmed), kept to prove old readers reject the new format when
// sharing a file.
func oldReadCache(b []byte, aud string) (string, bool) {
	tok := strings.TrimSpace(string(b))
	if tok == "" {
		return "", false
	}
	exp, auds, err := unverifiedExpiryAudience(tok)
	if err != nil || !time.Now().Before(exp) || !slices.Contains(auds, aud) {
		return "", false
	}
	return tok, true
}

func TestCacheFormatCompatibilityWithOldVersions(t *testing.T) {
	path := filepath.Join(t.TempDir(), "tok.jwt")
	jwt := fakeJWT(time.Now().Add(5*time.Minute), "aud")

	// Sanity: the old reader accepts a bare JWT, so the rejection below is meaningful.
	if _, ok := oldReadCache([]byte(jwt), "aud"); !ok {
		t.Fatal("old reader rejects a bare JWT; test harness is wrong")
	}

	// A new-format file written by this version is rejected by the old reader.
	ts := mustSource(t, &fakeSTS{token: jwt}, Config{Audience: "aud", CachePath: path})
	if _, err := ts.Token(context.Background()); err != nil {
		t.Fatalf("Token: %v", err)
	}
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read cache: %v", err)
	}
	if tok, ok := oldReadCache(b, "aud"); ok {
		t.Errorf("old reader accepted the new cache format as token %q", tok)
	}

	// An old-format (bare JWT) file is a miss for the new reader.
	if err := os.WriteFile(path, []byte(jwt), 0o600); err != nil {
		t.Fatalf("seed cache: %v", err)
	}
	if _, _, ok := ts.readCache(fingerprint(testAKID)); ok {
		t.Error("new reader accepted an old raw-JWT cache file")
	}
}

func TestCacheConcurrentAccess(t *testing.T) {
	path := filepath.Join(t.TempDir(), "tok.jwt")
	token := fakeJWT(time.Now().Add(5*time.Minute), "aud")
	var wg sync.WaitGroup
	for i := range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ts := withCredentials(mustSource(t, &fakeSTS{token: token}, Config{Audience: "aud", CachePath: path}), fmt.Sprintf("p%d", i%2))
			for range 20 {
				if got, err := ts.Token(context.Background()); err != nil || got != token {
					t.Errorf("Token = %q, %v", got, err)
					return
				}
			}
		}()
	}
	wg.Wait()
}

func TestDefaultCachePathPerAudience(t *testing.T) {
	t.Setenv("XDG_CACHE_HOME", t.TempDir()) // os.UserCacheDir honours this on Linux
	a, err := DefaultCachePath("nats://one")
	if err != nil {
		t.Fatalf("DefaultCachePath: %v", err)
	}
	b, err := DefaultCachePath("nats://two")
	if err != nil {
		t.Fatalf("DefaultCachePath: %v", err)
	}
	if a == b {
		t.Errorf("distinct audiences mapped to the same path %q", a)
	}
	if !strings.HasSuffix(a, ".jwt") {
		t.Errorf("path %q does not end in .jwt", a)
	}
}

// testAKID is the access key ID mustSource's sources sign with.
const testAKID = "AKIDTEST"

// fingerprint mirrors pinCredentials' binding for an access key ID.
func fingerprint(akid string) string {
	sum := sha256.Sum256([]byte(akid))
	return hex.EncodeToString(sum[:16])
}

// seedEntry builds the on-disk cache format, bound to the given access key ID,
// for tests that pre-seed a cache.
func seedEntry(token, akid string) []byte {
	b, _ := json.Marshal(cacheEntry{Version: cacheVersion, Credential: fingerprint(akid), Token: token})
	return b
}

func staticCreds(akid string) aws.CredentialsProvider {
	return aws.CredentialsProviderFunc(func(context.Context) (aws.Credentials, error) {
		return aws.Credentials{AccessKeyID: akid, SecretAccessKey: "secret"}, nil
	})
}

// withCredentials makes ts sign with a fixed access key ID.
func withCredentials(ts *TokenSource, akid string) *TokenSource {
	ts.credentials = staticCreds(akid)
	return ts
}

// seqCreds yields the given access key IDs on successive Retrieve calls and
// repeats the last one, modelling a provider that switches principal.
type seqCreds struct {
	mu   sync.Mutex
	ids  []string
	next int
}

func (c *seqCreds) Retrieve(context.Context) (aws.Credentials, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	id := c.ids[min(c.next, len(c.ids)-1)]
	c.next++
	return aws.Credentials{AccessKeyID: id, SecretAccessKey: "secret"}, nil
}

func (c *seqCreds) retrievals() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.next
}

// credSTS is an stsAPI that, like the real client, signs with whatever
// credentials the per-call options leave in sts.Options. The token it returns
// names the access key ID it was signed with (sub claim).
type credSTS struct {
	base aws.CredentialsProvider // used when no option overrides it
	exp  time.Time
}

func (c *credSTS) GetWebIdentityToken(ctx context.Context, _ *sts.GetWebIdentityTokenInput, optFns ...func(*sts.Options)) (*sts.GetWebIdentityTokenOutput, error) {
	o := sts.Options{Credentials: c.base}
	for _, fn := range optFns {
		fn(&o)
	}
	creds, err := o.Credentials.Retrieve(ctx)
	if err != nil {
		return nil, err
	}
	tok := fakeJWTSub(c.exp, "aud", creds.AccessKeyID)
	return &sts.GetWebIdentityTokenOutput{WebIdentityToken: &tok}, nil
}

func fakeJWTSub(exp time.Time, aud, sub string) string {
	enc := base64.RawURLEncoding.EncodeToString
	header := enc([]byte(`{"alg":"RS256","typ":"JWT"}`))
	payload := enc(fmt.Appendf(nil, `{"exp":%d,"aud":[%q],"sub":%q}`, exp.Unix(), aud, sub))
	return header + "." + payload + "." + enc([]byte("sig"))
}

func readEntry(t *testing.T, path string) cacheEntry {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read cache: %v", err)
	}
	var e cacheEntry
	if err := json.Unmarshal(b, &e); err != nil {
		t.Fatalf("parse cache: %v", err)
	}
	return e
}

func mustSource(t *testing.T, client stsAPI, cfg Config) *TokenSource {
	t.Helper()
	ts, err := newWithClient(client, cfg)
	if err != nil {
		t.Fatalf("newWithClient: %v", err)
	}
	return withCredentials(ts, testAKID)
}

// applyTokenHandler applies a nats.Option to an Options value and invokes the
// resulting token handler.
func applyTokenHandler(t *testing.T, opt nats.Option) string {
	t.Helper()
	var opts nats.Options
	if err := opt(&opts); err != nil {
		t.Fatalf("apply option: %v", err)
	}
	if opts.TokenHandler == nil {
		t.Fatal("TokenHandler not set")
	}
	return opts.TokenHandler()
}

func derefString(p *string) string {
	if p == nil {
		return ""
	}
	return *p
}

func derefInt32(p *int32) int32 {
	if p == nil {
		return 0
	}
	return *p
}
