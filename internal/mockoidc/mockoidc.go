// Package mockoidc is a hermetic OIDC identity provider for tests. It serves the
// OIDC discovery and JWKS endpoints and mints JWTs shaped like AWS Web Identity
// Tokens, with knobs for negative cases (key rotation, unknown kid, expiry,
// not-before, multiple audiences, wrong issuer).
package mockoidc

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"maps"
	"math/big"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sylr/nats-oidc-callout/internal/identity"
)

// key is a single RSA signing key with a stable kid.
type key struct {
	kid  string
	priv *rsa.PrivateKey
}

// Server is a running mock OIDC IdP.
type Server struct {
	httpSrv *httptest.Server
	mu      sync.Mutex
	keys    []*key // keys[0] is the default signer

	jwksRequests atomic.Int64
	jwksGate     chan struct{} // when non-nil, JWKS requests block until it is closed
	jwksEntered  chan struct{} // signalled when a request reaches the gate
}

// New starts a mock OIDC IdP with one RSA signing key and returns it. The caller
// is responsible for nothing — cleanup is registered via t.Cleanup.
func New(t *testing.T) *Server {
	t.Helper()
	s := &Server{}
	s.addKeyLocked(t, "key-1")

	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", s.handleDiscovery)
	mux.HandleFunc("/.well-known/jwks.json", s.handleJWKS)
	s.httpSrv = httptest.NewServer(mux)
	t.Cleanup(s.httpSrv.Close)
	return s
}

// Issuer returns the issuer URL (also the discovery base).
func (s *Server) Issuer() string { return s.httpSrv.URL }

// AddKey adds another signing key (for rotation tests) and returns its kid.
func (s *Server) AddKey(t *testing.T, kid string) string {
	t.Helper()
	s.mu.Lock()
	defer s.mu.Unlock()
	s.addKeyLocked(t, kid)
	return kid
}

// SetDefaultKey moves the key with the given kid to the front so new tokens are
// signed with it.
func (s *Server) SetDefaultKey(kid string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i, k := range s.keys {
		if k.kid == kid {
			s.keys[0], s.keys[i] = s.keys[i], s.keys[0]
			return
		}
	}
}

func (s *Server) addKeyLocked(t *testing.T, kid string) {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate RSA key: %v", err)
	}
	s.keys = append(s.keys, &key{kid: kid, priv: priv})
}

// TokenOptions controls a minted token. Zero values get sensible defaults.
type TokenOptions struct {
	Subject       string
	Audience      []string
	AWSAccount    string
	OrgID         string
	PrincipalTags map[string]string
	IssuedAt      time.Time
	NotBefore     time.Time
	Expiry        time.Time

	// ExtraClaims adds arbitrary top-level claims (e.g. GitHub-shaped
	// repository/repository_owner/repository_id). They are written before the
	// standard claims, so reserved names cannot be overridden.
	ExtraClaims map[string]any

	// IssuerOverride, when set, replaces the iss claim (to test wrong issuer).
	IssuerOverride string
	// KidOverride, when set, is written into the JWT header without signing
	// with a matching key — used to test unknown-kid rejection. When empty the
	// default key is used.
	KidOverride string
	// SignWithKid signs with a specific key (must exist). Empty = default key.
	SignWithKid string
}

// Mint builds and signs a token (RS256) with the given options.
func (s *Server) Mint(t *testing.T, opts TokenOptions) string {
	t.Helper()
	s.mu.Lock()
	defer s.mu.Unlock()

	signer := s.keys[0]
	if opts.SignWithKid != "" {
		signer = s.findKey(t, opts.SignWithKid)
	}

	now := time.Now()
	iat := opts.IssuedAt
	if iat.IsZero() {
		iat = now
	}
	exp := opts.Expiry
	if exp.IsZero() {
		exp = now.Add(5 * time.Minute)
	}
	iss := s.httpSrv.URL
	if opts.IssuerOverride != "" {
		iss = opts.IssuerOverride
	}

	claims := map[string]any{}
	maps.Copy(claims, opts.ExtraClaims)
	claims["iss"] = iss
	claims["sub"] = opts.Subject
	claims["aud"] = opts.Audience
	claims["iat"] = iat.Unix()
	claims["exp"] = exp.Unix()
	claims["jti"] = opts.Subject + "-" + strconvI(iat.UnixNano())
	if !opts.NotBefore.IsZero() {
		claims["nbf"] = opts.NotBefore.Unix()
	}
	ns := map[string]any{}
	if opts.AWSAccount != "" {
		ns["aws_account"] = opts.AWSAccount
	}
	if opts.OrgID != "" {
		ns["org_id"] = opts.OrgID
	}
	if len(opts.PrincipalTags) > 0 {
		ns["principal_tags"] = opts.PrincipalTags
	}
	if len(ns) > 0 {
		claims[identity.Namespace] = ns
	}

	kid := signer.kid
	if opts.KidOverride != "" {
		kid = opts.KidOverride
	}
	header := map[string]any{"alg": "RS256", "typ": "JWT", "kid": kid}

	signingInput := encodeSegment(t, header) + "." + encodeSegment(t, claims)
	digest := sha256.Sum256([]byte(signingInput))
	sig, err := rsa.SignPKCS1v15(rand.Reader, signer.priv, crypto.SHA256, digest[:])
	if err != nil {
		t.Fatalf("sign token: %v", err)
	}
	return signingInput + "." + base64.RawURLEncoding.EncodeToString(sig)
}

func (s *Server) findKey(t *testing.T, kid string) *key {
	t.Helper()
	for _, k := range s.keys {
		if k.kid == kid {
			return k
		}
	}
	t.Fatalf("no key with kid %q", kid)
	return nil
}

func (s *Server) handleDiscovery(w http.ResponseWriter, _ *http.Request) {
	doc := map[string]any{
		"issuer":                                s.httpSrv.URL,
		"jwks_uri":                              s.httpSrv.URL + "/.well-known/jwks.json",
		"authorization_endpoint":                s.httpSrv.URL + "/authorize",
		"token_endpoint":                        s.httpSrv.URL + "/token",
		"response_types_supported":              []string{"id_token"},
		"subject_types_supported":               []string{"public"},
		"id_token_signing_alg_values_supported": []string{"RS256", "ES384"},
	}
	writeJSON(w, doc)
}

// JWKSRequests returns how many times the JWKS endpoint has been requested.
func (s *Server) JWKSRequests() int { return int(s.jwksRequests.Load()) }

// HoldJWKS makes subsequent JWKS requests block until release is called (or
// the test ends). entered receives a value each time a request reaches the hold.
func (s *Server) HoldJWKS(t *testing.T) (entered <-chan struct{}, release func()) {
	t.Helper()
	s.mu.Lock()
	defer s.mu.Unlock()
	gate := make(chan struct{})
	s.jwksGate = gate
	s.jwksEntered = make(chan struct{}, 64)
	var once sync.Once
	release = func() {
		once.Do(func() {
			s.mu.Lock()
			s.jwksGate = nil
			s.mu.Unlock()
			close(gate)
		})
	}
	t.Cleanup(release)
	return s.jwksEntered, release
}

func (s *Server) handleJWKS(w http.ResponseWriter, r *http.Request) {
	s.jwksRequests.Add(1)
	s.mu.Lock()
	gate, entered := s.jwksGate, s.jwksEntered
	s.mu.Unlock()
	if gate != nil {
		select {
		case entered <- struct{}{}:
		default:
		}
		select {
		case <-gate:
		case <-r.Context().Done():
			return
		}
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	keys := make([]map[string]any, 0, len(s.keys))
	for _, k := range s.keys {
		pub := k.priv.Public().(*rsa.PublicKey)
		keys = append(keys, map[string]any{
			"kty": "RSA",
			"use": "sig",
			"alg": "RS256",
			"kid": k.kid,
			"n":   base64.RawURLEncoding.EncodeToString(pub.N.Bytes()),
			"e":   base64.RawURLEncoding.EncodeToString(encodeExponent(pub.E)),
		})
	}
	writeJSON(w, map[string]any{"keys": keys})
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

func encodeSegment(t *testing.T, v any) string {
	t.Helper()
	data, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("marshal segment: %v", err)
	}
	return base64.RawURLEncoding.EncodeToString(data)
}

// encodeExponent renders an RSA public exponent as a big-endian byte slice with
// no leading zero bytes, as required by the JWK "e" parameter.
func encodeExponent(e int) []byte {
	var buf [8]byte
	binary.BigEndian.PutUint64(buf[:], uint64(e))
	b := buf[:]
	for len(b) > 1 && b[0] == 0 {
		b = b[1:]
	}
	return b
}

func strconvI(n int64) string {
	return new(big.Int).SetInt64(n).String()
}
