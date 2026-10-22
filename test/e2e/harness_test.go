package e2e

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/nats-io/nats-server/v2/server"
	"github.com/nats-io/nats.go"
	"github.com/nats-io/nkeys"
	calloutlib "github.com/synadia-io/callout.go"

	"github.com/sylr/nats-oidc-callout/internal/authz"
	"github.com/sylr/nats-oidc-callout/internal/callout"
	"github.com/sylr/nats-oidc-callout/internal/config"
	"github.com/sylr/nats-oidc-callout/internal/metrics"
	"github.com/sylr/nats-oidc-callout/internal/mockoidc"
	"github.com/sylr/nats-oidc-callout/internal/verifier"
)

const (
	authUser     = "auth"
	authPassword = "authpass"
	testAudience = "nats://callout-e2e"
)

// harness is a running embedded NATS server with the auth callout service wired
// to a verifier trusting a mock OIDC IdP.
type harness struct {
	srv        *server.Server
	idp        *mockoidc.Server
	svc        *calloutlib.AuthorizationService
	svcConn    *nats.Conn
	metrics    *metrics.Metrics
	authorizer *callout.Authorizer
	verifier   *verifier.Verifier
}

// setup builds the full stack against a hermetic mock OIDC IdP.
func setup(t *testing.T, policy *authz.Policy, requireClaims map[string]string) *harness {
	t.Helper()
	idp := mockoidc.New(t)
	h := setupWithIssuer(t, policy, idp.Issuer(), requireClaims)
	h.idp = idp
	return h
}

// setupWithIssuer builds the stack trusting issuerURL and the default test
// audience.
func setupWithIssuer(t *testing.T, policy *authz.Policy, issuerURL string, requireClaims map[string]string) *harness {
	return setupWithIssuerAudience(t, policy, issuerURL, requireClaims, testAudience)
}

// setupWithIssuerAudience builds the embedded NATS server, verifier, and callout
// service trusting a single OIDC issuer and a single accepted audience. It is
// issuer-agnostic so both the mock IdP and the real-AWS suite can reuse it.
func setupWithIssuerAudience(t *testing.T, policy *authz.Policy, issuerURL string, requireClaims map[string]string, audience string) *harness {
	t.Helper()

	// Compile matchers and enforce guardrails, exactly as config.Load does in
	// production. Skipping this would leave ARN matchers uncompiled.
	if err := policy.Validate(); err != nil {
		t.Fatalf("policy.Validate: %v", err)
	}

	accountKP, err := nkeys.CreateAccount()
	if err != nil {
		t.Fatalf("create account key: %v", err)
	}
	accountPub, err := accountKP.PublicKey()
	if err != nil {
		t.Fatalf("account public key: %v", err)
	}
	xkeyKP, err := nkeys.CreateCurveKeys()
	if err != nil {
		t.Fatalf("create xkey: %v", err)
	}
	xkeyPub, err := xkeyKP.PublicKey()
	if err != nil {
		t.Fatalf("xkey public key: %v", err)
	}

	conf := fmt.Sprintf(`
listen: 127.0.0.1:-1
accounts {
  AUTH { users: [ { user: %q, password: %q } ] }
  APP {}
  SYS {}
}
system_account: SYS
authorization {
  auth_callout {
    issuer: %q
    account: AUTH
    auth_users: [ %q ]
    xkey: %q
  }
}
`, authUser, authPassword, accountPub, authUser, xkeyPub)

	confPath := filepath.Join(t.TempDir(), "server.conf")
	if err := os.WriteFile(confPath, []byte(conf), 0o600); err != nil {
		t.Fatalf("write server conf: %v", err)
	}

	opts, err := server.ProcessConfigFile(confPath)
	if err != nil {
		t.Fatalf("process server conf: %v", err)
	}
	opts.NoLog = true
	opts.NoSigs = true

	srv, err := server.NewServer(opts)
	if err != nil {
		t.Fatalf("new server: %v", err)
	}
	go srv.Start()
	if !srv.ReadyForConnections(10 * time.Second) {
		t.Fatal("server not ready")
	}
	t.Cleanup(srv.Shutdown)

	v, err := verifier.New(context.Background(), verifier.Options{
		Issuers:     []verifier.IssuerOption{{URL: issuerURL, RequireClaims: requireClaims}},
		Audiences:   []string{audience},
		SigningAlgs: []string{oidc.RS256},
		HTTPTimeout: 5 * time.Second,
	})
	if err != nil {
		t.Fatalf("verifier.New: %v", err)
	}

	m := metrics.New()
	authorizer := callout.New(v, policy, accountKP, discardLogger(), m, 0)

	svcConn, err := nats.Connect(srv.ClientURL(), nats.UserInfo(authUser, authPassword))
	if err != nil {
		t.Fatalf("service connect: %v", err)
	}
	t.Cleanup(svcConn.Close)

	svc, err := calloutlib.NewAuthorizationService(svcConn,
		calloutlib.Authorizer(authorizer.Authorize),
		calloutlib.ResponseSignerKey(accountKP),
		calloutlib.EncryptionKey(xkeyKP),
		calloutlib.AsyncWorkers(config.DefaultWorkers),
	)
	if err != nil {
		t.Fatalf("start callout service: %v", err)
	}
	t.Cleanup(func() { _ = svc.Stop() })

	return &harness{srv: srv, svc: svc, svcConn: svcConn, metrics: m, authorizer: authorizer, verifier: v}
}

// appPolicy returns a policy granting the given ARN access to the APP account
// limited to the "app.>" subject space.
func appPolicy(arn string) *authz.Policy {
	p := &authz.Policy{Rules: []authz.Rule{{
		Name:  "app",
		Match: authz.Match{Sub: arn},
		Grant: authz.Grant{
			Account:   "APP",
			Publish:   &authz.Permission{Allow: []string{"app.>"}},
			Subscribe: &authz.Permission{Allow: []string{"app.>", "_INBOX.>"}},
		},
	}}}
	return p
}

// connectClient attempts a client connection using token as the AWS web identity
// token. The caller closes the returned conn.
func (h *harness) connectClient(t *testing.T, token string) (*nats.Conn, error) {
	t.Helper()
	nc, err := nats.Connect(h.srv.ClientURL(),
		nats.Token(token),
		nats.MaxReconnects(0),
		nats.Timeout(5*time.Second),
	)
	if err == nil {
		t.Cleanup(nc.Close)
	}
	return nc, err
}

func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}
