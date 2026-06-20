//go:build e2e_aws

// This suite exercises the real AWS path. It is gated behind the `e2e_aws` build
// tag and the E2E_AWS=1 environment variable, and requires:
//   - AWS credentials in the environment (regional STS endpoint; the
//     GetWebIdentityToken API is NOT available on the STS global endpoint),
//   - outbound web identity federation enabled on the account
//     (`aws iam enable-outbound-web-identity-federation`),
//   - an IAM policy allowing sts:GetWebIdentityToken for E2E_AWS_AUDIENCE.
//
// Run with:
//
//	E2E_AWS=1 AWS_REGION=us-east-1 E2E_AWS_AUDIENCE=nats://callout-e2e \
//	  go test -tags e2e_aws -run AWS ./test/e2e/...
package e2e

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/sylr/nats-jwt-callout/internal/authz"
	"github.com/sylr/nats-jwt-callout/lib/awsauth"
)

func TestAWSRealToken(t *testing.T) {
	if os.Getenv("E2E_AWS") != "1" {
		t.Skip("E2E_AWS!=1; skipping real-AWS suite")
	}
	audience := os.Getenv("E2E_AWS_AUDIENCE")
	if audience == "" {
		audience = "nats://callout-e2e"
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// The lib loads the default AWS config and requires a region: the global
	// STS endpoint does not serve GetWebIdentityToken. Defaults (RS256, 5m)
	// preserve the previous inline behaviour's algorithm.
	ts, err := awsauth.New(ctx, awsauth.Config{Audience: audience})
	if err != nil {
		t.Fatalf("awsauth.New: %v", err)
	}
	token, err := ts.Token(ctx)
	if err != nil {
		t.Fatalf("mint web identity token: %v (is outbound web identity federation enabled?)", err)
	}

	iss, sub, account := inspectToken(t, token)
	t.Logf("issued token: iss=%s sub=%s aws_account=%s", iss, sub, account)

	// Build a policy that grants exactly this caller's ARN.
	policy := &authz.Policy{Rules: []authz.Rule{{
		Name:  "aws-caller",
		Match: authz.Match{Issuer: iss, Sub: sub, Claims: map[string]string{"aws.aws_account": account}},
		Grant: authz.Grant{
			Account:   "APP",
			Publish:   authz.Permission{Allow: []string{"app.>"}},
			Subscribe: authz.Permission{Allow: []string{"app.>", "_INBOX.>"}},
		},
	}}}

	// The verifier must accept the audience we requested from STS and bind the
	// issuer to this AWS account.
	h := setupWithIssuerAudience(t, policy, iss, map[string]string{"aws.aws_account": account}, audience)

	nc, err := h.connectClient(t, token)
	if err != nil {
		t.Fatalf("connect with real AWS token: %v", err)
	}
	sub2, err := nc.SubscribeSync("app.real")
	if err != nil {
		t.Fatalf("subscribe: %v", err)
	}
	if err := nc.Publish("app.real", []byte("aws")); err != nil {
		t.Fatalf("publish: %v", err)
	}
	_ = nc.Flush()
	if _, err := sub2.NextMsg(2 * time.Second); err != nil {
		t.Fatalf("expected message within grant: %v", err)
	}
}

// inspectToken parses the unverified token to extract iss, sub, and aws_account
// so the test can configure a matching verifier and policy.
func inspectToken(t *testing.T, token string) (iss, sub, account string) {
	t.Helper()
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		t.Fatalf("malformed token")
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatalf("decode token payload: %v", err)
	}
	var claims struct {
		Iss        string `json:"iss"`
		Sub        string `json:"sub"`
		Namespaced struct {
			AWSAccount string `json:"aws_account"`
		} `json:"https://sts.amazonaws.com/"`
	}
	if err := json.Unmarshal(payload, &claims); err != nil {
		t.Fatalf("parse token payload: %v", err)
	}
	return claims.Iss, claims.Sub, claims.Namespaced.AWSAccount
}
