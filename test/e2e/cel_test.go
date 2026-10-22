package e2e

import (
	"testing"
	"time"

	"github.com/sylr/nats-oidc-callout/internal/authz"
	"github.com/sylr/nats-oidc-callout/internal/mockoidc"
)

// celAppPolicy grants APP access only when a CEL expression over the verified
// identity holds. The expression pins the AWS account and an exact role ARN.
func celAppPolicy() *authz.Policy {
	return &authz.Policy{Rules: []authz.Rule{{
		Name: "cel",
		Match: authz.Match{
			Expr:       `claims["aws.aws_account"] == "123456789012" && sub == "arn:aws:iam::123456789012:role/AppRole"`,
			AllowBroad: true,
		},
		Grant: authz.Grant{
			Account:   "APP",
			Publish:   &authz.Permission{Allow: []string{"app.>"}},
			Subscribe: &authz.Permission{Allow: []string{"app.>", "_INBOX.>"}},
		},
	}}}
}

// TestCELPolicyEnforcedHermetic drives a CEL-gated policy through the full
// callout path with mock tokens: the expression both allows and denies.
func TestCELPolicyEnforcedHermetic(t *testing.T) {
	h := setup(t, celAppPolicy(), awsRequire)

	// validToken has sub=testARN and aws_account=testAccount → CEL matches.
	nc, err := h.connectClient(t, h.validToken(t))
	if err != nil {
		t.Fatalf("expected CEL-authorized connect: %v", err)
	}
	sub, err := nc.SubscribeSync("app.cel")
	if err != nil {
		t.Fatalf("subscribe: %v", err)
	}
	if err := nc.Publish("app.cel", []byte("ok")); err != nil {
		t.Fatalf("publish: %v", err)
	}
	_ = nc.Flush()
	if _, err := sub.NextMsg(2 * time.Second); err != nil {
		t.Fatalf("expected message within grant: %v", err)
	}

	// A token that passes verification (correct aws_account, so require_claims is
	// satisfied) but whose sub the CEL expression rejects → connection denied.
	denied := h.idp.Mint(t, mockoidc.TokenOptions{
		Subject:    "arn:aws:iam::123456789012:role/OtherRole",
		Audience:   []string{testAudience},
		AWSAccount: testAccount,
	})
	if _, err := h.connectClient(t, denied); err == nil {
		t.Fatal("expected CEL denial for a non-matching sub")
	}
}
