package authz

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/sylr/nats-oidc-callout/internal/identity"
)

func mustValidate(t *testing.T, p *Policy) {
	t.Helper()
	if err := p.Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}
}

func id(subject string, claims map[string]string) *identity.Identity {
	return identity.New(subject, claims)
}

func TestExactARNMatch(t *testing.T) {
	p := &Policy{Rules: []Rule{{
		Name:  "data-role",
		Match: Match{Sub: "arn:aws:iam::123456789012:role/DataRole"},
		Grant: Grant{Account: "APP", Publish: &Permission{Allow: []string{"app.>"}}},
	}}}
	mustValidate(t, p)

	d, err := p.Evaluate(id("arn:aws:iam::123456789012:role/DataRole", nil))
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if d.Account != "APP" {
		t.Errorf("account = %q, want APP", d.Account)
	}
	if _, err := p.Evaluate(id("arn:aws:iam::123456789012:role/Other", nil)); err == nil {
		t.Error("expected no match for different ARN")
	}
}

func TestGlobAccountPinnedAllowed(t *testing.T) {
	p := &Policy{Rules: []Rule{{
		Match: Match{Sub: "arn:aws:iam::123456789012:role/*"},
		Grant: Grant{Account: "APP"},
	}}}
	mustValidate(t, p) // account pinned in ARN, so not broad
	if _, err := p.Evaluate(id("arn:aws:iam::123456789012:role/AnyRole", nil)); err != nil {
		t.Errorf("expected match: %v", err)
	}
	if _, err := p.Evaluate(id("arn:aws:iam::999999999999:role/AnyRole", nil)); err == nil {
		t.Error("expected no match for different account")
	}
}

func TestGlobAccountPin(t *testing.T) {
	for sub, pinned := range map[string]bool{
		"arn:aws:iam::123456789012:role/*":    true,
		"arn:aws:iam::123456789012:*":         true,
		"arn:aws:iam::*:role/*":               false, // wildcard account
		"arn:aws:iam::12345678901*:role/App":  false, // partial account
		"arn:aws:sts:*:123456789012:*":        false, // "*" before the account can shift it
		"arn:*:iam::123456789012:role/*":      false,
		"*:*:*:*:123456789012:*":              false,
		"*:123456789012:*":                    false, // account is not the 5th field
		"arn:aws:iam::123456789012:role/App*": true,
	} {
		p := &Policy{Rules: []Rule{{Match: Match{Sub: sub}, Grant: Grant{Account: "APP"}}}}
		if err := p.Validate(); (err == nil) != pinned {
			t.Errorf("sub %q: pinned = %v, Validate err = %v", sub, pinned, err)
		}
	}
}

func TestGlobWildcardBeforeAccountMatchesOtherAccounts(t *testing.T) {
	// Why a "*" before the account field cannot count as a pin: it absorbs
	// colons, so the literal account can land in a later field.
	p := &Policy{Rules: []Rule{{
		Match: Match{Sub: "arn:aws:sts:*:123456789012:*", AllowBroad: true},
		Grant: Grant{Account: "APP"},
	}}}
	mustValidate(t, p)
	if _, err := p.Evaluate(id("arn:aws:sts:x:999999999999:y:123456789012:z", nil)); err != nil {
		t.Errorf("expected the shifted subject to match: %v", err)
	}
}

func TestRegexSubNeverPinsAccount(t *testing.T) {
	// Each expression's text has 123456789012 as its 5th colon-separated field,
	// which the old textual check took as an account pin. other is a subject
	// from account 999999999999; matchesOther is whether the expression really
	// admits it.
	for name, tc := range map[string]struct {
		sub, other   string
		matchesOther bool
	}{
		"alternation": {
			sub:   `re:^arn:aws:iam::123456789012:role/.*|.*$`,
			other: "arn:aws:iam::999999999999:role/Other", matchesOther: true,
		},
		"grouping": {
			sub:   `re:^(arn:aws:iam::123456789012:role/.*|arn:aws:iam::.*)$`,
			other: "arn:aws:iam::999999999999:role/Other", matchesOther: true,
		},
		"escaped": {
			sub:   `re:^.*\:.*\:.*\:.*:123456789012:.*$`,
			other: "arn:aws:iam::999999999999:role/a:123456789012:b", matchesOther: true,
		},
		"literal": {
			sub:   `re:^arn:aws:iam::123456789012:role/App$`,
			other: "arn:aws:iam::999999999999:role/App", matchesOther: false,
		},
	} {
		t.Run(name, func(t *testing.T) {
			p := &Policy{Rules: []Rule{{Match: Match{Sub: tc.sub}, Grant: Grant{Account: "APP"}}}}
			if err := p.Validate(); err == nil {
				t.Fatal("regex sub must require allow_broad or another pin")
			}

			// Acknowledged as broad: validates, and runtime matching follows the
			// expression's real meaning.
			p.Rules[0].Match.AllowBroad = true
			mustValidate(t, p)
			if _, err := p.Evaluate(id(tc.other, nil)); (err == nil) != tc.matchesOther {
				t.Errorf("match %q = %v, want %v", tc.other, err == nil, tc.matchesOther)
			}

			// A literal aws.aws_account claim is a strong pin and scopes the rule.
			p.Rules[0].Match.AllowBroad = false
			p.Rules[0].Match.Claims = map[string]string{"aws.aws_account": "123456789012"}
			mustValidate(t, p)
			if _, err := p.Evaluate(id(tc.other, map[string]string{"aws.aws_account": "999999999999"})); err == nil {
				t.Error("claim-pinned regex rule matched another account")
			}
		})
	}
}

func TestAWSAccountWildcardIsBroad(t *testing.T) {
	p := &Policy{Rules: []Rule{{
		Match: Match{Sub: "arn:aws:iam::*:role/*"},
		Grant: Grant{Account: "APP"},
	}}}
	if err := p.Validate(); err == nil {
		t.Fatal("expected broad-rule error for account-wildcard ARN")
	}
	// Pinning aws.aws_account via claims makes it acceptable.
	p.Rules[0].Match.Claims = map[string]string{"aws.aws_account": "123456789012"}
	mustValidate(t, p)
}

func TestClaimsMatch(t *testing.T) {
	p := &Policy{Rules: []Rule{{
		Match: Match{Claims: map[string]string{"aws.aws_account": "123456789012", "aws.org_id": "o-abc"}},
		Grant: Grant{Account: "APP"},
	}}}
	mustValidate(t, p)
	ok := id("arn:x", map[string]string{"aws.aws_account": "123456789012", "aws.org_id": "o-abc"})
	if _, err := p.Evaluate(ok); err != nil {
		t.Errorf("expected match: %v", err)
	}
	bad := id("arn:x", map[string]string{"aws.aws_account": "123456789012", "aws.org_id": "o-xyz"})
	if _, err := p.Evaluate(bad); err == nil {
		t.Error("expected no match for wrong org")
	}
}

func TestCrossProviderClaimCollisionPrevented(t *testing.T) {
	// A rule keyed aws.aws_account must NOT be satisfied by a top-level
	// aws_account claim from some other issuer.
	p := &Policy{Rules: []Rule{{
		Match: Match{Claims: map[string]string{"aws.aws_account": "123456789012"}},
		Grant: Grant{Account: "APP"},
	}}}
	mustValidate(t, p)
	spoof := id("whatever", map[string]string{"aws_account": "123456789012"}) // bare, not aws.*
	if _, err := p.Evaluate(spoof); err == nil {
		t.Fatal("bare aws_account must not satisfy an aws.aws_account rule")
	}
}

func TestGitHubRepositoryPinIsNotBroad(t *testing.T) {
	p := &Policy{Rules: []Rule{{
		Match: Match{
			Issuer: "https://token.actions.githubusercontent.com",
			Claims: map[string]string{"repository": "sylr/nats-oidc-callout"},
		},
		Grant: Grant{Account: "APP"},
	}}}
	mustValidate(t, p)
	ok := id("repo:sylr/nats-oidc-callout:ref:refs/heads/main",
		map[string]string{"repository": "sylr/nats-oidc-callout", "repository_owner": "sylr"})
	ok.Issuer = "https://token.actions.githubusercontent.com"
	if _, err := p.Evaluate(ok); err != nil {
		t.Errorf("expected match: %v", err)
	}
	// Different repo (same owner) must not match.
	other := id("repo:sylr/other:ref:refs/heads/main",
		map[string]string{"repository": "sylr/other"})
	other.Issuer = "https://token.actions.githubusercontent.com"
	if _, err := p.Evaluate(other); err == nil {
		t.Error("expected no match for different repository")
	}
}

func TestGitHubOwnerOnlyIsBroad(t *testing.T) {
	p := &Policy{Rules: []Rule{{
		Match: Match{Claims: map[string]string{"repository_owner": "sylr"}},
		Grant: Grant{Account: "APP"},
	}}}
	if err := p.Validate(); err == nil {
		t.Fatal("owner-only GitHub rule must require allow_broad")
	}
}

func TestGitHubWildcardSubsAreBroad(t *testing.T) {
	for _, sub := range []string{"*", "repo:*", "repo:sylr/*"} {
		p := &Policy{Rules: []Rule{{Match: Match{Sub: sub}, Grant: Grant{Account: "APP"}}}}
		if err := p.Validate(); err == nil {
			t.Errorf("sub %q should be broad", sub)
		}
	}
}

func TestIssuerScoping(t *testing.T) {
	p := &Policy{Rules: []Rule{{
		Match: Match{Issuer: "https://issuer-a", Sub: "arn:aws:iam::123456789012:role/R"},
		Grant: Grant{Account: "APP"},
	}}}
	mustValidate(t, p)
	wrongIss := id("arn:aws:iam::123456789012:role/R", nil)
	wrongIss.Issuer = "https://issuer-b"
	if _, err := p.Evaluate(wrongIss); err == nil {
		t.Error("rule scoped to issuer-a must not match issuer-b")
	}
}

func TestFullAnchorGlob(t *testing.T) {
	p := &Policy{Rules: []Rule{{
		Match: Match{Sub: "repo:sylr/nats-oidc-callout", Claims: map[string]string{"repository": "sylr/nats-oidc-callout"}},
		Grant: Grant{Account: "APP"},
	}}}
	mustValidate(t, p)
	// Must not match a superstring.
	if _, err := p.Evaluate(id("repo:sylr/nats-oidc-callout-evil", map[string]string{"repository": "sylr/nats-oidc-callout"})); err == nil {
		t.Error("exact sub must not match a superstring")
	}
}

func TestFullAnchorRegex(t *testing.T) {
	p := &Policy{Rules: []Rule{{
		Match: Match{Sub: `re:^repo:sylr/(nats-oidc-callout)$`, Claims: map[string]string{"repository": "sylr/nats-oidc-callout"}},
		Grant: Grant{Account: "APP"},
	}}}
	mustValidate(t, p)
	if _, err := p.Evaluate(id("repo:sylr/nats-oidc-callout-evil", map[string]string{"repository": "sylr/nats-oidc-callout"})); err == nil {
		t.Error("anchored regex must not match a superstring")
	}
}

func TestUnanchoredRegexRejected(t *testing.T) {
	p := &Policy{Rules: []Rule{{
		Match: Match{Sub: "re:arn:aws:iam::123456789012:role/.*", AllowBroad: true},
		Grant: Grant{Account: "APP"},
	}}}
	if err := p.Validate(); err == nil {
		t.Fatal("expected error for unanchored regex")
	}
}

func TestFirstMatchWins(t *testing.T) {
	p := &Policy{Rules: []Rule{
		{Name: "specific", Match: Match{Sub: "arn:aws:iam::123456789012:role/DataRole"}, Grant: Grant{Account: "DATA"}},
		{Name: "account", Match: Match{Claims: map[string]string{"aws.aws_account": "123456789012"}}, Grant: Grant{Account: "GENERAL"}},
	}}
	mustValidate(t, p)
	d, err := p.Evaluate(id("arn:aws:iam::123456789012:role/DataRole", map[string]string{"aws.aws_account": "123456789012"}))
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if d.Account != "DATA" {
		t.Errorf("account = %q, want DATA (first match)", d.Account)
	}
}

func TestResponsePermissionRendered(t *testing.T) {
	p := &Policy{Rules: []Rule{{
		Match: Match{Sub: "arn:aws:iam::123456789012:role/Svc"},
		Grant: Grant{Account: "APP", Response: &Response{Max: 1, TTL: 2 * time.Second}},
	}}}
	mustValidate(t, p)
	d, _ := p.Evaluate(id("arn:aws:iam::123456789012:role/Svc", nil))
	if d.Permissions.Resp == nil || d.Permissions.Resp.MaxMsgs != 1 || d.Permissions.Resp.Expires != 2*time.Second {
		t.Errorf("resp = %+v", d.Permissions.Resp)
	}
}

func TestUnvalidatedPolicyFailsClosed(t *testing.T) {
	p := &Policy{Rules: []Rule{{Match: Match{Sub: "arn:aws:iam::1:role/r"}, Grant: Grant{Account: "APP"}}}}
	if _, err := p.Evaluate(id("anything", nil)); err == nil {
		t.Fatal("Evaluate must fail before Validate")
	}
}

func TestMissingAccountRejected(t *testing.T) {
	p := &Policy{Rules: []Rule{{Match: Match{Sub: "arn:aws:iam::1:role/r"}}}}
	if err := p.Validate(); err == nil {
		t.Fatal("expected error for missing grant.account")
	}
}

// writePolicy writes body to a temporary policy file and returns its path.
func writePolicy(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "policy.yaml")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("write policy: %v", err)
	}
	return path
}

func TestLoadPolicyValid(t *testing.T) {
	p, err := LoadPolicy(writePolicy(t, `
rules:
- name: app
  match:
    issuer: "https://issuer"
    sub: "arn:aws:iam::123456789012:role/AppRole"
  grant:
    account: APP
    publish: { allow: ["app.>"], deny: ["app.secret"] }
    subscribe: { allow: ["app.>", "_INBOX.>"] }
    response: { max: 1, ttl: "1m" }
    max_expiry: "1h"
`))
	if err != nil {
		t.Fatalf("LoadPolicy: %v", err)
	}
	if g := p.Rules[0].Grant; g.MaxExpiry != time.Hour || g.Response == nil || g.Response.TTL != time.Minute {
		t.Errorf("grant = %+v", g)
	}
}

func TestLoadPolicyRejectsUnknownFields(t *testing.T) {
	// Each case misspells one field at a different nesting level; the typo must
	// fail the load rather than silently dropping the restriction it carried.
	for name, tc := range map[string]struct{ body, field string }{
		"top level": {field: "rule", body: `
rule:
- match: { sub: "arn:aws:iam::123456789012:role/AppRole" }
  grant: { account: APP }
`},
		"rule": {field: "matches", body: `
rules:
- matches: { sub: "arn:aws:iam::123456789012:role/AppRole" }
  grant: { account: APP }
`},
		"match": {field: "isuer", body: `
rules:
- match: { isuer: "https://issuer", sub: "arn:aws:iam::123456789012:role/AppRole" }
  grant: { account: APP }
`},
		"grant": {field: "publsh", body: `
rules:
- match: { sub: "arn:aws:iam::123456789012:role/AppRole" }
  grant: { account: APP, publsh: { allow: ["app.>"] } }
`},
		"permission": {field: "alow", body: `
rules:
- match: { sub: "arn:aws:iam::123456789012:role/AppRole" }
  grant:
    account: APP
    publish: { alow: ["app.>"] }
    subscribe: { allow: [">"] }
`},
		"response": {field: "max_msgs", body: `
rules:
- match: { sub: "arn:aws:iam::123456789012:role/AppRole" }
  grant: { account: APP, response: { max_msgs: 1 } }
`},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := LoadPolicy(writePolicy(t, tc.body))
			if err == nil {
				t.Fatal("expected unknown-field error")
			}
			if !strings.Contains(err.Error(), tc.field) {
				t.Errorf("error %q does not name field %q", err, tc.field)
			}
		})
	}
}

func TestLoadPolicyEmptyFile(t *testing.T) {
	_, err := LoadPolicy(writePolicy(t, ""))
	if err == nil || !strings.Contains(err.Error(), "no rules") {
		t.Fatalf("err = %v, want a no-rules validation error", err)
	}
}

func TestLoadPolicyRejectsExtraDocument(t *testing.T) {
	_, err := LoadPolicy(writePolicy(t, `
rules:
- match: { sub: "arn:aws:iam::123456789012:role/AppRole" }
  grant: { account: APP }
---
rules: []
`))
	if err == nil {
		t.Fatal("expected error for a second YAML document")
	}
}

func TestOmittedPermissionDeniesAll(t *testing.T) {
	p := &Policy{Rules: []Rule{{
		Match: Match{Sub: "arn:aws:iam::123456789012:role/Svc"},
		Grant: Grant{Account: "APP", Response: &Response{Max: 1}},
	}}}
	mustValidate(t, p)
	d, err := p.Evaluate(id("arn:aws:iam::123456789012:role/Svc", nil))
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	for dir, perm := range map[string][2][]string{
		"pub": {d.Permissions.Pub.Allow, d.Permissions.Pub.Deny},
		"sub": {d.Permissions.Sub.Allow, d.Permissions.Sub.Deny},
	} {
		if len(perm[0]) != 0 || !slices.Equal(perm[1], []string{">"}) {
			t.Errorf("%s = allow %v deny %v, want deny [>]", dir, perm[0], perm[1])
		}
	}
	// The response grant is still rendered, so replies remain possible.
	if d.Permissions.Resp == nil {
		t.Error("response permission dropped")
	}
}

func TestEmptyPermissionRejected(t *testing.T) {
	for _, body := range []string{
		`publish: {}`,
		`publish: { allow: [], deny: [] }`,
		`subscribe: {}`,
	} {
		_, err := LoadPolicy(writePolicy(t, `
rules:
- match: { sub: "arn:aws:iam::123456789012:role/AppRole" }
  grant: { account: APP, `+body+` }
`))
		if err == nil || !strings.Contains(err.Error(), "neither allow nor deny") {
			t.Errorf("%s: err = %v, want empty-permission error", body, err)
		}
	}
}

func TestExplicitPermissionsRendered(t *testing.T) {
	p := &Policy{Rules: []Rule{{
		Match: Match{Sub: "arn:aws:iam::123456789012:role/Svc"},
		Grant: Grant{
			Account:   "APP",
			Publish:   &Permission{Allow: []string{">"}},
			Subscribe: &Permission{Deny: []string{"secret.>"}},
		},
	}}}
	mustValidate(t, p)
	d, err := p.Evaluate(id("arn:aws:iam::123456789012:role/Svc", nil))
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if !slices.Equal(d.Permissions.Pub.Allow, []string{">"}) || len(d.Permissions.Pub.Deny) != 0 {
		t.Errorf("pub = %+v, want allow [>]", d.Permissions.Pub)
	}
	if len(d.Permissions.Sub.Allow) != 0 || !slices.Equal(d.Permissions.Sub.Deny, []string{"secret.>"}) {
		t.Errorf("sub = %+v, want deny [secret.>]", d.Permissions.Sub)
	}
}
