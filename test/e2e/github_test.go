package e2e

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/sylr/nats-oidc-callout/internal/authz"
)

// TestGitHubActionsToken exercises the full callout flow with a REAL GitHub
// Actions OIDC token. It runs only inside a GitHub Actions job that has
// `permissions: id-token: write` (which exposes the request env vars); it skips
// cleanly everywhere else (local runs, fork PRs without the permission). No SDK
// is needed, so the test carries no build tag and is part of the normal suite.
func TestGitHubActionsToken(t *testing.T) {
	reqURL := os.Getenv("ACTIONS_ID_TOKEN_REQUEST_URL")
	reqToken := os.Getenv("ACTIONS_ID_TOKEN_REQUEST_TOKEN")
	if reqURL == "" || reqToken == "" {
		t.Skip("not in a GitHub Actions job with id-token: write; skipping real GitHub OIDC e2e")
	}

	token := requestGitHubToken(t, reqURL, reqToken, testAudience)
	iss, claims := inspectGitHubToken(t, token)
	repo := claims["repository"]
	owner := claims["repository_owner"]
	if iss == "" || repo == "" || owner == "" {
		t.Fatalf("token missing iss/repository/repository_owner: iss=%q repo=%q owner=%q", iss, repo, owner)
	}
	t.Logf("github token: iss=%s repository=%s owner=%s", iss, repo, owner)

	ownerRequire := map[string]string{"repository_owner": owner}

	// Positive: issuer bound to this owner, policy pins this repository.
	t.Run("authorized", func(t *testing.T) {
		h := setupWithIssuerAudience(t, githubPolicy(iss, repo), iss, ownerRequire, testAudience)
		nc, err := h.connectClient(t, token)
		if err != nil {
			t.Fatalf("connect with real GitHub token: %v", err)
		}
		sub, err := nc.SubscribeSync("app.gh")
		if err != nil {
			t.Fatalf("subscribe: %v", err)
		}
		if err := nc.Publish("app.gh", []byte("ok")); err != nil {
			t.Fatalf("publish: %v", err)
		}
		_ = nc.Flush()
		if _, err := sub.NextMsg(2 * time.Second); err != nil {
			t.Fatalf("expected message within grant: %v", err)
		}
	})

	// Negative authz-boundary cases using the SAME real token — proving the
	// service enforces authorization, not just token acquisition.
	t.Run("wrong repository denied", func(t *testing.T) {
		h := setupWithIssuerAudience(t, githubPolicy(iss, "someone/else"), iss, ownerRequire, testAudience)
		if _, err := h.connectClient(t, token); err == nil {
			t.Fatal("expected rejection: policy pins a different repository")
		}
	})
	t.Run("wrong owner binding denied", func(t *testing.T) {
		h := setupWithIssuerAudience(t, githubPolicy(iss, repo), iss, map[string]string{"repository_owner": "not-the-owner"}, testAudience)
		if _, err := h.connectClient(t, token); err == nil {
			t.Fatal("expected rejection: issuer require_claims owner mismatch")
		}
	})
	t.Run("wrong audience denied", func(t *testing.T) {
		h := setupWithIssuerAudience(t, githubPolicy(iss, repo), iss, ownerRequire, "nats://not-the-audience")
		if _, err := h.connectClient(t, token); err == nil {
			t.Fatal("expected rejection: audience not allowed")
		}
	})

	// Same real token, gated by a CEL expression instead of the declarative
	// claims matcher.
	t.Run("authorized via CEL", func(t *testing.T) {
		expr := fmt.Sprintf(`claims["repository"] == %q && claims["repository_owner"] == %q`, repo, owner)
		h := setupWithIssuerAudience(t, celGithubPolicy(iss, expr), iss, ownerRequire, testAudience)
		nc, err := h.connectClient(t, token)
		if err != nil {
			t.Fatalf("expected CEL-authorized connect: %v", err)
		}
		sub, err := nc.SubscribeSync("app.ghcel")
		if err != nil {
			t.Fatalf("subscribe: %v", err)
		}
		if err := nc.Publish("app.ghcel", []byte("ok")); err != nil {
			t.Fatalf("publish: %v", err)
		}
		_ = nc.Flush()
		if _, err := sub.NextMsg(2 * time.Second); err != nil {
			t.Fatalf("expected message within grant: %v", err)
		}
	})
	t.Run("CEL deny on wrong repository", func(t *testing.T) {
		h := setupWithIssuerAudience(t, celGithubPolicy(iss, `claims["repository"] == "someone/else"`), iss, ownerRequire, testAudience)
		if _, err := h.connectClient(t, token); err == nil {
			t.Fatal("expected CEL rejection: expression pins a different repository")
		}
	})
}

// githubPolicy grants a single repository (issuer-scoped) access to APP/app.>.
func githubPolicy(issuer, repo string) *authz.Policy {
	return &authz.Policy{Rules: []authz.Rule{{
		Name: "github",
		Match: authz.Match{
			Issuer: issuer,
			Claims: map[string]string{"repository": repo},
		},
		Grant: authz.Grant{
			Account:   "APP",
			Publish:   &authz.Permission{Allow: []string{"app.>"}},
			Subscribe: &authz.Permission{Allow: []string{"app.>", "_INBOX.>"}},
		},
	}}}
}

// celGithubPolicy grants APP/app.> when the (issuer-scoped) CEL expression holds.
func celGithubPolicy(issuer, expr string) *authz.Policy {
	return &authz.Policy{Rules: []authz.Rule{{
		Name: "github-cel",
		Match: authz.Match{
			Issuer:     issuer,
			Expr:       expr,
			AllowBroad: true,
		},
		Grant: authz.Grant{
			Account:   "APP",
			Publish:   &authz.Permission{Allow: []string{"app.>"}},
			Subscribe: &authz.Permission{Allow: []string{"app.>", "_INBOX.>"}},
		},
	}}}
}

// requestGitHubToken mints an OIDC token for the given audience via the Actions
// token endpoint exposed to the job.
func requestGitHubToken(t *testing.T, reqURL, reqToken, audience string) string {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	u := reqURL + "&audience=" + url.QueryEscape(audience)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		t.Fatalf("build token request: %v", err)
	}
	req.Header.Set("Authorization", "Bearer "+reqToken)
	req.Header.Set("User-Agent", "nats-oidc-callout-e2e")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("request GitHub OIDC token: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("token endpoint returned %d: %s", resp.StatusCode, body)
	}
	var out struct {
		Value string `json:"value"`
	}
	if err := json.Unmarshal(body, &out); err != nil || out.Value == "" {
		t.Fatalf("decode token response: %v (body=%s)", err, body)
	}
	return out.Value
}

// inspectGitHubToken decodes the unverified payload to read iss + identity
// claims so the test can configure a matching verifier and policy.
func inspectGitHubToken(t *testing.T, token string) (iss string, claims map[string]string) {
	t.Helper()
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		t.Fatalf("malformed token")
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatalf("decode token payload: %v", err)
	}
	var raw struct {
		Iss             string `json:"iss"`
		Repository      string `json:"repository"`
		RepositoryOwner string `json:"repository_owner"`
	}
	if err := json.Unmarshal(payload, &raw); err != nil {
		t.Fatalf("parse token payload: %v", err)
	}
	return raw.Iss, map[string]string{
		"repository":       raw.Repository,
		"repository_owner": raw.RepositoryOwner,
	}
}
