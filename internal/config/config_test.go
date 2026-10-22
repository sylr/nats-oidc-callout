package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// validConfig is a minimal loadable configuration with an inline policy.
const validConfig = `
nats:
  url: "nats://127.0.0.1:4222"
issuer_account_seed: "SA-not-parsed-by-load"
audiences: ["nats://callout"]
signing_algs: ["RS256"]
issuers:
- url: "https://issuer"
  require_claims:
    aws.aws_account: "123456789012"
policy:
  rules:
  - match:
      issuer: "https://issuer"
      sub: "arn:aws:iam::123456789012:role/AppRole"
    grant:
      account: APP
      publish: { allow: ["app.>"] }
`

func writeFile(t *testing.T, dir, name, body string) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("write %s: %v", name, err)
	}
	return path
}

func TestLoadValid(t *testing.T) {
	cfg, err := Load(writeFile(t, t.TempDir(), "config.yaml", validConfig))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if got := cfg.Issuers[0].RequireClaims["aws.aws_account"]; got != "123456789012" {
		t.Errorf("require_claims = %q", got)
	}
	if cfg.HTTPTimeout != DefaultHTTPTimeout {
		t.Errorf("http_timeout = %v, want default", cfg.HTTPTimeout)
	}
}

func TestLoadRejectsUnknownFields(t *testing.T) {
	// Each case misspells one key; strict decoding must fail the load instead of
	// silently dropping the setting (e.g. an issuer's claim binding).
	for name, tc := range map[string]struct{ old, new, field string }{
		"top level":         {old: "audiences:", new: "audience:", field: "audience"},
		"nats":              {old: `  url: "nats://`, new: `  uri: "nats://`, field: "uri"},
		"issuer":            {old: "  require_claims:", new: "  require_claim:", field: "require_claim"},
		"inline match":      {old: `      issuer: "https`, new: `      isuer: "https`, field: "isuer"},
		"inline grant":      {old: "      account: APP", new: "      acount: APP", field: "acount"},
		"inline permission": {old: "publish: { allow:", new: "publish: { alow:", field: "alow"},
	} {
		t.Run(name, func(t *testing.T) {
			if !strings.Contains(validConfig, tc.old) {
				t.Fatalf("fixture does not contain %q", tc.old)
			}
			body := strings.Replace(validConfig, tc.old, tc.new, 1)
			_, err := Load(writeFile(t, t.TempDir(), "config.yaml", body))
			if err == nil {
				t.Fatal("expected unknown-field error")
			}
			if !strings.Contains(err.Error(), tc.field) {
				t.Errorf("error %q does not name field %q", err, tc.field)
			}
		})
	}
}

func TestLoadRejectsUnknownFieldInPolicyFile(t *testing.T) {
	dir := t.TempDir()
	policy := writeFile(t, dir, "policy.yaml", `
rules:
- match: { sub: "arn:aws:iam::123456789012:role/AppRole" }
  grant: { account: APP, publish: { alow: ["app.>"] } }
`)
	body, _, _ := strings.Cut(validConfig, "policy:")
	body += "policy_file: " + policy + "\n"
	if _, err := Load(writeFile(t, dir, "config.yaml", body)); err == nil || !strings.Contains(err.Error(), "alow") {
		t.Fatalf("err = %v, want unknown-field error for alow", err)
	}
}

func TestLoadEmptyFile(t *testing.T) {
	_, err := Load(writeFile(t, t.TempDir(), "config.yaml", ""))
	if err == nil || !strings.Contains(err.Error(), "nats.url is required") {
		t.Fatalf("err = %v, want a required-field validation error", err)
	}
}
