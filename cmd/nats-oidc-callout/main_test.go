package main

import (
	"bytes"
	"context"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/nats-io/nkeys"

	authzcallout "github.com/sylr/nats-oidc-callout/internal/callout"
	"github.com/sylr/nats-oidc-callout/internal/config"
	"github.com/sylr/nats-oidc-callout/internal/mockoidc"
)

// writeConfig writes a minimal valid service config pointing at issuerURL and
// natsURL to path.
func writeConfig(t *testing.T, path, issuerURL, natsURL, seed string) {
	t.Helper()
	cfg := fmt.Sprintf(`
nats:
  url: %q
issuer_account_seed: %q
audiences: ["nats://test"]
signing_algs: ["RS256"]
issuers:
- url: %q
policy:
  rules:
  - name: app
    match:
      sub: "arn:aws:iam::123456789012:role/AppRole"
    grant:
      account: APP
`, natsURL, seed, issuerURL)
	if err := os.WriteFile(path, []byte(cfg), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
}

// TestReloadKeepsWarningAboutRestartOnlySettings asserts that a change to a
// restart-only setting is reported on every reload, not just the first: the
// running process still uses the startup value until it is restarted.
func TestReloadKeepsWarningAboutRestartOnlySettings(t *testing.T) {
	idp := mockoidc.New(t)
	accountKP, err := nkeys.CreateAccount()
	if err != nil {
		t.Fatalf("create account key: %v", err)
	}
	seed, err := accountKP.Seed()
	if err != nil {
		t.Fatalf("account seed: %v", err)
	}

	path := filepath.Join(t.TempDir(), "config.yaml")
	writeConfig(t, path, idp.Issuer(), "nats://127.0.0.1:4222", string(seed))
	startup, err := config.Load(path)
	if err != nil {
		t.Fatalf("load startup config: %v", err)
	}

	var logs bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&logs, nil))
	ctx := context.Background()
	v, err := buildVerifier(ctx, startup)
	if err != nil {
		t.Fatalf("build verifier: %v", err)
	}
	a := authzcallout.New(v, &startup.Policy, accountKP, logger, nil)

	// Change a restart-only setting and reload twice.
	writeConfig(t, path, idp.Issuer(), "nats://127.0.0.1:5222", string(seed))
	for i := range 2 {
		logs.Reset()
		reloadConfig(ctx, path, startup, a, logger)
		out := logs.String()
		if !strings.Contains(out, "config reloaded") {
			t.Fatalf("reload %d did not succeed:\n%s", i+1, out)
		}
		if !strings.Contains(out, "nats connection settings changed; restart required") {
			t.Errorf("reload %d did not warn that a restart is required:\n%s", i+1, out)
		}
	}

	// Reverting to the startup value needs no restart, so no warning.
	writeConfig(t, path, idp.Issuer(), "nats://127.0.0.1:4222", string(seed))
	logs.Reset()
	reloadConfig(ctx, path, startup, a, logger)
	if out := logs.String(); strings.Contains(out, "restart required") {
		t.Errorf("reverted config should not warn:\n%s", out)
	}
}

const strictReloadConfig = `
nats:
  url: "nats://127.0.0.1:4222"
issuer_account_seed: "SA-not-parsed-by-load"
audiences: ["nats://callout"]
signing_algs: ["RS256"]
issuers:
- url: "https://issuer"
policy:
  rules:
  - match: { sub: "arn:aws:iam::123456789012:role/AppRole" }
    grant: { account: APP, publish: { allow: ["app.>"] } }
`

// TestReloadRejectsUnknownField proves a reload of a config with a misspelt
// permission field is rejected and never applied, so the previous config keeps
// serving.
func TestReloadRejectsUnknownField(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte(strictReloadConfig), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	cfg, err := config.Load(path)
	if err != nil {
		t.Fatalf("initial Load: %v", err)
	}

	typo := strings.Replace(strictReloadConfig, "allow:", "alow:", 1)
	if err := os.WriteFile(path, []byte(typo), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	var logs bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&logs, nil))
	a := authzcallout.New(nil, &cfg.Policy, nil, logger, nil)

	reloadConfig(context.Background(), path, cfg, a, logger)
	out := logs.String()
	if !strings.Contains(out, "config reload failed") {
		t.Fatalf("no reload failure logged; logs:\n%s", out)
	}
	if !strings.Contains(out, "alow") {
		t.Errorf("reload error does not name the unknown field; logs:\n%s", out)
	}
	if strings.Contains(out, "config reloaded") {
		t.Errorf("invalid config was applied; logs:\n%s", out)
	}
}
