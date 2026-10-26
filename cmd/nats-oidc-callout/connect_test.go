package main

import (
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/nats-io/nats-server/v2/server"
	"github.com/nats-io/nkeys"

	"github.com/sylr/nats-oidc-callout/internal/config"
)

// startNkeyServer starts an embedded server on port (random when -1) whose
// auth callout user is identified only by the public nkey userPub.
func startNkeyServer(t *testing.T, port int, userPub, accountPub string) *server.Server {
	t.Helper()
	conf := filepath.Join(t.TempDir(), "server.conf")
	if err := os.WriteFile(conf, fmt.Appendf(nil, `
listen: 127.0.0.1:%d
accounts {
  AUTH { users: [ { nkey: %q } ] }
  APP {}
  SYS {}
}
system_account: SYS
authorization {
  auth_callout {
    issuer: %q
    account: AUTH
    auth_users: [ %q ]
  }
}
`, port, userPub, accountPub, userPub), 0o600); err != nil {
		t.Fatalf("write server conf: %v", err)
	}
	opts, err := server.ProcessConfigFile(conf)
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
	return srv
}

// TestConnectNATSWithNkey checks that the service connects as an auth callout
// user identified by its nkey rather than by a username, and authenticates
// again after a server restart, signing the new server's nonce.
func TestConnectNATSWithNkey(t *testing.T) {
	userKP, err := nkeys.CreateUser()
	if err != nil {
		t.Fatalf("create user key: %v", err)
	}
	userSeed, _ := userKP.Seed()
	userPub, _ := userKP.PublicKey()
	accountKP, err := nkeys.CreateAccount()
	if err != nil {
		t.Fatalf("create account key: %v", err)
	}
	accountPub, _ := accountKP.PublicKey()

	srv := startNkeyServer(t, -1, userPub, accountPub)
	port := srv.Addr().(*net.TCPAddr).Port

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	nc, _, err := connectNATS(config.NATSConfig{URL: srv.ClientURL(), NkeySeed: string(userSeed)}, logger)
	if err != nil {
		t.Fatalf("connect with nkey: %v", err)
	}
	defer nc.Close()
	if !nc.IsConnected() {
		t.Fatalf("status = %v, want connected", nc.Status())
	}

	srv.Shutdown()
	srv.WaitForShutdown()
	startNkeyServer(t, port, userPub, accountPub)

	deadline := time.Now().Add(15 * time.Second)
	for nc.Stats().Reconnects == 0 || !nc.IsConnected() {
		if time.Now().After(deadline) {
			t.Fatalf("not reconnected within 15s: status %v, last error %v", nc.Status(), nc.LastError())
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// TestNkeyOptionRejectsInvalidSeeds checks that a malformed seed, or a valid
// seed of another key type, fails at startup instead of at the server.
func TestNkeyOptionRejectsInvalidSeeds(t *testing.T) {
	accountKP, err := nkeys.CreateAccount()
	if err != nil {
		t.Fatalf("create account key: %v", err)
	}
	accountSeed, _ := accountKP.Seed()
	for name, tc := range map[string]struct{ seed, want string }{
		"malformed":    {seed: "SU-not-a-seed", want: "load nkey seed"},
		"account seed": {seed: string(accountSeed), want: "not a user seed"},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := nkeyOption(tc.seed)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err = %v, want %q", err, tc.want)
			}
		})
	}
}
