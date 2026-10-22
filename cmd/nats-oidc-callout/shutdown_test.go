package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/nats-io/jwt/v2"
	"github.com/nats-io/nats-server/v2/server"
	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/micro"
	"github.com/nats-io/nkeys"
	callout "github.com/synadia-io/callout.go"
)

// The tests below shut the service down while authorization requests are
// being delivered. callout.go's Stop closes the async worker channel while
// deliveries may still be in their callback, which then panics sending on the
// closed channel; stopService must never let that happen, whether the drain
// completes or the connection drops first. The idle worker goroutines are left
// running on purpose, as in production (see stopService).

// TestStopServiceUnderLoad covers the normal path: the drain completes.
func TestStopServiceUnderLoad(t *testing.T) {
	for i := range 3 {
		t.Run(fmt.Sprint(i), func(t *testing.T) {
			e := startCalloutUnderLoad(t)
			stopWithin(t, e.nc)
			e.stopTraffic()
			if !e.nc.IsClosed() {
				t.Error("connection still open after stopService")
			}
			assertWorkerChannelOpen(t, e.svc)
		})
	}
}

// TestStopServiceAfterConnectionLoss covers the abnormal paths: the broker
// drops the service's connection, or the connection is closed, while
// deliveries are in flight, so any drain ends before their callbacks return.
// (Shutting the embedded server down under auth traffic instead trips a
// nil-pointer panic inside nats-server itself, so the broker side is
// simulated by disconnecting the client.)
func TestStopServiceAfterConnectionLoss(t *testing.T) {
	t.Run("disconnected by server", func(t *testing.T) {
		e := startCalloutUnderLoad(t)
		cid, err := e.nc.GetClientID()
		if err != nil {
			t.Fatalf("client id: %v", err)
		}
		if err := e.srv.DisconnectClientByID(cid); err != nil {
			t.Fatalf("disconnect service client: %v", err)
		}
		stopWithin(t, e.nc)
		e.stopTraffic()
		assertWorkerChannelOpen(t, e.svc)
	})
	t.Run("connection closed", func(t *testing.T) {
		e := startCalloutUnderLoad(t)
		e.nc.Close()
		stopWithin(t, e.nc)
		e.stopTraffic()
		assertWorkerChannelOpen(t, e.svc)
	})
}

type calloutLoad struct {
	srv         *server.Server
	nc          *nats.Conn
	svc         *callout.AuthorizationService
	stopTraffic func()
}

// startCalloutUnderLoad starts an embedded server with auth callout, a callout
// service with async workers, and clients that keep connecting (each attempt
// is an authorization request) until stopTraffic is called.
func startCalloutUnderLoad(t *testing.T) *calloutLoad {
	t.Helper()
	accountKP, err := nkeys.CreateAccount()
	if err != nil {
		t.Fatalf("create account key: %v", err)
	}
	accountPub, _ := accountKP.PublicKey()

	conf := fmt.Sprintf(`
listen: 127.0.0.1:-1
accounts {
  AUTH { users: [ { user: auth, password: authpass } ] }
  APP {}
  SYS {}
}
system_account: SYS
authorization {
  timeout: 0.5
  auth_callout {
    issuer: %q
    account: AUTH
    auth_users: [ auth ]
  }
}
`, accountPub)
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

	nc, err := nats.Connect(srv.ClientURL(), nats.UserInfo("auth", "authpass"))
	if err != nil {
		t.Fatalf("service connect: %v", err)
	}
	t.Cleanup(nc.Close)

	svc, err := callout.NewAuthorizationService(nc,
		callout.Authorizer(func(*jwt.AuthorizationRequest) (string, error) {
			time.Sleep(time.Millisecond)
			return "", errors.New("denied")
		}),
		callout.ResponseSignerKey(accountKP),
		callout.AsyncWorkers(2),
		callout.Logger(nopLogger{}),
	)
	if err != nil {
		t.Fatalf("start callout service: %v", err)
	}

	var stop atomic.Bool
	var wg sync.WaitGroup
	for range 16 {
		wg.Go(func() {
			for !stop.Load() {
				c, err := nats.Connect(srv.ClientURL(), nats.Token("x"), nats.MaxReconnects(0), nats.Timeout(time.Second))
				if err == nil {
					c.Close()
				}
			}
		})
	}
	time.Sleep(200 * time.Millisecond)

	return &calloutLoad{srv: srv, nc: nc, svc: svc, stopTraffic: func() {
		stop.Store(true)
		wg.Wait()
	}}
}

// stopWithin runs stopService and fails if it outlives the drain bound.
func stopWithin(t *testing.T, nc *nats.Conn) {
	t.Helper()
	done := make(chan struct{})
	go func() {
		defer close(done)
		stopService(nc)
	}()
	select {
	case <-done:
	case <-time.After(shutdownDrainTimeout + 5*time.Second):
		t.Fatal("stopService did not return")
	}
	// Check eventual closure, not a snapshot: when the drain was cut short by a
	// disconnect, nats.go's drain goroutine can still flip the status to
	// DRAINING_PUBS for a moment after the connection was closed.
	deadline := time.Now().Add(5 * time.Second)
	for !nc.IsClosed() {
		if time.Now().After(deadline) {
			t.Error("connection still open after stopService")
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// assertWorkerChannelOpen hands the service a request directly: if its worker
// channel had been closed, this sends on it and panics.
func assertWorkerChannelOpen(t *testing.T, svc *callout.AuthorizationService) {
	t.Helper()
	svc.AsyncWorkerHandler(shortRequest{})
}

// shortRequest is a request too short to decode; the worker rejects it after
// reading Data only.
type shortRequest struct{ micro.Request }

func (shortRequest) Data() []byte { return nil }

// nopLogger silences callout.go's default stderr logger.
type nopLogger struct{}

func (nopLogger) Noticef(string, ...any) {}
func (nopLogger) Warnf(string, ...any)   {}
func (nopLogger) Fatalf(string, ...any)  {}
func (nopLogger) Errorf(string, ...any)  {}
func (nopLogger) Debugf(string, ...any)  {}
func (nopLogger) Tracef(string, ...any)  {}
