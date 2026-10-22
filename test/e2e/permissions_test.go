package e2e

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/nats-io/nats.go"

	"github.com/sylr/nats-oidc-callout/internal/authz"
	"github.com/sylr/nats-oidc-callout/internal/mockoidc"
)

// Exact role ARNs used to give each identity in a test its own rule.
const (
	requesterARN = "arn:aws:iam::123456789012:role/Requester"
	responderARN = "arn:aws:iam::123456789012:role/Responder"
)

// grantPolicy returns a single-rule policy granting testARN the APP account with
// g's permissions.
func grantPolicy(g authz.Grant) *authz.Policy {
	g.Account = "APP"
	return &authz.Policy{Rules: []authz.Rule{{
		Name:  "perm",
		Match: authz.Match{Sub: testARN},
		Grant: g,
	}}}
}

// tokenFor mints a valid token for the given role ARN.
func (h *harness) tokenFor(t *testing.T, arn string) string {
	t.Helper()
	return h.idp.Mint(t, mockoidc.TokenOptions{
		Subject:    arn,
		Audience:   []string{testAudience},
		AWSAccount: testAccount,
	})
}

// permErrors connects with token and returns the conn plus a channel receiving
// its async permission-violation errors.
func (h *harness) permErrors(t *testing.T, token string) (*nats.Conn, <-chan error) {
	t.Helper()
	nc, err := h.connectClient(t, token)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	errCh := make(chan error, 8)
	nc.SetErrorHandler(func(_ *nats.Conn, _ *nats.Subscription, e error) {
		select {
		case errCh <- e:
		default:
		}
	})
	return nc, errCh
}

func expectPermViolation(t *testing.T, errCh <-chan error, op string) {
	t.Helper()
	select {
	case e := <-errCh:
		if !errors.Is(e, nats.ErrPermissionViolation) && !strings.Contains(strings.ToLower(e.Error()), "permissions violation") {
			t.Fatalf("%s: unexpected async error %v", op, e)
		}
	case <-time.After(2 * time.Second):
		t.Fatalf("%s: expected a permissions violation, got none", op)
	}
}

// TestOmittedPublishDeniesAll: a grant without publish must not be able to
// publish anywhere (NATS would treat an empty permission as unrestricted).
func TestOmittedPublishDeniesAll(t *testing.T) {
	h := setup(t, grantPolicy(authz.Grant{
		Subscribe: &authz.Permission{Allow: []string{">"}},
	}), awsRequire)
	nc, errCh := h.permErrors(t, h.validToken(t))

	sub, err := nc.SubscribeSync("app.events")
	if err != nil {
		t.Fatalf("subscribe: %v", err)
	}
	if err := nc.Publish("app.events", []byte("x")); err != nil {
		t.Fatalf("publish call: %v", err)
	}
	_ = nc.Flush()
	expectPermViolation(t, errCh, "publish")
	if msg, err := sub.NextMsg(500 * time.Millisecond); err == nil {
		t.Fatalf("publish with omitted permission was delivered: %q", msg.Data)
	}
}

// TestOmittedSubscribeDeniesAll: a grant without subscribe must not be able to
// subscribe anywhere.
func TestOmittedSubscribeDeniesAll(t *testing.T) {
	h := setup(t, grantPolicy(authz.Grant{
		Publish: &authz.Permission{Allow: []string{">"}},
	}), awsRequire)
	nc, errCh := h.permErrors(t, h.validToken(t))

	if _, err := nc.SubscribeSync("app.events"); err != nil {
		t.Fatalf("subscribe call: %v", err)
	}
	_ = nc.Flush()
	expectPermViolation(t, errCh, "subscribe")
}

// TestRestrictedSubscribeDenied: a subscribe allow list confines
// subscriptions to it.
func TestRestrictedSubscribeDenied(t *testing.T) {
	h := setup(t, appPolicy(testARN), awsRequire)
	nc, errCh := h.permErrors(t, h.validToken(t))

	if _, err := nc.SubscribeSync("forbidden.topic"); err != nil {
		t.Fatalf("subscribe call: %v", err)
	}
	_ = nc.Flush()
	expectPermViolation(t, errCh, "subscribe")
}

// TestExplicitWildcardAllowsAll: allow: [">"] is the explicit way to grant
// unrestricted publish and subscribe.
func TestExplicitWildcardAllowsAll(t *testing.T) {
	h := setup(t, grantPolicy(authz.Grant{
		Publish:   &authz.Permission{Allow: []string{">"}},
		Subscribe: &authz.Permission{Allow: []string{">"}},
	}), awsRequire)
	nc, errCh := h.permErrors(t, h.validToken(t))

	sub, err := nc.SubscribeSync("any.subject.at.all")
	if err != nil {
		t.Fatalf("subscribe: %v", err)
	}
	if err := nc.Publish("any.subject.at.all", []byte("hi")); err != nil {
		t.Fatalf("publish: %v", err)
	}
	if _, err := sub.NextMsg(2 * time.Second); err != nil {
		t.Fatalf("next msg: %v", err)
	}
	select {
	case e := <-errCh:
		t.Fatalf("unexpected async error: %v", e)
	default:
	}
}

// replyPolicy grants a requester that may publish to svc.echo, and a responder
// that may only subscribe to svc.echo, with publish omitted (deny all) and the
// given response permission.
func replyPolicy(resp *authz.Response) *authz.Policy {
	return &authz.Policy{Rules: []authz.Rule{
		{
			Name:  "requester",
			Match: authz.Match{Sub: requesterARN},
			Grant: authz.Grant{
				Account:   "APP",
				Publish:   &authz.Permission{Allow: []string{"svc.echo"}},
				Subscribe: &authz.Permission{Allow: []string{"_INBOX.>"}},
			},
		},
		{
			Name:  "responder",
			Match: authz.Match{Sub: responderARN},
			Grant: authz.Grant{
				Account:   "APP",
				Subscribe: &authz.Permission{Allow: []string{"svc.echo"}},
				Response:  resp,
			},
		},
	}}
}

// startResponder connects the responder identity and echoes svc.echo requests.
func (h *harness) startResponder(t *testing.T) (*nats.Conn, <-chan error) {
	t.Helper()
	nc, errCh := h.permErrors(t, h.tokenFor(t, responderARN))
	if _, err := nc.Subscribe("svc.echo", func(m *nats.Msg) { _ = m.Respond(m.Data) }); err != nil {
		t.Fatalf("responder subscribe: %v", err)
	}
	if err := nc.Flush(); err != nil {
		t.Fatalf("responder flush: %v", err)
	}
	return nc, errCh
}

// TestResponseGrantRepliesWithOmittedPublish: NATS tracks the reply subject of
// each delivered request and lets a user with a response permission publish to
// it even though its publish permission denies ">". So a responder can reply
// without any publish grant, while arbitrary publishes stay denied.
func TestResponseGrantRepliesWithOmittedPublish(t *testing.T) {
	h := setup(t, replyPolicy(&authz.Response{Max: 1, TTL: time.Minute}), awsRequire)
	responder, errCh := h.startResponder(t)

	requester, err := h.connectClient(t, h.tokenFor(t, requesterARN))
	if err != nil {
		t.Fatalf("requester connect: %v", err)
	}
	msg, err := requester.Request("svc.echo", []byte("ping"), 2*time.Second)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	if string(msg.Data) != "ping" {
		t.Errorf("reply = %q, want ping", msg.Data)
	}

	// Outside the tracked reply subject, publish is still denied.
	if err := responder.Publish("svc.other", []byte("x")); err != nil {
		t.Fatalf("publish call: %v", err)
	}
	_ = responder.Flush()
	expectPermViolation(t, errCh, "publish")
}

// TestNoResponseGrantCannotReply is the control for the test above: without a
// response permission the omitted publish denies the reply too.
func TestNoResponseGrantCannotReply(t *testing.T) {
	h := setup(t, replyPolicy(nil), awsRequire)
	h.startResponder(t)

	requester, err := h.connectClient(t, h.tokenFor(t, requesterARN))
	if err != nil {
		t.Fatalf("requester connect: %v", err)
	}
	if _, err := requester.Request("svc.echo", []byte("ping"), time.Second); err == nil {
		t.Fatal("reply delivered without a response permission")
	}
}
