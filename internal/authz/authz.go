// Package authz maps a verified OIDC identity to a NATS account and permission
// set via an ordered policy. The first matching rule wins; no match means deny.
//
// Matching is provider-neutral: a rule constrains the issuer, the subject, and
// any flattened claims (e.g. "repository" for GitHub, "aws.aws_account" for AWS).
package authz

import (
	"fmt"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/google/cel-go/cel"
	"github.com/nats-io/jwt/v2"
	"gopkg.in/yaml.v3"

	"github.com/sylr/nats-oidc-callout/internal/identity"
)

// Policy is an ordered list of authorization rules.
type Policy struct {
	Rules []Rule `yaml:"rules"`

	// validated is set by Validate. Evaluate refuses to run until it is true,
	// since rule matchers are compiled during validation; this fails closed
	// rather than silently matching everything.
	validated bool
}

// Rule pairs a match predicate with the grant applied when it matches.
type Rule struct {
	Name  string `yaml:"name"`
	Match Match  `yaml:"match"`
	Grant Grant  `yaml:"grant"`

	matcher    *regexp.Regexp // compiled sub, nil when unset
	celProgram cel.Program    // compiled Match.Expr, nil when unset
}

// Match describes the conditions an identity must satisfy. All set fields must
// match (logical AND). A rule with no strong identity pin requires AllowBroad.
type Match struct {
	// Issuer, when set, restricts the rule to tokens from this exact issuer.
	// Recommended for provider-specific rules (defense-in-depth against a claim
	// from one provider satisfying a rule meant for another).
	Issuer string `yaml:"issuer"`
	// Sub matches the token "sub". It is a glob (only "*" is special) matched
	// against the whole string, or a regular expression when prefixed with "re:"
	// (which must be anchored with ^ and $). Matching always requires the
	// pattern to span the entire subject. A regex sub is never treated as a
	// strong identity pin; pair it with one (e.g. aws.aws_account) or AllowBroad.
	Sub string `yaml:"sub"`
	// Claims requires each key to equal the given value in the verified token's
	// flattened claim set (e.g. {"repository": "owner/repo"},
	// {"aws.aws_account": "123456789012"}).
	Claims map[string]string `yaml:"claims"`
	// Expr is an optional CEL expression (must evaluate to bool) AND-ed with the
	// other conditions. It is given the variables sub, iss, aud, claims, exp, now
	// (see newCELEnv). Because an expression cannot be statically verified as
	// narrowly scoped, any rule using Expr must also set AllowBroad.
	Expr string `yaml:"expr"`
	// AllowBroad opts a rule into matching without a strong identity pin (and is
	// required for any rule using Expr).
	AllowBroad bool `yaml:"allow_broad"`
}

// Grant is what a matching identity is given.
type Grant struct {
	// Account is the NATS account NAME the user is bound to (e.g. "APP").
	Account string `yaml:"account"`
	// Publish/Subscribe permissions.
	Publish   Permission `yaml:"publish"`
	Subscribe Permission `yaml:"subscribe"`
	// Response, when set, allows the user to reply to requests it receives.
	Response *Response `yaml:"response"`
	// MaxExpiry caps the issued user JWT lifetime. The callout further caps it
	// to the verified token's own expiry. Zero means "no policy cap".
	MaxExpiry time.Duration `yaml:"max_expiry"`
}

// Permission is an allow/deny subject list.
type Permission struct {
	Allow []string `yaml:"allow"`
	Deny  []string `yaml:"deny"`
}

// Response mirrors jwt.ResponsePermission.
type Response struct {
	Max int           `yaml:"max"`
	TTL time.Duration `yaml:"ttl"`
}

// Decision is the result of evaluating the policy.
type Decision struct {
	RuleName    string
	Account     string
	Permissions jwt.UserPermissionLimits
	MaxExpiry   time.Duration
}

// githubStrongPinKeys are claims that pin a GitHub identity tightly enough that
// a rule using one is not considered broad.
var githubStrongPinKeys = map[string]struct{}{
	"repository":       {},
	"repository_id":    {},
	"job_workflow_ref": {},
}

// awsAccountID matches a literal 12-digit AWS account id.
var awsAccountID = regexp.MustCompile(`^[0-9]{12}$`)

// LoadPolicy reads a policy from a YAML file and validates it.
func LoadPolicy(path string) (*Policy, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read policy %q: %w", path, err)
	}
	var p Policy
	if err := yaml.Unmarshal(data, &p); err != nil {
		return nil, fmt.Errorf("parse policy %q: %w", path, err)
	}
	if err := p.Validate(); err != nil {
		return nil, err
	}
	return &p, nil
}

// Validate compiles matchers and enforces the broad-rule guardrail. It must be
// called before Evaluate; LoadPolicy and config.Load do this automatically.
func (p *Policy) Validate() error {
	if len(p.Rules) == 0 {
		return fmt.Errorf("policy has no rules")
	}
	var celEnv *cel.Env // created lazily on the first rule that uses Expr
	for i := range p.Rules {
		r := &p.Rules[i]
		if r.Grant.Account == "" {
			return fmt.Errorf("rule %q: grant.account is required", r.identity(i))
		}
		re, err := compileSub(r.Match.Sub)
		if err != nil {
			return fmt.Errorf("rule %q: %w", r.identity(i), err)
		}
		r.matcher = re

		if r.Match.Expr != "" {
			// A CEL expression is opaque to the broad-rule guardrail, so it must
			// be explicitly acknowledged.
			if !r.Match.AllowBroad {
				return fmt.Errorf("rule %q uses a CEL expr, which cannot be statically "+
					"verified as narrowly scoped; set allow_broad: true to confirm", r.identity(i))
			}
			if celEnv == nil {
				if celEnv, err = newCELEnv(); err != nil {
					return fmt.Errorf("cel environment: %w", err)
				}
			}
			prg, err := compileCELProgram(celEnv, r.Match.Expr)
			if err != nil {
				return fmt.Errorf("rule %q: %w", r.identity(i), err)
			}
			r.celProgram = prg
		}

		if !r.hasStrongPin() && !r.Match.AllowBroad {
			return fmt.Errorf("rule %q is broad: it has no strong identity pin "+
				"(an exact sub, a literal AWS account in a glob sub or aws.aws_account, "+
				"or repository/repository_id/job_workflow_ref; a regex sub never pins); "+
				"set allow_broad: true to confirm this is intentional",
				r.identity(i))
		}
	}
	p.validated = true
	return nil
}

// Evaluate returns the grant for the first rule that matches, or an error if no
// rule matches (deny).
func (p *Policy) Evaluate(id *identity.Identity) (*Decision, error) {
	if !p.validated {
		return nil, fmt.Errorf("policy not validated; call Validate before Evaluate")
	}
	for i := range p.Rules {
		r := &p.Rules[i]
		if r.matches(id) {
			return &Decision{
				RuleName:    r.identity(i),
				Account:     r.Grant.Account,
				Permissions: r.Grant.permissionLimits(),
				MaxExpiry:   r.Grant.MaxExpiry,
			}, nil
		}
	}
	return nil, fmt.Errorf("no policy rule matched")
}

func (r *Rule) matches(id *identity.Identity) bool {
	if r.Match.Issuer != "" && r.Match.Issuer != id.Issuer {
		return false
	}
	if !r.subMatches(id.Subject) {
		return false
	}
	for k, want := range r.Match.Claims {
		if got, ok := id.Claim(k); !ok || got != want {
			return false
		}
	}
	if r.celProgram != nil && !evalCEL(r.celProgram, id) {
		return false
	}
	return true
}

// subMatches reports whether the compiled subject pattern spans the entire
// subject. A nil matcher (no sub constraint) matches anything.
func (r *Rule) subMatches(sub string) bool {
	if r.matcher == nil {
		return true
	}
	loc := r.matcher.FindStringIndex(sub)
	return loc != nil && loc[0] == 0 && loc[1] == len(sub)
}

// hasStrongPin reports whether the rule pins a specific identity tightly enough
// to not be considered broad: an exact (wildcard-free) sub, a literal AWS
// account (in a glob ARN's account field or the aws.aws_account claim), or a
// strong GitHub claim. A regex sub is never a pin on its own.
func (r *Rule) hasStrongPin() bool {
	if subIsExact(r.Match.Sub) {
		return true
	}
	if accountPinnedInARN(r.Match.Sub) {
		return true
	}
	if v, ok := r.Match.Claims["aws.aws_account"]; ok && awsAccountID.MatchString(v) {
		return true
	}
	for k := range r.Match.Claims {
		if _, ok := githubStrongPinKeys[k]; ok {
			return true
		}
	}
	return false
}

func (r *Rule) identity(i int) string {
	if r.Name != "" {
		return r.Name
	}
	return fmt.Sprintf("#%d", i)
}

func (g *Grant) permissionLimits() jwt.UserPermissionLimits {
	var lim jwt.UserPermissionLimits
	lim.Pub = jwt.Permission{Allow: g.Publish.Allow, Deny: g.Publish.Deny}
	lim.Sub = jwt.Permission{Allow: g.Subscribe.Allow, Deny: g.Subscribe.Deny}
	if g.Response != nil {
		lim.Resp = &jwt.ResponsePermission{MaxMsgs: g.Response.Max, Expires: g.Response.TTL}
	}
	return lim
}

// subIsExact reports whether the sub pattern matches exactly one literal string
// (a glob with no "*"). Regex ("re:") patterns are never treated as exact.
func subIsExact(pattern string) bool {
	if pattern == "" || strings.HasPrefix(pattern, "re:") {
		return false
	}
	return !strings.Contains(pattern, "*")
}

// accountPinnedInARN reports whether a glob sub pattern fixes the account-id
// field (the 5th colon-separated ARN field) to a literal 12-digit AWS account
// id. The fields before it must be literal too: "*" also matches ":", so a
// wildcard there could shift where the digits land in the subject (e.g.
// "arn:aws:sts:*:123456789012:*" matches "arn:aws:sts:x:999999999999:y:123456789012:z").
//
// Regex ("re:") patterns never count: textual splitting cannot account for
// alternation, groups or escapes (e.g. "^arn:aws:iam::123456789012:role/.*|.*$"
// matches every subject). Such rules need another pin, such as an
// aws.aws_account claim, or allow_broad.
func accountPinnedInARN(pattern string) bool {
	if pattern == "" || strings.HasPrefix(pattern, "re:") {
		return false
	}
	fields := strings.SplitN(pattern, ":", 6)
	if len(fields) < 5 || strings.Contains(strings.Join(fields[:4], ":"), "*") {
		return false
	}
	return awsAccountID.MatchString(fields[4])
}

// compileSub turns a sub pattern into a regexp. Returns nil (match-anything)
// when the pattern is empty. Full-string matching is enforced by the caller via
// subMatches, but glob patterns are anchored here as well.
func compileSub(pattern string) (*regexp.Regexp, error) {
	if pattern == "" {
		return nil, nil
	}
	if rest, ok := strings.CutPrefix(pattern, "re:"); ok {
		if !strings.HasPrefix(rest, "^") || !strings.HasSuffix(rest, "$") {
			return nil, fmt.Errorf("regex sub must be anchored with ^ and $")
		}
		re, err := regexp.Compile(rest)
		if err != nil {
			return nil, fmt.Errorf("invalid sub regex: %w", err)
		}
		return re, nil
	}
	// Glob: escape everything, then turn the escaped "*" into ".*", anchored.
	var b strings.Builder
	b.WriteString("^")
	for part := range strings.SplitSeq(pattern, "*") {
		b.WriteString(regexp.QuoteMeta(part))
		b.WriteString(".*")
	}
	// Drop the trailing ".*" added after the final segment and anchor.
	s := strings.TrimSuffix(b.String(), ".*") + "$"
	re, err := regexp.Compile(s)
	if err != nil {
		return nil, fmt.Errorf("invalid sub glob: %w", err)
	}
	return re, nil
}
