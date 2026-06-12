// Package audit emits structured, security-relevant log records for the OIDC
// plugin: every auth decision in ExchangeCode (allow/deny + reason) and every
// admin config mutation. Records go through hclog (the logger already wired
// across this plugin) so they land in the same stream as the rest of the
// plugin's logs and pick up the host's log routing.
//
// Audit records intentionally never carry secrets, raw auth codes, tokens, or
// PII-heavy claim bodies. They carry stable identifiers (sub, actor user id)
// and coarse decision reasons so operators can reconstruct who authenticated,
// who changed config, and why a login was refused — without leaking material
// an attacker could replay.
package audit

import "github.com/hashicorp/go-hclog"

// Reason is a stable, low-cardinality decision code for an auth attempt. The
// set mirrors the gates in ExchangeCode so a denied login always maps to
// exactly one reason.
type Reason string

const (
	ReasonSuccess             Reason = "success"
	ReasonStateMismatch       Reason = "state-mismatch"
	ReasonNonceMismatch       Reason = "nonce-mismatch"
	ReasonEmailUnverified     Reason = "email-unverified"
	ReasonClaimFilterReject   Reason = "claim-filter-rejected"
	ReasonExchangeFailed      Reason = "exchange-failed"
	ReasonVerifyFailed        Reason = "verify-failed"
	ReasonRedirectMismatch    Reason = "redirect-uri-mismatch"
	ReasonStaleState          Reason = "state-expired"
	ReasonReplay              Reason = "replay-detected"
	ReasonInvalidProviderArgs Reason = "invalid-provider-state"
	ReasonRateLimited         Reason = "rate-limited"
	ReasonNotConfigured       Reason = "not-configured"
	ReasonSubjectMismatch     Reason = "subject-mismatch"
	ReasonMissingSubject      Reason = "missing-subject"
)

// Logger is the audit sink. It wraps an hclog.Logger and tags every record
// with component=audit so records are greppable as a group.
type Logger struct {
	log hclog.Logger
}

// New returns an audit Logger backed by base. A nil base falls back to
// hclog.Default() so callers never have to nil-check.
func New(base hclog.Logger) *Logger {
	if base == nil {
		base = hclog.Default()
	}
	return &Logger{log: base.Named("audit").With("component", "audit")}
}

// AuthDecision records the outcome of an ExchangeCode attempt. allowed=false
// records a denial with the supplied reason; sub may be empty when the failure
// happened before a subject could be extracted (e.g. exchange/verify failure).
// actor is the host-supplied requester id when one is available (often empty on
// the gRPC auth path), and peer is the requesting IP when known.
func (l *Logger) AuthDecision(allowed bool, reason Reason, sub, actor, peer string) {
	if l == nil {
		return
	}
	args := []any{
		"event", "auth_decision",
		"allowed", allowed,
		"reason", string(reason),
	}
	if sub != "" {
		args = append(args, "sub", sub)
	}
	if actor != "" {
		args = append(args, "actor", actor)
	}
	if peer != "" {
		args = append(args, "peer", peer)
	}
	if allowed {
		l.log.Info("oidc auth decision", args...)
		return
	}
	l.log.Warn("oidc auth decision", args...)
}

// ConfigMutation records an admin config change: the acting user id, the
// before/after issuer_url, and whether the client_secret changed. The secret
// itself is never logged — only the boolean.
func (l *Logger) ConfigMutation(actor, oldIssuer, newIssuer string, secretChanged bool) {
	if l == nil {
		return
	}
	l.log.Info("oidc admin config mutation",
		"event", "config_mutation",
		"actor", actor,
		"issuer_url_before", oldIssuer,
		"issuer_url_after", newIssuer,
		"secret_changed", secretChanged,
	)
}
