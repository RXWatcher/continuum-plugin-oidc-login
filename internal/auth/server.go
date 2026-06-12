// Package auth implements the auth_provider.v1 capability for OIDC. It owns
// InitAuthorize (PKCE + nonce + authorize URL construction) and ExchangeCode
// (token exchange, JWKS id_token verification, nonce check, userinfo merge,
// email_verified + claim-filter gating). The host applies the role mapping
// itself against the returned claims; this server returns the merged claims
// and lets that downstream pass do its job.
package auth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"net"
	"time"

	gooidc "github.com/coreos/go-oidc/v3/oidc"
	"github.com/hashicorp/go-hclog"
	"golang.org/x/oauth2"
	"google.golang.org/genproto/googleapis/rpc/errdetails"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/structpb"

	pluginv1 "github.com/Silo-Server/silo-plugin-sdk/pkg/pluginproto/silo/plugin/v1"

	"github.com/RXWatcher/silo-plugin-oidc-login/internal/audit"
	"github.com/RXWatcher/silo-plugin-oidc-login/internal/claims"
	pluginoidc "github.com/RXWatcher/silo-plugin-oidc-login/internal/oidc"
	"github.com/RXWatcher/silo-plugin-oidc-login/internal/ratelimit"
	pluginrt "github.com/RXWatcher/silo-plugin-oidc-login/internal/runtime"
	"github.com/RXWatcher/silo-plugin-oidc-login/internal/store"
)

// stateTTL bounds how long an issued provider_state stays valid. A callback
// arriving after this window is rejected as stale, shrinking the replay window
// for a captured authorize request and bounding nonce-table retention.
const stateTTL = 10 * time.Minute

// logDebug records upstream failure detail at debug level only. The caller-
// facing gRPC status stays generic so token-exchange / verification text (and
// any token context it may carry) never leaks to the client. The raw auth code
// and tokens are never passed in here.
func logDebug(msg string, err error) {
	hclog.Default().Debug("oidc auth: "+msg, "error", err)
}

// ConsumeNonceFn records a nonce as used, returning store.ErrReplay if it was
// already consumed. It backs one-time replay protection for ExchangeCode and
// is supplied by main.go once the store is available; when nil (store not yet
// wired) replay protection is skipped but every other gate still applies.
type ConsumeNonceFn func(ctx context.Context, nonce string, expiresAt time.Time) error

// Server implements pluginv1.AuthProviderServer. Configuration and the OIDC
// provider live behind closures so main.go can swap them at Configure time
// without locking. The limiter, audit logger, and nonce consumer are
// process-scoped collaborators wired once at construction.
type Server struct {
	pluginv1.UnimplementedAuthProviderServer
	cfgFn       func() pluginrt.Config
	provFn      func() *pluginoidc.Provider
	limiter     *ratelimit.Limiter
	auditLog    *audit.Logger
	consumeNonc ConsumeNonceFn
}

// NewServer wires the supplied accessors. cfgFn/provFn are called fresh per RPC;
// the plugin process holds the live values behind atomic pointers in main.go.
// limiter, auditLog, and consume may be nil — the server degrades to no rate
// limiting / a default logger / no replay protection respectively, so callers
// and tests that don't need them stay simple.
func NewServer(
	cfgFn func() pluginrt.Config,
	provFn func() *pluginoidc.Provider,
	limiter *ratelimit.Limiter,
	auditLog *audit.Logger,
	consume ConsumeNonceFn,
) *Server {
	if auditLog == nil {
		auditLog = audit.New(hclog.Default())
	}
	return &Server{
		cfgFn:       cfgFn,
		provFn:      provFn,
		limiter:     limiter,
		auditLog:    auditLog,
		consumeNonc: consume,
	}
}

// Authenticate is the password flow which OIDC does not support. The manifest
// declares auth_modes=["oauth2"], so the host should not be calling this.
func (s *Server) Authenticate(_ context.Context, _ *pluginv1.AuthenticateRequest) (*pluginv1.AuthenticateResponse, error) {
	return nil, status.Error(codes.Unimplemented, "OIDC plugin is OAuth-only; use InitAuthorize / ExchangeCode")
}

// RefreshSession is not supported in v1; the user re-runs the OAuth flow.
func (s *Server) RefreshSession(_ context.Context, _ *pluginv1.RefreshSessionRequest) (*pluginv1.AuthenticateResponse, error) {
	return nil, status.Error(codes.Unimplemented, "refresh not supported in v1")
}

// InitAuthorize generates PKCE + nonce, builds the authorize URL using the
// discovered authorization_endpoint, and returns the provider_state the host
// must round-trip back via ExchangeCode.
func (s *Server) InitAuthorize(_ context.Context, req *pluginv1.InitAuthorizeRequest) (*pluginv1.InitAuthorizeResponse, error) {
	prov := s.provFn()
	if prov == nil {
		return nil, status.Error(codes.FailedPrecondition, "plugin not configured")
	}

	verifier, err := randB64(48)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "entropy: %v", err)
	}
	challenge := pkceS256(verifier)
	nonce, err := randB64(32)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "entropy: %v", err)
	}

	cfg := prov.OAuth2Config()
	redirectURI := req.GetRedirectUri()
	cfg.RedirectURL = redirectURI

	reqState := req.GetState()
	authURL := cfg.AuthCodeURL(reqState,
		oauth2.SetAuthURLParam("nonce", nonce),
		oauth2.SetAuthURLParam("code_challenge", challenge),
		oauth2.SetAuthURLParam("code_challenge_method", "S256"),
	)

	// Stash pkce_verifier + nonce + the issued state + redirect_uri + an
	// issued-at timestamp so ExchangeCode can:
	//   - verify the callback's state matches what was sent to the IdP (CSRF),
	//   - assert the callback redirect_uri matches what we authorized with
	//     (defends against a buggy host turning this into an open redirect),
	//   - reject stale callbacks past stateTTL (shrinks the replay window).
	// This is defense-in-depth: the host is also expected to validate state at
	// the callback URL, but a plugin-side check protects users when the host's
	// check is buggy or skipped.
	pState, err := structpb.NewStruct(map[string]any{
		"pkce_verifier": verifier,
		"nonce":         nonce,
		"state":         reqState,
		"redirect_uri":  redirectURI,
		"issued_at":     time.Now().UTC().Format(time.RFC3339Nano),
	})
	if err != nil {
		return nil, status.Errorf(codes.Internal, "structpb: %v", err)
	}
	return &pluginv1.InitAuthorizeResponse{AuthorizeUrl: authURL, ProviderState: pState}, nil
}

// ExchangeCode runs the OIDC callback half of the flow:
//  1. Re-derive PKCE verifier + nonce from provider_state.
//  2. Exchange the auth code for tokens (oauth2 lib handles client auth).
//  3. Verify the id_token signature against JWKS, audience, issuer, expiry.
//  4. Verify nonce roundtrip.
//  5. Merge id_token claims with userinfo (userinfo wins on collision).
//  6. Apply email_verified_required + claim_filters gates.
//  7. Return identity + merged claims for the host's role-mapping pass.
func (s *Server) ExchangeCode(ctx context.Context, req *pluginv1.ExchangeCodeRequest) (*pluginv1.AuthenticateResponse, error) {
	peerIP := peerIP(ctx)

	// Rate-limit before any work: ExchangeCode runs token exchange + JWKS
	// verification on attacker-supplied input, so an unbounded caller could
	// hammer the IdP and the verifier. Limit per source IP when known, else a
	// shared bucket.
	if s.limiter != nil {
		if ok, retry := s.limiter.Allow("exchange:" + rateKey(peerIP)); !ok {
			s.auditLog.AuthDecision(false, audit.ReasonRateLimited, "", "", peerIP)
			return nil, rateLimitErr(retry)
		}
	}

	cfg := s.cfgFn()
	prov := s.provFn()
	if prov == nil {
		s.auditLog.AuthDecision(false, audit.ReasonNotConfigured, "", "", peerIP)
		return nil, status.Error(codes.FailedPrecondition, "plugin not configured")
	}

	pState := req.GetProviderState().AsMap()
	verifier, _ := pState["pkce_verifier"].(string)
	expectedNonce, _ := pState["nonce"].(string)
	expectedState, _ := pState["state"].(string)
	expectedRedirect, _ := pState["redirect_uri"].(string)
	issuedAt, _ := pState["issued_at"].(string)
	if verifier == "" || expectedNonce == "" {
		s.auditLog.AuthDecision(false, audit.ReasonInvalidProviderArgs, "", "", peerIP)
		return nil, status.Error(codes.InvalidArgument, "missing pkce_verifier or nonce in provider_state")
	}

	// Stale-state defense: a captured authorize request can't be replayed past
	// stateTTL. Only enforced when InitAuthorize stamped issued_at (older host
	// builds omit it; then the nonce one-time guard below still applies).
	if issuedAt != "" {
		if ts, perr := time.Parse(time.RFC3339Nano, issuedAt); perr == nil {
			if time.Since(ts) > stateTTL {
				s.auditLog.AuthDecision(false, audit.ReasonStaleState, "", "", peerIP)
				return nil, status.Error(codes.Unauthenticated, "authorization request expired")
			}
		}
	}

	// CSRF defense: the callback's state must match the state we issued
	// during InitAuthorize. Constant-time comparison so timing leaks can't
	// be used to recover state byte-by-byte. When InitAuthorize was called
	// with an empty state (older host builds), we skip this check — the
	// host is then responsible for state validation upstream.
	if expectedState != "" {
		callbackState := req.GetState()
		if subtle.ConstantTimeCompare([]byte(callbackState), []byte(expectedState)) != 1 {
			s.auditLog.AuthDecision(false, audit.ReasonStateMismatch, "", "", peerIP)
			return nil, status.Error(codes.Unauthenticated, "state mismatch")
		}
	}

	// Open-redirect defense: the callback's redirect_uri must match the one we
	// authorized with. A buggy host that forwarded an attacker-controlled
	// redirect_uri into ExchangeCode would otherwise let the auth code be
	// exchanged against an unexpected callback. Constant-time compare. Skipped
	// only when InitAuthorize didn't stash a redirect_uri (older host builds).
	if expectedRedirect != "" {
		if subtle.ConstantTimeCompare([]byte(req.GetRedirectUri()), []byte(expectedRedirect)) != 1 {
			s.auditLog.AuthDecision(false, audit.ReasonRedirectMismatch, "", "", peerIP)
			return nil, status.Error(codes.Unauthenticated, "redirect_uri mismatch")
		}
	}

	// One-time replay guard: consume the per-flow nonce. A captured callback
	// replayed against ExchangeCode is rejected here even if state and
	// redirect_uri still match. The nonce row is retained for stateTTL, which
	// is exactly the window in which a non-stale callback could arrive.
	if s.consumeNonc != nil {
		if err := s.consumeNonc(ctx, expectedNonce, time.Now().Add(stateTTL)); err != nil {
			if errors.Is(err, store.ErrReplay) {
				s.auditLog.AuthDecision(false, audit.ReasonReplay, "", "", peerIP)
				return nil, status.Error(codes.Unauthenticated, "authorization code already used")
			}
			logDebug("consume nonce failed", err)
			return nil, status.Error(codes.Internal, "replay check failed")
		}
	}

	// Pin token exchange, id_token JWKS refresh, and the UserInfo fetch below
	// to the provider's SSRF-hardened HTTP client.
	if hc := prov.HTTPClient(); hc != nil {
		ctx = gooidc.ClientContext(ctx, hc)
	}

	oc := prov.OAuth2Config()
	oc.RedirectURL = req.GetRedirectUri()

	tok, err := oc.Exchange(ctx, req.GetCode(),
		oauth2.SetAuthURLParam("code_verifier", verifier),
	)
	if err != nil {
		// Upstream errors can echo token/endpoint detail; never surface that to
		// the caller. Detail is logged at debug only (and never the raw code).
		logDebug("token exchange failed", err)
		s.auditLog.AuthDecision(false, audit.ReasonExchangeFailed, "", "", peerIP)
		return nil, status.Error(codes.Internal, "token exchange failed")
	}

	rawIDToken, _ := tok.Extra("id_token").(string)
	if rawIDToken == "" {
		s.auditLog.AuthDecision(false, audit.ReasonVerifyFailed, "", "", peerIP)
		return nil, status.Error(codes.Internal, "no id_token in response")
	}
	idToken, err := prov.Verifier().Verify(ctx, rawIDToken)
	if err != nil {
		logDebug("id_token verification failed", err)
		s.auditLog.AuthDecision(false, audit.ReasonVerifyFailed, "", "", peerIP)
		return nil, status.Error(codes.Internal, "id_token verification failed")
	}
	if idToken.Nonce != expectedNonce {
		s.auditLog.AuthDecision(false, audit.ReasonNonceMismatch, "", "", peerIP)
		return nil, status.Error(codes.Unauthenticated, "nonce mismatch")
	}

	var idClaims map[string]any
	if err := idToken.Claims(&idClaims); err != nil {
		s.auditLog.AuthDecision(false, audit.ReasonVerifyFailed, "", "", peerIP)
		return nil, status.Errorf(codes.Internal, "decode id_token claims: %v", err)
	}

	// Merge id_token claims with userinfo. userinfo wins on collision per spec
	// Layer 5.3 step 7. Userinfo fetch failure is non-fatal: the verified
	// id_token alone is enough to proceed.
	merged := make(map[string]any, len(idClaims))
	for k, v := range idClaims {
		merged[k] = v
	}
	idSub, _ := idClaims["sub"].(string)
	if idSub == "" {
		s.auditLog.AuthDecision(false, audit.ReasonMissingSubject, "", "", peerIP)
		return nil, status.Error(codes.Unauthenticated, "id_token missing subject")
	}
	if ui, err := prov.Inner().UserInfo(ctx, oauth2.StaticTokenSource(tok)); err == nil {
		var uClaims map[string]any
		if err := ui.Claims(&uClaims); err == nil {
			if uiSub, _ := uClaims["sub"].(string); uiSub != "" && uiSub != idSub {
				s.auditLog.AuthDecision(false, audit.ReasonSubjectMismatch, idSub, "", peerIP)
				return nil, status.Error(codes.Unauthenticated, "userinfo subject mismatch")
			}
			for k, v := range uClaims {
				merged[k] = v
			}
		}
	}

	// Security-sensitive email + email_verified MUST come from the signed
	// id_token, never the userinfo-merged map. Userinfo is unsigned and can
	// override id_token claims on collision; trusting it for the email-verified
	// gate or for email-based account linking would let an IdP (or an attacker
	// who can influence userinfo) claim an arbitrary verified email and take
	// over an existing account. sub is already pinned to the id_token above.
	idEmailVerified, _ := claims.EmailVerified(idClaims)
	idEmail, _ := idClaims["email"].(string)

	if cfg.EmailVerifiedRequired && !idEmailVerified {
		s.auditLog.AuthDecision(false, audit.ReasonEmailUnverified, idSub, "", peerIP)
		return nil, status.Error(codes.PermissionDenied, "email not verified")
	}

	if err := claims.EvaluateFilters(merged, cfg.ClaimFilters); err != nil {
		s.auditLog.AuthDecision(false, audit.ReasonClaimFilterReject, idSub, "", peerIP)
		return nil, status.Error(codes.PermissionDenied, "claim filter rejected")
	}
	merged["silo_role"] = claims.ResolveRole(merged, cfg.ClaimRoleMapping)
	// Account-takeover guard: only advertise email linking when the id_token's
	// email is verified AND non-empty, independent of the EmailVerifiedRequired
	// toggle. Linking an unverified/empty email would let a fresh OIDC identity
	// claim an existing local account by email.
	if cfg.LinkByEmail && idEmailVerified && idEmail != "" {
		merged["silo_link_by_email"] = true
	}

	id := claims.DeriveIdentity(merged)

	cs, err := structpb.NewStruct(merged)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "claims structpb: %v", err)
	}
	s.auditLog.AuthDecision(true, audit.ReasonSuccess, id.Subject, "", peerIP)
	return &pluginv1.AuthenticateResponse{
		ExternalSubject: id.Subject,
		DisplayName:     id.DisplayName,
		Email:           id.Email,
		Claims:          cs,
	}, nil
}

// peerIP extracts the caller's IP from the gRPC peer info, falling back to an
// empty string when unavailable (e.g. in-process test calls). Only the host
// in addr:port form is returned; the port is dropped so per-IP buckets aren't
// fragmented by ephemeral source ports.
func peerIP(ctx context.Context) string {
	p, ok := peer.FromContext(ctx)
	if !ok || p.Addr == nil {
		return ""
	}
	host, _, err := net.SplitHostPort(p.Addr.String())
	if err != nil {
		return p.Addr.String()
	}
	return host
}

// rateKey returns the limiter key for a peer IP, collapsing an unknown IP to a
// single shared bucket so callers we can't attribute still get bounded.
func rateKey(ip string) string {
	if ip == "" {
		return "unknown"
	}
	return ip
}

// rateLimitErr builds the ResourceExhausted gRPC status used for rate-limited
// calls, carrying a RetryInfo detail so a host that surfaces this over HTTP can
// translate it into a 429 + Retry-After.
func rateLimitErr(retry time.Duration) error {
	st := status.New(codes.ResourceExhausted, "rate limit exceeded")
	if d, derr := st.WithDetails(&errdetails.RetryInfo{
		RetryDelay: durationpb.New(retry),
	}); derr == nil {
		return d.Err()
	}
	return st.Err()
}

// randB64 returns n random bytes encoded as unpadded base64url. An entropy
// read failure is treated as fatal for the call: callers (InitAuthorize)
// must surface the error rather than mint zero-byte tokens. PKCE verifiers
// and nonces are security-critical; a silent fallback would produce
// predictable, brute-forceable values.
func randB64(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// pkceS256 returns the S256 PKCE challenge derived from verifier.
func pkceS256(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}
