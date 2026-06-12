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

	gooidc "github.com/coreos/go-oidc/v3/oidc"
	"github.com/hashicorp/go-hclog"
	"golang.org/x/oauth2"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/structpb"

	pluginv1 "github.com/Silo-Server/silo-plugin-sdk/pkg/pluginproto/silo/plugin/v1"

	"github.com/RXWatcher/silo-plugin-oidc-login/internal/claims"
	pluginoidc "github.com/RXWatcher/silo-plugin-oidc-login/internal/oidc"
	pluginrt "github.com/RXWatcher/silo-plugin-oidc-login/internal/runtime"
)

// logDebug records upstream failure detail at debug level only. The caller-
// facing gRPC status stays generic so token-exchange / verification text (and
// any token context it may carry) never leaks to the client. The raw auth code
// and tokens are never passed in here.
func logDebug(msg string, err error) {
	hclog.Default().Debug("oidc auth: "+msg, "error", err)
}

// Server implements pluginv1.AuthProviderServer. Configuration and the OIDC
// provider live behind closures so main.go can swap them at Configure time
// without locking.
type Server struct {
	pluginv1.UnimplementedAuthProviderServer
	cfgFn  func() pluginrt.Config
	provFn func() *pluginoidc.Provider
}

// NewServer wires the supplied accessors. Both are called fresh per RPC; the
// plugin process holds the live values behind atomic pointers in main.go.
func NewServer(cfgFn func() pluginrt.Config, provFn func() *pluginoidc.Provider) *Server {
	return &Server{cfgFn: cfgFn, provFn: provFn}
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
	cfg.RedirectURL = req.GetRedirectUri()

	reqState := req.GetState()
	authURL := cfg.AuthCodeURL(reqState,
		oauth2.SetAuthURLParam("nonce", nonce),
		oauth2.SetAuthURLParam("code_challenge", challenge),
		oauth2.SetAuthURLParam("code_challenge_method", "S256"),
	)

	// Stash the issued state alongside pkce_verifier + nonce so ExchangeCode
	// can verify the callback's state matches what was sent to the IdP.
	// This is defense-in-depth: the host is also expected to validate state
	// at the callback URL before invoking ExchangeCode, but a plugin-side
	// check protects users when the host's check is buggy or skipped.
	pState, err := structpb.NewStruct(map[string]any{
		"pkce_verifier": verifier,
		"nonce":         nonce,
		"state":         reqState,
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
	cfg := s.cfgFn()
	prov := s.provFn()
	if prov == nil {
		return nil, status.Error(codes.FailedPrecondition, "plugin not configured")
	}

	pState := req.GetProviderState().AsMap()
	verifier, _ := pState["pkce_verifier"].(string)
	expectedNonce, _ := pState["nonce"].(string)
	expectedState, _ := pState["state"].(string)
	if verifier == "" || expectedNonce == "" {
		return nil, status.Error(codes.InvalidArgument, "missing pkce_verifier or nonce in provider_state")
	}

	// CSRF defense: the callback's state must match the state we issued
	// during InitAuthorize. Constant-time comparison so timing leaks can't
	// be used to recover state byte-by-byte. When InitAuthorize was called
	// with an empty state (older host builds), we skip this check — the
	// host is then responsible for state validation upstream.
	if expectedState != "" {
		callbackState := req.GetState()
		if subtle.ConstantTimeCompare([]byte(callbackState), []byte(expectedState)) != 1 {
			return nil, status.Error(codes.Unauthenticated, "state mismatch")
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
		return nil, status.Error(codes.Internal, "token exchange failed")
	}

	rawIDToken, _ := tok.Extra("id_token").(string)
	if rawIDToken == "" {
		return nil, status.Error(codes.Internal, "no id_token in response")
	}
	idToken, err := prov.Verifier().Verify(ctx, rawIDToken)
	if err != nil {
		logDebug("id_token verification failed", err)
		return nil, status.Error(codes.Internal, "id_token verification failed")
	}
	if idToken.Nonce != expectedNonce {
		return nil, status.Error(codes.Unauthenticated, "nonce mismatch")
	}

	var idClaims map[string]any
	if err := idToken.Claims(&idClaims); err != nil {
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
		return nil, status.Error(codes.Unauthenticated, "id_token missing subject")
	}
	if ui, err := prov.Inner().UserInfo(ctx, oauth2.StaticTokenSource(tok)); err == nil {
		var uClaims map[string]any
		if err := ui.Claims(&uClaims); err == nil {
			if uiSub, _ := uClaims["sub"].(string); uiSub != "" && uiSub != idSub {
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
		return nil, status.Error(codes.PermissionDenied, "email not verified")
	}

	if err := claims.EvaluateFilters(merged, cfg.ClaimFilters); err != nil {
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
	return &pluginv1.AuthenticateResponse{
		ExternalSubject: id.Subject,
		DisplayName:     id.DisplayName,
		Email:           id.Email,
		Claims:          cs,
	}, nil
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
