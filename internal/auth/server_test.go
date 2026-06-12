package auth_test

import (
	"context"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"google.golang.org/genproto/googleapis/rpc/errdetails"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/structpb"

	pluginv1 "github.com/Silo-Server/silo-plugin-sdk/pkg/pluginproto/silo/plugin/v1"

	"github.com/RXWatcher/silo-plugin-oidc-login/internal/auth"
	pluginoidc "github.com/RXWatcher/silo-plugin-oidc-login/internal/oidc"
	"github.com/RXWatcher/silo-plugin-oidc-login/internal/oidctest"
	"github.com/RXWatcher/silo-plugin-oidc-login/internal/ratelimit"
	pluginrt "github.com/RXWatcher/silo-plugin-oidc-login/internal/runtime"
	"github.com/RXWatcher/silo-plugin-oidc-login/internal/store"
)

// memNonce is an in-memory ConsumeNonceFn mirroring the store's one-time
// semantics: the first use of a nonce succeeds, every replay returns
// store.ErrReplay.
type memNonce struct {
	mu   sync.Mutex
	seen map[string]bool
}

func newMemNonce() *memNonce { return &memNonce{seen: map[string]bool{}} }

func (m *memNonce) consume(_ context.Context, nonce string, _ time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.seen[nonce] {
		return store.ErrReplay
	}
	m.seen[nonce] = true
	return nil
}

// setupServerWith builds an auth.Server wired with the supplied limiter and
// nonce consumer so the new replay/rate-limit gates can be exercised.
func setupServerWith(t *testing.T, cfg pluginrt.Config, idp *oidctest.IdP, lim *ratelimit.Limiter, consume auth.ConsumeNonceFn) *auth.Server {
	t.Helper()
	prov, err := pluginoidc.NewProvider(context.Background(), pluginoidc.NewArgs{
		IssuerURL:     idp.URL,
		ClientID:      cfg.ClientID,
		ClientSecret:  cfg.ClientSecret,
		Scopes:        cfg.Scopes,
		AllowLoopback: true,
	})
	if err != nil {
		t.Fatalf("NewProvider: %v", err)
	}
	return auth.NewServer(
		func() pluginrt.Config { return cfg },
		func() *pluginoidc.Provider { return prov },
		lim, nil, consume,
	)
}

func setupServer(t *testing.T, cfg pluginrt.Config, idp *oidctest.IdP) *auth.Server {
	t.Helper()
	prov, err := pluginoidc.NewProvider(context.Background(), pluginoidc.NewArgs{
		IssuerURL:     idp.URL,
		ClientID:      cfg.ClientID,
		ClientSecret:  cfg.ClientSecret,
		Scopes:        cfg.Scopes,
		AllowLoopback: true,
	})
	if err != nil {
		t.Fatalf("NewProvider: %v", err)
	}
	return auth.NewServer(
		func() pluginrt.Config { return cfg },
		func() *pluginoidc.Provider { return prov },
		nil, nil, nil,
	)
}

func TestInitAuthorize_BuildsURLWithPKCEAndNonce(t *testing.T) {
	idp := oidctest.NewIdP(t, "client-1")
	cfg := pluginrt.Config{ClientID: "client-1", ClientSecret: "s", Scopes: "openid profile email"}
	s := setupServer(t, cfg, idp)

	resp, err := s.InitAuthorize(context.Background(), &pluginv1.InitAuthorizeRequest{
		RedirectUri: "https://app/cb",
		State:       "state-1",
	})
	if err != nil {
		t.Fatalf("InitAuthorize: %v", err)
	}

	parsed, _ := url.Parse(resp.GetAuthorizeUrl())
	q := parsed.Query()
	if q.Get("response_type") != "code" {
		t.Errorf("response_type = %q", q.Get("response_type"))
	}
	if q.Get("code_challenge_method") != "S256" {
		t.Errorf("code_challenge_method = %q", q.Get("code_challenge_method"))
	}
	if q.Get("code_challenge") == "" {
		t.Errorf("code_challenge missing")
	}
	if q.Get("nonce") == "" {
		t.Errorf("nonce missing")
	}
	if q.Get("state") != "state-1" {
		t.Errorf("state = %q", q.Get("state"))
	}
	if q.Get("redirect_uri") != "https://app/cb" {
		t.Errorf("redirect_uri = %q", q.Get("redirect_uri"))
	}
	if !strings.Contains(parsed.Path, "/authorize") {
		t.Errorf("path = %s", parsed.Path)
	}

	ps := resp.GetProviderState().AsMap()
	if ps["pkce_verifier"] == "" {
		t.Errorf("provider_state missing pkce_verifier")
	}
	if ps["nonce"] != q.Get("nonce") {
		t.Errorf("nonce mismatch: state=%v query=%v", ps["nonce"], q.Get("nonce"))
	}
}

func TestAuthenticate_Unimplemented(t *testing.T) {
	idp := oidctest.NewIdP(t, "c")
	s := setupServer(t, pluginrt.Config{ClientID: "c", ClientSecret: "s"}, idp)
	_, err := s.Authenticate(context.Background(), &pluginv1.AuthenticateRequest{Username: "u", Password: "p"})
	if status.Code(err) != codes.Unimplemented {
		t.Errorf("err = %v", err)
	}
}

func TestRefreshSession_Unimplemented(t *testing.T) {
	idp := oidctest.NewIdP(t, "c")
	s := setupServer(t, pluginrt.Config{ClientID: "c", ClientSecret: "s"}, idp)
	_, err := s.RefreshSession(context.Background(), &pluginv1.RefreshSessionRequest{})
	if status.Code(err) != codes.Unimplemented {
		t.Errorf("err = %v", err)
	}
}

func TestInitAuthorize_NoProvider_FailedPrecondition(t *testing.T) {
	s := auth.NewServer(
		func() pluginrt.Config { return pluginrt.Config{} },
		func() *pluginoidc.Provider { return nil },
		nil, nil, nil,
	)
	_, err := s.InitAuthorize(context.Background(), &pluginv1.InitAuthorizeRequest{})
	if status.Code(err) != codes.FailedPrecondition {
		t.Errorf("err = %v", err)
	}
}

func TestExchangeCode_HappyPath_VerifiesNonceReturnsClaims(t *testing.T) {
	idp := oidctest.NewIdP(t, "client-1")
	cfg := pluginrt.Config{ClientID: "client-1", ClientSecret: "s"}
	s := setupServer(t, cfg, idp)

	nonce := "test-nonce-1"
	code, _ := idp.IssueCode(t,
		map[string]any{"sub": "u-42", "nonce": nonce, "email": "u@x.com", "email_verified": true, "name": "User"},
		map[string]any{"sub": "u-42", "email": "u@x.com", "name": "User"},
		"access-tok-12345678",
	)

	pState, _ := structpb.NewStruct(map[string]any{"pkce_verifier": "v", "nonce": nonce})
	resp, err := s.ExchangeCode(context.Background(), &pluginv1.ExchangeCodeRequest{
		Code: code, State: "state", RedirectUri: "https://app/cb", ProviderState: pState,
	})
	if err != nil {
		t.Fatalf("ExchangeCode: %v", err)
	}
	if resp.GetExternalSubject() != "u-42" {
		t.Errorf("external_subject = %q", resp.GetExternalSubject())
	}
	if resp.GetEmail() != "u@x.com" {
		t.Errorf("email = %q", resp.GetEmail())
	}
	if resp.GetDisplayName() != "User" {
		t.Errorf("display_name = %q", resp.GetDisplayName())
	}
	if cs := resp.GetClaims(); cs == nil {
		t.Errorf("claims missing")
	} else if cs.AsMap()["sub"] != "u-42" {
		t.Errorf("claims = %v", cs.AsMap())
	}
}

func TestExchangeCode_DisplayName_FallbackToGivenFamily(t *testing.T) {
	idp := oidctest.NewIdP(t, "client-1")
	cfg := pluginrt.Config{ClientID: "client-1", ClientSecret: "s"}
	s := setupServer(t, cfg, idp)

	nonce := "n"
	code, _ := idp.IssueCode(t,
		map[string]any{"sub": "u", "nonce": nonce, "email": "u@x.com", "email_verified": true,
			"given_name": "Alice", "family_name": "Doe"},
		map[string]any{"sub": "u", "email": "u@x.com", "given_name": "Alice", "family_name": "Doe"},
		"access-tok-12345678",
	)
	pState, _ := structpb.NewStruct(map[string]any{"pkce_verifier": "v", "nonce": nonce})
	resp, err := s.ExchangeCode(context.Background(), &pluginv1.ExchangeCodeRequest{
		Code: code, State: "s", RedirectUri: "/cb", ProviderState: pState,
	})
	if err != nil {
		t.Fatalf("ExchangeCode: %v", err)
	}
	if resp.GetDisplayName() != "Alice Doe" {
		t.Errorf("display_name = %q", resp.GetDisplayName())
	}
}

func TestExchangeCode_NonceMismatch_Rejects(t *testing.T) {
	idp := oidctest.NewIdP(t, "client-1")
	cfg := pluginrt.Config{ClientID: "client-1", ClientSecret: "s"}
	s := setupServer(t, cfg, idp)

	code, _ := idp.IssueCode(t,
		map[string]any{"sub": "u", "nonce": "actual-nonce", "email": "u@x.com", "email_verified": true},
		map[string]any{"sub": "u", "email": "u@x.com"},
		"access-tok-12345678",
	)
	pState, _ := structpb.NewStruct(map[string]any{"pkce_verifier": "v", "nonce": "different-nonce"})
	_, err := s.ExchangeCode(context.Background(), &pluginv1.ExchangeCodeRequest{
		Code: code, State: "s", RedirectUri: "/cb", ProviderState: pState,
	})
	if err == nil {
		t.Fatal("expected nonce mismatch error")
	}
	if status.Code(err) != codes.Unauthenticated {
		t.Errorf("code = %v", status.Code(err))
	}
}

func TestExchangeCode_StateMismatch_Rejects(t *testing.T) {
	idp := oidctest.NewIdP(t, "client-1")
	cfg := pluginrt.Config{ClientID: "client-1", ClientSecret: "s"}
	s := setupServer(t, cfg, idp)

	nonce := "n"
	code, _ := idp.IssueCode(t,
		map[string]any{"sub": "u", "nonce": nonce, "email": "u@x.com", "email_verified": true},
		map[string]any{"sub": "u", "email": "u@x.com"},
		"access-tok-12345678",
	)
	// provider_state remembers the state we issued; the callback supplies a
	// different one (forged or buggy host). Plugin must reject Unauthenticated.
	pState, _ := structpb.NewStruct(map[string]any{
		"pkce_verifier": "v",
		"nonce":         nonce,
		"state":         "issued-state-abc",
	})
	_, err := s.ExchangeCode(context.Background(), &pluginv1.ExchangeCodeRequest{
		Code: code, State: "different-state-xyz", RedirectUri: "/cb", ProviderState: pState,
	})
	if err == nil {
		t.Fatal("expected state mismatch error")
	}
	if status.Code(err) != codes.Unauthenticated {
		t.Errorf("code = %v, want Unauthenticated", status.Code(err))
	}
}

func TestExchangeCode_StateMatch_Passes(t *testing.T) {
	idp := oidctest.NewIdP(t, "client-1")
	cfg := pluginrt.Config{ClientID: "client-1", ClientSecret: "s"}
	s := setupServer(t, cfg, idp)

	nonce := "n"
	code, _ := idp.IssueCode(t,
		map[string]any{"sub": "u", "nonce": nonce, "email": "u@x.com", "email_verified": true, "name": "User"},
		map[string]any{"sub": "u", "email": "u@x.com", "name": "User"},
		"access-tok-12345678",
	)
	pState, _ := structpb.NewStruct(map[string]any{
		"pkce_verifier": "v",
		"nonce":         nonce,
		"state":         "the-state",
	})
	resp, err := s.ExchangeCode(context.Background(), &pluginv1.ExchangeCodeRequest{
		Code: code, State: "the-state", RedirectUri: "/cb", ProviderState: pState,
	})
	if err != nil {
		t.Fatalf("ExchangeCode: %v", err)
	}
	if resp.GetExternalSubject() != "u" {
		t.Errorf("external_subject = %q, want u", resp.GetExternalSubject())
	}
}

// TestExchangeCode_NoStateInProviderState_SkipsCheck preserves backwards
// compatibility with older InitAuthorize callers that didn't stash state.
// The host is then responsible for state validation; the plugin doesn't
// fail-closed in that case.
func TestExchangeCode_NoStateInProviderState_SkipsCheck(t *testing.T) {
	idp := oidctest.NewIdP(t, "client-1")
	cfg := pluginrt.Config{ClientID: "client-1", ClientSecret: "s"}
	s := setupServer(t, cfg, idp)

	nonce := "n"
	code, _ := idp.IssueCode(t,
		map[string]any{"sub": "u", "nonce": nonce, "email": "u@x.com", "email_verified": true, "name": "User"},
		map[string]any{"sub": "u", "email": "u@x.com", "name": "User"},
		"access-tok-12345678",
	)
	pState, _ := structpb.NewStruct(map[string]any{
		"pkce_verifier": "v",
		"nonce":         nonce,
		// no "state" key — older shape
	})
	if _, err := s.ExchangeCode(context.Background(), &pluginv1.ExchangeCodeRequest{
		Code: code, State: "whatever", RedirectUri: "/cb", ProviderState: pState,
	}); err != nil {
		t.Fatalf("ExchangeCode (no stashed state) should pass: %v", err)
	}
}

func TestExchangeCode_EmailVerifiedRequired_RejectsUnverified(t *testing.T) {
	idp := oidctest.NewIdP(t, "client-1")
	cfg := pluginrt.Config{ClientID: "client-1", ClientSecret: "s", EmailVerifiedRequired: true}
	s := setupServer(t, cfg, idp)

	code, _ := idp.IssueCode(t,
		map[string]any{"sub": "u", "nonce": "n", "email": "u@x.com", "email_verified": false},
		map[string]any{"sub": "u", "email": "u@x.com", "email_verified": false},
		"access-tok-12345678",
	)
	pState, _ := structpb.NewStruct(map[string]any{"pkce_verifier": "v", "nonce": "n"})
	_, err := s.ExchangeCode(context.Background(), &pluginv1.ExchangeCodeRequest{
		Code: code, State: "s", RedirectUri: "/cb", ProviderState: pState,
	})
	if err == nil {
		t.Fatal("expected email_verified rejection")
	}
	if status.Code(err) != codes.PermissionDenied {
		t.Errorf("code = %v", status.Code(err))
	}
}

// TestExchangeCode_UserInfoCannotForgeEmailVerified proves userinfo (unsigned)
// cannot override the signed id_token's email_verified=false to bypass the
// EmailVerifiedRequired gate.
func TestExchangeCode_UserInfoCannotForgeEmailVerified(t *testing.T) {
	idp := oidctest.NewIdP(t, "client-1")
	cfg := pluginrt.Config{ClientID: "client-1", ClientSecret: "s", EmailVerifiedRequired: true}
	s := setupServer(t, cfg, idp)

	code, _ := idp.IssueCode(t,
		map[string]any{"sub": "u", "nonce": "n", "email": "u@x.com", "email_verified": false},
		map[string]any{"sub": "u", "email": "u@x.com", "email_verified": true}, // userinfo lies
		"access-tok-12345678",
	)
	pState, _ := structpb.NewStruct(map[string]any{"pkce_verifier": "v", "nonce": "n"})
	_, err := s.ExchangeCode(context.Background(), &pluginv1.ExchangeCodeRequest{
		Code: code, State: "s", RedirectUri: "/cb", ProviderState: pState,
	})
	if status.Code(err) != codes.PermissionDenied {
		t.Errorf("code = %v, want PermissionDenied (userinfo must not forge email_verified)", status.Code(err))
	}
}

// TestExchangeCode_LinkByEmail_RequiresVerifiedIDTokenEmail proves link_by_email
// is NOT advertised when the id_token's email is unverified, even though
// userinfo claims verification. EmailVerifiedRequired is off here so the login
// itself succeeds; only the link claim must be withheld.
func TestExchangeCode_LinkByEmail_RequiresVerifiedIDTokenEmail(t *testing.T) {
	idp := oidctest.NewIdP(t, "client-1")
	cfg := pluginrt.Config{ClientID: "client-1", ClientSecret: "s", LinkByEmail: true, EmailVerifiedRequired: false}
	s := setupServer(t, cfg, idp)

	code, _ := idp.IssueCode(t,
		map[string]any{"sub": "u", "nonce": "n", "email": "u@x.com", "email_verified": false},
		map[string]any{"sub": "u", "email": "u@x.com", "email_verified": true}, // userinfo lies
		"access-tok-12345678",
	)
	pState, _ := structpb.NewStruct(map[string]any{"pkce_verifier": "v", "nonce": "n"})
	resp, err := s.ExchangeCode(context.Background(), &pluginv1.ExchangeCodeRequest{
		Code: code, State: "s", RedirectUri: "/cb", ProviderState: pState,
	})
	if err != nil {
		t.Fatalf("ExchangeCode: %v", err)
	}
	if _, present := resp.GetClaims().AsMap()["silo_link_by_email"]; present {
		t.Errorf("silo_link_by_email must be absent when id_token email is unverified")
	}
}

func TestExchangeCode_MissingIDTokenSubject_Rejects(t *testing.T) {
	idp := oidctest.NewIdP(t, "client-1")
	cfg := pluginrt.Config{ClientID: "client-1", ClientSecret: "s"}
	s := setupServer(t, cfg, idp)

	code, _ := idp.IssueCode(t,
		map[string]any{"nonce": "n", "email": "u@x.com", "email_verified": true},
		map[string]any{"email": "u@x.com"},
		"access-tok-12345678",
	)
	pState, _ := structpb.NewStruct(map[string]any{"pkce_verifier": "v", "nonce": "n"})
	_, err := s.ExchangeCode(context.Background(), &pluginv1.ExchangeCodeRequest{
		Code: code, State: "s", RedirectUri: "/cb", ProviderState: pState,
	})
	if status.Code(err) != codes.Unauthenticated {
		t.Errorf("code = %v, want Unauthenticated; err = %v", status.Code(err), err)
	}
}

func TestExchangeCode_UserInfoSubjectMismatch_Rejects(t *testing.T) {
	idp := oidctest.NewIdP(t, "client-1")
	cfg := pluginrt.Config{ClientID: "client-1", ClientSecret: "s"}
	s := setupServer(t, cfg, idp)

	code, _ := idp.IssueCode(t,
		map[string]any{"sub": "id-token-sub", "nonce": "n", "email": "u@x.com", "email_verified": true},
		map[string]any{"sub": "different-userinfo-sub", "email": "u@x.com"},
		"access-tok-12345678",
	)
	pState, _ := structpb.NewStruct(map[string]any{"pkce_verifier": "v", "nonce": "n"})
	_, err := s.ExchangeCode(context.Background(), &pluginv1.ExchangeCodeRequest{
		Code: code, State: "s", RedirectUri: "/cb", ProviderState: pState,
	})
	if status.Code(err) != codes.Unauthenticated {
		t.Errorf("code = %v, want Unauthenticated; err = %v", status.Code(err), err)
	}
}

func TestExchangeCode_ClaimFilter_RejectsMissingGroup(t *testing.T) {
	idp := oidctest.NewIdP(t, "client-1")
	cfg := pluginrt.Config{
		ClientID: "client-1", ClientSecret: "s",
		ClaimFilters: []pluginrt.ClaimFilter{
			{ClaimPath: "groups", Operator: "contains", Value: "silo-users"},
		},
	}
	s := setupServer(t, cfg, idp)

	code, _ := idp.IssueCode(t,
		map[string]any{"sub": "u", "nonce": "n", "groups": []any{"other"}, "email": "u@x.com", "email_verified": true},
		map[string]any{"sub": "u", "email": "u@x.com"},
		"access-tok-12345678",
	)
	pState, _ := structpb.NewStruct(map[string]any{"pkce_verifier": "v", "nonce": "n"})
	_, err := s.ExchangeCode(context.Background(), &pluginv1.ExchangeCodeRequest{
		Code: code, State: "s", RedirectUri: "/cb", ProviderState: pState,
	})
	if err == nil {
		t.Fatal("expected claim filter rejection")
	}
	if status.Code(err) != codes.PermissionDenied {
		t.Errorf("code = %v", status.Code(err))
	}
}

func TestExchangeCode_ClaimFilter_AcceptsMatchingGroup(t *testing.T) {
	idp := oidctest.NewIdP(t, "client-1")
	cfg := pluginrt.Config{
		ClientID: "client-1", ClientSecret: "s",
		ClaimFilters: []pluginrt.ClaimFilter{
			{ClaimPath: "groups", Operator: "contains", Value: "silo-users"},
		},
	}
	s := setupServer(t, cfg, idp)

	code, _ := idp.IssueCode(t,
		map[string]any{"sub": "u", "nonce": "n", "groups": []any{"silo-users"}, "email": "u@x.com", "email_verified": true},
		map[string]any{"sub": "u", "email": "u@x.com"},
		"access-tok-12345678",
	)
	pState, _ := structpb.NewStruct(map[string]any{"pkce_verifier": "v", "nonce": "n"})
	if _, err := s.ExchangeCode(context.Background(), &pluginv1.ExchangeCodeRequest{
		Code: code, State: "s", RedirectUri: "/cb", ProviderState: pState,
	}); err != nil {
		t.Errorf("expected pass, got %v", err)
	}
}

func TestExchangeCode_RoleMapping_AssignsAdminFromClaims(t *testing.T) {
	idp := oidctest.NewIdP(t, "client-1")
	cfg := pluginrt.Config{
		ClientID: "client-1", ClientSecret: "s",
		ClaimRoleMapping: []pluginrt.RoleMappingRule{
			{ClaimPath: "groups", Operator: "contains", Value: "silo-admins", Role: "admin"},
		},
	}
	s := setupServer(t, cfg, idp)

	code, _ := idp.IssueCode(t,
		map[string]any{"sub": "u-9", "nonce": "n", "groups": []any{"silo-admins"}, "email": "u@x.com", "email_verified": true},
		map[string]any{"sub": "u-9", "email": "u@x.com"},
		"access-tok-12345678",
	)
	pState, _ := structpb.NewStruct(map[string]any{"pkce_verifier": "v", "nonce": "n"})
	resp, err := s.ExchangeCode(context.Background(), &pluginv1.ExchangeCodeRequest{
		Code: code, State: "s", RedirectUri: "/cb", ProviderState: pState,
	})
	if err != nil {
		t.Fatalf("ExchangeCode: %v", err)
	}
	claims := resp.GetClaims().AsMap()
	if claims["silo_role"] != "admin" {
		t.Errorf("silo_role = %v, want admin", claims["silo_role"])
	}
}

func TestExchangeCode_LinkByEmail_SetsLinkClaim(t *testing.T) {
	idp := oidctest.NewIdP(t, "client-1")
	cfg := pluginrt.Config{ClientID: "client-1", ClientSecret: "s", LinkByEmail: true}
	s := setupServer(t, cfg, idp)

	code, _ := idp.IssueCode(t,
		map[string]any{"sub": "u-10", "nonce": "n", "email": "u@x.com", "email_verified": true},
		map[string]any{"sub": "u-10", "email": "u@x.com"},
		"access-tok-12345678",
	)
	pState, _ := structpb.NewStruct(map[string]any{"pkce_verifier": "v", "nonce": "n"})
	resp, err := s.ExchangeCode(context.Background(), &pluginv1.ExchangeCodeRequest{
		Code: code, State: "s", RedirectUri: "/cb", ProviderState: pState,
	})
	if err != nil {
		t.Fatalf("ExchangeCode: %v", err)
	}
	if v, ok := resp.GetClaims().AsMap()["silo_link_by_email"].(bool); !ok || !v {
		t.Errorf("silo_link_by_email = %v (want true)", resp.GetClaims().AsMap()["silo_link_by_email"])
	}
}

func TestExchangeCode_LinkByEmail_Disabled_OmitsLinkClaim(t *testing.T) {
	idp := oidctest.NewIdP(t, "client-1")
	cfg := pluginrt.Config{ClientID: "client-1", ClientSecret: "s", LinkByEmail: false}
	s := setupServer(t, cfg, idp)

	code, _ := idp.IssueCode(t,
		map[string]any{"sub": "u-11", "nonce": "n", "email": "u@x.com", "email_verified": true},
		map[string]any{"sub": "u-11", "email": "u@x.com"},
		"access-tok-12345678",
	)
	pState, _ := structpb.NewStruct(map[string]any{"pkce_verifier": "v", "nonce": "n"})
	resp, err := s.ExchangeCode(context.Background(), &pluginv1.ExchangeCodeRequest{
		Code: code, State: "s", RedirectUri: "/cb", ProviderState: pState,
	})
	if err != nil {
		t.Fatalf("ExchangeCode: %v", err)
	}
	if _, present := resp.GetClaims().AsMap()["silo_link_by_email"]; present {
		t.Errorf("silo_link_by_email should be absent when LinkByEmail=false")
	}
}

func TestExchangeCode_DefaultRoleIsUser_WhenNoMappingMatches(t *testing.T) {
	idp := oidctest.NewIdP(t, "client-1")
	cfg := pluginrt.Config{
		ClientID: "client-1", ClientSecret: "s",
		ClaimRoleMapping: []pluginrt.RoleMappingRule{
			{ClaimPath: "groups", Operator: "contains", Value: "admins", Role: "admin"},
		},
	}
	s := setupServer(t, cfg, idp)

	code, _ := idp.IssueCode(t,
		map[string]any{"sub": "u-12", "nonce": "n", "groups": []any{"random"}, "email": "u@x.com", "email_verified": true},
		map[string]any{"sub": "u-12", "email": "u@x.com"},
		"access-tok-12345678",
	)
	pState, _ := structpb.NewStruct(map[string]any{"pkce_verifier": "v", "nonce": "n"})
	resp, err := s.ExchangeCode(context.Background(), &pluginv1.ExchangeCodeRequest{
		Code: code, State: "s", RedirectUri: "/cb", ProviderState: pState,
	})
	if err != nil {
		t.Fatalf("ExchangeCode: %v", err)
	}
	if got := resp.GetClaims().AsMap()["silo_role"]; got != "user" {
		t.Errorf("silo_role = %v, want user (default fallback)", got)
	}
}

func TestExchangeCode_MissingProviderState_Rejects(t *testing.T) {
	idp := oidctest.NewIdP(t, "client-1")
	cfg := pluginrt.Config{ClientID: "client-1", ClientSecret: "s"}
	s := setupServer(t, cfg, idp)

	_, err := s.ExchangeCode(context.Background(), &pluginv1.ExchangeCodeRequest{
		Code: "x", State: "s", RedirectUri: "/cb",
	})
	if status.Code(err) != codes.InvalidArgument {
		t.Errorf("err = %v", err)
	}
}

// TestInitAuthorize_StashesRedirectAndIssuedAt verifies the new provider_state
// fields backing redirect-uri allowlisting and stale-state rejection are set.
func TestInitAuthorize_StashesRedirectAndIssuedAt(t *testing.T) {
	idp := oidctest.NewIdP(t, "client-1")
	cfg := pluginrt.Config{ClientID: "client-1", ClientSecret: "s", Scopes: "openid profile email"}
	s := setupServer(t, cfg, idp)

	resp, err := s.InitAuthorize(context.Background(), &pluginv1.InitAuthorizeRequest{
		RedirectUri: "https://app/cb", State: "state-1",
	})
	if err != nil {
		t.Fatalf("InitAuthorize: %v", err)
	}
	ps := resp.GetProviderState().AsMap()
	if ps["redirect_uri"] != "https://app/cb" {
		t.Errorf("redirect_uri = %v", ps["redirect_uri"])
	}
	issued, _ := ps["issued_at"].(string)
	if issued == "" {
		t.Fatal("issued_at missing")
	}
	if _, perr := time.Parse(time.RFC3339Nano, issued); perr != nil {
		t.Errorf("issued_at not RFC3339Nano: %v", perr)
	}
}

// TestExchangeCode_RedirectURIMismatch_Rejects proves the plugin refuses a
// callback whose redirect_uri differs from the one stashed at InitAuthorize.
func TestExchangeCode_RedirectURIMismatch_Rejects(t *testing.T) {
	idp := oidctest.NewIdP(t, "client-1")
	cfg := pluginrt.Config{ClientID: "client-1", ClientSecret: "s"}
	s := setupServer(t, cfg, idp)

	nonce := "n"
	code, _ := idp.IssueCode(t,
		map[string]any{"sub": "u", "nonce": nonce, "email": "u@x.com", "email_verified": true},
		map[string]any{"sub": "u", "email": "u@x.com"},
		"access-tok-12345678",
	)
	pState, _ := structpb.NewStruct(map[string]any{
		"pkce_verifier": "v",
		"nonce":         nonce,
		"redirect_uri":  "https://app/cb",
	})
	_, err := s.ExchangeCode(context.Background(), &pluginv1.ExchangeCodeRequest{
		Code: code, State: "s", RedirectUri: "https://evil/cb", ProviderState: pState,
	})
	if status.Code(err) != codes.Unauthenticated {
		t.Errorf("code = %v, want Unauthenticated", status.Code(err))
	}
}

// TestExchangeCode_RedirectURIMatch_Passes proves a matching redirect_uri does
// not block an otherwise-valid login.
func TestExchangeCode_RedirectURIMatch_Passes(t *testing.T) {
	idp := oidctest.NewIdP(t, "client-1")
	cfg := pluginrt.Config{ClientID: "client-1", ClientSecret: "s"}
	s := setupServer(t, cfg, idp)

	nonce := "n"
	code, _ := idp.IssueCode(t,
		map[string]any{"sub": "u", "nonce": nonce, "email": "u@x.com", "email_verified": true, "name": "U"},
		map[string]any{"sub": "u", "email": "u@x.com", "name": "U"},
		"access-tok-12345678",
	)
	pState, _ := structpb.NewStruct(map[string]any{
		"pkce_verifier": "v",
		"nonce":         nonce,
		"redirect_uri":  "https://app/cb",
	})
	if _, err := s.ExchangeCode(context.Background(), &pluginv1.ExchangeCodeRequest{
		Code: code, State: "s", RedirectUri: "https://app/cb", ProviderState: pState,
	}); err != nil {
		t.Errorf("expected pass, got %v", err)
	}
}

// TestExchangeCode_StaleState_Rejects proves a callback whose issued_at is older
// than the TTL is refused.
func TestExchangeCode_StaleState_Rejects(t *testing.T) {
	idp := oidctest.NewIdP(t, "client-1")
	cfg := pluginrt.Config{ClientID: "client-1", ClientSecret: "s"}
	s := setupServer(t, cfg, idp)

	nonce := "n"
	code, _ := idp.IssueCode(t,
		map[string]any{"sub": "u", "nonce": nonce, "email": "u@x.com", "email_verified": true},
		map[string]any{"sub": "u", "email": "u@x.com"},
		"access-tok-12345678",
	)
	pState, _ := structpb.NewStruct(map[string]any{
		"pkce_verifier": "v",
		"nonce":         nonce,
		"issued_at":     time.Now().Add(-30 * time.Minute).UTC().Format(time.RFC3339Nano),
	})
	_, err := s.ExchangeCode(context.Background(), &pluginv1.ExchangeCodeRequest{
		Code: code, State: "s", RedirectUri: "/cb", ProviderState: pState,
	})
	if status.Code(err) != codes.Unauthenticated {
		t.Errorf("code = %v, want Unauthenticated (stale state)", status.Code(err))
	}
}

// TestExchangeCode_FreshState_Passes proves a recent issued_at does not block
// a valid login.
func TestExchangeCode_FreshState_Passes(t *testing.T) {
	idp := oidctest.NewIdP(t, "client-1")
	cfg := pluginrt.Config{ClientID: "client-1", ClientSecret: "s"}
	s := setupServer(t, cfg, idp)

	nonce := "n"
	code, _ := idp.IssueCode(t,
		map[string]any{"sub": "u", "nonce": nonce, "email": "u@x.com", "email_verified": true, "name": "U"},
		map[string]any{"sub": "u", "email": "u@x.com", "name": "U"},
		"access-tok-12345678",
	)
	pState, _ := structpb.NewStruct(map[string]any{
		"pkce_verifier": "v",
		"nonce":         nonce,
		"issued_at":     time.Now().UTC().Format(time.RFC3339Nano),
	})
	if _, err := s.ExchangeCode(context.Background(), &pluginv1.ExchangeCodeRequest{
		Code: code, State: "s", RedirectUri: "/cb", ProviderState: pState,
	}); err != nil {
		t.Errorf("expected pass, got %v", err)
	}
}

// TestExchangeCode_NonceReplay_Rejects proves the one-time nonce guard refuses
// a second ExchangeCode with the same nonce, even when everything else is
// valid. Each replay needs a freshly-issued auth code (the IdP code is also
// single-use), so the second attempt is rejected specifically by the replay
// guard before any exchange happens.
func TestExchangeCode_NonceReplay_Rejects(t *testing.T) {
	idp := oidctest.NewIdP(t, "client-1")
	cfg := pluginrt.Config{ClientID: "client-1", ClientSecret: "s"}
	nonce := newMemNonce()
	s := setupServerWith(t, cfg, idp, nil, nonce.consume)

	mkCode := func() string {
		code, _ := idp.IssueCode(t,
			map[string]any{"sub": "u", "nonce": "n", "email": "u@x.com", "email_verified": true, "name": "U"},
			map[string]any{"sub": "u", "email": "u@x.com", "name": "U"},
			"access-tok-12345678",
		)
		return code
	}
	mkState := func() *structpb.Struct {
		ps, _ := structpb.NewStruct(map[string]any{"pkce_verifier": "v", "nonce": "n"})
		return ps
	}

	if _, err := s.ExchangeCode(context.Background(), &pluginv1.ExchangeCodeRequest{
		Code: mkCode(), State: "s", RedirectUri: "/cb", ProviderState: mkState(),
	}); err != nil {
		t.Fatalf("first exchange should succeed: %v", err)
	}
	_, err := s.ExchangeCode(context.Background(), &pluginv1.ExchangeCodeRequest{
		Code: mkCode(), State: "s", RedirectUri: "/cb", ProviderState: mkState(),
	})
	if status.Code(err) != codes.Unauthenticated {
		t.Errorf("code = %v, want Unauthenticated (replay)", status.Code(err))
	}
}

// TestExchangeCode_RateLimited_ReturnsResourceExhausted proves an exhausted
// limiter short-circuits the call with ResourceExhausted + RetryInfo, before
// any token exchange.
func TestExchangeCode_RateLimited_ReturnsResourceExhausted(t *testing.T) {
	idp := oidctest.NewIdP(t, "client-1")
	cfg := pluginrt.Config{ClientID: "client-1", ClientSecret: "s"}
	lim := ratelimit.New(0.001, 1) // burst 1, effectively no refill
	s := setupServerWith(t, cfg, idp, lim, nil)

	pState, _ := structpb.NewStruct(map[string]any{"pkce_verifier": "v", "nonce": "n"})

	// First call consumes the only token. With no peer in context both calls
	// share the "unknown" bucket. The first will fail on exchange (bogus code)
	// but that still happens after the token is consumed.
	_, _ = s.ExchangeCode(context.Background(), &pluginv1.ExchangeCodeRequest{
		Code: "bogus", State: "s", RedirectUri: "/cb", ProviderState: pState,
	})
	_, err := s.ExchangeCode(context.Background(), &pluginv1.ExchangeCodeRequest{
		Code: "bogus", State: "s", RedirectUri: "/cb", ProviderState: pState,
	})
	if status.Code(err) != codes.ResourceExhausted {
		t.Fatalf("code = %v, want ResourceExhausted", status.Code(err))
	}
	// RetryInfo detail must be present so the host can build a Retry-After.
	var sawRetry bool
	for _, d := range status.Convert(err).Details() {
		if _, ok := d.(*errdetails.RetryInfo); ok {
			sawRetry = true
		}
	}
	if !sawRetry {
		t.Error("expected RetryInfo detail on rate-limit error")
	}
}
