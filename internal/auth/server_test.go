package auth_test

import (
	"context"
	"net/url"
	"strings"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/structpb"

	pluginv1 "github.com/ContinuumApp/continuum-plugin-sdk/pkg/pluginproto/continuum/plugin/v1"

	"github.com/ContinuumApp/continuum-plugin-oidc-login/internal/auth"
	pluginoidc "github.com/ContinuumApp/continuum-plugin-oidc-login/internal/oidc"
	"github.com/ContinuumApp/continuum-plugin-oidc-login/internal/oidctest"
	pluginrt "github.com/ContinuumApp/continuum-plugin-oidc-login/internal/runtime"
)

func setupServer(t *testing.T, cfg pluginrt.Config, idp *oidctest.IdP) *auth.Server {
	t.Helper()
	prov, err := pluginoidc.NewProvider(context.Background(), pluginoidc.NewArgs{
		IssuerURL:    idp.URL,
		ClientID:     cfg.ClientID,
		ClientSecret: cfg.ClientSecret,
		Scopes:       cfg.Scopes,
	})
	if err != nil {
		t.Fatalf("NewProvider: %v", err)
	}
	return auth.NewServer(
		func() pluginrt.Config { return cfg },
		func() *pluginoidc.Provider { return prov },
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
			{ClaimPath: "groups", Operator: "contains", Value: "continuum-users"},
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
			{ClaimPath: "groups", Operator: "contains", Value: "continuum-users"},
		},
	}
	s := setupServer(t, cfg, idp)

	code, _ := idp.IssueCode(t,
		map[string]any{"sub": "u", "nonce": "n", "groups": []any{"continuum-users"}, "email": "u@x.com", "email_verified": true},
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
