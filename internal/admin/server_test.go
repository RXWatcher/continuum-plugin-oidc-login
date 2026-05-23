package admin_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/RXWatcher/silo-plugin-oidc-login/internal/admin"
	pluginoidc "github.com/RXWatcher/silo-plugin-oidc-login/internal/oidc"
	"github.com/RXWatcher/silo-plugin-oidc-login/internal/oidctest"
	pluginrt "github.com/RXWatcher/silo-plugin-oidc-login/internal/runtime"
)

func newAdmin(t *testing.T, cfg pluginrt.Config, idp *oidctest.IdP) *admin.Server {
	t.Helper()
	prov, err := pluginoidc.NewProvider(context.Background(), pluginoidc.NewArgs{
		IssuerURL: idp.URL, ClientID: cfg.ClientID, ClientSecret: cfg.ClientSecret,
	})
	if err != nil {
		t.Fatalf("provider: %v", err)
	}
	// Default issuer_url to the IdP's URL when the cfg leaves it unset, so
	// /discovery always has somewhere to probe.
	if cfg.IssuerURL == "" {
		cfg.IssuerURL = idp.URL
	}
	return admin.NewServer(admin.Deps{
		ConfigFn:   func() pluginrt.Config { return cfg },
		ProviderFn: func() *pluginoidc.Provider { return prov },
	})
}

func TestWhoami_OpenToAnyAuthenticated(t *testing.T) {
	idp := oidctest.NewIdP(t, "c")
	s := newAdmin(t, pluginrt.Config{ClientID: "c", ClientSecret: "s"}, idp)

	r := httptest.NewRequest("GET", "/api/v1/admin/whoami", nil)
	r.Header.Set("X-Silo-User-Id", "u-1")
	r.Header.Set("X-Silo-User-Role", "user") // not admin — still allowed
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("code = %d", w.Code)
	}
	var body map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &body)
	if body["role"] != "user" {
		t.Errorf("role = %v", body["role"])
	}
	if body["user_id"] != "u-1" {
		t.Errorf("user_id = %v", body["user_id"])
	}
}

func TestConfigSummary_GatedAndRedacts(t *testing.T) {
	idp := oidctest.NewIdP(t, "c")
	cfg := pluginrt.Config{
		IssuerURL:             idp.URL,
		ClientID:              "cid",
		ClientSecret:          "shh",
		Scopes:                "openid profile email",
		DisplayName:           "Test IdP",
		IconURLPath:           "authentik.svg",
		ClaimFilters:          []pluginrt.ClaimFilter{{ClaimPath: "groups", Operator: "contains", Value: "x"}},
		ClaimRoleMapping:      []pluginrt.RoleMappingRule{{ClaimPath: "groups", Operator: "contains", Value: "y", Role: "admin"}},
		EmailVerifiedRequired: true,
		LinkByEmail:           false,
	}
	s := newAdmin(t, cfg, idp)

	// Non-admin rejected.
	r := httptest.NewRequest("GET", "/api/v1/admin/config-summary", nil)
	r.Header.Set("X-Silo-User-Role", "user")
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	if w.Code != http.StatusForbidden {
		t.Errorf("non-admin code = %d", w.Code)
	}

	// Admin OK.
	r = httptest.NewRequest("GET", "/api/v1/admin/config-summary", nil)
	r.Header.Set("X-Silo-User-Role", "admin")
	w = httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("admin code = %d body=%s", w.Code, w.Body.String())
	}
	var body map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &body)
	if _, present := body["client_secret"]; present {
		t.Errorf("client_secret should NOT appear: %+v", body)
	}
	if body["has_client_secret"] != true {
		t.Errorf("has_client_secret = %v", body["has_client_secret"])
	}
	if body["client_id"] != "cid" {
		t.Errorf("client_id = %v", body["client_id"])
	}
	icons, _ := body["available_icons"].([]any)
	if len(icons) < 5 {
		t.Errorf("available_icons too short: %v", icons)
	}
}

func TestDiscovery_FetchesLiveDoc(t *testing.T) {
	idp := oidctest.NewIdP(t, "c")
	s := newAdmin(t, pluginrt.Config{IssuerURL: idp.URL, ClientID: "c", ClientSecret: "s"}, idp)

	r := httptest.NewRequest("GET", "/api/v1/admin/discovery", nil)
	r.Header.Set("X-Silo-User-Role", "admin")
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("code = %d body = %s", w.Code, w.Body.String())
	}
	var body map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &body)
	if body["ok"] != true {
		t.Errorf("ok = %v error = %v", body["ok"], body["error"])
	}
	authEP, _ := body["authorization_endpoint"].(string)
	if !strings.HasSuffix(authEP, "/oauth/authorize") {
		t.Errorf("auth endpoint = %v", authEP)
	}
	keys, _ := body["jwks_keys"].([]any)
	if len(keys) != 1 {
		t.Errorf("jwks_keys = %v", keys)
	}
}

func TestDiscovery_NoIssuer_ReturnsError(t *testing.T) {
	idp := oidctest.NewIdP(t, "c")
	s := newAdmin(t, pluginrt.Config{ClientID: "c", ClientSecret: "s"}, idp)
	// Build an admin server whose ConfigFn returns an empty issuer_url.
	s = admin.NewServer(admin.Deps{
		ConfigFn:   func() pluginrt.Config { return pluginrt.Config{} },
		ProviderFn: func() *pluginoidc.Provider { return nil },
	})

	r := httptest.NewRequest("GET", "/api/v1/admin/discovery", nil)
	r.Header.Set("X-Silo-User-Role", "admin")
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	if w.Code == http.StatusOK {
		// Allowed to be 200 with ok=false too — check body.
		var body map[string]any
		_ = json.Unmarshal(w.Body.Bytes(), &body)
		if body["ok"] != false {
			t.Errorf("expected ok=false, got %v", body)
		}
	}
}

func TestDiscovery_UnreachableIssuer_ReturnsErrorPayload(t *testing.T) {
	idp := oidctest.NewIdP(t, "c")
	// IssuerURL points at a high port on the loopback that nothing is listening
	// on. Discovery should NOT return 5xx — it should return ok=false with the
	// dialer error so the SPA can render it inline.
	cfg := pluginrt.Config{IssuerURL: "http://127.0.0.1:1", ClientID: "c", ClientSecret: "s"}
	s := admin.NewServer(admin.Deps{
		ConfigFn:   func() pluginrt.Config { return cfg },
		ProviderFn: func() *pluginoidc.Provider { return nil },
	})
	_ = idp // keep linter happy

	r := httptest.NewRequest("GET", "/api/v1/admin/discovery", nil)
	r.Header.Set("X-Silo-User-Role", "admin")
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("code = %d, want 200 (errors must come back as ok=false payload)", w.Code)
	}
	var body map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &body)
	if body["ok"] != false {
		t.Errorf("ok = %v, want false", body["ok"])
	}
	if errMsg, _ := body["error"].(string); errMsg == "" {
		t.Errorf("expected error message describing the connect failure")
	}
}

func TestDecodeIDToken_VerifiesAndReturnsClaims(t *testing.T) {
	idp := oidctest.NewIdP(t, "client-1")
	s := newAdmin(t, pluginrt.Config{IssuerURL: idp.URL, ClientID: "client-1", ClientSecret: "s"}, idp)

	_, idToken := idp.IssueCode(t,
		map[string]any{"sub": "u-1", "nonce": "n", "email": "u@x.com"},
		map[string]any{"sub": "u-1", "email": "u@x.com"},
		"access-tok-12345678",
	)

	body, _ := json.Marshal(map[string]string{"id_token": idToken})
	r := httptest.NewRequest("POST", "/api/v1/admin/decode-id-token", strings.NewReader(string(body)))
	r.Header.Set("X-Silo-User-Role", "admin")
	r.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("code = %d body = %s", w.Code, w.Body.String())
	}
	var resp map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &resp)
	if resp["verified"] != true {
		t.Errorf("verified = %v error = %v", resp["verified"], resp["error"])
	}
	c, _ := resp["claims"].(map[string]any)
	if c["sub"] != "u-1" {
		t.Errorf("claims.sub = %v", c["sub"])
	}
}

func TestSimulateClaims_UsesLiveConfig_AndAcceptsValidUser(t *testing.T) {
	idp := oidctest.NewIdP(t, "client-1")
	cfg := pluginrt.Config{
		IssuerURL:    idp.URL,
		ClientID:     "client-1",
		ClientSecret: "s",
		ClaimFilters: []pluginrt.ClaimFilter{
			{ClaimPath: "groups", Operator: "contains", Value: "silo-users"},
		},
		ClaimRoleMapping: []pluginrt.RoleMappingRule{
			{ClaimPath: "groups", Operator: "contains", Value: "silo-admins", Role: "admin"},
		},
		EmailVerifiedRequired: true,
	}
	s := newAdmin(t, cfg, idp)

	body, _ := json.Marshal(map[string]any{
		"claims": map[string]any{
			"sub":            "u-1",
			"email":          "ada@example.com",
			"email_verified": true,
			"groups":         []any{"silo-users", "silo-admins"},
			"name":           "Ada",
		},
	})
	r := httptest.NewRequest("POST", "/api/v1/admin/simulate-claims", strings.NewReader(string(body)))
	r.Header.Set("X-Silo-User-Role", "admin")
	r.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("code = %d body = %s", w.Code, w.Body.String())
	}
	var resp map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &resp)
	if resp["allowed"] != true {
		t.Errorf("allowed = %v, want true", resp["allowed"])
	}
	if resp["role"] != "admin" {
		t.Errorf("role = %v, want admin", resp["role"])
	}
	ec, _ := resp["email_verified_check"].(map[string]any)
	if ec["passed"] != true {
		t.Errorf("email_verified_check.passed = %v", ec["passed"])
	}
}

func TestSimulateClaims_RejectsOnFilterMiss_AndReportsTrace(t *testing.T) {
	idp := oidctest.NewIdP(t, "client-1")
	cfg := pluginrt.Config{
		IssuerURL:    idp.URL,
		ClientID:     "client-1",
		ClientSecret: "s",
		ClaimFilters: []pluginrt.ClaimFilter{
			{ClaimPath: "groups", Operator: "contains", Value: "silo-users"},
		},
		EmailVerifiedRequired: false,
	}
	s := newAdmin(t, cfg, idp)

	body, _ := json.Marshal(map[string]any{
		"claims": map[string]any{
			"sub":    "u-1",
			"groups": []any{"random-group"},
		},
	})
	r := httptest.NewRequest("POST", "/api/v1/admin/simulate-claims", strings.NewReader(string(body)))
	r.Header.Set("X-Silo-User-Role", "admin")
	r.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("code = %d", w.Code)
	}
	var resp map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &resp)
	if resp["allowed"] != false {
		t.Errorf("allowed = %v, want false", resp["allowed"])
	}
	if resp["filters_passed"] != false {
		t.Errorf("filters_passed = %v, want false", resp["filters_passed"])
	}
	trace, _ := resp["filter_trace"].([]any)
	if len(trace) != 1 {
		t.Fatalf("filter_trace length = %d, want 1", len(trace))
	}
	first := trace[0].(map[string]any)
	if first["match"] != false {
		t.Errorf("first.match = %v, want false", first["match"])
	}
}

func TestSimulateClaims_BodyOverridesLiveConfig(t *testing.T) {
	idp := oidctest.NewIdP(t, "client-1")
	// Live config requires email_verified; body asks us to relax that.
	cfg := pluginrt.Config{
		IssuerURL:             idp.URL,
		ClientID:              "client-1",
		ClientSecret:          "s",
		EmailVerifiedRequired: true,
	}
	s := newAdmin(t, cfg, idp)

	relax := false
	body, _ := json.Marshal(map[string]any{
		"claims":                  map[string]any{"sub": "u-1", "email_verified": false},
		"email_verified_required": relax,
	})
	r := httptest.NewRequest("POST", "/api/v1/admin/simulate-claims", strings.NewReader(string(body)))
	r.Header.Set("X-Silo-User-Role", "admin")
	r.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("code = %d", w.Code)
	}
	var resp map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &resp)
	ec, _ := resp["email_verified_check"].(map[string]any)
	if ec["required"] != false {
		t.Errorf("override didn't take: required = %v", ec["required"])
	}
	if resp["allowed"] != true {
		t.Errorf("allowed = %v with overridden email check", resp["allowed"])
	}
}

func TestSimulateClaims_NonAdmin_403(t *testing.T) {
	idp := oidctest.NewIdP(t, "client-1")
	s := newAdmin(t, pluginrt.Config{IssuerURL: idp.URL, ClientID: "client-1", ClientSecret: "s"}, idp)
	r := httptest.NewRequest("POST", "/api/v1/admin/simulate-claims", strings.NewReader(`{"claims":{}}`))
	r.Header.Set("X-Silo-User-Role", "user")
	r.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	if w.Code != http.StatusForbidden {
		t.Errorf("code = %d, want 403", w.Code)
	}
}

func TestDecodeIDToken_BadTokenReportsError(t *testing.T) {
	idp := oidctest.NewIdP(t, "client-1")
	s := newAdmin(t, pluginrt.Config{IssuerURL: idp.URL, ClientID: "client-1", ClientSecret: "s"}, idp)

	body, _ := json.Marshal(map[string]string{"id_token": "not.a.real.token"})
	r := httptest.NewRequest("POST", "/api/v1/admin/decode-id-token", strings.NewReader(string(body)))
	r.Header.Set("X-Silo-User-Role", "admin")
	r.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("code = %d body = %s", w.Code, w.Body.String())
	}
	var resp map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &resp)
	if resp["verified"] != false {
		t.Errorf("verified = %v (should be false)", resp["verified"])
	}
	if resp["error"] == nil || resp["error"] == "" {
		t.Errorf("expected error reason")
	}
}
