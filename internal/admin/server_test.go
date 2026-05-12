package admin_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/ContinuumApp/continuum-plugin-oidc-login/internal/admin"
	pluginoidc "github.com/ContinuumApp/continuum-plugin-oidc-login/internal/oidc"
	"github.com/ContinuumApp/continuum-plugin-oidc-login/internal/oidctest"
	pluginrt "github.com/ContinuumApp/continuum-plugin-oidc-login/internal/runtime"
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
	r.Header.Set("X-Continuum-User-Id", "u-1")
	r.Header.Set("X-Continuum-User-Role", "user") // not admin — still allowed
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
	r.Header.Set("X-Continuum-User-Role", "user")
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	if w.Code != http.StatusForbidden {
		t.Errorf("non-admin code = %d", w.Code)
	}

	// Admin OK.
	r = httptest.NewRequest("GET", "/api/v1/admin/config-summary", nil)
	r.Header.Set("X-Continuum-User-Role", "admin")
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
	r.Header.Set("X-Continuum-User-Role", "admin")
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
	r.Header.Set("X-Continuum-User-Role", "admin")
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
	r.Header.Set("X-Continuum-User-Role", "admin")
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

func TestDecodeIDToken_BadTokenReportsError(t *testing.T) {
	idp := oidctest.NewIdP(t, "client-1")
	s := newAdmin(t, pluginrt.Config{IssuerURL: idp.URL, ClientID: "client-1", ClientSecret: "s"}, idp)

	body, _ := json.Marshal(map[string]string{"id_token": "not.a.real.token"})
	r := httptest.NewRequest("POST", "/api/v1/admin/decode-id-token", strings.NewReader(string(body)))
	r.Header.Set("X-Continuum-User-Role", "admin")
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
