package oidc_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	pluginoidc "github.com/RXWatcher/continuum-plugin-oidc-login/internal/oidc"
)

// fakeIdP returns an httptest server that serves a minimal OIDC discovery doc
// + an empty JWKS. Enough for go-oidc to construct a Provider; Phase 4 tests
// use the richer oidctest.IdP with real signed id_tokens.
func fakeIdP(t *testing.T) (*httptest.Server, string) {
	t.Helper()
	mux := http.NewServeMux()
	srv := httptest.NewUnstartedServer(mux)
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"issuer":                                srv.URL,
			"authorization_endpoint":                srv.URL + "/oauth/authorize",
			"token_endpoint":                        srv.URL + "/oauth/token",
			"userinfo_endpoint":                     srv.URL + "/oauth/userinfo",
			"jwks_uri":                              srv.URL + "/jwks.json",
			"scopes_supported":                      []string{"openid", "profile", "email"},
			"response_types_supported":              []string{"code"},
			"id_token_signing_alg_values_supported": []string{"RS256"},
		})
	})
	mux.HandleFunc("/jwks.json", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"keys":[]}`))
	})
	srv.Start()
	t.Cleanup(srv.Close)
	return srv, srv.URL
}

func TestNewProvider_DiscoversEndpoints(t *testing.T) {
	_, issuer := fakeIdP(t)
	p, err := pluginoidc.NewProvider(context.Background(), pluginoidc.NewArgs{
		IssuerURL:    issuer,
		ClientID:     "c1",
		ClientSecret: "s1",
		Scopes:       "openid profile email",
		RedirectURL:  "https://app/cb",
	})
	if err != nil {
		t.Fatalf("NewProvider: %v", err)
	}

	cfg := p.OAuth2Config()
	if !strings.HasSuffix(cfg.Endpoint.AuthURL, "/oauth/authorize") {
		t.Errorf("AuthURL = %s", cfg.Endpoint.AuthURL)
	}
	if !strings.HasSuffix(cfg.Endpoint.TokenURL, "/oauth/token") {
		t.Errorf("TokenURL = %s", cfg.Endpoint.TokenURL)
	}
	if cfg.ClientID != "c1" || cfg.ClientSecret != "s1" {
		t.Errorf("ClientID/Secret = %s/%s", cfg.ClientID, cfg.ClientSecret)
	}
	if len(cfg.Scopes) != 3 || cfg.Scopes[0] != "openid" {
		t.Errorf("scopes = %v", cfg.Scopes)
	}
	if p.Verifier() == nil {
		t.Errorf("Verifier() returned nil")
	}
	if p.Inner() == nil {
		t.Errorf("Inner() returned nil")
	}
}

func TestNewProvider_DefaultScopesFallback(t *testing.T) {
	_, issuer := fakeIdP(t)
	p, err := pluginoidc.NewProvider(context.Background(), pluginoidc.NewArgs{
		IssuerURL:    issuer,
		ClientID:     "c",
		ClientSecret: "s",
	})
	if err != nil {
		t.Fatalf("NewProvider: %v", err)
	}
	cfg := p.OAuth2Config()
	if len(cfg.Scopes) != 3 {
		t.Errorf("default scopes = %v", cfg.Scopes)
	}
}

func TestNewProvider_BadIssuerFails(t *testing.T) {
	// Use a URL that won't even DNS-resolve to keep the test fast and offline-friendly.
	_, err := pluginoidc.NewProvider(context.Background(), pluginoidc.NewArgs{
		IssuerURL:    "http://127.0.0.1:1/this-port-is-closed",
		ClientID:     "c",
		ClientSecret: "s",
	})
	if err == nil {
		t.Error("expected error for bad issuer")
	}
}
