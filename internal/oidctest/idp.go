// Package oidctest provides a fake OIDC IdP for testing. Spin up a server
// with NewIdP, mint signed id_tokens via IdP.IssueCode, and point the plugin
// at IdP.URL. The fake speaks discovery + JWKS + token + userinfo endpoints
// and signs id_tokens with a per-IdP RSA key whose public half is published
// at /jwks.json so go-oidc can verify them.
package oidctest

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
)

// IdP is a stand-in for a real OIDC provider in tests. Construct via NewIdP;
// the httptest server is automatically Closed at test cleanup.
type IdP struct {
	URL        string
	Server     *httptest.Server
	ClientID   string
	signingKey *rsa.PrivateKey
	jwks       []byte

	mu     sync.Mutex
	tokens map[string]TokenIssue
}

// TokenIssue is the bundle returned by /oauth/token for a given code.
type TokenIssue struct {
	IDToken     string
	AccessToken string
	UserInfo    map[string]any
}

// NewIdP starts a fake IdP with the supplied OAuth client_id. The test's
// cleanup hook closes the underlying httptest server.
func NewIdP(t *testing.T, clientID string) *IdP {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa key: %v", err)
	}
	jwk := jose.JSONWebKey{Key: &priv.PublicKey, KeyID: "test-key-1", Algorithm: "RS256", Use: "sig"}
	jwks := jose.JSONWebKeySet{Keys: []jose.JSONWebKey{jwk}}
	jwksBytes, err := json.Marshal(jwks)
	if err != nil {
		t.Fatalf("marshal jwks: %v", err)
	}

	idp := &IdP{
		signingKey: priv,
		jwks:       jwksBytes,
		ClientID:   clientID,
		tokens:     map[string]TokenIssue{},
	}

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
		_, _ = w.Write(jwksBytes)
	})

	mux.HandleFunc("/oauth/token", func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		code := r.Form.Get("code")
		idp.mu.Lock()
		issue, ok := idp.tokens[code]
		idp.mu.Unlock()
		if !ok {
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte(`{"error":"invalid_code"}`))
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"access_token": issue.AccessToken,
			"id_token":     issue.IDToken,
			"token_type":   "Bearer",
			"expires_in":   3600,
		})
	})

	mux.HandleFunc("/oauth/userinfo", func(w http.ResponseWriter, r *http.Request) {
		auth := r.Header.Get("Authorization")
		auth = strings.TrimPrefix(auth, "Bearer ")
		idp.mu.Lock()
		defer idp.mu.Unlock()
		for _, issue := range idp.tokens {
			if issue.AccessToken == auth {
				w.Header().Set("Content-Type", "application/json")
				_ = json.NewEncoder(w).Encode(issue.UserInfo)
				return
			}
		}
		w.WriteHeader(http.StatusUnauthorized)
	})

	srv.Start()
	t.Cleanup(srv.Close)
	idp.URL = srv.URL
	idp.Server = srv
	return idp
}

// IssueCode pre-stages a (code, id_token, userinfo) triple. Returns the code
// callers should pass to ExchangeCode, plus the raw id_token for tests that
// want to feed it through the admin /decode-id-token endpoint.
//
// The default claim set (iss, aud, iat, exp) is added automatically;
// idTokenClaims overlays anything callers want (sub, nonce, groups, etc.).
func (i *IdP) IssueCode(t *testing.T, idTokenClaims, userInfo map[string]any, accessToken string) (code, idToken string) {
	t.Helper()
	now := time.Now()
	claims := map[string]any{
		"iss": i.URL,
		"aud": i.ClientID,
		"iat": now.Unix(),
		"exp": now.Add(time.Hour).Unix(),
	}
	for k, v := range idTokenClaims {
		claims[k] = v
	}

	signer, err := jose.NewSigner(
		jose.SigningKey{Algorithm: jose.RS256, Key: i.signingKey},
		(&jose.SignerOptions{}).WithType("JWT").WithHeader("kid", "test-key-1"),
	)
	if err != nil {
		t.Fatalf("signer: %v", err)
	}
	idToken, err = jwt.Signed(signer).Claims(claims).Serialize()
	if err != nil {
		t.Fatalf("sign id_token: %v", err)
	}

	suffix := accessToken
	if len(suffix) > 8 {
		suffix = suffix[:8]
	}
	code = "code-" + suffix

	i.mu.Lock()
	i.tokens[code] = TokenIssue{
		IDToken:     idToken,
		AccessToken: accessToken,
		UserInfo:    userInfo,
	}
	i.mu.Unlock()
	return code, idToken
}
