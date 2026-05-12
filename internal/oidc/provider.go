// Package oidc wraps github.com/coreos/go-oidc/v3/oidc with the bits the
// plugin needs: discovery on construction, JWKS-backed id_token verifier,
// and a pre-built oauth2.Config for InitAuthorize / ExchangeCode.
package oidc

import (
	"context"
	"fmt"
	"strings"

	gooidc "github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

// NewArgs collects the inputs NewProvider needs from the parsed config.
// RedirectURL can be empty when the Provider is built for verification only;
// InitAuthorize overlays the per-request redirect_uri before constructing
// the authorize URL.
type NewArgs struct {
	IssuerURL    string
	ClientID     string
	ClientSecret string
	Scopes       string // space-separated; empty falls back to "openid profile email"
	RedirectURL  string
}

// Provider holds the discovered OIDC provider, the id_token verifier, and a
// pre-built oauth2.Config. Constructed once per Configure call and held
// behind an atomic pointer in main.go so handlers see consistent state.
type Provider struct {
	provider     *gooidc.Provider
	verifier     *gooidc.IDTokenVerifier
	oauth2Config oauth2.Config
}

// NewProvider performs OIDC discovery against issuerURL and returns a
// Provider ready to use. Discovery failures are surfaced as errors so the
// caller (Configure) can refuse the configuration.
func NewProvider(ctx context.Context, args NewArgs) (*Provider, error) {
	prov, err := gooidc.NewProvider(ctx, args.IssuerURL)
	if err != nil {
		return nil, fmt.Errorf("oidc discovery: %w", err)
	}
	verifier := prov.Verifier(&gooidc.Config{ClientID: args.ClientID})

	scopes := strings.Fields(args.Scopes)
	if len(scopes) == 0 {
		scopes = []string{"openid", "profile", "email"}
	}
	cfg := oauth2.Config{
		ClientID:     args.ClientID,
		ClientSecret: args.ClientSecret,
		Endpoint:     prov.Endpoint(),
		Scopes:       scopes,
		RedirectURL:  args.RedirectURL,
	}
	return &Provider{provider: prov, verifier: verifier, oauth2Config: cfg}, nil
}

// Verifier returns the JWKS-backed id_token verifier built during discovery.
func (p *Provider) Verifier() *gooidc.IDTokenVerifier { return p.verifier }

// OAuth2Config returns a copy of the pre-built oauth2.Config. Callers can
// freely overlay RedirectURL per request without mutating shared state.
func (p *Provider) OAuth2Config() oauth2.Config { return p.oauth2Config }

// Inner exposes the underlying *gooidc.Provider for callers that need
// UserInfo() / Claims() helpers not surfaced directly here.
func (p *Provider) Inner() *gooidc.Provider { return p.provider }
