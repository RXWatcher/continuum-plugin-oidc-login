// Package oidc wraps github.com/coreos/go-oidc/v3/oidc with the bits the
// plugin needs: discovery on construction, JWKS-backed id_token verifier,
// and a pre-built oauth2.Config for InitAuthorize / ExchangeCode.
package oidc

import (
	"context"
	"fmt"
	"net/http"
	"strings"

	gooidc "github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

// supportedSigningAlgs pins id_token verification to asymmetric algorithms.
// Symmetric (HMAC) algs are deliberately excluded: they would let an attacker
// who learns the client_secret forge tokens, and "alg":"none" downgrade
// attacks are refused outright.
var supportedSigningAlgs = []string{gooidc.RS256, gooidc.ES256, gooidc.PS256}

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
	// AllowLoopback permits discovery/JWKS fetches to loopback addresses. It is
	// set only for explicitly-configured localhost issuers; the SSRF-hardened
	// client otherwise refuses loopback/private/link-local/metadata targets.
	AllowLoopback bool
}

// Provider holds the discovered OIDC provider, the id_token verifier, and a
// pre-built oauth2.Config. Constructed once per Configure call and held
// behind an atomic pointer in main.go so handlers see consistent state.
type Provider struct {
	provider     *gooidc.Provider
	verifier     *gooidc.IDTokenVerifier
	oauth2Config oauth2.Config
	httpClient   *http.Client
}

// NewProvider performs OIDC discovery against issuerURL and returns a
// Provider ready to use. Discovery failures are surfaced as errors so the
// caller (Configure) can refuse the configuration.
func NewProvider(ctx context.Context, args NewArgs) (*Provider, error) {
	httpClient := SecureHTTPClient(args.AllowLoopback)
	// Pin discovery + JWKS fetches (and any later UserInfo call sharing this
	// context) to the SSRF-hardened client.
	dctx := gooidc.ClientContext(ctx, httpClient)
	prov, err := gooidc.NewProvider(dctx, args.IssuerURL)
	if err != nil {
		return nil, fmt.Errorf("oidc discovery: %w", err)
	}
	verifier := prov.Verifier(&gooidc.Config{
		ClientID:             args.ClientID,
		SupportedSigningAlgs: supportedSigningAlgs,
	})

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
	return &Provider{provider: prov, verifier: verifier, oauth2Config: cfg, httpClient: httpClient}, nil
}

// Verifier returns the JWKS-backed id_token verifier built during discovery.
func (p *Provider) Verifier() *gooidc.IDTokenVerifier { return p.verifier }

// OAuth2Config returns a copy of the pre-built oauth2.Config. Callers can
// freely overlay RedirectURL per request without mutating shared state.
func (p *Provider) OAuth2Config() oauth2.Config { return p.oauth2Config }

// Inner exposes the underlying *gooidc.Provider for callers that need
// UserInfo() / Claims() helpers not surfaced directly here.
func (p *Provider) Inner() *gooidc.Provider { return p.provider }

// HTTPClient returns the SSRF-hardened HTTP client used for discovery/JWKS.
// Callers wrap their RPC context with oidc.ClientContext(ctx, prov.HTTPClient())
// so token exchange, id_token JWKS refresh, and UserInfo fetches all flow
// through the same hardened dialer.
func (p *Provider) HTTPClient() *http.Client { return p.httpClient }
