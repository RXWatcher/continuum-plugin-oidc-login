// Package runtime implements the plugin's Runtime gRPC server. Its Configure
// handler parses the global config payload into Config, validates it, and
// invokes a callback supplied by main.go so the plugin can (re)wire its
// OIDC provider + admin handlers.
package runtime

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/url"
	"regexp"
	"strings"
	"sync"

	pluginv1 "github.com/ContinuumApp/continuum-plugin-sdk/pkg/pluginproto/continuum/plugin/v1"
	"github.com/ContinuumApp/continuum-plugin-sdk/pkg/pluginsdk/runtimedefault"
)

// AllowedIcons is the allowlist of bundled icon SVGs. The icon_url_path config
// entry must reference one of these filenames; arbitrary paths are rejected at
// Configure time to prevent file-disclosure via the assets handler.
var AllowedIcons = []string{
	"authentik.svg",
	"keycloak.svg",
	"auth0.svg",
	"okta.svg",
	"microsoft.svg",
	"google.svg",
	"gitlab.svg",
	"generic-key.svg",
}

// ClaimFilter is a single gating rule. All filters in claim_filters must pass
// (AND semantics) for the user to sign in.
type ClaimFilter struct {
	ClaimPath string `json:"claim_path"`
	Operator  string `json:"operator"` // equals | contains | starts_with | regex
	Value     any    `json:"value"`
}

// RoleMappingRule is a single role-elevation rule. Rules are evaluated in
// order and the first match wins; default role is "user".
type RoleMappingRule struct {
	ClaimPath string `json:"claim_path"`
	Operator  string `json:"operator"`
	Value     any    `json:"value"`
	Role      string `json:"role"` // user | admin
}

// Config is the parsed plugin global config (spec Layer 2.2).
type Config struct {
	IssuerURL             string            `json:"issuer_url"`
	ClientID              string            `json:"client_id"`
	ClientSecret          string            `json:"client_secret"`
	Scopes                string            `json:"scopes"`
	DisplayName           string            `json:"display_name"`
	IconURLPath           string            `json:"icon_url_path"`
	ClaimFilters          []ClaimFilter     `json:"claim_filters"`
	ClaimRoleMapping      []RoleMappingRule `json:"claim_role_mapping"`
	EmailVerifiedRequired bool              `json:"email_verified_required"`
	LinkByEmail           bool              `json:"link_by_email"`
}

// ProviderConfigured reports whether the OIDC provider has enough settings to
// run discovery and participate in login flows.
func (c Config) ProviderConfigured() bool {
	return c.IssuerURL != "" && c.ClientID != "" && c.ClientSecret != ""
}

func (c Config) providerPartiallyConfigured() bool {
	return c.IssuerURL != "" || c.ClientID != "" || c.ClientSecret != ""
}

// Server implements the plugin's Runtime service.
type Server struct {
	runtimedefault.Server
	manifest *pluginv1.PluginManifest
	onCfg    func(Config) error

	mu  sync.RWMutex
	cfg Config
}

// New constructs a Runtime server bound to the supplied manifest and onConfig
// callback. The callback runs on every Configure call (initial + reconfigure)
// and is where the plugin builds its OIDC provider, admin handlers, etc.
func New(manifest *pluginv1.PluginManifest, onConfig func(Config) error) *Server {
	return &Server{manifest: manifest, onCfg: onConfig}
}

func (s *Server) GetManifest(_ context.Context, _ *pluginv1.GetManifestRequest) (*pluginv1.GetManifestResponse, error) {
	return &pluginv1.GetManifestResponse{Manifest: s.manifest}, nil
}

func (s *Server) Configure(_ context.Context, req *pluginv1.ConfigureRequest) (*pluginv1.ConfigureResponse, error) {
	cfg, err := LoadConfig(req.GetConfig())
	if err != nil {
		return nil, err
	}
	if s.onCfg != nil {
		if err := s.onCfg(cfg); err != nil {
			return nil, err
		}
	}
	s.mu.Lock()
	s.cfg = cfg
	s.mu.Unlock()
	return &pluginv1.ConfigureResponse{}, nil
}

// Snapshot returns the most recently applied Config.
func (s *Server) Snapshot() Config {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.cfg
}

// LoadConfig parses a slice of ConfigEntry protos into a validated Config.
// Exported so tests can exercise it without a gRPC server.
func LoadConfig(entries []*pluginv1.ConfigEntry) (Config, error) {
	cfg := Config{
		Scopes:                "openid profile email",
		DisplayName:           "Sign in with OIDC",
		IconURLPath:           "generic-key.svg",
		EmailVerifiedRequired: true,
	}

	for _, e := range entries {
		v := e.GetValue()
		if v == nil {
			continue
		}
		m := v.AsMap()
		val := m["value"]
		switch e.GetKey() {
		case "issuer_url":
			cfg.IssuerURL = strings.TrimRight(stringOf(val), "/")
		case "client_id":
			cfg.ClientID = stringOf(val)
		case "client_secret":
			cfg.ClientSecret = stringOf(val)
		case "scopes":
			if s := stringOf(val); s != "" {
				cfg.Scopes = s
			}
		case "display_name":
			if s := stringOf(val); s != "" {
				cfg.DisplayName = s
			}
		case "icon_url_path":
			if s := stringOf(val); s != "" {
				cfg.IconURLPath = s
			}
		case "claim_filters":
			raw, err := json.Marshal(val)
			if err != nil {
				return Config{}, fmt.Errorf("claim_filters: marshal value: %w", err)
			}
			if err := json.Unmarshal(raw, &cfg.ClaimFilters); err != nil {
				return Config{}, fmt.Errorf("claim_filters: invalid JSON shape: %w", err)
			}
		case "claim_role_mapping":
			raw, err := json.Marshal(val)
			if err != nil {
				return Config{}, fmt.Errorf("claim_role_mapping: marshal value: %w", err)
			}
			if err := json.Unmarshal(raw, &cfg.ClaimRoleMapping); err != nil {
				return Config{}, fmt.Errorf("claim_role_mapping: invalid JSON shape: %w", err)
			}
		case "email_verified_required":
			if b, ok := val.(bool); ok {
				cfg.EmailVerifiedRequired = b
			}
		case "link_by_email":
			if b, ok := val.(bool); ok {
				cfg.LinkByEmail = b
			}
		}
	}

	if err := validate(cfg); err != nil {
		return Config{}, err
	}
	return cfg, nil
}

func validate(cfg Config) error {
	if cfg.providerPartiallyConfigured() {
		if cfg.IssuerURL == "" {
			return errors.New("issuer_url is required when OIDC provider settings are present")
		}
		if err := validateIssuerURL(cfg.IssuerURL); err != nil {
			return err
		}
		if cfg.ClientID == "" {
			return errors.New("client_id is required when OIDC provider settings are present")
		}
		if cfg.ClientSecret == "" {
			return errors.New("client_secret is required when OIDC provider settings are present")
		}
	}
	if !scopeIncludesOpenID(cfg.Scopes) {
		return errors.New("scopes must include openid")
	}
	if !IconAllowed(cfg.IconURLPath) {
		return fmt.Errorf("icon_url_path %q not in allowlist", cfg.IconURLPath)
	}
	for i, f := range cfg.ClaimFilters {
		if err := ValidateOperator(f.Operator); err != nil {
			return fmt.Errorf("claim_filters[%d]: %w", i, err)
		}
		if f.ClaimPath == "" {
			return fmt.Errorf("claim_filters[%d]: claim_path required", i)
		}
		if err := ValidateClaimPath(f.ClaimPath); err != nil {
			return fmt.Errorf("claim_filters[%d]: %w", i, err)
		}
		if err := ValidateOperatorValue(f.Operator, f.Value); err != nil {
			return fmt.Errorf("claim_filters[%d]: %w", i, err)
		}
		if f.Operator == "regex" {
			if _, err := regexp.Compile(stringOf(f.Value)); err != nil {
				return fmt.Errorf("claim_filters[%d]: invalid regex: %w", i, err)
			}
		}
	}
	for i, r := range cfg.ClaimRoleMapping {
		if err := ValidateOperator(r.Operator); err != nil {
			return fmt.Errorf("claim_role_mapping[%d]: %w", i, err)
		}
		if r.ClaimPath == "" {
			return fmt.Errorf("claim_role_mapping[%d]: claim_path required", i)
		}
		if err := ValidateClaimPath(r.ClaimPath); err != nil {
			return fmt.Errorf("claim_role_mapping[%d]: %w", i, err)
		}
		if r.Role != "user" && r.Role != "admin" {
			return fmt.Errorf("claim_role_mapping[%d]: role must be user or admin (got %q)", i, r.Role)
		}
		if err := ValidateOperatorValue(r.Operator, r.Value); err != nil {
			return fmt.Errorf("claim_role_mapping[%d]: %w", i, err)
		}
		if r.Operator == "regex" {
			if _, err := regexp.Compile(stringOf(r.Value)); err != nil {
				return fmt.Errorf("claim_role_mapping[%d]: invalid regex: %w", i, err)
			}
		}
	}
	return nil
}

func validateIssuerURL(raw string) error {
	u, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("issuer_url is not a valid URL: %w", err)
	}
	if u.Scheme != "https" && u.Scheme != "http" {
		return fmt.Errorf("issuer_url scheme must be http or https")
	}
	if u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return fmt.Errorf("issuer_url must be an origin URL without credentials, query, or fragment")
	}
	if u.Scheme == "http" && !isLocalhost(u.Hostname()) {
		return fmt.Errorf("issuer_url must use https except for localhost")
	}
	return nil
}

func isLocalhost(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func scopeIncludesOpenID(scopes string) bool {
	for _, scope := range strings.Fields(scopes) {
		if scope == "openid" {
			return true
		}
	}
	return false
}

// claimPathSegment matches a single dotted segment: identifier-ish chars only.
// Mirrors the conservative shape of JWT claim names (no whitespace, no quoting,
// no bracket indexing). Hyphens are permitted because some IdPs emit kebab-case
// custom claims; leading char must be a letter or underscore.
var claimPathSegment = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_-]*$`)

// ValidateClaimPath returns nil iff path is a non-empty dot-separated chain of
// identifier-shaped segments (e.g. "groups", "realm_access.roles"). It refuses
// empty segments, bracket/quote/whitespace chars, and leading-digit segments.
func ValidateClaimPath(path string) error {
	if path == "" {
		return errors.New("claim_path required")
	}
	for _, seg := range strings.Split(path, ".") {
		if seg == "" {
			return fmt.Errorf("claim_path %q has empty segment", path)
		}
		if !claimPathSegment.MatchString(seg) {
			return fmt.Errorf("claim_path %q: segment %q must match [A-Za-z_][A-Za-z0-9_-]*", path, seg)
		}
	}
	return nil
}

// ValidateOperator returns nil iff op is one of equals|contains|starts_with|regex.
func ValidateOperator(op string) error {
	switch op {
	case "equals", "contains", "starts_with", "regex":
		return nil
	}
	return fmt.Errorf("operator must be one of equals|contains|starts_with|regex (got %q)", op)
}

// ValidateOperatorValue rejects rule values that cannot be interpreted by the
// selected operator. equals and contains accept any JSON value; starts_with and
// regex operate on string patterns only.
func ValidateOperatorValue(op string, value any) error {
	switch op {
	case "starts_with", "regex":
		if _, ok := value.(string); !ok {
			return fmt.Errorf("operator %s requires a string value", op)
		}
	}
	return nil
}

// IconAllowed returns true iff name is in AllowedIcons.
func IconAllowed(name string) bool {
	for _, a := range AllowedIcons {
		if a == name {
			return true
		}
	}
	return false
}

func stringOf(v any) string {
	if s, ok := v.(string); ok {
		return s
	}
	return ""
}
