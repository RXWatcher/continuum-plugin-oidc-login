// Package admin serves the plugin's admin HTTP endpoints. All endpoints under
// /api/v1/admin/ are gated on X-Silo-User-Role: admin, except whoami
// which is open to any authenticated user (it's how the SPA detects whether
// the current user has access to the admin page).
package admin

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/RXWatcher/silo-plugin-oidc-login/internal/claims"
	pluginoidc "github.com/RXWatcher/silo-plugin-oidc-login/internal/oidc"
	pluginrt "github.com/RXWatcher/silo-plugin-oidc-login/internal/runtime"
)

// maxResponseBytes caps outbound discovery/JWKS response bodies. Both
// well-formed OIDC discovery documents and JWKS payloads are well under
// this; the cap defends against memory exhaustion if a misbehaving or
// hostile IdP returns a runaway body.
const maxResponseBytes = 10 << 20 // 10 MiB

// Deps wires the closures the handlers read at request time. ConfigFn and
// ProviderFn are called per-request so the latest Configure values are
// always observed.
type Deps struct {
	ConfigFn       func() pluginrt.Config
	ProviderFn     func() *pluginoidc.Provider
	UpdateConfigFn func(context.Context, pluginrt.Config) error
}

// Server exposes a chi handler. It owns no state of its own beyond Deps.
type Server struct {
	deps Deps
}

// NewServer constructs an admin server.
func NewServer(d Deps) *Server { return &Server{deps: d} }

// Handler returns the chi router. /whoami is open to any authenticated user;
// all other endpoints sit behind requireAdmin.
func (s *Server) Handler() http.Handler {
	r := chi.NewRouter()
	r.Get("/api/v1/admin/whoami", s.handleWhoami)
	r.Group(func(r chi.Router) {
		r.Use(s.requireAdmin)
		r.Get("/api/v1/admin/config-summary", s.handleConfigSummary)
		r.Patch("/api/v1/admin/config", s.handleUpdateConfig)
		r.Get("/api/v1/admin/discovery", s.handleDiscovery)
		r.Post("/api/v1/admin/decode-id-token", s.handleDecodeIDToken)
		r.Post("/api/v1/admin/simulate-claims", s.handleSimulateClaims)
	})
	return r
}

func (s *Server) handleUpdateConfig(w http.ResponseWriter, r *http.Request) {
	if s.deps.UpdateConfigFn == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{"error": "config store unavailable"})
		return
	}
	cur := s.deps.ConfigFn()
	var req struct {
		IssuerURL             *string                     `json:"issuer_url"`
		ClientID              *string                     `json:"client_id"`
		ClientSecret          *string                     `json:"client_secret"`
		Scopes                *string                     `json:"scopes"`
		DisplayName           *string                     `json:"display_name"`
		IconURLPath           *string                     `json:"icon_url_path"`
		ClaimFilters          *[]pluginrt.ClaimFilter     `json:"claim_filters"`
		ClaimRoleMapping      *[]pluginrt.RoleMappingRule `json:"claim_role_mapping"`
		EmailVerifiedRequired *bool                       `json:"email_verified_required"`
		LinkByEmail           *bool                       `json:"link_by_email"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid JSON body"})
		return
	}
	if req.IssuerURL != nil {
		cur.IssuerURL = strings.TrimRight(strings.TrimSpace(*req.IssuerURL), "/")
	}
	if req.ClientID != nil {
		cur.ClientID = strings.TrimSpace(*req.ClientID)
	}
	if req.ClientSecret != nil && *req.ClientSecret != "" {
		cur.ClientSecret = *req.ClientSecret
	}
	if req.Scopes != nil {
		cur.Scopes = strings.TrimSpace(*req.Scopes)
	}
	if req.DisplayName != nil {
		cur.DisplayName = strings.TrimSpace(*req.DisplayName)
	}
	if req.IconURLPath != nil {
		cur.IconURLPath = strings.TrimSpace(*req.IconURLPath)
	}
	if req.ClaimFilters != nil {
		cur.ClaimFilters = *req.ClaimFilters
	}
	if req.ClaimRoleMapping != nil {
		cur.ClaimRoleMapping = *req.ClaimRoleMapping
	}
	if req.EmailVerifiedRequired != nil {
		cur.EmailVerifiedRequired = *req.EmailVerifiedRequired
	}
	if req.LinkByEmail != nil {
		cur.LinkByEmail = *req.LinkByEmail
	}
	cur.DatabaseURL = ""
	if err := s.deps.UpdateConfigFn(r.Context(), cur); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

// requireAdmin gates the wrapped handlers on X-Silo-User-Role: admin.
// The silo host stamps these headers on every authenticated request to
// plugin routes; absence (or non-admin) is rejected with 403.
func (s *Server) requireAdmin(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Silo-User-Role") != "admin" {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// handleWhoami returns the host-injected identity headers verbatim. The SPA
// uses it for admin-gate detection and theme selection.
func (s *Server) handleWhoami(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"user_id": r.Header.Get("X-Silo-User-Id"),
		"role":    r.Header.Get("X-Silo-User-Role"),
		"theme":   r.Header.Get("X-Silo-User-Theme"),
	})
}

// handleConfigSummary returns the SPA-friendly subset of the live config.
// Secrets (client_secret) are replaced with a boolean has_client_secret;
// available_icons is filled from the runtime allowlist so the IconPicker
// can render thumbnails without an extra round-trip.
func (s *Server) handleConfigSummary(w http.ResponseWriter, _ *http.Request) {
	cfg := s.deps.ConfigFn()
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"issuer_url":              cfg.IssuerURL,
		"client_id":               cfg.ClientID,
		"has_client_secret":       cfg.ClientSecret != "",
		"scopes":                  cfg.Scopes,
		"display_name":            cfg.DisplayName,
		"icon_url_path":           cfg.IconURLPath,
		"claim_filters":           cfg.ClaimFilters,
		"claim_role_mapping":      cfg.ClaimRoleMapping,
		"email_verified_required": cfg.EmailVerifiedRequired,
		"link_by_email":           cfg.LinkByEmail,
		"available_icons":         pluginrt.AllowedIcons,
	})
}

// handleDiscovery does a live fetch of the configured issuer's discovery doc
// and (best-effort) summarises its JWKS. Returns ok=false with a reason on
// any failure rather than non-200; the SPA shows the error inline.
func (s *Server) handleDiscovery(w http.ResponseWriter, r *http.Request) {
	cfg := s.deps.ConfigFn()
	if cfg.IssuerURL == "" {
		writeJSON(w, http.StatusOK, map[string]any{"ok": false, "error": "issuer_url not configured"})
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()

	// SSRF-hardened client: rejects loopback/private/link-local/metadata IPs at
	// dial time (after DNS resolution). Loopback is permitted only when the
	// operator explicitly configured a localhost issuer.
	httpClient := pluginoidc.SecureHTTPClient(pluginrt.IssuerAllowsLoopback(cfg.IssuerURL))

	url := strings.TrimRight(cfg.IssuerURL, "/") + "/.well-known/openid-configuration"
	req, _ := http.NewRequestWithContext(ctx, "GET", url, nil)
	resp, err := httpClient.Do(req)
	if err != nil {
		writeJSON(w, http.StatusOK, map[string]any{"ok": false, "error": err.Error()})
		return
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes))
	if err != nil {
		writeJSON(w, http.StatusOK, map[string]any{"ok": false, "error": err.Error()})
		return
	}
	if resp.StatusCode >= 400 {
		writeJSON(w, http.StatusOK, map[string]any{
			"ok":    false,
			"error": fmt.Sprintf("discovery %d: %s", resp.StatusCode, string(body)),
		})
		return
	}
	var doc map[string]any
	if err := json.Unmarshal(body, &doc); err != nil {
		writeJSON(w, http.StatusOK, map[string]any{"ok": false, "error": "invalid JSON: " + err.Error()})
		return
	}
	doc["ok"] = true

	if jwksURI, _ := doc["jwks_uri"].(string); jwksURI != "" {
		// The discovery doc is attacker-influenceable; re-validate its jwks_uri
		// (scheme/host/credentials/https) before fetching, then route the fetch
		// through the same SSRF-hardened client.
		if err := pluginrt.ValidateFetchURL(jwksURI); err != nil {
			doc["jwks_error"] = "rejected jwks_uri: " + err.Error()
		} else if keys := fetchJWKSSummary(ctx, httpClient, jwksURI); keys != nil {
			doc["jwks_keys"] = keys
		}
	}
	writeJSON(w, http.StatusOK, doc)
}

// fetchJWKSSummary returns a stripped-down summary of the JWKS at jwksURI
// (kid/kty/alg/use only). Returns nil on any failure — the discovery handler
// degrades gracefully.
func fetchJWKSSummary(ctx context.Context, httpClient *http.Client, jwksURI string) []map[string]any {
	req, _ := http.NewRequestWithContext(ctx, "GET", jwksURI, nil)
	resp, err := httpClient.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		return nil
	}
	var doc struct {
		Keys []map[string]any `json:"keys"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&doc); err != nil {
		return nil
	}
	out := make([]map[string]any, 0, len(doc.Keys))
	for _, k := range doc.Keys {
		out = append(out, map[string]any{
			"kid": k["kid"],
			"kty": k["kty"],
			"alg": k["alg"],
			"use": k["use"],
		})
	}
	return out
}

type decodeReq struct {
	IDToken string `json:"id_token"`
}

// handleDecodeIDToken runs the supplied id_token through the live JWKS
// verifier and returns the decoded claims. Used by the SPA's Diagnostics
// panel for debugging which claims to gate on.
func (s *Server) handleDecodeIDToken(w http.ResponseWriter, r *http.Request) {
	var req decodeReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"verified": false, "error": "bad request body"})
		return
	}
	prov := s.deps.ProviderFn()
	if prov == nil {
		writeJSON(w, http.StatusOK, map[string]any{"verified": false, "error": "plugin not configured"})
		return
	}
	idToken, err := prov.Verifier().Verify(r.Context(), req.IDToken)
	if err != nil {
		writeJSON(w, http.StatusOK, map[string]any{"verified": false, "error": err.Error()})
		return
	}
	var c map[string]any
	_ = idToken.Claims(&c)
	writeJSON(w, http.StatusOK, map[string]any{"verified": true, "claims": c})
}

// simulateClaimsReq is the SPA-facing body for /simulate-claims. Filters,
// RoleMapping, and EmailVerifiedRequired are pointers so the SPA can opt to
// preview *unsaved* page state without persisting it — omit the field to fall
// back to the live config.
type simulateClaimsReq struct {
	Claims                map[string]any              `json:"claims"`
	Filters               *[]pluginrt.ClaimFilter     `json:"filters,omitempty"`
	RoleMapping           *[]pluginrt.RoleMappingRule `json:"role_mapping,omitempty"`
	EmailVerifiedRequired *bool                       `json:"email_verified_required,omitempty"`
}

// handleSimulateClaims runs the same filter / email_verified / role-mapping
// pass that ExchangeCode applies after merging id_token + userinfo, but
// against admin-supplied claims and (optionally) admin-supplied unsaved
// rules. The response is a per-filter trace + the resolved role + the
// identity that would be returned to the host. The SPA renders it as the
// "Claim simulator" panel so admins can sanity-check their rules without
// triggering a real OAuth dance.
func (s *Server) handleSimulateClaims(w http.ResponseWriter, r *http.Request) {
	var req simulateClaimsReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid JSON body"})
		return
	}
	if req.Claims == nil {
		req.Claims = map[string]any{}
	}

	cfg := s.deps.ConfigFn()
	filters := cfg.ClaimFilters
	if req.Filters != nil {
		filters = *req.Filters
	}
	mapping := cfg.ClaimRoleMapping
	if req.RoleMapping != nil {
		mapping = *req.RoleMapping
	}
	emailRequired := cfg.EmailVerifiedRequired
	if req.EmailVerifiedRequired != nil {
		emailRequired = *req.EmailVerifiedRequired
	}

	filterTrace, filtersPassed := claims.TraceFilters(req.Claims, filters)

	// Mirror ExchangeCode's email_verified evaluation via the shared helper so
	// the simulator can't drift from the real gate.
	emailVerified, emailVerifiedFound := claims.EmailVerified(req.Claims)
	emailVerifiedValue := req.Claims["email_verified"]
	emailPassed := !emailRequired || emailVerified

	role, ruleIdx := claims.TraceRole(req.Claims, mapping)

	id := claims.DeriveIdentity(req.Claims)

	writeJSON(w, http.StatusOK, map[string]any{
		"allowed":        filtersPassed && emailPassed && id.Subject != "",
		"filters_passed": filtersPassed,
		"filter_trace":   filterTrace,
		"email_verified_check": map[string]any{
			"required":    emailRequired,
			"claim_found": emailVerifiedFound,
			"claim_value": emailVerifiedValue,
			"passed":      emailPassed,
		},
		"sub_present":     id.Subject != "",
		"role":            role,
		"role_rule_index": ruleIdx,
		"identity": map[string]any{
			"sub":   id.Subject,
			"email": id.Email,
			"name":  id.DisplayName,
		},
	})
}

func writeJSON(w http.ResponseWriter, code int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(body)
}
