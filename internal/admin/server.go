// Package admin serves the plugin's admin HTTP endpoints. All endpoints under
// /api/v1/admin/ are gated on X-Continuum-User-Role: admin, except whoami
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

	pluginoidc "github.com/ContinuumApp/continuum-plugin-oidc-login/internal/oidc"
	pluginrt "github.com/ContinuumApp/continuum-plugin-oidc-login/internal/runtime"
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

// requireAdmin gates the wrapped handlers on X-Continuum-User-Role: admin.
// The continuum host stamps these headers on every authenticated request to
// plugin routes; absence (or non-admin) is rejected with 403.
func (s *Server) requireAdmin(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Continuum-User-Role") != "admin" {
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
		"user_id": r.Header.Get("X-Continuum-User-Id"),
		"role":    r.Header.Get("X-Continuum-User-Role"),
		"theme":   r.Header.Get("X-Continuum-User-Theme"),
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

	url := strings.TrimRight(cfg.IssuerURL, "/") + "/.well-known/openid-configuration"
	req, _ := http.NewRequestWithContext(ctx, "GET", url, nil)
	resp, err := http.DefaultClient.Do(req)
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
		if keys := fetchJWKSSummary(ctx, jwksURI); keys != nil {
			doc["jwks_keys"] = keys
		}
	}
	writeJSON(w, http.StatusOK, doc)
}

// fetchJWKSSummary returns a stripped-down summary of the JWKS at jwksURI
// (kid/kty/alg/use only). Returns nil on any failure — the discovery handler
// degrades gracefully.
func fetchJWKSSummary(ctx context.Context, jwksURI string) []map[string]any {
	req, _ := http.NewRequestWithContext(ctx, "GET", jwksURI, nil)
	resp, err := http.DefaultClient.Do(req)
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

func writeJSON(w http.ResponseWriter, code int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(body)
}
