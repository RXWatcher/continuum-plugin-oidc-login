// Package server constructs the chi-based HTTP handler the plugin's
// http_routes.v1 capability exposes:
//
//   - /api/v1/health           public health probe
//   - /api/v1/logout           public stub (RP-initiated logout is v2)
//   - /api/v1/admin/*          admin endpoints (gated by the admin handler)
//   - /assets/*                bundled icon SVGs (public)
//   - /admin, /admin/*         embedded React SPA (theme-injected HTML)
//
// embed.FS instances are passed in via Deps so this package stays free of
// filesystem-y dependencies and is testable in isolation.
package server

import (
	"encoding/json"
	"io/fs"
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
)

// Deps is the wiring this package needs from main.go.
type Deps struct {
	// AdminHandler is mounted to serve /api/v1/admin/*. Nil until Configure.
	AdminHandler http.Handler
	// WebFS is the embedded SPA filesystem rooted at the dist/ directory.
	// Nil disables /admin SPA serving.
	WebFS fs.FS
	// AssetsFS is the embedded icon filesystem with .svg files at the root.
	// Nil disables /assets/* serving.
	AssetsFS fs.FS
}

// Server holds the wired dependencies and exposes an http.Handler.
type Server struct {
	deps Deps
}

// New constructs a Server from the supplied Deps.
func New(d Deps) *Server { return &Server{deps: d} }

// Handler returns the chi router with the four route groups described in the
// package doc.
func (s *Server) Handler() http.Handler {
	r := chi.NewRouter()
	r.Use(middleware.Recoverer)
	r.Get("/api/v1/health", s.handleHealth)
	r.Post("/api/v1/logout", s.handleLogout)
	if s.deps.AdminHandler != nil {
		r.Mount("/", s.deps.AdminHandler)
	}
	if s.deps.AssetsFS != nil || s.deps.WebFS != nil {
		r.Get("/assets/*", s.handleAssets)
	}
	if s.deps.WebFS != nil {
		r.Get("/admin", s.handleSPA)
		r.Get("/admin/*", s.handleSPA)
	}
	return r
}

func (s *Server) handleHealth(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{"ok": true})
}

// handleLogout is a documentation surface: the host owns session lifecycle,
// so this plugin only acknowledges the request. RP-initiated logout against
// the upstream IdP is a v2 concern; in multi-IdP setups callers were getting
// confused expecting this endpoint to invalidate IdP sessions, so we return
// a clear 200 explaining what it does (and doesn't) do.
func (s *Server) handleLogout(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"ok":      true,
		"scope":   "local",
		"message": "local logout only; RP-initiated logout is v2",
	})
}

// handleAssets serves bundled icon SVGs from AssetsFS. The runtime.AllowedIcons
// allowlist is enforced upstream at Configure time (icon_url_path must match);
// the handler itself simply refuses paths outside the embedded filesystem.
func (s *Server) handleAssets(w http.ResponseWriter, r *http.Request) {
	relative := strings.TrimPrefix(r.URL.Path, "/assets/")
	if relative == "" || strings.Contains(relative, "..") {
		http.NotFound(w, r)
		return
	}
	if s.deps.WebFS != nil {
		if data, err := fs.ReadFile(s.deps.WebFS, "assets/"+relative); err == nil {
			writeStatic(w, "assets/"+relative, data)
			return
		}
	}
	if s.deps.AssetsFS == nil {
		http.NotFound(w, r)
		return
	}
	data, err := fs.ReadFile(s.deps.AssetsFS, relative)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	writeStatic(w, relative, data)
}

// handleSPA serves the embedded React SPA. /admin and /admin/* land on
// index.html (with data-theme injected from the host/query theme); Vite assets
// must resolve through /assets/* because /admin/* is admin-gated by the host
// and browser asset requests do not carry the initial token query parameter.
func (s *Server) handleSPA(w http.ResponseWriter, r *http.Request) {
	var rel string
	switch {
	case strings.HasPrefix(r.URL.Path, "/admin/assets/"):
		rel = "assets/" + strings.TrimPrefix(r.URL.Path, "/admin/assets/")
	case r.URL.Path == "/admin" || r.URL.Path == "/admin/" || strings.HasPrefix(r.URL.Path, "/admin/"):
		rel = "index.html"
	default:
		http.NotFound(w, r)
		return
	}
	data, err := fs.ReadFile(s.deps.WebFS, rel)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	if strings.HasSuffix(rel, ".html") {
		theme := r.URL.Query().Get("theme")
		if theme == "" {
			theme = r.Header.Get("X-Continuum-Theme")
		}
		if theme == "" {
			theme = r.Header.Get("X-Continuum-User-Theme")
		}
		if theme == "" {
			theme = "dark"
		}
		data = rewriteAdminAssetPaths(data)
		if strings.Contains(string(data), `<html lang="en">`) {
			data = []byte(strings.Replace(string(data), `<html lang="en">`, `<html lang="en" data-theme="`+theme+`">`, 1))
		} else {
			data = []byte(strings.Replace(string(data), `<html`, `<html data-theme="`+theme+`"`, 1))
		}
	}
	writeStatic(w, rel, data)
}

func rewriteAdminAssetPaths(data []byte) []byte {
	html := string(data)
	html = strings.ReplaceAll(html, `src="./assets/`, `src="../assets/`)
	html = strings.ReplaceAll(html, `href="./assets/`, `href="../assets/`)
	return []byte(html)
}

func writeStatic(w http.ResponseWriter, rel string, data []byte) {
	switch {
	case strings.HasSuffix(rel, ".html"):
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write(data)
	case strings.HasSuffix(rel, ".js"):
		w.Header().Set("Content-Type", "application/javascript")
		_, _ = w.Write(data)
	case strings.HasSuffix(rel, ".css"):
		w.Header().Set("Content-Type", "text/css")
		_, _ = w.Write(data)
	case strings.HasSuffix(rel, ".svg"):
		w.Header().Set("Content-Type", "image/svg+xml")
		_, _ = w.Write(data)
	default:
		_, _ = w.Write(data)
	}
}
