// Package server constructs the chi-based HTTP handler that the plugin's
// http_routes.v1 capability exposes. In Phase 1 it only serves /api/v1/health;
// later phases mount the admin handler and SPA serve here.
package server

import (
	"encoding/json"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
)

// Deps is the wiring this package needs from main.go.
type Deps struct {
	// AdminHandler is mounted under the chi mux to serve /api/v1/admin/*.
	// Nil during early phases / before Configure.
	AdminHandler http.Handler
}

// Server holds the wired dependencies and exposes an http.Handler.
type Server struct {
	deps Deps
}

// New constructs a Server from the supplied Deps.
func New(d Deps) *Server { return &Server{deps: d} }

// Handler builds the chi router. /api/v1/health is always public; an
// AdminHandler (if provided) is mounted to serve /api/v1/admin/*.
func (s *Server) Handler() http.Handler {
	r := chi.NewRouter()
	r.Use(middleware.Recoverer)
	r.Get("/api/v1/health", s.handleHealth)
	if s.deps.AdminHandler != nil {
		// AdminHandler uses absolute paths under /api/v1/admin/.
		r.Mount("/", s.deps.AdminHandler)
	}
	return r
}

func (s *Server) handleHealth(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{"ok": true})
}
