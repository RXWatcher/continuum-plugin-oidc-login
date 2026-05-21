package server_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/RXWatcher/continuum-plugin-oidc-login/internal/server"
)

func TestHealthOK(t *testing.T) {
	s := server.New(server.Deps{})
	r := httptest.NewRequest("GET", "/api/v1/health", nil)
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("code = %d", w.Code)
	}
	var body map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode body: %v", err)
	}
	if body["ok"] != true {
		t.Errorf("ok = %v", body["ok"])
	}
}

func TestLogoutStub(t *testing.T) {
	s := server.New(server.Deps{})
	r := httptest.NewRequest("POST", "/api/v1/logout", nil)
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("code = %d", w.Code)
	}
	var body map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode body: %v", err)
	}
	if body["scope"] != "local" {
		t.Errorf("scope = %v", body["scope"])
	}
	if !strings.Contains(strings.ToLower(body["message"].(string)), "v2") {
		t.Errorf("message should mention v2 limitation: %v", body["message"])
	}
}

func TestAssetsServesSVG(t *testing.T) {
	fsys := fstest.MapFS{
		"authentik.svg": &fstest.MapFile{Data: []byte("<svg></svg>")},
	}
	s := server.New(server.Deps{AssetsFS: fsys})
	r := httptest.NewRequest("GET", "/assets/authentik.svg", nil)
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("code = %d", w.Code)
	}
	if ct := w.Header().Get("Content-Type"); ct != "image/svg+xml" {
		t.Errorf("content-type = %q", ct)
	}
	if !strings.Contains(w.Body.String(), "<svg>") {
		t.Errorf("body = %q", w.Body.String())
	}
}

func TestAssetsRejectsTraversal(t *testing.T) {
	fsys := fstest.MapFS{"x.svg": &fstest.MapFile{Data: []byte("<svg/>")}}
	s := server.New(server.Deps{AssetsFS: fsys})
	r := httptest.NewRequest("GET", "/assets/../etc/passwd", nil)
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	if w.Code != http.StatusNotFound {
		t.Errorf("expected 404, got %d", w.Code)
	}
}

func TestSPAIndexHTMLThemeInjected(t *testing.T) {
	fsys := fstest.MapFS{
		"index.html": &fstest.MapFile{Data: []byte(`<!doctype html><html lang="en"><body></body></html>`)},
	}
	s := server.New(server.Deps{WebFS: fsys})
	r := httptest.NewRequest("GET", "/admin", nil)
	r.Header.Set("X-Continuum-User-Theme", "cinema-light")
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("code = %d", w.Code)
	}
	if !strings.Contains(w.Body.String(), `data-theme="cinema-light"`) {
		t.Errorf("body missing theme: %s", w.Body.String())
	}
	if ct := w.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/html") {
		t.Errorf("content-type = %q", ct)
	}
}

func TestSPASubpathFallsBack(t *testing.T) {
	fsys := fstest.MapFS{
		"index.html": &fstest.MapFile{Data: []byte(`<html lang="en"></html>`)},
	}
	s := server.New(server.Deps{WebFS: fsys})
	r := httptest.NewRequest("GET", "/admin/some/route", nil)
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	if w.Code != http.StatusOK {
		t.Errorf("code = %d", w.Code)
	}
}

func TestSPAAssetsServed(t *testing.T) {
	fsys := fstest.MapFS{
		"assets/index.js": &fstest.MapFile{Data: []byte("console.log('hi')")},
	}
	s := server.New(server.Deps{WebFS: fsys})
	r := httptest.NewRequest("GET", "/admin/assets/index.js", nil)
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("code = %d", w.Code)
	}
	if ct := w.Header().Get("Content-Type"); ct != "application/javascript" {
		t.Errorf("content-type = %q", ct)
	}
}

func TestRootAssetsServeSPAAssets(t *testing.T) {
	fsys := fstest.MapFS{
		"assets/index.js":  &fstest.MapFile{Data: []byte("console.log('hi')")},
		"assets/index.css": &fstest.MapFile{Data: []byte("body{}")},
	}
	s := server.New(server.Deps{WebFS: fsys})

	for _, tc := range []struct {
		path        string
		contentType string
	}{
		{path: "/assets/index.js", contentType: "application/javascript"},
		{path: "/assets/index.css", contentType: "text/css"},
	} {
		t.Run(tc.path, func(t *testing.T) {
			r := httptest.NewRequest("GET", tc.path, nil)
			w := httptest.NewRecorder()
			s.Handler().ServeHTTP(w, r)
			if w.Code != http.StatusOK {
				t.Fatalf("code = %d", w.Code)
			}
			if ct := w.Header().Get("Content-Type"); ct != tc.contentType {
				t.Errorf("content-type = %q", ct)
			}
		})
	}
}
