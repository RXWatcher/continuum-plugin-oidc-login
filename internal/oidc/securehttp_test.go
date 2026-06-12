package oidc_test

import (
	"context"
	"net/http"
	"strings"
	"testing"
	"time"

	pluginoidc "github.com/RXWatcher/silo-plugin-oidc-login/internal/oidc"
)

// TestSecureHTTPClient_BlocksPrivateAndMetadata verifies the hardened dialer
// refuses to connect to private / loopback / metadata addresses. These are
// numeric literals so no DNS is involved; the Control hook rejects them before
// any connection is attempted.
func TestSecureHTTPClient_BlocksPrivateAndMetadata(t *testing.T) {
	client := pluginoidc.SecureHTTPClient(false)
	client.Timeout = 2 * time.Second

	blocked := []string{
		"http://127.0.0.1:80/",
		"http://10.0.0.1:80/",
		"http://192.168.1.1:80/",
		"http://169.254.169.254/latest/meta-data/", // cloud metadata
		"http://[::1]:80/",
	}
	for _, target := range blocked {
		req, _ := http.NewRequestWithContext(context.Background(), "GET", target, nil)
		resp, err := client.Do(req)
		if err == nil {
			resp.Body.Close()
			t.Errorf("SecureHTTPClient reached %q, expected block", target)
			continue
		}
		if !strings.Contains(err.Error(), "blocked") {
			t.Errorf("target %q error = %v, want a 'blocked' dial error", target, err)
		}
	}
}

// TestSecureHTTPClient_AllowLoopback lets loopback through (explicit localhost
// issuer) while still blocking private/metadata ranges.
func TestSecureHTTPClient_AllowLoopback(t *testing.T) {
	client := pluginoidc.SecureHTTPClient(true)
	client.Timeout = 2 * time.Second

	// Loopback with allowLoopback=true should NOT be blocked by the Control
	// hook. Nothing is listening, so we expect a connection-refused style error,
	// not a "blocked" error.
	req, _ := http.NewRequestWithContext(context.Background(), "GET", "http://127.0.0.1:1/", nil)
	if _, err := client.Do(req); err != nil && strings.Contains(err.Error(), "blocked") {
		t.Errorf("loopback should be permitted when allowLoopback=true, got %v", err)
	}

	// Private ranges stay blocked even with allowLoopback.
	req, _ = http.NewRequestWithContext(context.Background(), "GET", "http://10.1.2.3:80/", nil)
	if _, err := client.Do(req); err == nil || !strings.Contains(err.Error(), "blocked") {
		t.Errorf("private range must stay blocked, got %v", err)
	}
}
