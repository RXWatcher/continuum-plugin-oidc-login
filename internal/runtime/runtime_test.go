package runtime_test

import (
	"strings"
	"testing"

	pluginv1 "github.com/ContinuumApp/continuum-plugin-sdk/pkg/pluginproto/continuum/plugin/v1"
	"google.golang.org/protobuf/types/known/structpb"

	pluginrt "github.com/ContinuumApp/continuum-plugin-oidc-login/internal/runtime"
)

func entry(key string, value any) *pluginv1.ConfigEntry {
	v, _ := structpb.NewStruct(map[string]any{"value": value})
	return &pluginv1.ConfigEntry{Key: key, Value: v}
}

func TestLoadConfig_Defaults(t *testing.T) {
	cfg, err := pluginrt.LoadConfig([]*pluginv1.ConfigEntry{
		entry("issuer_url", "https://idp.example.com/"),
		entry("client_id", "c1"),
		entry("client_secret", "s1"),
	})
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	if cfg.Scopes != "openid profile email" {
		t.Errorf("default scopes = %q", cfg.Scopes)
	}
	if cfg.DisplayName != "Sign in with OIDC" {
		t.Errorf("default display_name = %q", cfg.DisplayName)
	}
	if cfg.IconURLPath != "generic-key.svg" {
		t.Errorf("default icon = %q", cfg.IconURLPath)
	}
	if !cfg.EmailVerifiedRequired {
		t.Errorf("email_verified_required default should be true")
	}
	if cfg.LinkByEmail {
		t.Errorf("link_by_email default should be false")
	}
	if strings.HasSuffix(cfg.IssuerURL, "/") {
		t.Errorf("issuer_url should be right-trimmed: %q", cfg.IssuerURL)
	}
}

func TestLoadConfig_RequiresIssuerClient(t *testing.T) {
	_, err := pluginrt.LoadConfig(nil)
	if err == nil {
		t.Error("expected error for missing required fields")
	}
}

func TestLoadConfig_RejectsBadIcon(t *testing.T) {
	_, err := pluginrt.LoadConfig([]*pluginv1.ConfigEntry{
		entry("issuer_url", "https://idp"),
		entry("client_id", "c"),
		entry("client_secret", "s"),
		entry("icon_url_path", "../../../etc/passwd"),
	})
	if err == nil {
		t.Error("expected icon allowlist rejection")
	}
}

func TestLoadConfig_RejectsBadOperator(t *testing.T) {
	filters, _ := structpb.NewList([]any{
		map[string]any{"claim_path": "groups", "operator": "is-not-an-operator", "value": "x"},
	})
	v, _ := structpb.NewStruct(map[string]any{"value": filters.AsSlice()})
	_, err := pluginrt.LoadConfig([]*pluginv1.ConfigEntry{
		entry("issuer_url", "https://idp"),
		entry("client_id", "c"),
		entry("client_secret", "s"),
		{Key: "claim_filters", Value: v},
	})
	if err == nil {
		t.Error("expected operator rejection")
	}
}

func TestLoadConfig_RejectsBadRole(t *testing.T) {
	rules, _ := structpb.NewList([]any{
		map[string]any{"claim_path": "groups", "operator": "contains", "value": "x", "role": "superadmin"},
	})
	v, _ := structpb.NewStruct(map[string]any{"value": rules.AsSlice()})
	_, err := pluginrt.LoadConfig([]*pluginv1.ConfigEntry{
		entry("issuer_url", "https://idp"),
		entry("client_id", "c"),
		entry("client_secret", "s"),
		{Key: "claim_role_mapping", Value: v},
	})
	if err == nil {
		t.Error("expected role rejection")
	}
}

func TestLoadConfig_RejectsBadRegex(t *testing.T) {
	filters, _ := structpb.NewList([]any{
		map[string]any{"claim_path": "groups", "operator": "regex", "value": "[unclosed"},
	})
	v, _ := structpb.NewStruct(map[string]any{"value": filters.AsSlice()})
	_, err := pluginrt.LoadConfig([]*pluginv1.ConfigEntry{
		entry("issuer_url", "https://idp"),
		entry("client_id", "c"),
		entry("client_secret", "s"),
		{Key: "claim_filters", Value: v},
	})
	if err == nil {
		t.Error("expected regex compile rejection")
	}
}

func TestLoadConfig_AllowedIconAccepted(t *testing.T) {
	cfg, err := pluginrt.LoadConfig([]*pluginv1.ConfigEntry{
		entry("issuer_url", "https://idp"),
		entry("client_id", "c"),
		entry("client_secret", "s"),
		entry("icon_url_path", "authentik.svg"),
	})
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	if cfg.IconURLPath != "authentik.svg" {
		t.Errorf("icon = %q", cfg.IconURLPath)
	}
}

func TestValidateClaimPath(t *testing.T) {
	valid := []string{
		"groups",
		"email_verified",
		"realm_access.roles",
		"a.b.c",
		"_underscore",
		"resource-access.continuum.roles",
	}
	for _, p := range valid {
		if err := pluginrt.ValidateClaimPath(p); err != nil {
			t.Errorf("ValidateClaimPath(%q) unexpected err: %v", p, err)
		}
	}
	invalid := []string{
		"",          // empty
		".",         // empty segment
		"a.",        // trailing empty
		".a",        // leading empty
		"a..b",      // empty middle segment
		"1groups",   // leading digit
		"a b",       // whitespace
		"groups[0]", // bracket indexing
		"foo$",      // dollar sign
		"a.b\"c",    // quote
	}
	for _, p := range invalid {
		if err := pluginrt.ValidateClaimPath(p); err == nil {
			t.Errorf("ValidateClaimPath(%q) expected error, got nil", p)
		}
	}
}

func TestLoadConfig_RejectsBadClaimPath(t *testing.T) {
	filters, _ := structpb.NewList([]any{
		map[string]any{"claim_path": "realm_access..roles", "operator": "contains", "value": "x"},
	})
	v, _ := structpb.NewStruct(map[string]any{"value": filters.AsSlice()})
	_, err := pluginrt.LoadConfig([]*pluginv1.ConfigEntry{
		entry("issuer_url", "https://idp"),
		entry("client_id", "c"),
		entry("client_secret", "s"),
		{Key: "claim_filters", Value: v},
	})
	if err == nil {
		t.Fatal("expected claim_path rejection")
	}
	if !strings.Contains(err.Error(), "claim_path") {
		t.Errorf("error should mention claim_path, got: %v", err)
	}
}

func TestLoadConfig_FiltersAndMappingParse(t *testing.T) {
	filters, _ := structpb.NewList([]any{
		map[string]any{"claim_path": "groups", "operator": "contains", "value": "continuum-users"},
	})
	fv, _ := structpb.NewStruct(map[string]any{"value": filters.AsSlice()})

	rules, _ := structpb.NewList([]any{
		map[string]any{"claim_path": "groups", "operator": "contains", "value": "continuum-admins", "role": "admin"},
	})
	rv, _ := structpb.NewStruct(map[string]any{"value": rules.AsSlice()})

	cfg, err := pluginrt.LoadConfig([]*pluginv1.ConfigEntry{
		entry("issuer_url", "https://idp"),
		entry("client_id", "c"),
		entry("client_secret", "s"),
		{Key: "claim_filters", Value: fv},
		{Key: "claim_role_mapping", Value: rv},
	})
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	if len(cfg.ClaimFilters) != 1 || cfg.ClaimFilters[0].ClaimPath != "groups" {
		t.Errorf("filters = %+v", cfg.ClaimFilters)
	}
	if len(cfg.ClaimRoleMapping) != 1 || cfg.ClaimRoleMapping[0].Role != "admin" {
		t.Errorf("mapping = %+v", cfg.ClaimRoleMapping)
	}
}
