// Command silo-plugin-oidc-login is the entrypoint for the OIDC login
// plugin. It loads the embedded manifest, hashes its own binary for the
// checksum field, wires the runtime/http_routes/auth_provider servers, and
// hands control off to the SDK's Serve loop.
package main

import (
	"context"
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"fmt"
	"os"
	goruntime "runtime"
	"sync/atomic"

	"github.com/hashicorp/go-hclog"
	"github.com/jackc/pgx/v5/pgxpool"

	pluginv1 "github.com/ContinuumApp/continuum-plugin-sdk/pkg/pluginproto/silo/plugin/v1"
	publicmanifest "github.com/ContinuumApp/continuum-plugin-sdk/pkg/pluginsdk/manifest"
	sdkruntime "github.com/ContinuumApp/continuum-plugin-sdk/pkg/pluginsdk/runtime"

	"github.com/RXWatcher/silo-plugin-oidc-login/cmd/silo-plugin-oidc-login/assets"
	pluginadmin "github.com/RXWatcher/silo-plugin-oidc-login/internal/admin"
	pluginauth "github.com/RXWatcher/silo-plugin-oidc-login/internal/auth"
	"github.com/RXWatcher/silo-plugin-oidc-login/internal/httproutes"
	pluginoidc "github.com/RXWatcher/silo-plugin-oidc-login/internal/oidc"
	pluginrt "github.com/RXWatcher/silo-plugin-oidc-login/internal/runtime"
	"github.com/RXWatcher/silo-plugin-oidc-login/internal/server"
	"github.com/RXWatcher/silo-plugin-oidc-login/internal/store"
	"github.com/RXWatcher/silo-plugin-oidc-login/web"
)

//go:embed manifest.json
var manifestRaw []byte

func main() {
	logger := hclog.New(&hclog.LoggerOptions{Name: "silo-plugin-oidc-login"})

	manifest, err := loadManifest()
	if err != nil {
		fmt.Fprintf(os.Stderr, "load manifest: %v\n", err)
		os.Exit(1)
	}

	httpSrv := httproutes.NewServer()

	// Live config + provider live behind atomic pointers. Capability handlers
	// read them per-RPC; Configure swaps them atomically.
	var (
		cfgPtr   atomic.Pointer[pluginrt.Config]
		provPtr  atomic.Pointer[pluginoidc.Provider]
		poolPtr  atomic.Pointer[pgxpool.Pool]
		storePtr atomic.Pointer[store.Store]
	)

	authSrv := pluginauth.NewServer(
		func() pluginrt.Config {
			if p := cfgPtr.Load(); p != nil {
				return *p
			}
			return pluginrt.Config{}
		},
		func() *pluginoidc.Provider { return provPtr.Load() },
	)

	applyConfig := func(cfg pluginrt.Config) error {
		var prov *pluginoidc.Provider
		if cfg.ProviderConfigured() {
			var err error
			prov, err = pluginoidc.NewProvider(context.Background(), pluginoidc.NewArgs{
				IssuerURL:    cfg.IssuerURL,
				ClientID:     cfg.ClientID,
				ClientSecret: cfg.ClientSecret,
				Scopes:       cfg.Scopes,
			})
			if err != nil {
				return fmt.Errorf("oidc provider: %w", err)
			}
		}
		cfgPtr.Store(&cfg)
		provPtr.Store(prov)
		logger.Info("configured", "issuer_url", cfg.IssuerURL, "display_name", cfg.DisplayName, "provider_configured", cfg.ProviderConfigured())
		return nil
	}

	rt := pluginrt.New(manifest, func(cfg pluginrt.Config) error {
		if cfg.DatabaseURL == "" {
			return fmt.Errorf("database_url is required")
		}
		ctx := context.Background()
		pcfg, err := pgxpool.ParseConfig(cfg.DatabaseURL)
		if err != nil {
			return fmt.Errorf("parse database_url: %w", err)
		}
		if pcfg.MaxConns < 8 {
			pcfg.MaxConns = 8
		}
		pool, err := pgxpool.NewWithConfig(ctx, pcfg)
		if err != nil {
			return fmt.Errorf("connect database: %w", err)
		}
		if err := store.Migrate(ctx, pool); err != nil {
			pool.Close()
			return fmt.Errorf("migrate: %w", err)
		}
		st := store.New(pool)
		effective, err := st.ImportLegacyConfig(ctx, cfg)
		if err != nil {
			pool.Close()
			return fmt.Errorf("import app config: %w", err)
		}
		if err := applyConfig(effective); err != nil {
			pool.Close()
			return err
		}
		storePtr.Store(st)

		adminSrv := pluginadmin.NewServer(pluginadmin.Deps{
			ConfigFn: func() pluginrt.Config {
				if p := cfgPtr.Load(); p != nil {
					return *p
				}
				return pluginrt.Config{}
			},
			ProviderFn: func() *pluginoidc.Provider { return provPtr.Load() },
			UpdateConfigFn: func(ctx context.Context, next pluginrt.Config) error {
				st := storePtr.Load()
				if st == nil {
					return fmt.Errorf("store not configured")
				}
				if err := st.UpdateConfig(ctx, next); err != nil {
					return err
				}
				return applyConfig(next)
			},
		})

		srv := server.New(server.Deps{
			AdminHandler: adminSrv.Handler(),
			WebFS:        web.FS(),
			AssetsFS:     assets.FS(),
		})
		httpSrv.SetHandler(srv.Handler())
		if old := poolPtr.Swap(pool); old != nil {
			old.Close()
		}
		return nil
	})

	sdkruntime.Serve(sdkruntime.ServeConfig{
		Logger: logger,
		Servers: sdkruntime.CapabilityServers{
			Runtime:      rt,
			HttpRoutes:   httpSrv,
			AuthProvider: authSrv,
		},
	})
}

// loadManifest parses the embedded manifest JSON, sets the checksum field
// to the SHA-256 of the running binary, and fills SupportedPlatforms if the
// manifest didn't declare any.
func loadManifest() (*pluginv1.PluginManifest, error) {
	manifest, err := publicmanifest.Load(manifestRaw)
	if err != nil {
		return nil, fmt.Errorf("load embedded manifest: %w", err)
	}
	exe, err := os.Executable()
	if err != nil {
		return nil, fmt.Errorf("resolve executable: %w", err)
	}
	bin, err := os.ReadFile(exe)
	if err != nil {
		return nil, fmt.Errorf("read executable: %w", err)
	}
	sum := sha256.Sum256(bin)
	manifest.Checksum = hex.EncodeToString(sum[:])
	if len(manifest.GetSupportedPlatforms()) == 0 {
		manifest.SupportedPlatforms = []*pluginv1.SupportedPlatform{
			{Os: goruntime.GOOS, Arch: goruntime.GOARCH},
		}
	}
	return manifest, nil
}
