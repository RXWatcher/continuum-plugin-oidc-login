// Command continuum-plugin-oidc-login is the entrypoint for the OIDC login
// plugin. It loads the embedded manifest, hashes its own binary for the
// checksum field, wires the runtime/http_routes/auth_provider servers, and
// hands control off to the SDK's Serve loop.
package main

import (
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"fmt"
	"os"
	goruntime "runtime"

	"github.com/hashicorp/go-hclog"

	pluginv1 "github.com/ContinuumApp/continuum-plugin-sdk/pkg/pluginproto/continuum/plugin/v1"
	publicmanifest "github.com/ContinuumApp/continuum-plugin-sdk/pkg/pluginsdk/manifest"
	sdkruntime "github.com/ContinuumApp/continuum-plugin-sdk/pkg/pluginsdk/runtime"

	"github.com/ContinuumApp/continuum-plugin-oidc-login/internal/httproutes"
	pluginrt "github.com/ContinuumApp/continuum-plugin-oidc-login/internal/runtime"
	"github.com/ContinuumApp/continuum-plugin-oidc-login/internal/server"
)

//go:embed manifest.json
var manifestRaw []byte

func main() {
	logger := hclog.New(&hclog.LoggerOptions{Name: "continuum-plugin-oidc-login"})

	manifest, err := loadManifest()
	if err != nil {
		fmt.Fprintf(os.Stderr, "load manifest: %v\n", err)
		os.Exit(1)
	}

	httpSrv := httproutes.NewServer()

	rt := pluginrt.New(manifest, func(cfg pluginrt.Config) error {
		srv := server.New(server.Deps{})
		httpSrv.SetHandler(srv.Handler())
		logger.Info("configured", "issuer_url", cfg.IssuerURL, "display_name", cfg.DisplayName)
		return nil
	})

	sdkruntime.Serve(sdkruntime.ServeConfig{
		Logger: logger,
		Servers: sdkruntime.CapabilityServers{
			Runtime:    rt,
			HttpRoutes: httpSrv,
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
