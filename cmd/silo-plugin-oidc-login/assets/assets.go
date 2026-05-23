// Package assets embeds the bundled icon SVGs so the http_routes.v1 handler
// can serve them under /assets/. Each filename matches an entry in
// runtime.AllowedIcons; the admin SPA's IconPicker renders previews using
// the same paths.
package assets

import (
	"embed"
	"io/fs"
)

//go:embed *.svg
var fsys embed.FS

// FS returns the bundled icon filesystem rooted at the package directory.
func FS() fs.FS { return fsys }
