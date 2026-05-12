// Package web embeds the built SPA. The embed sits in web/ so it can reach
// the sibling dist/ directory; //go:embed is constrained to the package
// directory and its descendants.
package web

import (
	"embed"
	"io/fs"
)

//go:embed all:dist
var dist embed.FS

// FS returns the SPA file system rooted at dist/.
func FS() fs.FS {
	sub, err := fs.Sub(dist, "dist")
	if err != nil {
		panic("web: " + err.Error())
	}
	return sub
}
